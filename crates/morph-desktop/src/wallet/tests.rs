use super::{Screen, WalletPane};
use crate::{design as d, i18n::Language};
use gpui_kit::{AppContext, Bounds, WindowBounds, WindowOptions, px, size};
use gpui_kit::{TestAppContext, test::TestWindowExt};
use morph_wallet::{address::Network, service::WalletView};
fn view() -> WalletView {
    WalletView { exists:true,unlocked:true,name:"本机钱包 / Local wallet".into(),public_key:String::new(),
        address:"ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdnnw7qkdnnclfkg59uzn8umtfd2kwxceqxwquc4".into(),
        settings:Some(morph_wallet::service::Settings { chain:morph_wallet::rpc::NetworkConfig{network:Network::Devnet,rpc_url:"http://127.0.0.1:18314".into(),indexer_url:"http://127.0.0.1:18314".into(),genesis_hash:format!("0x{}","01".repeat(32))},assets:vec![] }),balance:None,local_transactions:vec![] }
}
#[gpui_kit::test]
fn wallet_tabs_keep_hitboxes_and_support_keyboard_at_large_type(cx: &mut TestAppContext) {
    let (window, pane) = cx.update(|cx| {
        gpui_kit::init(cx);
        d::install(cx);
        gpui_kit::open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                    Default::default(),
                    size(px(650.), px(480.)),
                ))),
                ..Default::default()
            },
            cx,
            |w, cx| cx.new(|cx| WalletPane::new(Language::English, w, cx)),
        )
        .unwrap()
    });
    cx.update_window(window, |_, w, cx| {
        for language in [Language::English, Language::Chinese] {
            for scale in [0.9, 1.0, 1.5] {
                w.set_rem_size(px(d::BASE_FONT_SIZE * scale));
                pane.update(cx, |v, cx| {
                    v.state = Some(view());
                    v.language(language, w, cx);
                    v.screen = Screen::Home;
                });
                w.render_frame(cx);
                let baseline = (0_usize..5)
                    .map(|i| w.find(("wallet-tabs", i)).bounds())
                    .collect::<Vec<_>>();
                for (i, screen) in [
                    Screen::Home,
                    Screen::Send,
                    Screen::Receive,
                    Screen::History,
                    Screen::Settings,
                ]
                .into_iter()
                .enumerate()
                {
                    pane.update(cx, |v, cx| {
                        v.screen = screen;
                        cx.notify();
                    });
                    w.render_frame(cx);
                    for (j, bounds) in baseline.iter().enumerate() {
                        assert_eq!(
                            *bounds,
                            w.find(("wallet-tabs", j)).bounds(),
                            "tab moved on screen {i}"
                        );
                        assert!(bounds.right() <= px(650.));
                    }
                    assert!(w.find("wallet-scroll").bounds().right() <= px(650.));
                }
                w.click(("wallet-tabs", 0_usize), cx);
                w.press("end", cx);
                assert!(pane.read(cx).screen == Screen::Settings);
                w.press("home", cx);
                assert!(pane.read(cx).screen == Screen::Home);
                w.press("left", cx);
                assert!(pane.read(cx).screen == Screen::Settings);
                w.press("right", cx);
                assert!(pane.read(cx).screen == Screen::Home);
            }
        }
    })
    .unwrap();
}
#[gpui_kit::test]
fn wallet_language_preserves_payment_and_submitted_password_drops_undo_entity(
    cx: &mut TestAppContext,
) {
    let (window, pane) = cx.update(|cx| {
        gpui_kit::init(cx);
        d::install(cx);
        gpui_kit::open_window(WindowOptions::default(), cx, |w, cx| {
            cx.new(|cx| WalletPane::new(Language::English, w, cx))
        })
        .unwrap()
    });
    cx.update_window(window, |_, w, cx| {
        pane.update(cx, |v, cx| {
            v.recipient
                .update(cx, |s, cx| s.set_value("an exact recipient", w, cx));
            v.amount
                .update(cx, |s, cx| s.set_value("1.00000001", w, cx));
            v.password
                .update(cx, |s, cx| s.set_value("synthetic test password", w, cx));
            let old = v.password.entity_id();
            let secret = v.take_password(w, cx);
            assert_eq!(&*secret, "synthetic test password");
            assert_ne!(old, v.password.entity_id());
            assert!(v.password.read(cx).value().is_empty());
            v.language(Language::Chinese, w, cx);
            assert_eq!(v.recipient.read(cx).value(), "an exact recipient");
            assert_eq!(v.amount.read(cx).value(), "1.00000001");
            assert!(v.secret_delivery.is_none());
        });
    })
    .unwrap();
}

#[gpui_kit::test]
fn background_observation_does_not_release_a_pending_command(cx: &mut TestAppContext) {
    use super::worker::{Reply, Update, Worker};
    let (window, pane) = cx.update(|cx| {
        gpui_kit::init(cx);
        d::install(cx);
        gpui_kit::open_window(WindowOptions::default(), cx, |w, cx| {
            cx.new(|cx| WalletPane::new(Language::English, w, cx))
        })
        .unwrap()
    });
    let (out, receive) = std::sync::mpsc::sync_channel(2);
    let (send, _commands) = std::sync::mpsc::sync_channel(1);
    cx.update_window(window, |_, w, cx| {
        pane.update(cx, |v, cx| {
            v.worker = Some(Worker {
                send,
                receive,
                visible: Default::default(),
            });
            v.busy = true;
            out.send(Update {
                completed: false,
                result: Ok(Reply::View(Box::new(view()))),
                view: None,
            })
            .unwrap();
            v.poll(w, cx);
            assert!(v.busy, "background snapshot must not enable a second write");
            out.send(Update {
                completed: true,
                result: Err(anyhow::anyhow!("wallet.indexer_behind")),
                view: Some(Box::new(view())),
            })
            .unwrap();
            v.poll(w, cx);
            assert!(!v.busy);
            assert!(v.state.as_ref().unwrap().balance.is_none());
        });
    })
    .unwrap();
}

#[test]
fn connection_presets_preserve_network_separation_and_custom_indexers() {
    use super::ConnectionPreset as P;
    assert_eq!(P::Public.endpoint(Network::Devnet), None);
    assert_eq!(
        P::Public.endpoint(Network::Testnet),
        Some("https://testnet.ckb.dev/")
    );
    assert_eq!(
        P::Public.endpoint(Network::Mainnet),
        Some("https://mainnet.ckb.dev/")
    );
    assert_eq!(
        P::Local.endpoint(Network::Mainnet),
        Some("http://127.0.0.1:8114")
    );
    assert_eq!(
        P::Local.endpoint(Network::Devnet),
        Some("http://127.0.0.1:18114")
    );
    assert_eq!(
        P::detect(
            Network::Testnet,
            "https://testnet.ckb.dev",
            "https://testnet.ckb.dev/"
        ),
        P::Public
    );
    assert_eq!(
        P::detect(
            Network::Testnet,
            "https://testnet.ckb.dev/",
            "http://127.0.0.1:8116"
        ),
        P::Custom
    );
    assert_eq!(
        P::detect(Network::Devnet, "http://127.0.0.1:18314", ""),
        P::Custom
    );
}
