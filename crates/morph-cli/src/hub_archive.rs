//! Explicit transport conversion. Private persistence never consumes public DTO
//! bytes, and public archives never deserialize directly into runtime state.
use super::*;
use morph_hub_api::admin::*;

macro_rules! enum_pair {
    ($out:ident, $input:ident, $core:ident, $api:ident, [$($variant:ident),+]) => {
        fn $out(value: $core) -> $api { match value { $($core::$variant => $api::$variant,)+ } }
        fn $input(value: $api) -> $core { match value { $($api::$variant => $core::$variant,)+ } }
    }
}
enum_pair!(
    network_out,
    network_in,
    MorphNetwork,
    ArchiveNetwork,
    [Devnet, Testnet, Mainnet]
);
enum_pair!(
    phase_out,
    phase_in,
    Phase,
    ArchivePhase,
    [Funding, Active, Settling, Closed]
);
enum_pair!(
    status_out,
    status_in,
    MorphInvoiceStatus,
    ArchiveInvoiceStatus,
    [Open, Received, Paid, Cancelled, Expired]
);
enum_pair!(
    flow_out,
    flow_in,
    MorphBusinessFlow,
    ArchiveFlow,
    [
        PeerConnected,
        InvoiceCreated,
        InvoiceReceived,
        InvoiceSettled,
        ChannelOpened,
        StatePublished,
        ChannelFinalised,
        ChannelSpliced,
        FactoryOpened,
        FactoryAdvanced,
        FactoryChildMaterialised
    ]
);

fn balance_out(value: MorphAssetBalance) -> ArchiveBalance {
    ArchiveBalance {
        asset: match value.asset {
            MorphAsset::Ckb => AssetRequest::Ckb {},
            MorphAsset::Xudt(hash) => AssetRequest::Xudt {
                type_hash: hex_prefixed(&hash),
            },
        },
        local: value.local.to_string(),
        remote: value.remote.to_string(),
        pending: value.pending.to_string(),
    }
}
// A balance may be zero, unlike a new invoice's required positive amount.
fn archive_amount(label: &str, value: &str, asset: &MorphAsset) -> Result<u128> {
    if value == "0" {
        Ok(0)
    } else {
        parse_amount_for_asset(label, value, asset)
    }
}
fn balance_in(value: ArchiveBalance) -> Result<MorphAssetBalance> {
    let asset = parse_asset(Some(value.asset))?;
    let balance = MorphAssetBalance {
        local: archive_amount("local", &value.local, &asset)?,
        remote: archive_amount("remote", &value.remote, &asset)?,
        pending: archive_amount("pending", &value.pending, &asset)?,
        asset,
    };
    balance.total()?;
    Ok(balance)
}
impl From<PersistedHubState> for StateArchive {
    fn from(value: PersistedHubState) -> Self {
        Self {
            pubkey: value.pubkey,
            network: network_out(value.network),
            peers: value
                .peers
                .into_iter()
                .map(|p| ArchivePeer {
                    pubkey: p.pubkey,
                    alias: p.alias,
                })
                .collect(),
            channels: value
                .channels
                .into_iter()
                .map(|c| ArchiveChannel {
                    channel_id: c.channel_id,
                    counterparty_pubkey: c.counterparty_pubkey,
                    funding_epoch: c.funding_epoch,
                    funding_context_id: c.funding_context_id,
                    state_number: c.state_number,
                    phase: phase_out(c.phase),
                    balances: c.balances.into_iter().map(balance_out).collect(),
                    sponsor_budget: c.sponsor_budget,
                })
                .collect(),
            factories: value
                .factories
                .into_iter()
                .map(|f| ArchiveFactory {
                    factory_id: f.factory_id,
                    participant_pubkeys: f.participant_pubkeys,
                    update_number: f.update_number,
                    reserve_balances: f.reserve_balances.into_iter().map(balance_out).collect(),
                    materialised_child_channels: f.materialised_child_channels,
                })
                .collect(),
            conditional_batches: value.conditional_batches,
            multi_asset_packages: value.multi_asset_packages,
            root_fundings: value.root_fundings,
            // The encoded invoice already binds all signed fields. Do not add
            // a second editable copy of its amount, identity or signature.
            invoices: value
                .invoices
                .into_iter()
                .map(|i| ArchiveInvoice {
                    encoded_invoice: i.encoded_invoice,
                    status: status_out(i.status),
                    received_at_unix: i.received_at_unix,
                    paid_at_unix: i.paid_at_unix,
                    cancelled_at_unix: i.cancelled_at_unix,
                })
                .collect(),
            completed_flows: value.completed_flows.into_iter().map(flow_out).collect(),
            events: value
                .events
                .into_iter()
                .map(|e| ArchiveEvent {
                    id: e.id,
                    severity: e.severity,
                    event: e.event,
                    subject_id: e.subject_id.map(|id| hex_prefixed(&id)),
                    message: e.message,
                    created_at_unix: e.created_at_unix,
                })
                .collect(),
        }
    }
}
impl TryFrom<StateArchive> for PersistedHubState {
    type Error = anyhow::Error;
    fn try_from(value: StateArchive) -> Result<Self> {
        Ok(Self {
            pubkey: value.pubkey,
            network: network_in(value.network),
            peers: value
                .peers
                .into_iter()
                .map(|p| PersistedPeer {
                    pubkey: p.pubkey,
                    alias: p.alias,
                })
                .collect(),
            channels: value
                .channels
                .into_iter()
                .map(|c| {
                    Ok(PersistedChannel {
                        channel_id: c.channel_id,
                        counterparty_pubkey: c.counterparty_pubkey,
                        funding_epoch: c.funding_epoch,
                        funding_context_id: c.funding_context_id,
                        state_number: c.state_number,
                        phase: phase_in(c.phase),
                        balances: c
                            .balances
                            .into_iter()
                            .map(balance_in)
                            .collect::<Result<_>>()?,
                        sponsor_budget: c.sponsor_budget,
                    })
                })
                .collect::<Result<_>>()?,
            factories: value
                .factories
                .into_iter()
                .map(|f| {
                    Ok(PersistedFactory {
                        factory_id: f.factory_id,
                        participant_pubkeys: f.participant_pubkeys,
                        update_number: f.update_number,
                        reserve_balances: f
                            .reserve_balances
                            .into_iter()
                            .map(balance_in)
                            .collect::<Result<_>>()?,
                        materialised_child_channels: f.materialised_child_channels,
                    })
                })
                .collect::<Result<_>>()?,
            conditional_batches: value.conditional_batches,
            multi_asset_packages: value.multi_asset_packages,
            root_fundings: value.root_fundings,
            invoices: value
                .invoices
                .into_iter()
                .map(|i| {
                    let invoice = MorphInvoice::decode(&i.encoded_invoice)?;
                    ensure!(
                        invoice.encode() == i.encoded_invoice,
                        "invoice encoding must be canonical"
                    );
                    Ok(StoredMorphInvoice {
                        invoice,
                        encoded_invoice: i.encoded_invoice,
                        status: status_in(i.status),
                        received_at_unix: i.received_at_unix,
                        paid_at_unix: i.paid_at_unix,
                        cancelled_at_unix: i.cancelled_at_unix,
                    })
                })
                .collect::<Result<_>>()?,
            completed_flows: value.completed_flows.into_iter().map(flow_in).collect(),
            events: value
                .events
                .into_iter()
                .map(|e| {
                    Ok(HubEvent {
                        id: e.id,
                        severity: e.severity,
                        event: e.event,
                        subject_id: e
                            .subject_id
                            .map(|id| parse_bytes32("event subject_id", &id))
                            .transpose()?,
                        message: e.message,
                        created_at_unix: e.created_at_unix,
                    })
                })
                .collect::<Result<_>>()?,
        })
    }
}
