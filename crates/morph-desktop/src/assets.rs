//! The exact application icon set plus the native component defaults.
use gpui_kit::{AssetSource, Result, SharedString};
use std::borrow::Cow;
gpui_kit::assets::icon_assets!(
    ApplicationIcons,
    [
        Activity,
        ArrowLeft,
        ArrowLeftRight,
        ArrowRight,
        ChevronRight,
        ChevronDown,
        CircleAlert,
        Code,
        Copy,
        Download,
        FileCheck,
        FileSearch,
        FolderOpen,
        Info,
        Layers,
        LayoutDashboard,
        Network,
        Plug,
        Plus,
        RefreshCw,
        Search,
        Settings,
        Shield,
        ShieldAlert,
        Trash,
        Upload,
        Users,
        Wallet,
        X
    ]
);
pub struct Assets;
impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if path == "branding/morph-logo.png" {
            return Ok(Some(Cow::Borrowed(include_bytes!(
                "../assets/branding/morph-logo.png"
            ))));
        }
        if let Some(bytes) = ApplicationIcons.load(path)? {
            return Ok(Some(bytes));
        }
        gpui_kit::assets::Assets.load(path)
    }
    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut files = gpui_kit::assets::Assets.list(path)?;
        files.extend(ApplicationIcons.list(path)?);
        if path.is_empty() || "branding/morph-logo.png".starts_with(path) {
            files.push("branding/morph-logo.png".into());
        }
        files.sort();
        files.dedup();
        Ok(files)
    }
}
