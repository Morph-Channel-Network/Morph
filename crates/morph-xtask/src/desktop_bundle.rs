//! Local native bundle staging. No release/upload operation is performed.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::Command,
};
#[derive(Deserialize)]
struct Package {
    id: String,
    name: String,
    version: String,
    license: Option<String>,
    license_file: Option<PathBuf>,
    repository: Option<String>,
    manifest_path: PathBuf,
    source: Option<String>,
}
#[derive(Deserialize)]
struct Node {
    id: String,
    deps: Vec<Edge>,
}
#[derive(Deserialize)]
struct Edge {
    pkg: String,
    dep_kinds: Vec<Kind>,
}
#[derive(Deserialize)]
struct Kind {
    kind: Option<String>,
}
#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}
#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    resolve: Resolve,
}
fn copy_tree(source: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        let ty = entry.file_type()?;
        ensure!(
            !ty.is_symlink(),
            "source bundle refuses symlinks: {}",
            entry.path().display()
        );
        if ty.is_dir() {
            copy_tree(&entry.path(), &dest.join(name))?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), dest.join(name))?;
        }
    }
    Ok(())
}
fn sha(path: &Path) -> Result<String> {
    Ok(morph_sdk::gateway::sha256_hex(&std::fs::read(path)?)
        .trim_start_matches("0x")
        .into())
}
pub fn stage(binary: &Path, output: &Path) -> Result<()> {
    ensure!(!output.exists(), "desktop staging directory must be new");
    ensure!(binary.is_file(), "build the native desktop binary first");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let platform = format!("{}-unknown-linux-gnu", std::env::consts::ARCH);
    let result = Command::new("cargo")
        .current_dir(&root)
        .args([
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--filter-platform",
            &platform,
        ])
        .output()?;
    ensure!(
        result.status.success(),
        "cargo metadata failed; no bundle staged"
    );
    let metadata: Metadata = serde_json::from_slice(&result.stdout)?;
    let packages = metadata
        .packages
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect::<BTreeMap<_, _>>();
    let nodes = metadata
        .resolve
        .nodes
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect::<BTreeMap<_, _>>();
    let desktop = metadata
        .packages
        .iter()
        .find(|p| p.name == "morph-desktop")
        .context("desktop package missing")?;
    let mut wanted = BTreeSet::new();
    let mut pending = vec![desktop.id.as_str()];
    while let Some(id) = pending.pop() {
        if !wanted.insert(id) {
            continue;
        }
        let node = nodes.get(id).context("missing dependency graph node")?;
        for dep in &node.deps {
            if dep
                .dep_kinds
                .iter()
                .any(|k| k.kind.as_deref() != Some("dev"))
            {
                pending.push(&dep.pkg);
            }
        }
    }
    std::fs::create_dir_all(output.join("sources/registry"))?;
    std::fs::create_dir_all(output.join("sources/patched"))?;
    std::fs::create_dir_all(output.join("sources/git"))?;
    std::fs::create_dir_all(output.join("licenses"))?;
    std::fs::create_dir_all(output.join("bin"))?;
    std::fs::copy(binary, output.join("bin/morph-desktop"))?;
    let mut notices = String::from(
        "# Morph native dependency notices\n\nThis local Linux build carries exact published registry source archives, modified consumer sources and pinned Git sources for its normal/build dependency closure. Their original license/copyright notices remain in those sources. MPL source archives and notices are also provided under `sources/mpl` and `licenses/native-desktop`. No Node or browser runtime is bundled.\n\n",
    );
    let mut rows = Vec::new();
    for id in wanted {
        let p = packages.get(id).context("missing package metadata")?;
        let base = p.manifest_path.parent().context("missing package root")?;
        let name = format!("{}-{}", p.name, p.version);
        notices.push_str(&format!(
            "## {name}\n\nLicense: {}\n\nUpstream: {}\n\n",
            p.license.as_deref().unwrap_or("license-file"),
            p.repository
                .as_deref()
                .unwrap_or("see original source manifest")
        ));
        let kind = if p
            .source
            .as_deref()
            .is_some_and(|s| s.starts_with("registry+"))
        {
            let index = base.parent().context("missing registry index")?;
            let registry = index
                .parent()
                .and_then(Path::parent)
                .context("missing registry cache")?;
            let archive = registry
                .join("cache")
                .join(index.file_name().context("missing index name")?)
                .join(format!("{name}.crate"));
            ensure!(
                archive.is_file(),
                "missing exact published source archive for {name}"
            );
            std::fs::copy(
                &archive,
                output
                    .join("sources/registry")
                    .join(format!("{name}.crate")),
            )?;
            "registry_archive"
        } else if p.source.as_deref().is_some_and(|s| s.starts_with("git+")) {
            copy_tree(base, &output.join("sources/git").join(&name))?;
            // Workspace-level upstream notices may sit above a Git package.
            for ancestor in base.ancestors().take(4) {
                for file in ["LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE"] {
                    let f = ancestor.join(file);
                    if f.is_file() {
                        std::fs::copy(
                            f,
                            output
                                .join("sources/git")
                                .join(&name)
                                .join(format!("workspace-{file}")),
                        )?;
                    }
                }
            }
            "pinned_git_source"
        } else if base.starts_with(root.join("vendor")) {
            copy_tree(base, &output.join("sources/patched").join(&name))?;
            "verified_patched_source"
        } else {
            // Morph's complete source is recorded by the clean-candidate Git/tree hashes.
            copy_tree(base, &output.join("sources/morph").join(&p.name))?;
            "morph_source"
        };
        for entry in std::fs::read_dir(base)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let file = entry.file_name().to_string_lossy().into_owned();
            let upper = file.to_ascii_uppercase();
            if ["LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"]
                .iter()
                .any(|prefix| upper.starts_with(prefix))
            {
                let text =
                    std::fs::read_to_string(entry.path()).context("non-text license notice")?;
                notices.push_str(&format!("### {file}\n\n```text\n{text}\n```\n\n"));
            }
        }
        if let Some(file) = &p.license_file {
            let file = if file.is_absolute() {
                file.clone()
            } else {
                base.join(file)
            };
            if file.is_file() {
                notices.push_str(&format!(
                    "```text\n{}\n```\n\n",
                    std::fs::read_to_string(file)?
                ));
            }
        }
        rows.push(json!({"name":p.name,"version":p.version,"license":p.license,"repository":p.repository,"source":p.source,"source_kind":kind}));
    }
    copy_tree(
        &root.join("vendor/redistribution"),
        &output.join("sources/mpl"),
    )?;
    copy_tree(&root.join("vendor/licenses"), &output.join("licenses"))?;
    for file in ["Cargo.lock", "Cargo.toml", "rust-toolchain.toml", "LICENSE"] {
        std::fs::copy(root.join(file), output.join(file))?;
    }
    std::fs::copy(
        root.join("vendor/provenance.json"),
        output.join("vendor-provenance.json"),
    )?;
    std::fs::copy(
        root.join("docs/native-gui-dependencies.md"),
        output.join("native-gui-dependencies.md"),
    )?;
    std::fs::copy(
        root.join("docs/native-desktop.md"),
        output.join("README.md"),
    )?;
    std::fs::write(output.join("THIRD_PARTY_NOTICES.md"), notices)?;
    let commit = Command::new("git")
        .current_dir(&root)
        .args(["rev-parse", "HEAD"])
        .output()?;
    ensure!(commit.status.success(), "missing source commit");
    let dirty = Command::new("git")
        .current_dir(&root)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()?;
    ensure!(dirty.status.success(), "cannot read source status");
    let manifest = json!({"schema":"morph.native_desktop_bundle.v1","platform":platform,"binary_sha256":sha(&output.join("bin/morph-desktop"))?,"cargo_lock_sha256":sha(&root.join("Cargo.lock"))?,"vendor_provenance_sha256":sha(&root.join("vendor/provenance.json"))?,"source_commit":String::from_utf8(commit.stdout)?.trim(),"tracked_clean":dirty.stdout.is_empty(),"published":false,"packages":rows});
    std::fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}
