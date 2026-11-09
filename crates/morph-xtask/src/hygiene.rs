use anyhow::{Context, Result, ensure};
use std::path::Path;

/// Enforce the supported source surface, including untracked new sources. Build
/// outputs and Git objects are not source. Symlinks are never followed.
pub fn verify(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut retired = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("cannot inspect {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == ".git" || name == "target" {
                continue;
            }
            if name == "node_modules"
                || matches!(
                    name.as_ref(),
                    "package.json"
                        | "package-lock.json"
                        | "yarn.lock"
                        | "pnpm-lock.yaml"
                        | "bun.lock"
                        | "bun.lockb"
                        | ".babelrc"
                        | ".eslintrc"
                        | ".npmrc"
                )
                || name.starts_with("tsconfig") && name.ends_with(".json")
                || path.extension().and_then(|s| s.to_str()).is_some_and(|s| {
                    matches!(
                        s,
                        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts"
                    )
                })
            {
                retired.push(
                    path.strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                );
                continue;
            }
            if entry.file_type()?.is_dir() {
                pending.push(path);
            }
        }
    }
    ensure!(
        retired.is_empty(),
        "retired JavaScript/TypeScript source or build inputs remain:\n{}",
        retired.join("\n")
    );
    println!("Rust-only client/tool source surface verified");
    Ok(())
}
