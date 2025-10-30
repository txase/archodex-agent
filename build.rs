use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::Context;
use git2::Repository;
use libbpf_cargo::SkeletonBuilder;
use semver::Version;
use serde::Deserialize;

const BPF_C_FILENAME_EXT: &str = ".bpf.c";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cargo_manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");

    let dotenv_path = PathBuf::from(&cargo_manifest_dir)
        .join(".vscode")
        .join(".env");

    match dotenvy::from_path(&dotenv_path) {
        Ok(()) => {}
        Err(dotenvy::Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "Failed to load .env file from path '{}'",
                    dotenv_path.display()
                )
            });
        }
    }
    println!("cargo:rerun-if-changed={}", dotenv_path.to_string_lossy());

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap_or_else(|_| panic!("Failed to install AWS LC PKI provider"));

    let src_dir = PathBuf::from(&cargo_manifest_dir).join("src");

    let proto_files = vec![src_dir.join("report_api_key.proto")];

    prost_build::compile_protos(&proto_files, &[&src_dir])?;

    for proto_file in proto_files {
        println!("cargo:rerun-if-changed={}", proto_file.to_string_lossy());
    }

    let src_bpf_path = src_dir.join("bpf");

    let src_bpfs = fs::read_dir(src_bpf_path)?
        .map(|dir_entry| {
            dir_entry
                .expect("Failed to read DirEntry for file")
                .file_name()
                .to_str()
                .expect("Failed to read filename from DirEntry")
                .to_owned()
        })
        .filter(|filename| filename.ends_with(BPF_C_FILENAME_EXT))
        .map(|bpf_c_filename| {
            bpf_c_filename[..bpf_c_filename.len() - BPF_C_FILENAME_EXT.len()].to_owned()
        });

    let skel_dir = src_dir
        .join("skel")
        .join(std::env::var("CARGO_CFG_TARGET_ARCH").unwrap());

    fs::create_dir_all(&skel_dir).expect("Failed to create BPF skeleton directory");

    for src_bpf in src_bpfs {
        let out = skel_dir.join(format!("{src_bpf}.skel.rs"));

        let src_path = src_dir.join("bpf").join(format!("{src_bpf}.bpf.c"));

        SkeletonBuilder::new()
            .source(&src_path)
            .clang_args([
                &format!("-I/usr/include/{}-linux-gnu", std::env::consts::ARCH),
                "-Wextra",
                "-Wno-unused-parameter",
                "-Werror",
                "-mcpu=v4",
            ])
            .build_and_generate(&out)
            .unwrap_or_else(|err| panic!("Failed to build and generate skeleton: {err:#?}"));
    }

    println!(
        "cargo:rerun-if-changed={}",
        src_dir.join("bpf").to_string_lossy()
    );

    fetch_rulesets(&cargo_manifest_dir).await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ArchodexRules<'a> {
    #[serde(borrow)]
    rules: Vec<&'a str>,
}

#[allow(clippy::too_many_lines)]
async fn fetch_rulesets(cargo_manifest_dir: &OsString) -> anyhow::Result<()> {
    let ruleset_dir = Path::join(Path::new(cargo_manifest_dir), "archodex-rulesets");

    if ruleset_dir.exists() {
        fs::remove_dir_all(&ruleset_dir).with_context(|| {
            format!(
                "Failed to delete existing ruleset directory '{}'",
                ruleset_dir.display()
            )
        })?;
    }

    fs::create_dir_all(Path::join(&ruleset_dir, "enabled")).with_context(|| {
        format!(
            "Failed to create ruleset enabled directory '{}/enabled'",
            ruleset_dir.display()
        )
    })?;
    fs::create_dir_all(Path::join(&ruleset_dir, "disabled")).with_context(|| {
        format!(
            "Failed to create ruleset disabled directory '{}/disabled'",
            ruleset_dir.display()
        )
    })?;

    let repo = Repository::open(cargo_manifest_dir).with_context(
        || "Failed to open source directory as a git repo to check for tags on the current commit",
    )?;

    let mut repo_status_options = git2::StatusOptions::new();
    repo_status_options.include_untracked(true);
    let repo_statuses = repo.statuses(Some(&mut repo_status_options))?;

    let mut max_tag = None;
    if repo_statuses.is_empty() {
        for name in repo.tag_names(Some("v*"))?.iter().flatten() {
            if let Some(stripped) = name.strip_prefix('v')
                && let Ok(ver) = Version::parse(stripped)
                && max_tag.as_ref().is_none_or(|t| ver > *t)
            {
                max_tag = Some(ver);
            }
        }

        if let Some(ver) = &max_tag {
            println!("cargo::warning=Building with rulesets for agent version {ver}");
        } else {
            println!(
                "cargo::warning=No release tags found for current commit, building with dev rulesets"
            );
        }
    } else {
        println!("cargo::warning=Not a clean git state, building with dev rulesets");
    }

    let domain = env::var("ARCHODEX_DOMAIN").unwrap_or_else(|_| "archodex.com".to_owned());
    let url_prefix = match max_tag {
        Some(version) => format!("https://rules.{domain}/agent-v{version}"),
        None => format!("https://rules.{domain}/dev"),
    };

    let rules_url = format!("{url_prefix}/rules.json");
    let resp = reqwest::get(&rules_url)
        .await
        .with_context(|| format!("Failed to fetch {rules_url}"))?
        .error_for_status()
        .with_context(|| format!("Failed to fetch {rules_url}"))?
        .text()
        .await
        .with_context(|| format!("Failed to fetch {rules_url}"))?;

    let parsed: ArchodexRules = serde_json::from_str(&resp)
        .with_context(|| format!("Failed to parse rules from {rules_url}"))?;

    let rules = parsed
        .rules
        .into_iter()
        .map(|rule| format!("{rule}.yaml"))
        .collect::<HashSet<_>>();

    let mut joinset = tokio::task::JoinSet::new();

    for rule in rules {
        let url = format!("{url_prefix}/{rule}");
        let ruleset_dir = ruleset_dir.clone();
        joinset.spawn(async move {
            #[derive(Deserialize)]
            #[serde(rename_all = "PascalCase")]
            struct RulesetEnableCheck {
                default: Option<bool>,
            }

            let ruleset = reqwest::get(&url)
                .await
                .with_context(|| format!("Failed to fetch ruleset from {url}"))?
                .error_for_status()
                .with_context(|| format!("Failed to fetch ruleset from {url}"))?
                .text()
                .await
                .with_context(|| format!("Failed to fetch ruleset from {url}"))?;

            let enable_check: RulesetEnableCheck =
                serde_yaml::from_str(&ruleset).with_context(|| {
                    format!(
                        "Failed to parse ruleset from {url} to check if it has a `Default` value"
                    )
                })?;

            let rule_path = if let Some(true) = enable_check.default {
                ruleset_dir.join("enabled").join(&rule)
            } else {
                ruleset_dir.join("disabled").join(&rule)
            };

            fs::write(&rule_path, ruleset)
                .with_context(|| format!("Failed to write ruleset to '{}'", rule_path.display()))?;

            println!(
                "cargo::warning=Downloaded ruleset from: {url} to: '{}'",
                rule_path.display()
            );

            anyhow::Ok(())
        });
    }

    while let Some(res) = joinset.join_next().await {
        res??;
    }

    Ok(())
}
