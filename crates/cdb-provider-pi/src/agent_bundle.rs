use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::{MODEL, THINKING};

pub const LEGACY_EXTRACTION_FILES: [&str; 9] = [
    "extensions/ctxql-ontology-tool.ts",
    "profiles/acquisition.toml",
    "prompts/ctxql-acquisition-v1.md",
    "prompts/ctxql-acquisition-v2.md",
    "prompts/provider-system-v2.md",
    "prompts/provider-system.md",
    "skills/graph-workspace/SKILL.md",
    "skills/read-loan-agreement-v2/SKILL.md",
    "skills/read-loan-agreement/SKILL.md",
];

pub const EXTRACTION_FILES: [&str; 11] = [
    "extensions/ctxql-ontology-tool.ts",
    "profiles/acquisition.toml",
    "prompts/ctxql-acquisition-v1.md",
    "prompts/ctxql-acquisition-v2.md",
    "prompts/provider-system-v2.md",
    "prompts/provider-system.md",
    "skills/ctxql-ontology/SKILL.md",
    "skills/ctxql-query/SKILL.md",
    "skills/graph-workspace/SKILL.md",
    "skills/read-loan-agreement-v2/SKILL.md",
    "skills/read-loan-agreement/SKILL.md",
];

pub const CHAT_FILES: [&str; 6] = [
    "extensions/ctxql-ontology-tool.ts",
    "profiles/chat.toml",
    "prompts/provider-chat.md",
    "skills/ctxql-answer/SKILL.md",
    "skills/ctxql-ontology/SKILL.md",
    "skills/ctxql-query/SKILL.md",
];

/// Compatibility name for callers that explicitly use the live extraction closure.
pub const APPROVED_FILES: [&str; 11] = EXTRACTION_FILES;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BundleProfile {
    Extraction,
    Chat,
}
impl BundleProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Extraction => "extraction",
            Self::Chat => "chat",
        }
    }

    fn files(self) -> &'static [&'static str] {
        match self {
            Self::Extraction => &EXTRACTION_FILES,
            Self::Chat => &CHAT_FILES,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BundleManifest {
    pub schema: &'static str,
    pub profile: BundleProfile,
    pub model: &'static str,
    pub thinking: &'static str,
    pub files: Vec<BundleFile>,
}

#[derive(Debug, Eq, PartialEq)]
struct StagedRoot(PathBuf);
impl Drop for StagedRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentBundle {
    pub root: PathBuf,
    pub hash: String,
    pub manifest: BundleManifest,
    staged: Option<Arc<StagedRoot>>,
}
static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

impl AgentBundle {
    pub fn profile(&self) -> BundleProfile {
        self.manifest.profile
    }

    pub fn system_prompt(&self) -> Result<String, BundleError> {
        self.require_profile(BundleProfile::Extraction)?;
        self.versioned_system_prompt("provider-system.md", "ctxql-acquisition-v1.md")
    }

    pub fn system_prompt_v2(&self) -> Result<String, BundleError> {
        self.require_profile(BundleProfile::Extraction)?;
        self.versioned_system_prompt("provider-system-v2.md", "ctxql-acquisition-v2.md")
    }

    /// Compose verified chat instructions eagerly because chat exposes no skill
    /// loader or filesystem tool. Ordering is part of the trusted prompt.
    pub fn chat_system_prompt(&self) -> Result<String, BundleError> {
        self.require_profile(BundleProfile::Chat)?;
        let mut parts = vec![read_text(&self.root, "prompts/provider-chat.md")?];
        for skill in ["ctxql-ontology", "ctxql-query", "ctxql-answer"] {
            parts.push(read_text(&self.root, &format!("skills/{skill}/SKILL.md"))?);
        }
        Ok(parts
            .into_iter()
            .map(|part| part.trim_end().to_owned())
            .collect::<Vec<_>>()
            .join("\n\n"))
    }

    pub fn stage_verified(&self) -> Result<Self, BundleError> {
        let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let destination =
            std::env::temp_dir().join(format!("ctxql-pi-bundle-{}-{sequence}", std::process::id()));
        fs::create_dir(&destination).map_err(|_| BundleError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
                .map_err(|_| BundleError::Io)?;
        }
        let staged = Arc::new(StagedRoot(destination.clone()));
        for file in &self.manifest.files {
            let source = self.root.join(&file.path);
            let metadata = fs::symlink_metadata(&source).map_err(|_| BundleError::Io)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || fs::canonicalize(&source).map_err(|_| BundleError::Io)? != source
            {
                return Err(BundleError::UnsafeFile);
            }
            let target = destination.join(&file.path);
            fs::create_dir_all(target.parent().ok_or(BundleError::Io)?)
                .map_err(|_| BundleError::Io)?;
            let bytes = fs::read(&source).map_err(|_| BundleError::Io)?;
            use std::io::Write;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(|_| BundleError::Io)?;
            output.write_all(&bytes).map_err(|_| BundleError::Io)?;
            output.sync_all().map_err(|_| BundleError::Io)?;
        }
        let mut verified = hash_agent_bundle_for_profile(&destination, self.profile())?;
        if verified.hash != self.hash || verified.manifest != self.manifest {
            return Err(BundleError::WrongClosure);
        }
        let source_now = hash_agent_bundle_for_profile(&self.root, self.profile())?;
        if source_now.hash != self.hash || source_now.manifest != self.manifest {
            return Err(BundleError::WrongClosure);
        }
        verified.staged = Some(staged);
        Ok(verified)
    }

    fn require_profile(&self, profile: BundleProfile) -> Result<(), BundleError> {
        (self.profile() == profile)
            .then_some(())
            .ok_or(BundleError::WrongProfile)
    }

    fn versioned_system_prompt(
        &self,
        provider: &str,
        acquisition: &str,
    ) -> Result<String, BundleError> {
        let provider = read_text(&self.root, &format!("prompts/{provider}"))?;
        let acquisition = read_text(&self.root, &format!("prompts/{acquisition}"))?;
        Ok(format!(
            "{}\n\n{}",
            provider.trim_end(),
            acquisition.trim_end()
        ))
    }
}

fn read_text(root: &Path, relative: &str) -> Result<String, BundleError> {
    fs::read_to_string(root.join(relative)).map_err(|_| BundleError::Io)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecordedAssets {
    pub schema: String,
    pub profile: BundleProfile,
    pub model: String,
    pub thinking: String,
    pub files: Vec<BundleFile>,
    pub assets: BTreeMap<String, String>,
    pub hash: String,
}
impl VerifiedRecordedAssets {
    pub fn is_legacy_v1(&self) -> bool {
        self.schema == "ctxql.pi-agent-bundle/v1"
    }

    pub fn required_graph_skills(&self) -> &'static [&'static str] {
        if self.is_legacy_v1() {
            &["read-loan-agreement-v2", "graph-workspace"]
        } else {
            &[
                "read-loan-agreement-v2",
                "ctxql-ontology",
                "ctxql-query",
                "graph-workspace",
            ]
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedManifestV1 {
    schema: String,
    model: String,
    thinking: String,
    files: Vec<BundleFile>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedManifestV2 {
    schema: String,
    profile: BundleProfile,
    model: String,
    thinking: String,
    files: Vec<BundleFile>,
}

/// Verify retained bundle bytes as data. This never stages or executes the
/// recorded extension and never consults mutable live assets.
pub fn verify_recorded_assets(
    manifest: &serde_json::Value,
    assets: &BTreeMap<String, String>,
    expected_hash: &str,
) -> Result<VerifiedRecordedAssets, BundleError> {
    let schema = manifest
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or(BundleError::WrongClosure)?;
    let (profile, model, thinking, files, encoded) = match schema {
        "ctxql.pi-agent-bundle/v1" => {
            let value: RecordedManifestV1 =
                serde_json::from_value(manifest.clone()).map_err(|_| BundleError::WrongClosure)?;
            if paths(&value.files) != LEGACY_EXTRACTION_FILES {
                return Err(BundleError::WrongClosure);
            }
            let encoded = serde_json::to_vec(&value).map_err(|_| BundleError::Serialize)?;
            (
                BundleProfile::Extraction,
                value.model,
                value.thinking,
                value.files,
                encoded,
            )
        }
        "ctxql.pi-agent-bundle/v2" => {
            let value: RecordedManifestV2 =
                serde_json::from_value(manifest.clone()).map_err(|_| BundleError::WrongClosure)?;
            if paths(&value.files) != value.profile.files() {
                return Err(BundleError::WrongClosure);
            }
            let encoded = serde_json::to_vec(&value).map_err(|_| BundleError::Serialize)?;
            (
                value.profile,
                value.model,
                value.thinking,
                value.files,
                encoded,
            )
        }
        _ => return Err(BundleError::WrongClosure),
    };
    // Both supported extraction schemas bind the same pinned provider identity.
    // A self-consistent hash is not evidence that an arbitrary identity is supported.
    if model != MODEL || thinking != THINKING {
        return Err(BundleError::WrongClosure);
    }
    if profile != BundleProfile::Extraction || sha256(&encoded) != expected_hash {
        return Err(BundleError::WrongClosure);
    }
    if files.len() != assets.len() {
        return Err(BundleError::WrongClosure);
    }
    for file in &files {
        let bytes = assets
            .get(&file.path)
            .ok_or(BundleError::WrongClosure)?
            .as_bytes();
        if bytes.len() as u64 != file.size || sha256(bytes) != file.sha256 {
            return Err(BundleError::WrongClosure);
        }
    }
    Ok(VerifiedRecordedAssets {
        schema: schema.to_owned(),
        profile,
        model,
        thinking,
        files,
        assets: assets.clone(),
        hash: expected_hash.to_owned(),
    })
}

fn paths(files: &[BundleFile]) -> Vec<&str> {
    files.iter().map(|file| file.path.as_str()).collect()
}

#[derive(Debug)]
pub enum BundleError {
    Io,
    UnsafeFile,
    WrongClosure,
    WrongProfile,
    Serialize,
}
impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BundleError {}

/// Extraction convenience wrapper retained for existing callers.
pub fn hash_agent_bundle(root: impl AsRef<Path>) -> Result<AgentBundle, BundleError> {
    hash_agent_bundle_for_profile(root, BundleProfile::Extraction)
}

pub fn hash_agent_bundle_for_profile(
    root: impl AsRef<Path>,
    profile: BundleProfile,
) -> Result<AgentBundle, BundleError> {
    let requested_root = root.as_ref();
    let metadata = fs::symlink_metadata(requested_root).map_err(|_| BundleError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(BundleError::UnsafeFile);
    }
    let root = fs::canonicalize(requested_root).map_err(|_| BundleError::Io)?;
    let mut files = Vec::new();
    for relative in profile.files() {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|_| BundleError::WrongClosure)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || fs::canonicalize(&path).map_err(|_| BundleError::Io)? != path
        {
            return Err(BundleError::UnsafeFile);
        }
        let bytes = fs::read(path).map_err(|_| BundleError::Io)?;
        files.push(BundleFile {
            path: (*relative).to_owned(),
            sha256: sha256(&bytes),
            size: bytes.len() as u64,
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = BundleManifest {
        schema: "ctxql.pi-agent-bundle/v2",
        profile,
        model: MODEL,
        thinking: THINKING,
        files,
    };
    let canonical = serde_json::to_vec(&manifest).map_err(|_| BundleError::Serialize)?;
    Ok(AgentBundle {
        root: root.to_path_buf(),
        hash: sha256(&canonical),
        manifest,
        staged: None,
    })
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(71);
    out.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
