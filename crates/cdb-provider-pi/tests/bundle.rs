use cdb_provider_pi::agent_bundle::{
    hash_agent_bundle, hash_agent_bundle_for_profile, verify_recorded_assets, BundleProfile,
    CHAT_FILES, EXTRACTION_FILES, LEGACY_EXTRACTION_FILES,
};
use cdb_provider_pi::{MODEL, THINKING};
use sha2::Digest;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/pi")
}

#[test]
fn production_profiles_are_closed_sorted_and_pinned() {
    let extraction = hash_agent_bundle(root()).unwrap();
    assert_eq!(extraction.manifest.schema, "ctxql.pi-agent-bundle/v2");
    assert_eq!(extraction.manifest.profile, BundleProfile::Extraction);
    assert_eq!(extraction.manifest.model, MODEL);
    assert_eq!(extraction.manifest.thinking, THINKING);
    let paths: Vec<_> = extraction
        .manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(paths, EXTRACTION_FILES);
    assert!(paths.contains(&"skills/ctxql-ontology/SKILL.md"));
    assert!(paths.contains(&"skills/ctxql-query/SKILL.md"));
    assert!(!paths.iter().any(|path| path.contains("ctxql-answer")));
    assert!(!paths.iter().any(|path| path.contains("baseline")));

    let prompt = extraction.system_prompt_v2().unwrap();
    for required in [
        "ctxql-extraction-text/v1",
        "read-loan-agreement-v2",
        "ctxql-ontology",
        "ctxql-query",
        "graph-workspace",
        "model must normalize unambiguous complete calendar dates",
        "Keep the evidence quote unchanged",
    ] {
        assert!(
            prompt.contains(required),
            "missing extraction prompt: {required}"
        );
    }
    assert!(!prompt.contains("ctxql-extraction-proposals/v"));

    let query =
        std::fs::read_to_string(extraction.root.join("skills/ctxql-query/SKILL.md")).unwrap();
    assert!(query.contains("rdfs:label"));
    assert!(query.contains("skos:prefLabel"));
    assert!(query.contains("does not search arbitrary identifiers"));
    let workspace =
        std::fs::read_to_string(extraction.root.join("skills/graph-workspace/SKILL.md")).unwrap();
    assert!(!workspace.contains("## Constructing CTXQL"));
    assert!(workspace.contains("must actually use the tools"));
    assert!(workspace.contains("Final output is text, never JSON"));
    let apply_example = workspace
        .split("```text\n")
        .nth(1)
        .unwrap()
        .split("\n```")
        .next()
        .unwrap();
    let apply: serde_json::Value = serde_json::from_str(apply_example).unwrap();
    assert_eq!(apply["operation"], "apply");
    assert_eq!(apply["edits"].as_array().unwrap().len(), 3);

    let chat = hash_agent_bundle_for_profile(root(), BundleProfile::Chat).unwrap();
    assert_eq!(chat.manifest.schema, "ctxql.pi-agent-bundle/v2");
    assert_eq!(chat.manifest.profile, BundleProfile::Chat);
    let chat_paths: Vec<_> = chat
        .manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(chat_paths, CHAT_FILES);
    assert!(!chat_paths
        .iter()
        .any(|path| path.contains("graph-workspace")));
    assert!(!chat_paths.iter().any(|path| path.contains("read-loan")));
    let chat_prompt = chat.chat_system_prompt().unwrap();
    let ontology = chat_prompt.find("# CTXQL ontology guidance").unwrap();
    let query = chat_prompt.find("# Query CTXQL").unwrap();
    let answer = chat_prompt.find("# Answer with CTXQL evidence").unwrap();
    assert!(ontology < query && query < answer);
    assert!(extraction.chat_system_prompt().is_err());
    assert!(chat.system_prompt_v2().is_err());

    for bundle in [extraction, chat] {
        let staged = bundle.stage_verified().unwrap();
        assert_ne!(staged.root, bundle.root);
        assert_eq!(staged.hash, bundle.hash);
        assert_eq!(staged.manifest, bundle.manifest);
    }
}

#[test]
fn extraction_guidance_and_submission_protocol_survive_the_skill_split() {
    let bundle = hash_agent_bundle(root()).unwrap();
    let legacy = bundle.system_prompt().unwrap();
    assert!(legacy.contains("Classify and extract from the current full supplied document"));
    assert!(legacy.contains("call `ctxql_skill`"));
    let prompt = bundle.system_prompt_v2().unwrap();
    for grammar in [
        "ENTITY:",
        "ALIAS:",
        "CLAIM:",
        "CLAIM_METADATA:",
        "Predicate note:",
        "Datatype selected:",
        "Known entity: none",
        "NO_CLAIMS",
        "never JSON",
        "Only entities carry model-assigned IDs",
        "ctxql_graph_query",
    ] {
        assert!(prompt.contains(grammar), "missing text protocol: {grammar}");
    }
    assert!(!prompt.contains("Output JSON only"));
    assert!(!prompt.contains("Preserve the exact source spelling in `lexical`"));
    let loan = std::fs::read_to_string(bundle.root.join("skills/read-loan-agreement-v2/SKILL.md"))
        .unwrap();
    for instruction in [
        "hasBusinessPurposeDescription",
        "hasPrincipalRepaymentDate",
        "hasCompoundingFrequency",
        "hasLegalDescription",
        "RecurrenceInterval",
        "at most two related concepts",
        "2022-12-06",
        "06/12/2022",
        "A concrete date can be classified as ExplicitDate",
        "one to eight genuine suggestions",
        "ctxql-extraction-text/v1",
        "CLAIM_METADATA",
        "required suggestion-note lines",
        "No JSON",
        "Do not invent confidence",
        "specific unresolved issue",
        "Existing briefing metadata is usable verification",
        "narrower propositions",
        "query → draft → view → check",
        "Rust does not convert the value for you",
    ] {
        assert!(
            loan.contains(instruction),
            "missing loan guidance: {instruction}"
        );
    }
    assert!(!loan.contains("Do not replace source spelling with `5` or `2022-12-06`"));
    assert!(!loan.contains("proposal JSON envelope"));
    let workspace =
        std::fs::read_to_string(bundle.root.join("skills/graph-workspace/SKILL.md")).unwrap();
    for instruction in [
        "ctxql-extraction-text/v1",
        "must actually use the tools",
        "Reserve at least six calls",
        "continue source-only drafting",
        "structural diagnostics, not semantic approval",
        "do not circumvent permissions",
    ] {
        assert!(
            workspace.contains(instruction),
            "missing workspace guidance: {instruction}"
        );
    }
    let extension =
        std::fs::read_to_string(bundle.root.join("extensions/ctxql-ontology-tool.ts")).unwrap();
    for instruction in [
        "related financial concepts",
        "domain/range",
        "available restrictions",
        "Missing constraints are not approval",
    ] {
        assert!(
            extension.contains(instruction),
            "missing tool guidance: {instruction}"
        );
    }
    let staged = bundle.stage_verified().unwrap();
    assert_eq!(staged.system_prompt_v2().unwrap(), prompt);
    assert_eq!(
        std::fs::read_to_string(staged.root.join("skills/graph-workspace/SKILL.md")).unwrap(),
        workspace
    );
}

#[test]
fn staging_rejects_mutation_and_excludes_unapproved_files() {
    for profile in [BundleProfile::Extraction, BundleProfile::Chat] {
        let staged = hash_agent_bundle_for_profile(root(), profile)
            .unwrap()
            .stage_verified()
            .unwrap();
        std::fs::write(
            staged.root.join("unapproved.ts"),
            "throw new Error('never load');",
        )
        .unwrap();
        let copy = staged.stage_verified().unwrap();
        assert!(!copy.root.join("unapproved.ts").exists());
        let file = staged.root.join(&staged.manifest.files[0].path);
        std::fs::write(file, "changed after verification").unwrap();
        assert!(staged.stage_verified().is_err());
    }
}

#[cfg(unix)]
#[test]
fn bundles_reject_symlinked_parent_directories() {
    let staged = hash_agent_bundle(root()).unwrap().stage_verified().unwrap();
    let original = staged.root.join("skills");
    let relocated = staged.root.join("relocated-skills");
    std::fs::rename(&original, &relocated).unwrap();
    std::os::unix::fs::symlink(&relocated, &original).unwrap();
    assert!(hash_agent_bundle(&staged.root).is_err());
    assert!(staged.stage_verified().is_err());
}

#[test]
fn retained_v2_assets_reject_missing_extra_corrupt_and_wrong_profile_context() {
    let bundle = hash_agent_bundle(root()).unwrap();
    let manifest = serde_json::to_value(&bundle.manifest).unwrap();
    let assets: BTreeMap<_, _> = bundle
        .manifest
        .files
        .iter()
        .map(|file| {
            (
                file.path.clone(),
                std::fs::read_to_string(bundle.root.join(&file.path)).unwrap(),
            )
        })
        .collect();
    let recorded = verify_recorded_assets(&manifest, &assets, &bundle.hash).unwrap();
    assert!(!recorded.is_legacy_v1());
    for (model, thinking) in [("other/model", THINKING), (MODEL, "low")] {
        let mut unsupported = bundle.manifest.clone();
        unsupported.model = model;
        unsupported.thinking = thinking;
        let rehashed = format!(
            "sha256:{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&unsupported).unwrap())
        );
        assert!(verify_recorded_assets(
            &serde_json::to_value(&unsupported).unwrap(),
            &assets,
            &rehashed
        )
        .is_err());
    }
    assert_eq!(
        recorded.required_graph_skills(),
        &[
            "read-loan-agreement-v2",
            "ctxql-ontology",
            "ctxql-query",
            "graph-workspace"
        ]
    );
    let mut missing = assets.clone();
    missing.remove("skills/ctxql-query/SKILL.md");
    assert!(verify_recorded_assets(&manifest, &missing, &bundle.hash).is_err());
    let mut extra = assets.clone();
    extra.insert("../injected.ts".into(), "injected".into());
    assert!(verify_recorded_assets(&manifest, &extra, &bundle.hash).is_err());
    let mut corrupt = assets.clone();
    corrupt
        .get_mut("skills/ctxql-query/SKILL.md")
        .unwrap()
        .push('!');
    assert!(verify_recorded_assets(&manifest, &corrupt, &bundle.hash).is_err());
    let mut wrong_profile = manifest.clone();
    wrong_profile["profile"] = serde_json::json!("chat");
    assert!(verify_recorded_assets(&wrong_profile, &assets, &bundle.hash).is_err());
    let mut unknown = manifest.clone();
    unknown["schema"] = serde_json::json!("ctxql.pi-agent-bundle/v999");
    assert!(verify_recorded_assets(&unknown, &assets, &bundle.hash).is_err());
    assert!(
        verify_recorded_assets(&manifest, &assets, &format!("sha256:{}", "0".repeat(64))).is_err()
    );
}

#[test]
fn retained_v1_assets_verify_with_the_original_algorithm_and_closure() {
    let mut assets = BTreeMap::new();
    let mut files = Vec::new();
    for path in LEGACY_EXTRACTION_FILES {
        let text = format!("historical bytes for {path}\n");
        let bytes = text.as_bytes();
        let digest = format!("sha256:{:x}", sha2::Sha256::digest(bytes));
        files.push(serde_json::json!({"path":path,"sha256":digest,"size":bytes.len()}));
        assets.insert(path.to_owned(), text);
    }
    files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    let manifest = serde_json::json!({
        "schema":"ctxql.pi-agent-bundle/v1",
        "model":MODEL,
        "thinking":THINKING,
        "files":files,
    });
    #[derive(serde::Serialize)]
    struct Legacy<'a> {
        schema: &'a str,
        model: &'a str,
        thinking: &'a str,
        files: &'a serde_json::Value,
    }
    let ordered = Legacy {
        schema: "ctxql.pi-agent-bundle/v1",
        model: MODEL,
        thinking: THINKING,
        files: &manifest["files"],
    };
    let hash = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(serde_json::to_vec(&ordered).unwrap())
    );
    let verified = verify_recorded_assets(&manifest, &assets, &hash).unwrap();
    assert!(verified.is_legacy_v1());
    assert_eq!(
        verified.required_graph_skills(),
        &["read-loan-agreement-v2", "graph-workspace"]
    );

    for (model, thinking) in [("other/model", THINKING), (MODEL, "low")] {
        let unsupported = Legacy {
            schema: "ctxql.pi-agent-bundle/v1",
            model,
            thinking,
            files: &manifest["files"],
        };
        let rehashed = format!(
            "sha256:{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&unsupported).unwrap())
        );
        assert!(verify_recorded_assets(
            &serde_json::to_value(&unsupported).unwrap(),
            &assets,
            &rehashed
        )
        .is_err());
    }

    let mut tampered = assets.clone();
    tampered.insert("skills/graph-workspace/SKILL.md".into(), "changed".into());
    assert!(verify_recorded_assets(&manifest, &tampered, &hash).is_err());
    let mut swapped = manifest.clone();
    swapped["profile"] = serde_json::json!("chat");
    assert!(verify_recorded_assets(&swapped, &assets, &hash).is_err());
}
