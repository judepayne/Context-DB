//! Pinned official-FIBO source loading and historical profile preparation.

use crate::{
    authorized_view::{framed_root, quad_root, ExactTerm, SourceQuad},
    executable_profile_v3::{
        CategoryCommitmentV3, CategoryCommitmentsV3, ExecutableProfileManifestV3,
        ExecutableProfileManifestV3Input,
    },
    ontology_construct_audit::{
        audit_ontology_closure, build_audited_closure_from_conversions, ConstructAuditLimits,
        ConstructDisposition,
    },
    ontology_conversion::{
        convert_rdfxml, structural_quad_commitment, ConversionLimits, ConversionRequest,
        BLANK_NODE_ALGORITHM,
    },
    ontology_dependency_universe::ConversionPin,
    ontology_profile_load::{
        load_file_once_with_review_graph, load_raw_file_once, raw_structural_mapping_commitment,
        verify_read_only_reopen, LoadResult, OntologyProfileLoadLimits, OntologyProfileLoadPlan,
        OntologyProfileLoadReceipt, RawOntologyLoadPlan,
    },
    ontology_profile_v3::{
        certification_semantic_coverage_root, certify_ontology_profile_v3,
        classify_ontology_closure_v3_supported_subset, scope_bound_gate3_roots,
        CertifiedOntologyProfileV3, DeclarationEvidenceV3, OntologyMemberCategory,
        OntologyProfileV3CertificationEvidence, OntologyProfileV3Limits,
        TrustedAcquisitionAuthorityV3, TrustedOntologyScopeAuthorityV3,
        TrustedOntologySourceMemberV3, UninterpretedNonInterferenceEvidenceV3,
        ONTOLOGY_PROFILE_V3_RESULT_LABEL,
    },
};
use cdb_core::{id::ContentHash, Limits};
use fluree_db_api::{FlureeBuilder, NameServiceMode, ResolvedValue};
use fluree_db_nameservice::file::FileNameService;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::Path, sync::Arc};

pub const PROFILE: &str = "ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3-supported-subset";
pub const AGREEMENTS_SCOPE: &str = "FND/Agreements/Agreements";
pub const COMMERCIAL_LOANS_SCOPE: &str = "LOAN/LoansSpecific/CommercialLoans";
pub const PARTY_BACKGROUND_SCOPE: &str = "party-background";
pub const POC_LEDGER: &str = "ctxql/poc:main";
pub const ACQUISITION_V2_FIXTURE_LEDGER: &str = "semantic:main";
pub const ACQUISITION_V2_FIXTURE_SCHEMA_GRAPH: &str = "urn:ctxql:a2:schema";
pub const ACQUISITION_V2_FIXTURE_CLAIMS_GRAPH: &str = "urn:ctxql:a2:claims";
pub const ACQUISITION_V2_FIXTURE_DATA_GRAPH: &str = "urn:ctxql:a2:data";
pub const ACQUISITION_V2_FIXTURE_REVIEW_GRAPH: &str = "urn:ctxql:a2:review";
pub const ACQUISITION_V2_FIXTURE_PRINCIPAL: &str = "urn:ctxql:trusted-acquisition";
pub const ACQUISITION_V2_FIXTURE_ACTION: &str = "https://ns.flur.ee/db#modify";
const ACQUISITION_V2_FIXTURE_ONTOLOGY: &str =
    include_str!("../../../fixtures/conformance/p6/ontology-guided/a2-small-ontology.ttl");
const AGREEMENTS_INVENTORY: &str =
    include_str!("../../../fixtures/conformance/p5_7/official-agreements-closure.json");
const COMMERCIAL_LOANS_INVENTORY: &str =
    include_str!("../../../fixtures/conformance/p6/official-commercial-loans-closure.json");
const PARTY_BACKGROUND_INVENTORY: &str =
    include_str!("../../../fixtures/conformance/party-background-closure.json");
const PARTY_BACKGROUND_EXTENSION: &[u8] =
    include_bytes!("../../../assets/party-background/party-background.rdf");
const PARTY_BACKGROUND_EXTENSION_PATH: &str = "assets/party-background/party-background.rdf";
const COMMERCIAL_LOANS_SCHEMA: &str = "ctxql.p6-official-commercial-loans-closure/v1";
const PARTY_BACKGROUND_SCHEMA: &str = "ctxql.party-background-closure/v1";
pub const RAW_BOOTSTRAP_LOADER_ID: &str = "ctxql-raw-ontology-bootstrap/v3";
pub const RAW_BOOTSTRAP_NORMALIZATION_ID: &str =
    "ctxql-raw-ontology-native-normalization/language-lowercase-datetime-default-utc/v1";
pub const RAW_BOOTSTRAP_BACKEND_ID: &str =
    "fluree-db/4.2.1@82dbcec3e435d6ed1d45bc0ed929432323b6b201";
const RAW_MAX_BLANK_NODES: usize = 200_000;
const RAW_MAX_CANONICALIZATION_WORK: usize = 50_000_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfficialClosure {
    file_count: usize,
    files: Vec<OfficialFile>,
    inventory_root: String,
    schema: String,
    total_authoritative_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfficialFile {
    path: String,
    bytes: usize,
    sha256: String,
    #[serde(default)]
    source: Option<String>,
}

impl OfficialFile {
    fn source_kind(&self) -> &str {
        self.source.as_deref().unwrap_or("official")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FiboBootstrapReceipt {
    pub schema: String,
    pub status: String,
    pub certified: bool,
    pub scope: String,
    pub storage_path: String,
    pub source_cache_path: String,
    pub ledger: String,
    pub t: i64,
    pub cid: String,
    pub source_file_count: usize,
    pub source_inventory_root: String,
    pub source_quad_count: usize,
    pub source_quad_root: String,
    pub submitted_quad_count: usize,
    pub omitted_quad_count: usize,
    pub omitted_quads: Vec<String>,
    pub omitted_quad_root: String,
    pub loaded_quad_root: String,
    pub graph_set: Vec<String>,
    pub graph_set_root: String,
    pub structural_algorithm: String,
    pub normalization_identity: String,
    pub structural_mapping_root: String,
    pub loader_identity: String,
    pub backend_identity: String,
    pub exact_capture: String,
    pub transaction_quad_count: usize,
    pub transaction_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedRawOntology {
    pub source_quads: BTreeSet<SourceQuad>,
    pub loaded_quads: BTreeSet<SourceQuad>,
    pub omissions: BTreeSet<SourceQuad>,
    pub source_quad_root: ContentHash,
    pub loaded_quad_root: ContentHash,
    pub omission_root: ContentHash,
    pub graphs: BTreeSet<String>,
    pub graph_set_root: ContentHash,
}

fn official_identity(file: &OfficialFile) -> LoadResult<(&'static str, String, String)> {
    if file.source_kind() != "official" {
        return Err("local extension was presented as an official ontology source".into());
    }
    if let Some(name) = file
        .path
        .strip_prefix("commons/")
        .and_then(|path| path.strip_suffix(".rdf"))
    {
        Ok((
            "sha256:07f8a4aba315edd5eb3373b406ea0b9bc48d1bd9d12c142206972f91b79785bb",
            format!("https://www.omg.org/spec/Commons/20250801/{name}.rdf"),
            format!("https://www.omg.org/spec/Commons/{name}/"),
        ))
    } else if let Some(name) = file
        .path
        .strip_prefix("lcc/")
        .and_then(|path| path.strip_suffix(".rdf"))
    {
        Ok((
            "sha256:9e3fd1aa076d58aab16b9b6000805c33127f4a8c420fb5360f6546471d1ebfc5",
            format!("https://www.omg.org/spec/LCC/20211101/{name}.rdf"),
            format!("https://www.omg.org/spec/LCC/{name}/"),
        ))
    } else {
        let relative = file
            .path
            .strip_prefix("fibo/")
            .ok_or("official ontology inventory path invalid")?;
        let ontology = relative
            .strip_suffix(".rdf")
            .ok_or("official FIBO inventory media type invalid")?;
        Ok((
            "sha256:203a6a9d6e7a5d7ee855f299ad99a11ca5f1ac1d5e61f0ff293619d1526f13b2",
            format!("https://spec.edmcouncil.org/fibo/ontology/master/2026Q2/{relative}"),
            format!("https://spec.edmcouncil.org/fibo/ontology/{ontology}/"),
        ))
    }
}

fn inventory_metadata_is_valid(inventory: &OfficialClosure, scope: &str) -> bool {
    let common = inventory.file_count == inventory.files.len()
        && inventory.total_authoritative_bytes
            == inventory.files.iter().map(|file| file.bytes).sum::<usize>()
        && ContentHash::parse(&inventory.inventory_root).is_ok();
    if !common {
        return false;
    }
    if inventory.schema.starts_with("ctxql.p5-7-official-")
        && inventory.schema.ends_with("-closure/v1")
    {
        return inventory.files.iter().all(|file| file.source.is_none());
    }
    if scope == PARTY_BACKGROUND_SCOPE && inventory.schema == PARTY_BACKGROUND_SCHEMA {
        let extensions = inventory
            .files
            .iter()
            .filter(|file| file.source_kind() == "local_extension")
            .collect::<Vec<_>>();
        return inventory.file_count == 43
            && extensions.len() == 1
            && extensions[0].path == PARTY_BACKGROUND_EXTENSION_PATH
            && inventory.files.iter().all(|file| {
                matches!(file.source_kind(), "official" | "local_extension")
                    && (file.source_kind() != "official"
                        || file.path.starts_with("fibo/")
                        || file.path.starts_with("commons/")
                        || file.path.starts_with("lcc/"))
            })
            && [
                "fibo/FND/Agreements/Agreements.rdf",
                "fibo/BE/LegalEntities/CorporateBodies.rdf",
                "fibo/BE/LegalEntities/FormalBusinessOrganizations.rdf",
                "fibo/FND/Places/Addresses.rdf",
                "fibo/FND/Parties/Parties.rdf",
                "commons/RegistrationAuthorities.rdf",
            ]
            .iter()
            .all(|required| inventory.files.iter().any(|file| file.path == *required))
            && !inventory
                .files
                .iter()
                .any(|file| file.path == "fibo/FBC/DebtAndEquities/Debt.rdf");
    }
    if scope != COMMERCIAL_LOANS_SCOPE
        || inventory.schema != COMMERCIAL_LOANS_SCHEMA
        || inventory.file_count != 73
    {
        return false;
    }
    let count = |prefix: &str| {
        inventory
            .files
            .iter()
            .filter(|file| file.path.starts_with(prefix))
            .count()
    };
    count("fibo/") == 51
        && count("commons/") == 20
        && count("lcc/") == 2
        && [
            "fibo/FBC/DebtAndEquities/Debt.rdf",
            "fibo/FND/Agreements/Agreements.rdf",
            "fibo/LOAN/LoansGeneral/Loans.rdf",
            "fibo/LOAN/LoansSpecific/CommercialLoans.rdf",
            "lcc/Countries/CountryRepresentation.rdf",
            "lcc/Languages/LanguageRepresentation.rdf",
        ]
        .iter()
        .all(|required| inventory.files.iter().any(|file| file.path == *required))
}

fn inventory_is_exact(inventory: &OfficialClosure, scope: &str) -> bool {
    if !inventory_metadata_is_valid(inventory, scope) {
        return false;
    }
    let paths = inventory
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    if paths.len() != inventory.files.len()
        || inventory
            .files
            .iter()
            .any(|file| ContentHash::parse(format!("sha256:{}", file.sha256)).is_err())
    {
        return false;
    }
    let mut material = Vec::new();
    for path in paths {
        let file = inventory
            .files
            .iter()
            .find(|file| file.path == path)
            .expect("inventory path came from files");
        material.extend_from_slice(path.as_bytes());
        material.push(0);
        material.extend_from_slice(file.sha256.as_bytes());
        if inventory.schema == PARTY_BACKGROUND_SCHEMA {
            material.push(0);
            material.extend_from_slice(file.source_kind().as_bytes());
        }
        material.push(b'\n');
    }
    ContentHash::of_bytes(&material).as_str() == inventory.inventory_root
}

fn prepare_official_sources(
    cache: &Path,
    fixture: &str,
    scope: &str,
) -> LoadResult<(BTreeSet<SourceQuad>, OfficialClosure)> {
    let inventory: OfficialClosure = serde_json::from_str(fixture)?;
    if !inventory_is_exact(&inventory, scope) {
        return Err("pinned ontology inventory invalid".into());
    }

    // Finish byte verification for the complete pinned inventory before any
    // conversion. The caller does not create the destination until both phases
    // have succeeded.
    let mut sources = Vec::with_capacity(inventory.files.len());
    for file in &inventory.files {
        let bytes = if file.source_kind() == "local_extension" {
            if file.path != PARTY_BACKGROUND_EXTENSION_PATH {
                return Err("unapproved local ontology extension path".into());
            }
            PARTY_BACKGROUND_EXTENSION.to_vec()
        } else {
            fs::read(cache.join(&file.path))?
        };
        if bytes.len() != file.bytes {
            return Err(format!("{} byte count differs", file.path).into());
        }
        if ContentHash::of_bytes(&bytes).as_str()[7..] != file.sha256 {
            return Err(format!("{} hash differs", file.path).into());
        }
        sources.push((file, bytes));
    }

    let mut bundle = BTreeSet::new();
    for (file, bytes) in sources {
        let (release, base, graph) = if file.source_kind() == "local_extension" {
            (
                "sha256:a408254dc088c62340bee4a4603a92abaaafa85e790254ca7bdb73daf394a6e1",
                "https://ctxql.org/ontology/party-background/".to_owned(),
                "https://ctxql.org/ontology/party-background/".to_owned(),
            )
        } else {
            official_identity(file)?
        };
        let converted = convert_rdfxml(ConversionRequest {
            authoritative_bytes: &bytes,
            source_release_id: release,
            source_file_id: &file.path,
            base_iri: &base,
            graph_iri: &graph,
            limits: ConversionLimits {
                max_input_bytes: 128 * 1024 * 1024,
                max_input_triples: 1_000_000,
                max_output_bytes: 256 * 1024 * 1024,
                max_blank_nodes: 200_000,
                max_canonicalization_work: 50_000_000,
            },
        })?;
        bundle.extend(converted.quads);
    }
    Ok((bundle, inventory))
}

fn fixture_for_scope(scope: &str) -> LoadResult<&'static str> {
    match scope {
        AGREEMENTS_SCOPE => Ok(AGREEMENTS_INVENTORY),
        COMMERCIAL_LOANS_SCOPE => Ok(COMMERCIAL_LOANS_INVENTORY),
        PARTY_BACKGROUND_SCOPE => Ok(PARTY_BACKGROUND_INVENTORY),
        _ => Err("official ontology scope is not allowed".into()),
    }
}

fn framed_string_root(domain: &str, values: impl IntoIterator<Item = String>) -> ContentHash {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    let mut material = Vec::new();
    material.extend_from_slice(domain.as_bytes());
    material.push(0);
    for value in values {
        material.extend_from_slice(value.len().to_string().as_bytes());
        material.push(b':');
        material.extend_from_slice(value.as_bytes());
        material.push(b'\n');
    }
    ContentHash::of_bytes(&material)
}

/// Rebuild the exact expected raw image from embedded trusted inventory bytes
/// and hash-verified source files. No receipt field participates in this step.
pub fn reconstruct_official_raw(cache: &Path, scope: &str) -> LoadResult<ExpectedRawOntology> {
    let fixture = fixture_for_scope(scope)?;
    let (source_quads, _) = prepare_official_sources(cache, fixture, scope)?;
    let omissions = source_quads
        .iter()
        .filter(|quad| {
            quad.predicate == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
                && !matches!(quad.object, ExactTerm::Iri(_))
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_omissions = usize::from(scope == COMMERCIAL_LOANS_SCOPE);
    if omissions.len() != expected_omissions
        || omissions
            .iter()
            .any(|quad| !matches!(quad.object, ExactTerm::ScopedBlankNode(_)))
    {
        return Err("official ontology documented omission set differs".into());
    }
    // Apply the closed, receipt-pinned set of lexical normalizations performed
    // by Fluree's native value codec before both loading and verification.
    let loaded_quads = source_quads
        .difference(&omissions)
        .cloned()
        .map(normalize_for_native_load)
        .collect::<BTreeSet<_>>();
    let structural = structural_quad_commitment(
        &loaded_quads,
        RAW_MAX_BLANK_NODES,
        RAW_MAX_CANONICALIZATION_WORK,
    )?;
    let graphs = loaded_quads
        .iter()
        .map(|quad| quad.graph.clone())
        .collect::<BTreeSet<_>>();
    Ok(ExpectedRawOntology {
        source_quad_root: quad_root(&source_quads),
        loaded_quad_root: structural.root,
        omission_root: framed_string_root(
            "ctxql-raw-ontology-omissions/v1",
            omissions.iter().map(SourceQuad::commitment),
        ),
        graph_set_root: framed_string_root("ctxql-raw-ontology-graphs/v1", graphs.iter().cloned()),
        source_quads,
        loaded_quads,
        omissions,
        graphs,
    })
}

fn normalize_for_native_load(mut quad: SourceQuad) -> SourceQuad {
    if let ExactTerm::Literal {
        lexical,
        datatype,
        language,
    } = &mut quad.object
    {
        if let Some(language) = language {
            *language = language.to_ascii_lowercase();
        }
        if datatype == "http://www.w3.org/2001/XMLSchema#dateTime"
            && lexical.contains('T')
            && !lexical.ends_with('Z')
            && !lexical
                .get(lexical.len().saturating_sub(6)..)
                .is_some_and(|tail| {
                    matches!(tail.as_bytes().first(), Some(b'+' | b'-'))
                        && tail.as_bytes().get(3) == Some(&b':')
                })
        {
            lexical.push('Z');
        }
    }
    quad
}

fn expand_commit_iri(value: &str, context: &std::collections::HashMap<String, String>) -> String {
    let Some((prefix, local)) = value.split_once(':') else {
        return value.to_owned();
    };
    context.get(prefix).map_or_else(
        || value.to_owned(),
        |namespace| format!("{namespace}{local}"),
    )
}

/// Decode one native commit into exact quads, expanding its captured context.
/// This is exposed for hermetic bootstrap/readback conformance tests.
pub fn native_ontology_quads(
    detail: &fluree_db_api::CommitDetail,
) -> LoadResult<BTreeSet<SourceQuad>> {
    let mut quads = BTreeSet::new();
    for flake in &detail.flakes {
        if !flake.op {
            return Err("raw ontology readback contains a retraction".into());
        }
        let graph = flake
            .graph
            .as_deref()
            .map(|value| expand_commit_iri(value, &detail.context))
            .ok_or("raw ontology readback contains a default-graph statement")?;
        let subject_value = expand_commit_iri(&flake.s, &detail.context);
        let subject = if subject_value.starts_with("_:") {
            crate::authorized_view::RdfNodeId::ScopedBlankNode(subject_value)
        } else {
            crate::authorized_view::RdfNodeId::Iri(subject_value)
        };
        let lexical = match &flake.o {
            ResolvedValue::String(value) | ResolvedValue::Lexical(value) => value.clone(),
            ResolvedValue::Boolean(value) => value.to_string(),
            ResolvedValue::Long(value) => value.to_string(),
            ResolvedValue::Double(_) => {
                return Err("raw ontology readback contains an inexact double".into())
            }
        };
        let object = if flake.dt == "@id" {
            let value = expand_commit_iri(&lexical, &detail.context);
            if value.starts_with("_:") {
                ExactTerm::ScopedBlankNode(value)
            } else {
                ExactTerm::Iri(value)
            }
        } else {
            ExactTerm::Literal {
                lexical,
                datatype: expand_commit_iri(&flake.dt, &detail.context),
                language: flake.lang.clone(),
            }
        };
        quads.insert(SourceQuad {
            graph,
            subject,
            predicate: expand_commit_iri(&flake.p, &detail.context),
            object,
        });
    }
    Ok(quads)
}

fn exact_capture(receipt: &FiboBootstrapReceipt) -> ContentHash {
    let t = receipt.t.to_string();
    framed_root(
        "ctxql-raw-ontology-capture/v3",
        [
            ("scope", receipt.scope.as_str()),
            ("ledger", receipt.ledger.as_str()),
            ("t", t.as_str()),
            ("cid", receipt.cid.as_str()),
            ("inventory", receipt.source_inventory_root.as_str()),
            ("source", receipt.source_quad_root.as_str()),
            ("omissions", receipt.omitted_quad_root.as_str()),
            ("loaded", receipt.loaded_quad_root.as_str()),
            ("graphs", receipt.graph_set_root.as_str()),
            (
                "structural_algorithm",
                receipt.structural_algorithm.as_str(),
            ),
            ("normalization", receipt.normalization_identity.as_str()),
            (
                "structural_mapping",
                receipt.structural_mapping_root.as_str(),
            ),
            ("loader", receipt.loader_identity.as_str()),
            ("backend", receipt.backend_identity.as_str()),
        ],
    )
}

/// Verify a v3 receipt against independently reconstructed trusted source and
/// exact native readback. This is content integrity only: it never invokes the
/// executable ontology certification path.
pub async fn verify_official_raw_bootstrap(
    storage: &Path,
    receipt: &FiboBootstrapReceipt,
) -> LoadResult<ExpectedRawOntology> {
    if receipt.schema != "ctxql-fibo-bootstrap/v3"
        || receipt.status != "loaded_uncertified"
        || receipt.certified
        || receipt.ledger != POC_LEDGER
        || receipt.t != 1
        || receipt.structural_algorithm != BLANK_NODE_ALGORITHM
        || receipt.normalization_identity != RAW_BOOTSTRAP_NORMALIZATION_ID
        || receipt.loader_identity != RAW_BOOTSTRAP_LOADER_ID
        || receipt.backend_identity != RAW_BOOTSTRAP_BACKEND_ID
    {
        return Err("raw ontology bootstrap receipt identity invalid".into());
    }
    let storage = storage.canonicalize()?;
    if Path::new(&receipt.storage_path).canonicalize()? != storage {
        return Err("raw ontology bootstrap storage path differs".into());
    }
    let cache = Path::new(&receipt.source_cache_path).canonicalize()?;
    let expected = reconstruct_official_raw(&cache, &receipt.scope)?;
    let omission_lines = expected
        .omissions
        .iter()
        .map(SourceQuad::commitment)
        .collect::<Vec<_>>();
    let trusted_inventory: OfficialClosure =
        serde_json::from_str(fixture_for_scope(&receipt.scope)?)?;
    let (expected_mapping_root, _) =
        raw_structural_mapping_commitment(&expected.loaded_quads, RAW_MAX_BLANK_NODES)?;
    if receipt.source_file_count != trusted_inventory.file_count
        || receipt.source_inventory_root != trusted_inventory.inventory_root
        || receipt.source_quad_count != expected.source_quads.len()
        || receipt.submitted_quad_count != expected.loaded_quads.len()
        || receipt.omitted_quad_count != expected.omissions.len()
        || receipt.omitted_quads != omission_lines
        || receipt.source_quad_root != expected.source_quad_root.as_str()
        || receipt.omitted_quad_root != expected.omission_root.as_str()
        || receipt.loaded_quad_root != expected.loaded_quad_root.as_str()
        || receipt.graph_set != expected.graphs.iter().cloned().collect::<Vec<_>>()
        || receipt.graph_set_root != expected.graph_set_root.as_str()
        || receipt.structural_mapping_root != expected_mapping_root.as_str()
        || receipt.transaction_quad_count != expected.loaded_quads.len()
        || receipt.transaction_bytes == 0
        || receipt.transaction_bytes > 64 * 1024 * 1024
        || receipt.exact_capture != exact_capture(receipt).as_str()
    {
        return Err("raw ontology bootstrap receipt differs from trusted content".into());
    }

    let nameservice = NameServiceMode::ReadOnly(Arc::new(FileNameService::new(&storage)));
    let reader = FlureeBuilder::file(storage.to_string_lossy().into_owned())
        .without_indexing()
        .build_client_with_nameservice(nameservice)
        .await?;
    let head = reader.ledger(&receipt.ledger).await?;
    if head.t() != receipt.t
        || head
            .head_commit_id
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            != Some(receipt.cid.as_str())
    {
        return Err("raw ontology ledger head differs".into());
    }
    let detail = reader
        .graph(&receipt.ledger)
        .commit_t(receipt.t)
        .execute()
        .await?;
    if detail.t != receipt.t || detail.id != receipt.cid {
        return Err("raw ontology commit differs".into());
    }
    let actual = native_ontology_quads(&detail)?;
    let actual_graphs = actual
        .iter()
        .map(|quad| quad.graph.clone())
        .collect::<BTreeSet<_>>();
    let actual_commitment =
        structural_quad_commitment(&actual, RAW_MAX_BLANK_NODES, RAW_MAX_CANONICALIZATION_WORK)?;
    if actual.len() != expected.loaded_quads.len()
        || actual_graphs != expected.graphs
        || actual_commitment.quad_count != expected.loaded_quads.len()
        || actual_commitment.root != expected.loaded_quad_root
    {
        let has_blank = |quad: &&SourceQuad| {
            matches!(
                quad.subject,
                crate::authorized_view::RdfNodeId::ScopedBlankNode(_)
            ) || matches!(quad.object, ExactTerm::ScopedBlankNode(_))
        };
        let expected_named = expected
            .loaded_quads
            .iter()
            .filter(|quad| !has_blank(quad))
            .collect::<BTreeSet<_>>();
        let actual_named = actual
            .iter()
            .filter(|quad| !has_blank(quad))
            .collect::<BTreeSet<_>>();
        return Err(format!(
            "raw ontology native content differs from trusted source: actual_count={} expected_count={} actual_root={} expected_root={} actual_graphs={} expected_graphs={} first_unexpected_named={:?} first_missing_named={:?}",
            actual.len(),
            expected.loaded_quads.len(),
            actual_commitment.root.as_str(),
            expected.loaded_quad_root.as_str(),
            actual_graphs.len(),
            expected.graphs.len(),
            actual_named.difference(&expected_named).next(),
            expected_named.difference(&actual_named).next(),
        )
        .into());
    }
    Ok(expected)
}

pub fn prepare_official_profile(
    cache: &Path,
    fixture: &str,
    scope: &str,
) -> LoadResult<(BTreeSet<SourceQuad>, CertifiedOntologyProfileV3)> {
    let inventory: OfficialClosure = serde_json::from_str(fixture)?;
    if !inventory_metadata_is_valid(&inventory, scope) {
        return Err("official closure inventory metadata invalid".into());
    }
    let mut conversions = Vec::with_capacity(inventory.files.len());
    for file in &inventory.files {
        let bytes = fs::read(cache.join(&file.path))?;
        if bytes.len() != file.bytes {
            return Err(format!("{} byte count differs", file.path).into());
        }
        if ContentHash::of_bytes(&bytes).as_str()[7..] != file.sha256 {
            return Err(format!("{} hash differs", file.path).into());
        }
        let (release, base, graph) = official_identity(file)?;
        let conversion = convert_rdfxml(ConversionRequest {
            authoritative_bytes: &bytes,
            source_release_id: release,
            source_file_id: &file.path,
            base_iri: &base,
            graph_iri: &graph,
            limits: ConversionLimits {
                max_input_bytes: 128 * 1024 * 1024,
                max_input_triples: 1_000_000,
                max_output_bytes: 256 * 1024 * 1024,
                max_blank_nodes: 200_000,
                max_canonicalization_work: 50_000_000,
            },
        })?;
        let pin = ConversionPin::from_result(&conversion, &bytes)?;
        conversions.push((graph, pin, conversion));
    }
    let closure = build_audited_closure_from_conversions(conversions)?;
    let audit = audit_ontology_closure(
        &closure,
        ConstructAuditLimits {
            max_bundle_quads: 500_000,
            max_source_occurrences: 1_000_000,
            max_structural_work: 50_000_000,
            max_issues: 500_000,
            max_serialized_output_bytes: 256 * 1024 * 1024,
            ..ConstructAuditLimits::default()
        },
    )?;
    if let Some(issue) = audit.issues.iter().find(|issue| {
        matches!(
            issue.class,
            ConstructDisposition::Malformed | ConstructDisposition::Incomplete
        )
    }) {
        return Err(format!(
            "official profile certification blocked: {} in {} ({} {} {})",
            issue.reason, issue.source_file_id, issue.subject, issue.predicate, issue.object
        )
        .into());
    }
    let analysis = classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )?;
    let commitment = |category| CategoryCommitmentV3 {
        count: analysis.category_counts[&category] as u64,
        root: analysis.category_roots[&category].clone(),
        occurrence_root: analysis.category_occurrence_roots[&category].clone(),
    };
    let dependency_limits = ContentHash::of_bytes(b"candidate-scoped-dependency-limits-v2");
    let selected_path = format!("fibo/{scope}.rdf");
    let selected = closure
        .members
        .iter()
        .find(|member| member.source_file_id == selected_path)
        .ok_or("selected official source member missing")?;
    let authority = TrustedOntologyScopeAuthorityV3::verify(
        scope.into(),
        selected.source_release_id.clone(),
        selected.source_file_id.clone(),
        selected.ontology_iri.clone(),
        TrustedAcquisitionAuthorityV3::from_canonical_bytes(fixture.as_bytes())?,
        dependency_limits.clone(),
        closure
            .members
            .iter()
            .map(|member| TrustedOntologySourceMemberV3 {
                source_release_id: member.source_release_id.clone(),
                source_file_id: member.source_file_id.clone(),
                ontology_iri: member.ontology_iri.clone(),
                authoritative_hash: member.authoritative_hash.clone(),
                conversion_root: member.conversion_root.clone(),
                graph: member.graph.clone(),
                graph_root: member.graph_root.clone(),
            })
            .collect(),
        &closure,
        &audit,
    )?;
    let certification_evidence = OntologyProfileV3CertificationEvidence {
        reasoned_family_inventory_bytes: include_bytes!(
            "../../../fixtures/conformance/p5_6/direct-reasoner-inventory.json"
        )
        .to_vec(),
        declaration_evidence: DeclarationEvidenceV3::from_canonical_bytes(include_bytes!(
            "../../../fixtures/conformance/p5_7/declaration-evidence.json"
        ))?,
        uninterpreted_non_interference_evidence:
            UninterpretedNonInterferenceEvidenceV3::from_canonical_bytes(include_bytes!(
                "../../../fixtures/conformance/p5_7/non-interference-evidence.json"
            ))?,
        parity_matrix_bytes: include_bytes!(
            "../../../fixtures/conformance/p5_7/parity-applicability-matrix.json"
        )
        .to_vec(),
    };
    let gate3 = scope_bound_gate3_roots(&analysis, &authority, &certification_evidence)?;
    let final_coverage =
        certification_semantic_coverage_root(&analysis, &authority, &certification_evidence)?;
    let executable = ExecutableProfileManifestV3::new(
        ExecutableProfileManifestV3Input {
            selected_scope: scope.into(),
            scope_authority_root: authority.root().clone(),
            acquisition_authority_root: authority.acquisition_authority_root().clone(),
            selected_source_release_id: authority.selected_source_release_id().into(),
            selected_source_file_id: authority.selected_source_file_id().into(),
            selected_ontology_iri: authority.selected_ontology_iri().into(),
            source_member_root: authority.member_root().clone(),
            source_closure_root: closure.closure_root.clone(),
            dependency_universe_root: authority.dependency_universe_root().clone(),
            full_bundle_root: analysis.full_bundle_root.clone(),
            full_bundle_count: analysis.full_bundle.len() as u64,
            construct_audit_root: audit.construct_audit_root.clone(),
            source_entry_root: audit.source_entry_root.clone(),
            categories: CategoryCommitmentsV3 {
                reasoned: commitment(OntologyMemberCategory::Reasoned),
                inference_inert_declaration: commitment(
                    OntologyMemberCategory::InferenceInertDeclaration,
                ),
                retained_annotation: commitment(OntologyMemberCategory::RetainedAnnotation),
                retained_uninterpreted_semantic: commitment(
                    OntologyMemberCategory::RetainedUninterpretedSemantic,
                ),
            },
            annotation_policy_root: analysis.annotation_policy_root.clone(),
            registry_root: analysis.registry_root.clone(),
            family_root: analysis.family_root.clone(),
            component_projection_root: analysis.component_projection_root.clone(),
            source_occurrence_root: authority.source_occurrence_root().clone(),
            reasoned_family_inventory_root: gate3.reasoned_family_inventory_root,
            declaration_evidence_root: gate3.declaration_evidence_root,
            uninterpreted_non_interference_root: gate3.uninterpreted_non_interference_root,
            parity_matrix_root: gate3.parity_matrix_root,
            final_gate3_semantic_coverage_root: final_coverage,
            caveat_set_root: analysis.caveat_set_root.clone(),
            ontology_c0_input_root: analysis.ontology_c0_input_root.clone(),
            ontology_c0_input_count: analysis.ontology_c0_input.len() as u64,
            profile_limits_identity: analysis.limits_identity.clone(),
            dependency_limits_identity: dependency_limits,
        },
        Limits::default(),
    )?;
    let certified = certify_ontology_profile_v3(
        closure.clone(),
        audit,
        authority,
        OntologyProfileV3Limits::default(),
        certification_evidence,
        executable,
    )?;
    if certified.identity() != PROFILE
        || certified.result_label() != ONTOLOGY_PROFILE_V3_RESULT_LABEL
    {
        return Err("certified profile identity differs".into());
    }
    Ok((closure.bundle, certified))
}

async fn bootstrap_official(
    cache: &Path,
    output: &Path,
    fixture: &str,
    scope: &'static str,
) -> LoadResult<FiboBootstrapReceipt> {
    if !cache.is_absolute() || !output.is_absolute() {
        return Err("bootstrap paths must be absolute".into());
    }
    if output.exists() {
        return Err("bootstrap output already exists".into());
    }
    // Verify all pinned source bytes and parse them before creating the ledger.
    // Ontology constructs are loaded as-is; no CTXQL profile is certified.
    let cache = cache.canonicalize()?;
    let expected = reconstruct_official_raw(&cache, scope)?;
    let inventory: OfficialClosure = serde_json::from_str(fixture)?;
    let source_quad_count = expected.source_quads.len();
    let loadable = expected.loaded_quads.clone();
    let parent = output.parent().ok_or("bootstrap output has no parent")?;
    fs::create_dir_all(parent)?;
    fs::create_dir(output)?;
    let loaded = load_raw_file_once(
        output,
        RawOntologyLoadPlan {
            ledger: POC_LEDGER.into(),
            source_quads: loadable,
            limits: OntologyProfileLoadLimits {
                max_quads: 500_000,
                max_transaction_bytes: 64 * 1024 * 1024,
                max_structural_nodes: 200_000,
            },
        },
    )
    .await?;
    verify_read_only_reopen(output, &loaded).await?;
    let mut receipt = FiboBootstrapReceipt {
        schema: "ctxql-fibo-bootstrap/v3".into(),
        status: "loaded_uncertified".into(),
        certified: false,
        scope: scope.to_owned(),
        storage_path: output.canonicalize()?.to_string_lossy().into_owned(),
        source_cache_path: cache.to_string_lossy().into_owned(),
        ledger: loaded.ledger,
        t: loaded.t,
        cid: loaded.cid,
        source_file_count: inventory.file_count,
        source_inventory_root: inventory.inventory_root,
        source_quad_count,
        source_quad_root: expected.source_quad_root.as_str().into(),
        submitted_quad_count: loaded.ontology_quad_count,
        omitted_quad_count: expected.omissions.len(),
        omitted_quads: expected
            .omissions
            .iter()
            .map(SourceQuad::commitment)
            .collect(),
        omitted_quad_root: expected.omission_root.as_str().into(),
        loaded_quad_root: expected.loaded_quad_root.as_str().into(),
        graph_set: expected.graphs.iter().cloned().collect(),
        graph_set_root: expected.graph_set_root.as_str().into(),
        structural_algorithm: BLANK_NODE_ALGORITHM.into(),
        normalization_identity: RAW_BOOTSTRAP_NORMALIZATION_ID.into(),
        structural_mapping_root: loaded.structural_mapping_root.as_str().into(),
        loader_identity: RAW_BOOTSTRAP_LOADER_ID.into(),
        backend_identity: RAW_BOOTSTRAP_BACKEND_ID.into(),
        exact_capture: String::new(),
        transaction_quad_count: loaded.transaction_quad_count,
        transaction_bytes: loaded.transaction_bytes,
    };
    receipt.exact_capture = exact_capture(&receipt).as_str().into();
    verify_official_raw_bootstrap(output, &receipt).await?;
    Ok(receipt)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionV2BootstrapReceipt {
    pub ledger: String,
    pub t: i64,
    pub cid: String,
    pub ontology_hash: ContentHash,
    pub config_graph: String,
    pub schema_graph: String,
    pub claims_graph: String,
    pub data_graph: String,
    pub review_graph: String,
    pub reasoning_mode: String,
}

/// Create the hermetic acquisition-v2 semantic store used by service tests.
/// The store is always new, uses the linked 4.2.1 engine, and configures
/// `f:none`; it does not activate or relabel either archived executable profile.
pub async fn bootstrap_acquisition_v2_fixture(
    output: &Path,
) -> LoadResult<AcquisitionV2BootstrapReceipt> {
    bootstrap_acquisition_v2_fixture_with_denied_claims(output, &[]).await
}

/// Fixture-only variant that installs claim-level view denials in the actual
/// Semantic policy graph before any business claims are admitted.
pub async fn bootstrap_acquisition_v2_fixture_with_denied_claims(
    output: &Path,
    denied_claims: &[String],
) -> LoadResult<AcquisitionV2BootstrapReceipt> {
    if !output.is_absolute() || output.exists() {
        return Err("acquisition fixture bootstrap requires an absolute new output path".into());
    }
    let parent = output
        .parent()
        .ok_or("acquisition fixture output has no parent")?;
    fs::create_dir_all(parent)?;
    let config_graph =
        fluree_db_core::graph_registry::config_graph_iri(ACQUISITION_V2_FIXTURE_LEDGER);
    let ontology_body = ACQUISITION_V2_FIXTURE_ONTOLOGY
        .lines()
        .filter(|line| !line.starts_with("@prefix"))
        .collect::<Vec<_>>()
        .join("\n");
    let denied_claims = denied_claims
        .iter()
        .enumerate()
        .map(|(index, claim)| {
            cdb_core::id::Iri::new(claim.clone())?;
            Ok(format!(
                "  <urn:ctxql:a2:quality-deny-{index}> rdf:type f:AccessPolicy, <urn:ctxql:a2:PublicPolicy> ; f:action f:view ; f:onSubject <{claim}> ; f:allow false ."
            ))
        })
        .collect::<Result<Vec<_>, cdb_core::Error>>()?
        .join("\n");
    let fixture = format!(
        r#"@prefix f: <https://ns.flur.ee/db#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix ctxql: <https://ctxql.example/semantic-rdf/v1/> .
@prefix ex: <urn:ctxql:a2:> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
GRAPH <{config_graph}> {{
  <urn:ctxql:a2:config> rdf:type f:LedgerConfig ;
    f:reasoningDefaults <urn:ctxql:a2:reasoning> ;
    f:policyDefaults <urn:ctxql:a2:policy-defaults> ;
    ctxql:governedDataGraph <{claims}>, <{data}> ;
    ctxql:claimGraph <{claims}> ;
    ctxql:reviewGraph <{review}> ;
    ctxql:infrastructureGraph <{schema}> .
  <urn:ctxql:a2:reasoning> f:reasoningModes f:none ;
    f:schemaSource <urn:ctxql:a2:schema-ref> ; f:followOwlImports false .
  <urn:ctxql:a2:schema-ref> rdf:type f:GraphRef ;
    f:graphSource <urn:ctxql:a2:schema-source> .
  <urn:ctxql:a2:schema-source> f:graphSelector <{schema}> .
  <urn:ctxql:a2:policy-defaults> f:defaultAllow true ;
    f:policySource <urn:ctxql:a2:policy-ref> .
  <urn:ctxql:a2:policy-ref> rdf:type f:GraphRef ;
    f:graphSource <urn:ctxql:a2:policy-source> .
  <urn:ctxql:a2:policy-source> f:graphSelector <urn:ctxql:a2:policy> .
}}
GRAPH <urn:ctxql:a2:policy> {{
  <{principal}> f:policyClass <urn:ctxql:a2:PublicPolicy> .
{denied_claims}
}}
GRAPH <{schema}> {{
{ontology}
}}
GRAPH <{claims}> {{ <urn:ctxql:a2:claim-placeholder> <urn:ctxql:a2:unused> <urn:ctxql:a2:value> . }}
GRAPH <{data}> {{ <urn:ctxql:a2:data-placeholder> <urn:ctxql:a2:unused> <urn:ctxql:a2:value> . }}"#,
        claims = ACQUISITION_V2_FIXTURE_CLAIMS_GRAPH,
        data = ACQUISITION_V2_FIXTURE_DATA_GRAPH,
        review = ACQUISITION_V2_FIXTURE_REVIEW_GRAPH,
        schema = ACQUISITION_V2_FIXTURE_SCHEMA_GRAPH,
        principal = ACQUISITION_V2_FIXTURE_PRINCIPAL,
        denied_claims = denied_claims,
        ontology = ontology_body,
    );
    let writer = FlureeBuilder::file(output.to_string_lossy().into_owned())
        .without_indexing()
        .build()?;
    let ledger = writer.create_ledger(ACQUISITION_V2_FIXTURE_LEDGER).await?;
    let committed = writer
        .stage_owned(ledger)
        .upsert_turtle(&fixture)
        .execute()
        .await?
        .ledger;
    let cid = committed
        .head_commit_id
        .as_ref()
        .ok_or("acquisition fixture bootstrap missing commit CID")?
        .to_string();
    if committed.t() != 1 {
        return Err("acquisition fixture bootstrap was not one transaction".into());
    }
    drop(writer);
    let receipt = AcquisitionV2BootstrapReceipt {
        ledger: ACQUISITION_V2_FIXTURE_LEDGER.into(),
        t: 1,
        cid,
        ontology_hash: ContentHash::of_bytes(ACQUISITION_V2_FIXTURE_ONTOLOGY.as_bytes()),
        config_graph,
        schema_graph: ACQUISITION_V2_FIXTURE_SCHEMA_GRAPH.into(),
        claims_graph: ACQUISITION_V2_FIXTURE_CLAIMS_GRAPH.into(),
        data_graph: ACQUISITION_V2_FIXTURE_DATA_GRAPH.into(),
        review_graph: ACQUISITION_V2_FIXTURE_REVIEW_GRAPH.into(),
        reasoning_mode: "none".into(),
    };
    verify_read_only_reopen(
        output,
        &OntologyProfileLoadReceipt {
            ledger: receipt.ledger.clone(),
            t: receipt.t,
            cid: receipt.cid.clone(),
            ontology_quad_count: 0,
            transaction_quad_count: 0,
            transaction_bytes: 0,
            structural_node_count: 0,
            structural_mapping_root: ContentHash::of_bytes(b"fixture-turtle-loader"),
        },
    )
    .await?;
    Ok(receipt)
}

/// Create a fresh certified Agreements ledger with the current embedded
/// backend. Historical profile identity remains unchanged; this never opens or
/// mutates an existing ledger.
pub async fn bootstrap_certified_agreements(
    cache: &Path,
    output: &Path,
) -> LoadResult<OntologyProfileLoadReceipt> {
    if !cache.is_absolute() || !output.is_absolute() || output.exists() {
        return Err("certified bootstrap requires absolute cache and new output paths".into());
    }
    let (bundle, certified_profile) =
        prepare_official_profile(cache, AGREEMENTS_INVENTORY, AGREEMENTS_SCOPE)?;
    load_file_once_with_review_graph(
        output,
        OntologyProfileLoadPlan {
            ledger: POC_LEDGER.into(),
            source_closure: bundle,
            config_graph: format!("urn:fluree:{POC_LEDGER}#config"),
            config_subject: "urn:ctxql:p5-7:agreements-ledger".into(),
            certified_profile,
            limits: OntologyProfileLoadLimits::default(),
        },
        "urn:ctxql:acquisition-review:v1",
    )
    .await
}

pub async fn bootstrap_agreements(cache: &Path, output: &Path) -> LoadResult<FiboBootstrapReceipt> {
    bootstrap_official(cache, output, AGREEMENTS_INVENTORY, AGREEMENTS_SCOPE).await
}

pub async fn bootstrap_party_background(
    cache: &Path,
    output: &Path,
) -> LoadResult<FiboBootstrapReceipt> {
    bootstrap_official(
        cache,
        output,
        PARTY_BACKGROUND_INVENTORY,
        PARTY_BACKGROUND_SCOPE,
    )
    .await
}

pub async fn bootstrap_commercial_loans(
    cache: &Path,
    output: &Path,
) -> LoadResult<FiboBootstrapReceipt> {
    bootstrap_official(
        cache,
        output,
        COMMERCIAL_LOANS_INVENTORY,
        COMMERCIAL_LOANS_SCOPE,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commercial_loans_manifest_and_lcc_identities_are_exact() {
        let inventory: OfficialClosure = serde_json::from_str(COMMERCIAL_LOANS_INVENTORY).unwrap();
        assert!(inventory_is_exact(&inventory, COMMERCIAL_LOANS_SCOPE));
        let mut altered: OfficialClosure =
            serde_json::from_str(COMMERCIAL_LOANS_INVENTORY).unwrap();
        altered.files[0].sha256 = "0".repeat(64);
        assert!(!inventory_is_exact(&altered, COMMERCIAL_LOANS_SCOPE));
        for path in [
            "lcc/Countries/CountryRepresentation.rdf",
            "lcc/Languages/LanguageRepresentation.rdf",
        ] {
            let file = inventory
                .files
                .iter()
                .find(|file| file.path == path)
                .unwrap();
            let (release, base, graph) = official_identity(file).unwrap();
            assert_eq!(
                release,
                "sha256:9e3fd1aa076d58aab16b9b6000805c33127f4a8c420fb5360f6546471d1ebfc5"
            );
            let name = path.strip_prefix("lcc/").unwrap();
            assert_eq!(
                base,
                format!("https://www.omg.org/spec/LCC/20211101/{name}")
            );
            assert_eq!(
                graph,
                format!(
                    "https://www.omg.org/spec/LCC/{}/",
                    name.strip_suffix(".rdf").unwrap()
                )
            );
        }
    }

    #[test]
    fn party_background_manifest_separates_official_sources_from_extension() {
        let inventory: OfficialClosure = serde_json::from_str(PARTY_BACKGROUND_INVENTORY).unwrap();
        assert!(inventory_is_exact(&inventory, PARTY_BACKGROUND_SCOPE));
        assert_eq!(inventory.file_count, 43);
        let extension = inventory
            .files
            .iter()
            .find(|file| file.path == PARTY_BACKGROUND_EXTENSION_PATH)
            .unwrap();
        assert_eq!(extension.source_kind(), "local_extension");
        assert_eq!(
            ContentHash::of_bytes(PARTY_BACKGROUND_EXTENSION).as_str()[7..],
            extension.sha256
        );
        assert!(!inventory
            .files
            .iter()
            .any(|file| file.path == "fibo/FBC/DebtAndEquities/Debt.rdf"));

        let mut altered: OfficialClosure =
            serde_json::from_str(PARTY_BACKGROUND_INVENTORY).unwrap();
        altered
            .files
            .iter_mut()
            .find(|file| file.path == PARTY_BACKGROUND_EXTENSION_PATH)
            .unwrap()
            .source = Some("official".into());
        assert!(!inventory_is_exact(&altered, PARTY_BACKGROUND_SCOPE));
    }

    #[test]
    fn raw_commitment_is_blank_label_invariant_and_term_sensitive() {
        use crate::authorized_view::RdfNodeId;

        let graph = "urn:test:graph".to_owned();
        let predicate = "urn:test:predicate".to_owned();
        let quads = BTreeSet::from([
            SourceQuad {
                graph: graph.clone(),
                subject: RdfNodeId::Iri("urn:test:subject".into()),
                predicate: predicate.clone(),
                object: ExactTerm::ScopedBlankNode("_:source-a".into()),
            },
            SourceQuad {
                graph: graph.clone(),
                subject: RdfNodeId::ScopedBlankNode("_:source-a".into()),
                predicate: predicate.clone(),
                object: ExactTerm::Literal {
                    lexical: "value".into(),
                    datatype: "http://www.w3.org/2001/XMLSchema#string".into(),
                    language: None,
                },
            },
        ]);
        let relabelled = quads
            .iter()
            .cloned()
            .map(|mut quad| {
                if quad.subject == RdfNodeId::ScopedBlankNode("_:source-a".into()) {
                    quad.subject = RdfNodeId::ScopedBlankNode("_:native-z".into());
                }
                if quad.object == ExactTerm::ScopedBlankNode("_:source-a".into()) {
                    quad.object = ExactTerm::ScopedBlankNode("_:native-z".into());
                }
                quad
            })
            .collect();
        let canonical = |value: &BTreeSet<SourceQuad>| {
            structural_quad_commitment(value, 8, 1_000).unwrap().root
        };
        assert_eq!(canonical(&quads), canonical(&relabelled));

        for mutation in ["lexical", "datatype", "language", "graph"] {
            let mut changed = relabelled.clone();
            let literal = changed
                .iter()
                .find(|quad| matches!(quad.object, ExactTerm::Literal { .. }))
                .unwrap()
                .clone();
            changed.remove(&literal);
            let mut replacement = literal;
            match (&mut replacement.object, mutation) {
                (ExactTerm::Literal { lexical, .. }, "lexical") => *lexical = "other".into(),
                (ExactTerm::Literal { datatype, .. }, "datatype") => {
                    *datatype = "http://www.w3.org/2001/XMLSchema#token".into()
                }
                (ExactTerm::Literal { language, .. }, "language") => *language = Some("en".into()),
                (_, "graph") => replacement.graph = "urn:test:unexpected".into(),
                _ => unreachable!(),
            }
            changed.insert(replacement);
            assert_ne!(canonical(&quads), canonical(&changed), "{mutation}");
        }
    }

    #[tokio::test]
    async fn historical_raw_receipt_cannot_verify_as_current() {
        let mut receipt = FiboBootstrapReceipt {
            schema: "ctxql-fibo-bootstrap/v2".into(),
            status: "loaded_uncertified".into(),
            certified: false,
            scope: COMMERCIAL_LOANS_SCOPE.into(),
            storage_path: "/does/not/exist".into(),
            source_cache_path: "/does/not/exist".into(),
            ledger: POC_LEDGER.into(),
            t: 1,
            cid: "historical".into(),
            source_file_count: 73,
            source_inventory_root: "sha256:historical".into(),
            source_quad_count: 1,
            source_quad_root: "sha256:historical".into(),
            submitted_quad_count: 1,
            omitted_quad_count: 0,
            omitted_quads: vec![],
            omitted_quad_root: "sha256:historical".into(),
            loaded_quad_root: "sha256:historical".into(),
            graph_set: vec![],
            graph_set_root: "sha256:historical".into(),
            structural_algorithm: BLANK_NODE_ALGORITHM.into(),
            normalization_identity: RAW_BOOTSTRAP_NORMALIZATION_ID.into(),
            structural_mapping_root: "sha256:historical".into(),
            loader_identity: "ctxql-raw-ontology-bootstrap/v2".into(),
            backend_identity: RAW_BOOTSTRAP_BACKEND_ID.into(),
            exact_capture: "sha256:historical".into(),
            transaction_quad_count: 1,
            transaction_bytes: 1,
        };
        assert!(
            verify_official_raw_bootstrap(Path::new("/does/not/exist"), &receipt)
                .await
                .unwrap_err()
                .to_string()
                .contains("identity invalid")
        );
        receipt.schema = "ctxql-fibo-bootstrap/v3".into();
        assert!(
            verify_official_raw_bootstrap(Path::new("/does/not/exist"), &receipt)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires the exact external party-background ontology cache"]
    async fn party_background_bootstrap_loads_reopens_and_verifies_terms() {
        let cache = std::env::var("CDB_PARTY_BACKGROUND_CACHE")
            .expect("CDB_PARTY_BACKGROUND_CACHE must name the exact external cache");
        let path = std::env::temp_dir().join(format!(
            "ctxql-party-background-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let loaded = bootstrap_party_background(Path::new(&cache), &path)
            .await
            .unwrap();
        assert_eq!(loaded.source_file_count, 43);
        assert_eq!(loaded.omitted_quad_count, 0);
        verify_official_raw_bootstrap(&path, &loaded).await.unwrap();
        let nameservice = fluree_db_api::NameServiceMode::ReadOnly(std::sync::Arc::new(
            fluree_db_nameservice::file::FileNameService::new(&path),
        ));
        let reader = fluree_db_api::FlureeBuilder::file(path.to_string_lossy().into_owned())
            .without_indexing()
            .build_client_with_nameservice(nameservice)
            .await
            .unwrap();
        let ledger = reader.ledger(POC_LEDGER).await.unwrap();
        for term in [
            "https://spec.edmcouncil.org/fibo/ontology/BE/LegalEntities/CorporateBodies/Corporation",
            "https://spec.edmcouncil.org/fibo/ontology/FND/Places/Addresses/PhysicalAddress",
            "https://ctxql.org/ontology/party-background/hasTaxResidence",
            "https://ctxql.org/ontology/party-background/hasServiceAddress",
        ] {
            let query = format!("SELECT ?p ?o WHERE {{ GRAPH ?g {{ <{term}> ?p ?o }} }}");
            let result = reader
                .query(&fluree_db_api::GraphDb::from_ledger_state(&ledger), &query)
                .await
                .unwrap()
                .to_sparql_json(&ledger.snapshot)
                .unwrap();
            assert!(
                !result["results"]["bindings"].as_array().unwrap().is_empty(),
                "{term} not queryable in reopened Fluree"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires the exact external CommercialLoans ontology cache"]
    async fn commercial_loans_bootstrap_loads_unchecked_source() {
        let cache = std::env::var("CTXQL_P6_COMMERCIAL_LOANS_CACHE")
            .expect("CTXQL_P6_COMMERCIAL_LOANS_CACHE must name the exact external cache");
        let path = std::env::temp_dir().join(format!(
            "ctxql-fibo-unchecked-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let loaded = bootstrap_commercial_loans(Path::new(&cache), &path).await;
        assert!(loaded.is_ok(), "{loaded:?}");
        let loaded = loaded.unwrap();
        assert_eq!(loaded.source_file_count, 73);
        assert_eq!(loaded.omitted_quad_count, 1);
        let nameservice = fluree_db_api::NameServiceMode::ReadOnly(std::sync::Arc::new(
            fluree_db_nameservice::file::FileNameService::new(&path),
        ));
        let reader = fluree_db_api::FlureeBuilder::file(path.to_string_lossy().into_owned())
            .without_indexing()
            .build_client_with_nameservice(nameservice)
            .await
            .unwrap();
        let ledger = reader.ledger(POC_LEDGER).await.unwrap();
        for term in ["Borrower", "hasBorrower"] {
            let query = format!(
                "SELECT ?p ?o WHERE {{ GRAPH ?g {{ <https://spec.edmcouncil.org/fibo/ontology/FBC/DebtAndEquities/Debt/{term}> ?p ?o }} }}"
            );
            let result = reader
                .query(&fluree_db_api::GraphDb::from_ledger_state(&ledger), &query)
                .await
                .unwrap()
                .to_sparql_json(&ledger.snapshot)
                .unwrap();
            assert!(
                !result["results"]["bindings"].as_array().unwrap().is_empty(),
                "{term} not queryable in Fluree"
            );
        }
        let restrictions = reader
            .query(
                &fluree_db_api::GraphDb::from_ledger_state(&ledger),
                "SELECT ?r WHERE { GRAPH ?g { ?r <http://www.w3.org/2002/07/owl#minQualifiedCardinality> ?min . ?r <http://www.w3.org/2002/07/owl#someValuesFrom> ?some } }",
            )
            .await
            .unwrap()
            .to_sparql_json(&ledger.snapshot)
            .unwrap();
        assert!(!restrictions["results"]["bindings"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    #[ignore = "requires the exact external CommercialLoans ontology cache"]
    async fn commercial_loans_equal_count_substitution_fails_closed() {
        let cache = std::path::PathBuf::from(
            std::env::var("CTXQL_P6_COMMERCIAL_LOANS_CACHE")
                .expect("CTXQL_P6_COMMERCIAL_LOANS_CACHE must name the exact external cache"),
        );
        let root = std::env::temp_dir().join(format!(
            "ctxql-raw-integrity-mutation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let baseline_path = root.join("baseline");
        let baseline = bootstrap_commercial_loans(&cache, &baseline_path)
            .await
            .unwrap();
        verify_official_raw_bootstrap(&baseline_path, &baseline)
            .await
            .unwrap();

        // Rewriting receipt metadata cannot hide a same-cardinality content
        // substitution: trusted source reconstruction is independent, and the
        // native commit is compared under structural blank-node normalization.
        let expected = reconstruct_official_raw(&cache, COMMERCIAL_LOANS_SCOPE).unwrap();
        let original = expected
            .loaded_quads
            .iter()
            .find(|quad| matches!(quad.object, ExactTerm::Literal { .. }))
            .unwrap()
            .clone();
        let mut substituted = expected.loaded_quads.clone();
        substituted.remove(&original);
        let mut replacement = original;
        if let ExactTerm::Literal { lexical, .. } = &mut replacement.object {
            lexical.push_str(" [substituted]");
        }
        substituted.insert(replacement);
        assert_eq!(substituted.len(), expected.loaded_quads.len());
        let substituted_path = root.join("equal-count-substitution");
        let loaded = load_raw_file_once(
            &substituted_path,
            RawOntologyLoadPlan {
                ledger: POC_LEDGER.into(),
                source_quads: substituted,
                limits: OntologyProfileLoadLimits {
                    max_quads: 500_000,
                    max_transaction_bytes: 64 * 1024 * 1024,
                    max_structural_nodes: RAW_MAX_BLANK_NODES,
                },
            },
        )
        .await
        .unwrap();
        let mut forged = baseline.clone();
        forged.storage_path = substituted_path
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        forged.cid = loaded.cid;
        forged.transaction_bytes = loaded.transaction_bytes;
        forged.exact_capture = exact_capture(&forged).as_str().into();
        let error = verify_official_raw_bootstrap(&substituted_path, &forged)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("native content differs"), "{error}");

        let mut omitted_forgery = baseline;
        omitted_forgery.omitted_quads[0].push_str(" altered");
        omitted_forgery.exact_capture = exact_capture(&omitted_forgery).as_str().into();
        let error = verify_official_raw_bootstrap(&baseline_path, &omitted_forgery)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("receipt differs"), "{error}");
    }

    #[test]
    #[ignore = "requires the exact external CommercialLoans ontology cache"]
    fn commercial_loans_sources_parse_without_profile_checks() {
        let cache = std::env::var("CTXQL_P6_COMMERCIAL_LOANS_CACHE")
            .expect("CTXQL_P6_COMMERCIAL_LOANS_CACHE must name the exact external cache");
        let (bundle, inventory) = prepare_official_sources(
            Path::new(&cache),
            COMMERCIAL_LOANS_INVENTORY,
            COMMERCIAL_LOANS_SCOPE,
        )
        .unwrap();
        assert_eq!(inventory.file_count, 73);
        for name in ["Borrower", "hasBorrower"] {
            assert!(bundle.iter().any(|quad| {
                matches!(&quad.subject, crate::authorized_view::RdfNodeId::Iri(iri) if iri.ends_with(&format!("/{name}")))
            }), "missing {name}");
        }
    }
}
