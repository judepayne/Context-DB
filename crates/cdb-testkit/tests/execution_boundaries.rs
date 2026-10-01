//! Bounded execution regressions; expected paths come from the tiny graphs below.
use cdb_core::{claim::ClaimObject, id::EntityId, CanonicalValue as V, ErrorKind, Limits, Result};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{execute, ExecutionOptions},
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::{FixtureBuilder, ReferenceFixture};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

async fn graph(edges: &[(&str, &str, &str)]) -> ReferenceFixture {
    let mut b = FixtureBuilder::new();
    let nodes: std::collections::BTreeSet<_> =
        edges.iter().flat_map(|(_, a, z)| [*a, *z]).collect();
    for node in nodes {
        b.entity(&format!("https://e/{node}"), Some(node)).unwrap();
    }
    for (id, a, z) in edges {
        b.edge(
            &format!("https://e/{id}"),
            &format!("https://e/{a}"),
            ClaimObject::Entity(EntityId::new(format!("https://e/{z}")).unwrap()),
            "1",
        )
        .unwrap();
    }
    b.build().await.unwrap()
}
fn query(about: &str, caps: &str, selection: &str) -> String {
    // Captures have distinct pins; fixed semantic cutoff and explain=false are required
    // for comparisons across captures of this same, unchanged fixture.
    format!(
        r#"{{"about":{about},"bounds":{{"as_of":"2026-04-01T00:00:00Z","max_depth":3,"path_limit":32,{caps}}},"return":{selection}}}"#
    )
}
const ABOUT: &str = r#"[{"from":["A"],"match":"exact"}]"#;
const SELECT: &str = r#"{"claims":true,"paths":true,"evidence":false,"explain":false}"#;
async fn run(f: &ReferenceFixture, q: &str, options: ExecutionOptions) -> (Result<()>, Vec<u8>) {
    let draft = compile(
        QuerySource::inline(q.as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut bytes = vec![];
    let result = execute(
        draft,
        &f.backend,
        &f.backend,
        &f.principal,
        f,
        options,
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await;
    (result, bytes)
}
async fn successful(f: &ReferenceFixture, q: &str, options: ExecutionOptions) -> (V, Vec<u8>) {
    let (result, bytes) = run(f, q, options).await;
    result.unwrap();
    (V::parse(&bytes, Limits::default()).unwrap(), bytes)
}
fn paths(v: &V) -> Vec<Vec<&str>> {
    v.field("paths")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            p.field("claim_ids")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|id| id.as_str().unwrap())
                .collect()
        })
        .collect()
}
fn claims(v: &V) -> Vec<&str> {
    v.field("claims")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            c.field("meta")
                .unwrap()
                .field("claim_id")
                .unwrap()
                .as_str()
                .unwrap()
        })
        .collect()
}

#[tokio::test]
async fn all_sixteen_selections_execute_with_status_and_hash() {
    let f = graph(&[("a", "A", "B")]).await;
    for mask in 0..16 {
        let flags = [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0, mask & 8 != 0];
        let selection = format!(
            r#"{{"claims":{},"paths":{},"evidence":{},"explain":{}}}"#,
            flags[0], flags[1], flags[2], flags[3]
        );
        // Also prove selected empty arrays differ from unselected null.
        for (about, empty) in [
            (ABOUT, false),
            (r#"[{"from":["missing"],"match":"exact"}]"#, true),
        ] {
            let (v, _) = successful(
                &f,
                &query(about, "\"max_claims\":16", &selection),
                ExecutionOptions::default(),
            )
            .await;
            assert_eq!(
                v.field("selection").unwrap(),
                &V::parse(selection.as_bytes(), Limits::default()).unwrap(),
                "mask={mask}"
            );
            assert_eq!(v.field("status").unwrap(), v.field("graph_status").unwrap());
            assert_eq!(
                v.field("status").unwrap().as_str().unwrap(),
                if empty {
                    "ready_with_warnings"
                } else {
                    "ready"
                }
            );
            for key in ["response_hash", "plan_hash"] {
                let hash = v.field(key).unwrap().as_str().unwrap();
                assert!(
                    hash.starts_with("sha256:") && hash.len() == 71,
                    "mask={mask}: {key}"
                );
            }
            for (key, selected) in [
                ("claims", flags[0]),
                ("paths", flags[1]),
                ("explain", flags[3]),
            ] {
                assert_eq!(
                    v.field(key).unwrap() == &V::Null,
                    !selected,
                    "mask={mask}: {key}"
                );
            }
            if flags[0] {
                assert_eq!(claims(&v), if empty { vec![] } else { vec!["https://e/a"] });
            }
            if flags[1] {
                assert_eq!(
                    paths(&v),
                    if empty {
                        vec![]
                    } else {
                        vec![vec!["https://e/a"]]
                    }
                );
            }
            if flags[3] {
                assert_eq!(
                    v.field("explain")
                        .unwrap()
                        .field("traversal_stats")
                        .unwrap()
                        .field("returned_paths")
                        .unwrap(),
                    &V::integer(if empty { 0 } else { 1 })
                );
            }
            // Evidence is transport-only, not a canonical ResponseProjection section.
            if flags[2] {
                assert_eq!(v.field("evidence").unwrap(), &V::Array(vec![]));
            } else {
                assert!(!v.as_object().unwrap().contains_key("evidence"));
            }
        }
    }
}

#[tokio::test]
async fn nonbinding_operational_limits_preserve_exact_bytes_and_hashes() {
    let f = graph(&[("a", "A", "B"), ("b", "A", "C"), ("c", "B", "D")]).await;
    let q = query(ABOUT, "\"max_claims\":16", SELECT);
    let (baseline, bytes) = successful(&f, &q, ExecutionOptions::default()).await;
    assert_eq!(
        paths(&baseline),
        vec![
            vec!["https://e/a"],
            vec!["https://e/b"],
            vec!["https://e/a", "https://e/c"]
        ]
    );
    let options = ExecutionOptions {
        limits: Limits::new(4 * 1024 * 1024, 48, 50_000, 500_000, 8 * 1024 * 1024).unwrap(),
        max_work: 500_000,
        max_records: 50_000,
        max_frontier: 100,
        max_paths: 100,
        max_retained_bytes: 8 * 1024 * 1024,
        page_size: cdb_core::snapshot::PageSize::new(1).unwrap(),
        ..ExecutionOptions::default()
    };
    let (changed, changed_bytes) = successful(&f, &q, options).await;
    assert_eq!(bytes, changed_bytes);
    for key in ["response_hash", "plan_hash"] {
        assert_eq!(baseline.field(key).unwrap(), changed.field(key).unwrap());
    }
}

#[tokio::test]
async fn interruption_and_binding_budgets_release_zero_bytes() {
    let f = graph(&[("a", "A", "B"), ("b", "A", "C"), ("c", "B", "D")]).await;
    let q = query(ABOUT, "\"max_claims\":16", SELECT);
    let defaults = ExecutionOptions::default();
    let l = defaults.limits;
    let cases = [
        (
            "cancelled",
            ExecutionOptions {
                cancellation: Some(Arc::new(AtomicBool::new(true))),
                ..defaults.clone()
            },
            ErrorKind::Deadline,
        ),
        (
            "preexpired",
            ExecutionOptions {
                deadline: Some(Instant::now().checked_sub(Duration::from_secs(1)).unwrap()),
                ..defaults.clone()
            },
            ErrorKind::Deadline,
        ),
        // One root fits, but its two children exceed the next-frontier budget.
        (
            "frontier",
            ExecutionOptions {
                max_frontier: 1,
                ..defaults.clone()
            },
            ErrorKind::Limit,
        ),
        // Two depth-one prefixes fit; A-B-D is the third retained result.
        (
            "paths",
            ExecutionOptions {
                max_paths: 2,
                ..defaults.clone()
            },
            ErrorKind::Limit,
        ),
        // Limits::new's LAST argument is the serialization/output byte bound.
        (
            "output-bytes",
            ExecutionOptions {
                limits: Limits::new(l.input_bytes(), l.depth(), l.values(), l.work(), 1024)
                    .unwrap(),
                ..defaults.clone()
            },
            ErrorKind::Limit,
        ),
        // Cumulative export/retention accounting, not a peak-memory assertion.
        (
            "retained-bytes",
            ExecutionOptions {
                max_retained_bytes: 1,
                ..defaults
            },
            ErrorKind::Limit,
        ),
    ];
    let (v, _) = successful(&f, &q, ExecutionOptions::default()).await;
    assert_eq!(paths(&v).len(), 3);
    for (name, options, kind) in cases {
        let (result, bytes) = run(&f, &q, options).await;
        assert_eq!(result.unwrap_err().kind, kind, "{name}");
        assert!(bytes.is_empty(), "{name} released {} bytes", bytes.len());
    }
}

#[tokio::test]
async fn global_bfs_across_seeds_and_blocks_precedes_deeper_paths() {
    let f = graph(&[
        ("a", "A", "B"),
        ("deep", "B", "D"),
        ("x", "X", "Y"),
        ("z", "Z", "W"),
    ])
    .await;
    for about in [
        r#"[{"from":["A","X","Z"],"match":"exact"}]"#,
        r#"[{"from":["A","X"],"match":"exact"},{"from":["Z"],"match":"exact"}]"#,
    ] {
        let q = query(about, "\"seed_limit\":3,\"max_claims\":3", SELECT);
        let (v, _) = successful(&f, &q, ExecutionOptions::default()).await;
        // All three roots take one edge before A's second hop. Per-seed BFS/DFS
        // would spend one of the three unique-ID slots on `deep` instead of `z`.
        assert_eq!(
            paths(&v),
            vec![
                vec!["https://e/a"],
                vec!["https://e/x"],
                vec!["https://e/z"]
            ]
        );
        assert_eq!(
            claims(&v),
            vec!["https://e/a", "https://e/x", "https://e/z"]
        );
    }
}

#[tokio::test]
async fn parallel_identical_triples_return_independent_assertion_ids() {
    let f = graph(&[("a", "A", "B"), ("b", "A", "B")]).await;
    let (v, _) = successful(
        &f,
        &query(ABOUT, "\"max_claims\":2", SELECT),
        ExecutionOptions::default(),
    )
    .await;
    assert_eq!(claims(&v), vec!["https://e/a", "https://e/b"]);
    assert_eq!(paths(&v), vec![vec!["https://e/a"], vec!["https://e/b"]]);
    for path in v.field("paths").unwrap().as_array().unwrap() {
        assert_eq!(
            path.field("node_ids").unwrap(),
            &V::Array(vec![V::string("https://e/A"), V::string("https://e/B")])
        );
    }
}
