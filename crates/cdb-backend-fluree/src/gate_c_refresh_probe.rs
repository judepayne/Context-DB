//! Private native feasibility analogue, not a production broker or v3 seal.
#[path = "gate_c_refresh_probe/remaining.rs"]
mod remaining;
use super::*;
use crate::{
    runs::{ExternalPublicationFence, Operation},
    AuthorityOptions,
};
use cdb_core::{
    artifact::ArtifactRef, canonical::CanonicalProjection, contracts::GraphBackend, recording::*,
    Limits,
};
use std::{
    sync::atomic::{AtomicBool, AtomicUsize},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
// Read the shared immutable byte vectors without loading its helper module twice
// in the same lib-test crate (runs.rs already includes that private module).
fn fixture(name: &str) -> V {
    let all = V::parse(
        include_bytes!("../../../fixtures/conformance/p1/bytes-v1.json"),
        Limits::default(),
    )
    .unwrap();
    let row = all
        .field("vectors")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row.field("id").unwrap().as_str().unwrap() == name)
        .unwrap();
    V::parse(
        row.field("canonical_utf8")
            .unwrap()
            .as_str()
            .unwrap()
            .as_bytes(),
        Limits::default(),
    )
    .unwrap()
}

// Same independently hashed v2 fixture binding as run_service_gates.rs.
fn envelope(snapshot: SnapshotRef, id: &str, owner: &str) -> RunEnvelope {
    let limits = Limits::default();
    let mut value = fixture("plan");
    let V::Object(root) = &mut value else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(artifacts) = payload.get_mut("artifacts").unwrap() else {
        unreachable!()
    };
    artifacts.insert("query".into(), artifacts["config"].clone());
    let plan = CanonicalProjection::read(&value.canonical_bytes(limits).unwrap(), limits).unwrap();
    let config = ArtifactRef::from_value(
        plan.payload()
            .field("artifacts")
            .unwrap()
            .field("config")
            .unwrap(),
    )
    .unwrap();
    let data = ReplayData::new(
        ReplayDataInput {
            snapshot: snapshot.clone(),
            requested_snapshot: snapshot,
            as_of: cdb_core::Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
            stale: false,
            plan_hash: ContentHash::parse(
                "sha256:c62caf74fbecd39100be7fa9fbcbcea7f9c0bb84815814c125fcfc61bc9fe5a3",
            )
            .unwrap(),
            plan,
            response: CanonicalProjection::read(
                &fixture("response").canonical_bytes(limits).unwrap(),
                limits,
            )
            .unwrap(),
            response_hash: ContentHash::parse(
                "sha256:17489b4f791a43e0a36b1af79ea9eacd60e7ecbfda760516503be24ca0dba55a",
            )
            .unwrap(),
            query: config.clone(),
            config,
            profile: None,
            engine: RecordingEngine {
                name: ResourceId::new("engine").unwrap(),
                version: VersionId::new("1").unwrap(),
                build: ContentHash::of_bytes(b"engine"),
            },
            replay_abi: VersionId::new("native/v1").unwrap(),
            landings: vec![],
            catalog: vec![],
            policy: vec![],
            reads: vec![],
            scopes: REQUIRED_SCOPES
                .iter()
                .map(|s| ResourceId::new(*s).unwrap())
                .collect(),
            functions: vec![],
        },
        limits,
    )
    .unwrap();
    RunEnvelope::new(
        RunId::new(id).unwrap(),
        PrincipalId::new(owner).unwrap(),
        ContentHash::of_bytes(id.as_bytes()),
        data,
        limits,
    )
    .unwrap()
}
fn policy(allow: bool) -> cdb_core::policy::PolicySet {
    cdb_core::policy::PolicySet::parse(format!(r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{{"@id":"https://gate.example/view","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":{allow}}}]}}"#).as_bytes(), Limits::default()).unwrap()
}
fn batch(id: &str) -> AdmissionBatch {
    AdmissionBatch::new(
        vec![],
        vec![],
        vec![ResourceChange::Add(
            DependencyRecord::new(
                "ctxql-resource/v1",
                ResourceId::new(id).unwrap(),
                ResourceKind::Identity,
                vec![Fact::new(
                    Iri::new("urn:gate:kind").unwrap(),
                    FactTerm::Reference(ResourceId::new("urn:gate:entity").unwrap()),
                )],
            )
            .unwrap(),
        )],
        vec![],
        V::object([]).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
async fn setup() -> (tempfile::TempDir, Arc<FlureeBackend>, PolicyState) {
    let dir = tempfile::tempdir().unwrap();
    let options = AuthorityOptions::new(
        dir.path().join("db"),
        "gate-c:main".into(),
        BackendId::new("fluree").unwrap(),
        AuthorityId::new("owner").unwrap(),
        GraphId::new("graph").unwrap(),
    );
    let b = Arc::new(FlureeBackend::create(options).await.unwrap());
    b.bootstrap_governance().await.unwrap();
    let mut state = PolicyState::deny_all().unwrap();
    state.policy = policy(true);
    for name in ["alice", "bob"] {
        state.principals.insert(
            PrincipalId::new(name).unwrap(),
            (
                true,
                [Operation::Query, Operation::Read]
                    .into_iter()
                    .map(|o| Iri::http(o.role()).unwrap())
                    .collect(),
            ),
        );
    }
    b.set_policy_state(&IdempotencyKey::new("initial-policy").unwrap(), &state)
        .await
        .unwrap();
    b.admit(&IdempotencyKey::new("seed").unwrap(), &batch("seed"))
        .await
        .unwrap();
    (dir, b, state)
}
struct OpenFence;
impl ExternalPublicationFence for OpenFence {
    fn check(&self) -> Result<()> {
        Ok(())
    }
}
fn native_test<F: std::future::Future<Output = ()>>(make: impl FnOnce() -> F + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(make());
        })
        .unwrap()
        .join()
        .unwrap();
}

// Deliberately small retained-state budgets, NOT pre-materialization SDK limits.
// Native read_records limits rows in SPARQL but checks result bytes only AFTER
// execute_formatted and serde_json::to_vec allocate; see the gate README.
const MAX_BYTES: usize = 256 * 1024;
const MAX_DEPS: usize = 64;
const LIFETIME: Duration = Duration::from_secs(20);
const WAIT: Duration = Duration::from_secs(2);

struct Basis {
    original: FlureePolicyContext,
    run: RunEnvelope,
    // Trusted fixture controller contract: seed includes rejected/cap-denied work;
    // these scopes conservatively represent complete interpretation/absence reads.
    required: BTreeSet<Need>,
    deadline: Instant,
    // Private cumulative ledger includes positives first discovered after preparation.
    observed: std::sync::Mutex<BTreeSet<Need>>,
    observation_overflow: AtomicBool,
}
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Need(ResourceId, Iri);
struct Footprint {
    basis: Arc<Basis>,
    operation: Operation,
    needs: BTreeSet<Need>,
}
fn view(id: &str) -> Need {
    Need(
        ResourceId::new(id).unwrap(),
        Iri::http("https://ns.flur.ee/db#view").unwrap(),
    )
}
fn denied_probe() -> Error {
    err(ErrorKind::Denied, "probe authorization denied")
}
impl Basis {
    async fn capture(
        b: &FlureeBackend,
        p: &FlureePrincipal,
        run: RunEnvelope,
    ) -> Result<Arc<Self>> {
        let _gate = tokio::time::timeout(WAIT, b.mutation_gate.lock())
            .await
            .map_err(|_| err(ErrorKind::Limit, "capture wait"))?;
        let original = b.policy_context_locked(p).await?;
        if run.owner() != p.id() {
            return Err(denied_probe());
        }
        b.validate_snapshot(&run.replay().data().snapshot)
            .await
            .map_err(backend)?;
        retained_context_budget(&original, 4096, MAX_BYTES)?;
        Ok(Arc::new(Self {
            original,
            run,
            required: std::iter::once(view("seed"))
                .chain(REQUIRED_SCOPES.iter().map(|s| view(s)))
                .collect(),
            deadline: Instant::now() + LIFETIME,
            observed: std::sync::Mutex::new(BTreeSet::new()),
            observation_overflow: AtomicBool::new(false),
        }))
    }
    // Pure frozen evaluator: this is NOT a live PolicyService context accessor.
    fn visible(&self, need: &Need) -> bool {
        let c = &self.original;
        let Some((enabled, roles)) = c.state.principals.get(&c.principal) else {
            return false;
        };
        let empty = BTreeSet::new();
        let allowed = c.state.policy.allows_resource(
            *enabled,
            roles,
            need.0.as_str(),
            &need.1,
            c.existing
                .contains(need.0.as_str())
                .then(|| c.state.classes.get(&need.0).unwrap_or(&empty)),
        );
        if allowed {
            let mut observed = self.observed.lock().unwrap();
            if !observed.contains(need) {
                let bytes = observed.iter().fold(0usize, |bytes, n| {
                    bytes
                        .saturating_add(n.0.as_str().len())
                        .saturating_add(n.1.as_str().len())
                });
                if observed.len() >= MAX_DEPS
                    || bytes
                        .saturating_add(need.0.as_str().len())
                        .saturating_add(need.1.as_str().len())
                        > MAX_BYTES
                {
                    self.observation_overflow.store(true, Ordering::SeqCst);
                } else {
                    observed.insert(need.clone());
                }
            }
        }
        allowed
    }
    fn footprint(self: &Arc<Self>, needs: impl IntoIterator<Item = Need>) -> Result<Footprint> {
        let mut all = BTreeSet::new();
        let mut bytes = 0usize;
        for (index, need) in needs.into_iter().enumerate() {
            if index >= MAX_DEPS {
                return Err(err(ErrorKind::Limit, "dependency count"));
            }
            bytes = bytes
                .saturating_add(need.0.as_str().len())
                .saturating_add(need.1.as_str().len());
            if bytes > MAX_BYTES {
                return Err(err(ErrorKind::Limit, "dependency bytes"));
            }
            // False is a frozen exclusion, never a release grant.
            if self.visible(&need) {
                all.insert(need);
            }
        }
        if all
            .iter()
            .map(|n| n.0.as_str().len() + n.1.as_str().len())
            .sum::<usize>()
            > MAX_BYTES
        {
            return Err(err(ErrorKind::Limit, "dependency bytes"));
        }
        Ok(Footprint {
            basis: self.clone(),
            operation: Operation::Query,
            needs: all,
        })
    }
}
// This rejects oversized retained contexts, not the allocations already made by
// policy_context_locked, PolicyState::projection or the native formatted query.
fn retained_context_budget(c: &FlureePolicyContext, entries: usize, bytes: usize) -> Result<()> {
    if c.existing.len() > entries {
        return Err(err(ErrorKind::Limit, "retained existence count"));
    }
    let existence_bytes = c
        .existing
        .iter()
        .fold(0usize, |n, s| n.saturating_add(s.len()));
    let remaining = bytes
        .checked_sub(existence_bytes)
        .ok_or_else(|| err(ErrorKind::Limit, "retained existence bytes"))?;
    c.state.projection().canonical_bytes(Limits::new(
        MAX_BYTES, 128, MAX_BYTES, MAX_BYTES, remaining,
    )?)?;
    Ok(())
}
impl Footprint {
    async fn validate(
        &self,
        b: &FlureeBackend,
        p: &FlureePrincipal,
        basis: &Arc<Basis>,
    ) -> Result<FlureePolicyContext> {
        b.check_issuer(&basis.original.issuer)?;
        if self.needs.len() > MAX_DEPS
            || self.needs.iter().fold(0usize, |bytes, need| {
                bytes
                    .saturating_add(need.0.as_str().len())
                    .saturating_add(need.1.as_str().len())
            }) > MAX_BYTES
        {
            return Err(err(ErrorKind::Limit, "descriptor budget"));
        }
        if !Arc::ptr_eq(&self.basis, basis)
            || p.id != basis.original.principal
            || Instant::now() >= basis.deadline
        {
            return Err(denied_probe());
        }
        {
            let observed = basis.observed.lock().unwrap();
            if basis.observation_overflow.load(Ordering::SeqCst)
                || observed.len() > MAX_DEPS
                || observed.iter().fold(0usize, |bytes, need| {
                    bytes
                        .saturating_add(need.0.as_str().len())
                        .saturating_add(need.1.as_str().len())
                }) > MAX_BYTES
            {
                return Err(err(ErrorKind::Limit, "cumulative dependency count"));
            }
            if self.operation != Operation::Query
                || !basis.required.is_subset(&self.needs)
                || !observed.is_subset(&self.needs)
            {
                return Err(denied_probe());
            }
        }
        // A typed internal forgery cannot promote an original exclusion to a grant.
        if self.needs.iter().any(|need| !basis.visible(need)) {
            return Err(denied_probe());
        }
        let current = b.policy_context_locked(p).await?;
        retained_context_budget(&current, 4096, MAX_BYTES)?;
        b.require_operation(&current, self.operation)?;
        for n in &self.needs {
            if !b.fact_allowed(&current, &n.0, &n.1)? {
                return Err(denied_probe());
            }
        }
        Ok(current)
    }
}

// No refreshed capability escapes: one bounded enqueue, while gate and fence live.
async fn release(
    b: Arc<FlureeBackend>,
    p: FlureePrincipal,
    basis: Arc<Basis>,
    footprint: Footprint,
    fence: Box<dyn ExternalPublicationFence>,
    sink: impl FnOnce() -> Result<()> + Send + 'static,
) -> Result<()> {
    tokio::spawn(async move {
        fence.check()?;
        let _gate = tokio::time::timeout(WAIT, b.mutation_gate.clone().lock_owned())
            .await
            .map_err(|_| err(ErrorKind::Limit, "release wait"))?;
        let started = Instant::now();
        fence.check()?;
        let current = footprint.validate(&b, &p, &basis).await?;
        fence.check()?;
        if Instant::now() >= basis.deadline {
            return Err(denied_probe());
        }
        sink()?;
        eprintln!(
            "gate-c refresh scan={} gate_us={}",
            current.existing.len(),
            started.elapsed().as_micros()
        );
        Ok(())
    })
    .await
    .map_err(|_| err(ErrorKind::Backend, "probe owner failed"))?
}

async fn stored(b: &FlureeBackend, run: &RunEnvelope) -> Result<Option<RunEnvelope>> {
    let head = b.native.head().await.map_err(backend)?;
    let raw = b
        .keyed(
            &head,
            "record",
            &resource_key(run.descriptor_id()?.as_str()),
        )
        .await
        .map_err(backend)?;
    raw.map(|raw| {
        RunEnvelope::from_record(
            &decode(&raw, b.options.codec_limits).map_err(backend)?,
            b.options.codec_limits,
        )
    })
    .transpose()
}
fn authorize_record(b: &FlureeBackend, c: &FlureePolicyContext, run: &RunEnvelope) -> Result<()> {
    for scope in &run.replay().data().scopes {
        if !b.resource_allowed(c, scope)? {
            return Err(denied_probe());
        }
    }
    for observation in &run.replay().data().policy {
        if observation.allowed
            && !match &observation.predicate {
                Some(p) => b.fact_allowed(c, &observation.resource, p)?,
                None => b.resource_allowed(c, &observation.resource)?,
            }
        {
            return Err(denied_probe());
        }
    }
    let id = run.descriptor_id()?;
    if !b.resource_allowed(c, &id)? || !b.fact_allowed(c, &id, &Iri::http(RUN_PAYLOAD)?)? {
        return Err(denied_probe());
    }
    Ok(())
}
async fn commit(
    b: Arc<FlureeBackend>,
    p: FlureePrincipal,
    basis: Arc<Basis>,
    footprint: Footprint,
    fence: Box<dyn ExternalPublicationFence>,
    sink: impl FnOnce(&RunEnvelope, &SnapshotRef) -> Result<()> + Send + 'static,
) -> Result<SnapshotRef> {
    tokio::spawn(async move {
        let gate = Arc::new(
            tokio::time::timeout(WAIT, b.mutation_gate.clone().lock_owned())
                .await
                .map_err(|_| err(ErrorKind::Limit, "commit wait"))?,
        );
        fence.check()?;
        let current = footprint.validate(&b, &p, &basis).await?;
        let run = &basis.run;
        if run.owner() != p.id() {
            return Err(denied_probe());
        }
        b.validate_snapshot(&run.replay().data().snapshot)
            .await
            .map_err(backend)?;
        let key = IdempotencyKey::new(format!(
            "{INTERNAL_PREFIX}runs/{}",
            ContentHash::of_bytes(run.id().as_str().as_bytes()).as_str()
        ))?;
        let receipt = if let Some(old) = stored(&b, run).await? {
            // Exact fixture binding is deliberately stricter than operation-hash matching.
            if old != *run {
                return Err(err(ErrorKind::Conflict, "original mismatch"));
            }
            authorize_record(&b, &current, &old)?;
            b.receipt(&key)
                .await
                .map_err(backend)?
                .ok_or_else(|| err(ErrorKind::Backend, "receipt absent"))?
        } else {
            authorize_record(
                &b,
                &current.clone().with_existing(&run.descriptor_id()?),
                run,
            )?;
            let ExportRecord::Resource(record) = run.to_record(b.options.codec_limits)? else {
                unreachable!()
            };
            let batch = AdmissionBatch::new(
                vec![],
                vec![],
                vec![ResourceChange::Add(record)],
                vec![],
                obj([]),
                b.options.codec_limits,
            )?;
            fence.check()?;
            b.admit_locked(&key, &batch, true, gate.clone())
                .await
                .map_err(backend)?
        };
        let current = footprint.validate(&b, &p, &basis).await?;
        let original = stored(&b, run).await?.ok_or_else(denied_probe)?;
        if original != *run {
            return Err(err(ErrorKind::Conflict, "stored binding"));
        }
        authorize_record(&b, &current, &original)?;
        fence.check()?;
        if Instant::now() >= basis.deadline {
            return Err(denied_probe());
        }
        sink(&original, receipt.snapshot())?;
        Ok(receipt.snapshot().clone())
    })
    .await
    .map_err(|_| err(ErrorKind::Backend, "commit owner failed"))?
}
async fn prepared(b: &FlureeBackend, id: &str) -> (FlureePrincipal, Arc<Basis>) {
    let p = b
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let run = envelope(b.head().await.unwrap(), id, "alice");
    let basis = Basis::capture(b, &p, run).await.unwrap();
    (p, basis)
}
fn required(basis: &Arc<Basis>) -> Footprint {
    basis
        .footprint(std::iter::once(view("seed")).chain(REQUIRED_SCOPES.iter().map(|s| view(s))))
        .unwrap()
}

#[test]
fn peer_and_unrelated_commit_refresh_without_re_evaluation() {
    native_test(|| async {
        let (_dir, b, _) = setup().await;
        let (p, basis) = prepared(&b, "original").await;
        let old = GraphBackend::open_snapshot(b.as_ref(), &basis.run.replay().data().snapshot)
            .await
            .unwrap();
        let before = old
            .resource(&ResourceId::new("seed").unwrap())
            .await
            .unwrap();
        let evaluations = Arc::new(AtomicUsize::new(1));
        let calls = Arc::new(AtomicUsize::new(1));
        let (ready, ready_rx) = oneshot::channel();
        let (resume, resume_rx) = oneshot::channel();
        let owner = b.clone();
        let principal = p.clone();
        let frozen = basis.clone();
        let paused = tokio::spawn(async move {
            ready.send(()).unwrap();
            resume_rx.await.unwrap();
            release(
                owner.clone(),
                principal.clone(),
                frozen.clone(),
                required(&frozen),
                Box::new(OpenFence),
                || Ok(()),
            )
            .await
            .unwrap();
            commit(
                owner,
                principal,
                frozen.clone(),
                required(&frozen),
                Box::new(OpenFence),
                |_, _| Ok(()),
            )
            .await
            .unwrap()
        });
        ready_rx.await.unwrap();
        let peer = b
            .issue_principal(PrincipalId::new("bob").unwrap())
            .await
            .unwrap();
        b.clone()
            .guarded_owned_commit_record(
                peer.clone(),
                b.current(&peer).await.unwrap(),
                envelope(b.head().await.unwrap(), "peer", "bob"),
                Box::new(OpenFence),
                |_, _| Ok(()),
            )
            .await
            .unwrap();
        b.admit(
            &IdempotencyKey::new("unrelated-refresh").unwrap(),
            &batch("later"),
        )
        .await
        .unwrap();
        assert_eq!(
            b.resource_allowed(&basis.original, &view("seed").0)
                .unwrap_err()
                .kind,
            ErrorKind::PolicyChanged
        );
        resume.send(()).unwrap();
        let receipt = paused.await.unwrap();
        assert_ne!(receipt, basis.run.replay().data().snapshot);
        assert_eq!(old.resource(&view("seed").0).await.unwrap(), before);
        assert!(basis.visible(&view("seed")));
        let head = b.head().await.unwrap();
        let original = basis.run.clone();
        let expected_receipt = receipt.clone();
        let retry = commit(
            b.clone(),
            p,
            basis.clone(),
            required(&basis),
            Box::new(OpenFence),
            move |r, s| {
                assert_eq!(r, &original);
                assert_eq!(s, &expected_receipt);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(retry, receipt);
        assert_eq!(b.head().await.unwrap(), head);
        assert_eq!(evaluations.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn unseen_lazy_existence_and_policy_false_stay_frozen() {
    native_test(|| async {
        let (_dir, b, mut state) = setup().await;
        let (p, basis) = prepared(&b, "lazy").await;
        // Do NOT observe 'late-lazy' before mutation.
        b.admit(
            &IdempotencyKey::new("lazy-add").unwrap(),
            &batch("late-lazy"),
        )
        .await
        .unwrap();
        assert!(b
            .resource_allowed(&b.current(&p).await.unwrap(), &view("late-lazy").0)
            .unwrap());
        assert!(!basis.visible(&view("late-lazy")));
        assert!(
            !basis.visible(&view("late-lazy")),
            "replay uses same frozen basis"
        );
        state.policy = policy(false);
        b.set_policy_state(&IdempotencyKey::new("deny-before").unwrap(), &state)
            .await
            .unwrap();
        let (_, denied_basis) = prepared(&b, "false-mask").await;
        assert!(!denied_basis.visible(&view("seed")));
        state.policy = policy(true);
        b.set_policy_state(&IdempotencyKey::new("grant-after").unwrap(), &state)
            .await
            .unwrap();
        assert!(!denied_basis.visible(&view("seed")));
        assert!(
            !denied_basis.visible(&view(REQUIRED_SCOPES[0])),
            "unseen policy false"
        );
        assert!(denied_basis
            .footprint([view("seed")])
            .unwrap()
            .needs
            .is_empty());
    });
}

#[test]
fn revoked_positive_and_disabled_principal_deny_release_and_record() {
    native_test(|| async {
        let (_dir, b, mut state) = setup().await;
        let (p, basis) = prepared(&b, "revoked").await;
        state.policy = policy(false);
        b.set_policy_state(&IdempotencyKey::new("revoke-positive").unwrap(), &state)
            .await
            .unwrap();
        assert!(basis.visible(&view("seed")));
        assert_eq!(
            release(
                b.clone(),
                p.clone(),
                basis.clone(),
                required(&basis),
                Box::new(OpenFence),
                || panic!("denied enqueue")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        assert_eq!(
            commit(
                b.clone(),
                p.clone(),
                basis.clone(),
                required(&basis),
                Box::new(OpenFence),
                |_, _| panic!("denied publication")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        state.policy = policy(true);
        state.principals.get_mut(p.id()).unwrap().0 = false;
        b.set_policy_state(&IdempotencyKey::new("disable-refresh").unwrap(), &state)
            .await
            .unwrap();
        assert_eq!(
            release(
                b.clone(),
                p,
                basis.clone(),
                required(&basis),
                Box::new(OpenFence),
                || panic!("disabled enqueue")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        assert!(stored(&b, &basis.run).await.unwrap().is_none());
    });
}

struct CancelFence {
    cancelled: Arc<AtomicBool>,
    dropped: Option<oneshot::Sender<()>>,
}
impl ExternalPublicationFence for CancelFence {
    fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(denied_probe())
        } else {
            Ok(())
        }
    }
}
impl Drop for CancelFence {
    fn drop(&mut self) {
        if let Some(tx) = self.dropped.take() {
            let _ = tx.send(());
        }
    }
}
#[test]
fn cancellation_during_native_commit_retains_gate_fence_and_original_retry() {
    native_test(|| async {
        let (_dir, b, _) = setup().await;
        let (p, basis) = prepared(&b, "cancel-owned").await;
        let cancelled = Arc::new(AtomicBool::new(false));
        let (dropped, mut dropped_rx) = oneshot::channel();
        let fence = CancelFence {
            cancelled: cancelled.clone(),
            dropped: Some(dropped),
        };
        let (entered, resume) = b.native.pause_commit().await;
        let owner = b.clone();
        let principal = p.clone();
        let frozen = basis.clone();
        let caller = tokio::spawn(async move {
            commit(
                owner,
                principal,
                frozen.clone(),
                required(&frozen),
                Box::new(fence),
                |_, _| panic!("cancelled delivery"),
            )
            .await
        });
        entered.notified().await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        cancelled.store(true, Ordering::SeqCst);
        assert!(
            b.mutation_gate.try_lock().is_err(),
            "owned native admission retains gate"
        );
        assert!(matches!(
            dropped_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        resume.notify_one();
        dropped_rx.await.unwrap();
        let receipt = b.head().await.unwrap();
        assert_eq!(stored(&b, &basis.run).await.unwrap().unwrap(), basis.run);
        assert_ne!(receipt, basis.run.replay().data().snapshot);
        let original = basis.run.clone();
        assert_eq!(
            commit(
                b.clone(),
                p,
                basis.clone(),
                required(&basis),
                Box::new(OpenFence),
                move |r, _| {
                    assert_eq!(r, &original);
                    Ok(())
                }
            )
            .await
            .unwrap(),
            receipt
        );
        assert_eq!(b.head().await.unwrap(), receipt);
    });
}

#[test]
fn same_gate_enqueue_and_pre_release_cancellation() {
    native_test(|| async {
        let (_dir, b, _) = setup().await;
        let (p, basis) = prepared(&b, "atomic-release").await;
        let owner = b.clone();
        release(
            b.clone(),
            p.clone(),
            basis.clone(),
            required(&basis),
            Box::new(OpenFence),
            move || {
                assert!(
                    owner.mutation_gate.try_lock().is_err(),
                    "no refresh/enqueue gap"
                );
                Ok(())
            },
        )
        .await
        .unwrap();
        let fence = CancelFence {
            cancelled: Arc::new(AtomicBool::new(true)),
            dropped: None,
        };
        assert_eq!(
            release(
                b,
                p,
                basis.clone(),
                required(&basis),
                Box::new(fence),
                || panic!("cancelled")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
    });
}

#[test]
fn foreign_principal_basis_mismatch_and_expired_wait_fail_closed() {
    native_test(|| async {
        let (_dir, b, _) = setup().await;
        let (p, basis) = prepared(&b, "binding").await;
        let (_, other) = prepared(&b, "other-binding").await;
        assert_eq!(
            release(
                b.clone(),
                p.clone(),
                basis.clone(),
                required(&other),
                Box::new(OpenFence),
                || panic!("mismatched descriptor")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        let bob = b
            .issue_principal(PrincipalId::new("bob").unwrap())
            .await
            .unwrap();
        assert_eq!(
            release(
                b.clone(),
                bob,
                basis.clone(),
                required(&basis),
                Box::new(OpenFence),
                || panic!("wrong principal")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        let (_other_dir, foreign, _) = setup().await;
        let foreign_p = foreign.issue_principal(p.id().clone()).await.unwrap();
        assert_eq!(
            release(
                b.clone(),
                foreign_p,
                basis.clone(),
                required(&basis),
                Box::new(OpenFence),
                || panic!("foreign issuer")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        let (_, mut expired) = prepared(&b, "expired").await;
        Arc::get_mut(&mut expired).unwrap().deadline = Instant::now();
        let gate = b.mutation_gate.clone().lock_owned().await;
        let owner = b.clone();
        let frozen = expired.clone();
        let task = tokio::spawn(async move {
            release(
                owner,
                p,
                frozen.clone(),
                required(&frozen),
                Box::new(OpenFence),
                || panic!("expired wait"),
            )
            .await
        });
        drop(gate);
        assert_eq!(task.await.unwrap().unwrap_err().kind, ErrorKind::Denied);
        let needs = (0..=MAX_DEPS).map(|i| {
            Need(
                view("seed").0,
                Iri::http(format!("https://gate.example/property/{i}")).unwrap(),
            )
        });
        assert_eq!(basis.footprint(needs).err().unwrap().kind, ErrorKind::Limit);
    });
}

fn targeted_deny(state: &mut PolicyState, target: &str, value: &str) {
    let mut policy = state.policy.projection();
    let V::Object(root) = &mut policy else {
        unreachable!()
    };
    let V::Array(rules) = root.get_mut("policies").unwrap() else {
        unreachable!()
    };
    rules.push(V::parse(format!(r#"{{"@id":"https://gate.example/deny-specific","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#{target}":"{value}"}}"#).as_bytes(), Limits::default()).unwrap());
    state.policy = PolicySet::from_value(&policy).unwrap();
}
#[test]
fn exact_fact_scope_function_provider_and_unchanged_policy_class_revocations() {
    native_test(|| async {
        for mode in ["resource", "fact", "scope", "function", "provider", "class"] {
            let (_dir, b, mut state) = setup().await;
            for id in [
                "https://gate.example/support",
                "https://gate.example/function/hash-1",
                "https://gate.example/provider/endpoint-1",
            ] {
                b.admit(
                    &IdempotencyKey::new(format!("seed-{id}")).unwrap(),
                    &batch(id),
                )
                .await
                .unwrap();
            }
            if mode == "class" {
                targeted_deny(&mut state, "onClass", "https://gate.example/revoked");
                b.set_policy_state(&IdempotencyKey::new("class-rule").unwrap(), &state)
                    .await
                    .unwrap();
            }
            let (p, mut basis) = prepared(&b, "specific").await;
            let fact = Need(
                view("https://gate.example/support").0,
                Iri::http("https://gate.example/argument").unwrap(),
            );
            // Fixture preparation binds exact disclosure resources AND graph/state argument fact.
            // This is not endpoint registration, provider code or broker authorization.
            Arc::get_mut(&mut basis).unwrap().required.extend([
                view("https://gate.example/support"),
                fact.clone(),
                view("https://gate.example/function/hash-1"),
                view("https://gate.example/provider/endpoint-1"),
            ]);
            let footprint = || basis.footprint(basis.required.iter().cloned()).unwrap();
            release(
                b.clone(),
                p.clone(),
                basis.clone(),
                footprint(),
                Box::new(OpenFence),
                || Ok(()),
            )
            .await
            .unwrap();
            let prior_policy = state.policy.clone();
            match mode {
                "resource" => {
                    targeted_deny(&mut state, "onSubject", "https://gate.example/support")
                }
                "fact" => targeted_deny(&mut state, "onProperty", fact.1.as_str()),
                "scope" => targeted_deny(&mut state, "onSubject", REQUIRED_SCOPES[0]),
                "function" => targeted_deny(
                    &mut state,
                    "onSubject",
                    "https://gate.example/function/hash-1",
                ),
                "provider" => targeted_deny(
                    &mut state,
                    "onSubject",
                    "https://gate.example/provider/endpoint-1",
                ),
                "class" => {
                    state.classes.insert(
                        view("https://gate.example/support").0,
                        [Iri::http("https://gate.example/revoked").unwrap()]
                            .into_iter()
                            .collect(),
                    );
                }
                _ => unreachable!(),
            }
            b.set_policy_state(&IdempotencyKey::new("specific-revoke").unwrap(), &state)
                .await
                .unwrap();
            if mode == "class" {
                assert_eq!(prior_policy, b.policy_state().await.unwrap().policy);
            }
            // Repeat represents cache hit/retry/postcallback boundaries: every use recomputes.
            for _ in 0..2 {
                assert_eq!(
                    release(
                        b.clone(),
                        p.clone(),
                        basis.clone(),
                        footprint(),
                        Box::new(OpenFence),
                        || panic!("revoked exact dependency")
                    )
                    .await
                    .unwrap_err()
                    .kind,
                    ErrorKind::Denied,
                    "{mode}"
                );
            }
            assert_eq!(
                commit(
                    b.clone(),
                    p.clone(),
                    basis.clone(),
                    footprint(),
                    Box::new(OpenFence),
                    |_, _| panic!("revoked cumulative publication")
                )
                .await
                .unwrap_err()
                .kind,
                ErrorKind::Denied,
                "{mode}"
            );
        }
    });
}

#[test]
fn incomplete_descriptor_and_bounded_gate_wait_reject() {
    native_test(|| async {
        let (_dir, b, _) = setup().await;
        let (p, basis) = prepared(&b, "bounded").await;
        let mut incomplete = required(&basis);
        incomplete.needs.remove(&view("seed"));
        assert_eq!(
            release(
                b.clone(),
                p.clone(),
                basis.clone(),
                incomplete,
                Box::new(OpenFence),
                || panic!("omitted rejected-work support")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        let gate = b.mutation_gate.clone().lock_owned().await;
        assert_eq!(
            release(
                b.clone(),
                p,
                basis.clone(),
                required(&basis),
                Box::new(OpenFence),
                || panic!("gate wait exceeded")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Limit
        );
        drop(gate);
    });
}
