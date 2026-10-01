//! Explicit native stale recording retains both identities; replay does not capture again.
#[allow(dead_code)]
mod common_p3;
use cdb_backend_fluree::runs::ExternalPublicationFence;
use cdb_core::{contracts::*, id::*, recording::RunEnvelope, CanonicalValue as V, Limits};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{
        prepare_recorded, prepare_replay, Consistency, ExecutionOptions, PreparedView, ViewProvider,
    },
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::{artifact, FixtureBuilder, CONFIG};
use common_p3::{reader_policy, NativeFixture};
struct Stale<'a> {
    f: &'a NativeFixture,
    pin: cdb_core::snapshot::SnapshotRef,
}
impl ViewProvider for Stale<'_> {
    fn propose_stale<'a>(
        &'a self,
        _: &'a CapturedSnapshot,
        _: &'a ExecutionOptions,
    ) -> IoFuture<'a, Option<cdb_core::snapshot::SnapshotRef>> {
        Box::pin(async { Ok(Some(self.pin.clone())) })
    }
    fn open<'a>(
        &'a self,
        c: &'a CapturedSnapshot,
        o: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        self.f.provider.open(c, o)
    }
}
struct Fence;
impl ExternalPublicationFence for Fence {
    fn check(&self) -> cdb_core::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn explicit_stale_native_run_roundtrips_and_replays_actual_pin() {
    let query = artifact(
        "https://fixture.example/stale-query",
        br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1},"return":{"explain":true}}"#,
    )
    .unwrap();
    let config = artifact("https://fixture.example/config", CONFIG.as_bytes()).unwrap();
    let mut builder = FixtureBuilder::new();
    builder
        .entity("A", None)
        .unwrap()
        .artifact(query.clone())
        .artifact(config.clone());
    let mut state = reader_policy();
    for op in [
        cdb_backend_fluree::runs::Operation::Query,
        cdb_backend_fluree::runs::Operation::Read,
    ] {
        state
            .principals
            .get_mut(&PrincipalId::new("reader").unwrap())
            .unwrap()
            .1
            .insert(Iri::new(op.role()).unwrap());
    }
    let f = NativeFixture::new(builder, state, 128).await;
    f.advance();
    f.backend.bootstrap_governance().await.unwrap();
    let actual = f.backend.head().await.unwrap();
    f.advance();
    let provider = Stale {
        f: &f,
        pin: actual.clone(),
    };
    let draft = compile(
        QuerySource::published(&query),
        None,
        &config,
        CompileOptions::default(),
    )
    .unwrap();
    let prepared = prepare_recorded(
        draft,
        f.backend.as_ref(),
        f.backend.as_ref(),
        &f.principal,
        &provider,
        Some(Consistency::AllowStale),
        ExecutionOptions::default(),
    )
    .await
    .unwrap();
    assert!(prepared.data().data().stale);
    assert_eq!(prepared.data().data().snapshot, actual);
    assert_ne!(prepared.data().data().requested_snapshot, actual);
    let wire = V::parse(prepared.wire_bytes(), Limits::default()).unwrap();
    assert_eq!(
        wire.field("consistency").unwrap().field("stale").unwrap(),
        &V::Bool(true)
    );
    let (data, context, _) = prepared.into_parts();
    let run = RunEnvelope::new(
        RunId::new("stale").unwrap(),
        PrincipalId::new("reader").unwrap(),
        ContentHash::of_bytes(b"explicit stale request"),
        data,
        Limits::default(),
    )
    .unwrap();
    f.backend
        .clone()
        .guarded_owned_commit_record(
            f.principal.clone(),
            context,
            run.clone(),
            Box::new(Fence),
            |_, _| Ok(()),
        )
        .await
        .unwrap();
    let context = f.backend.current(&f.principal).await.unwrap();
    let stored = f
        .backend
        .guarded_run(&f.principal, &context, run.id())
        .await
        .unwrap();
    assert_eq!(stored, run);
    let head = f.backend.head().await.unwrap();
    let replay = prepare_replay(
        stored.replay(),
        f.backend.as_ref(),
        f.backend.as_ref(),
        &f.principal,
        &provider,
        ExecutionOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        replay.verdict(),
        cdb_core::replay::ReplayVerdict::Reproduced
    );
    assert_eq!(
        head,
        f.backend.head().await.unwrap(),
        "replay must not capture or advance the clock"
    );
    drop(provider);
    f.shutdown().await;
    println!("P4_CASE {{\"id\":\"P4-Q027\",\"outcome\":\"passed\"}}");
}
