use cdb_backend_fluree::{
    native::NativeResult, policy::PolicyState, AuthorityOptions, FlureeBackend,
};
use cdb_core::{
    admission::*, claim::TypedLiteral, contracts::PolicyService, id::*, policy::PolicySet,
    storage_origin::INTERNAL_PREFIX, CanonicalValue as V, ErrorKind, Limits,
};
use std::collections::BTreeSet;
use std::future::Future;
fn key(s: &str) -> IdempotencyKey {
    IdempotencyKey::new(s).unwrap()
}
fn iri(s: &str) -> Iri {
    Iri::http(format!("https://test.example/{s}")).unwrap()
}
fn resource() -> ResourceId {
    ResourceId::new("https://test.example/item").unwrap()
}
fn principal() -> PrincipalId {
    PrincipalId::new("alice").unwrap()
}
fn options(path: &std::path::Path) -> AuthorityOptions {
    AuthorityOptions::new(
        path.join("db"),
        "policy:main".into(),
        BackendId::new("fluree").unwrap(),
        AuthorityId::new("owner").unwrap(),
        GraphId::new("graph").unwrap(),
    )
}
fn state(rules: &str) -> NativeResult<PolicyState> {
    let mut s = PolicyState::deny_all()?;
    s.principals
        .insert(principal(), (true, BTreeSet::from([iri("Reader")])));
    s.policy = PolicySet::parse(format!(r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{rules}]}}"#).as_bytes(), Limits::default())?;
    Ok(s)
}
fn rule(target: &str, allow: bool) -> String {
    format!(
        r#"{{"@id":"https://test.example/{allow}","@type":["https://ns.flur.ee/db#AccessPolicy","https://test.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":{allow}{target}}}"#
    )
}
fn batch(id: ResourceId) -> NativeResult<AdmissionBatch> {
    let r = DependencyRecord::new(
        "ctxql-resource/v1",
        id,
        ResourceKind::Policy,
        vec![Fact::new(
            iri("name"),
            FactTerm::Literal(TypedLiteral::new(
                Iri::http("http://www.w3.org/2001/XMLSchema#string")?,
                V::string("item"),
                None,
            )?),
        )],
    )?;
    Ok(AdmissionBatch::new(
        vec![],
        vec![],
        vec![ResourceChange::Add(r)],
        vec![],
        V::Object(Default::default()),
        Limits::default(),
    )?)
}
async fn setup() -> NativeResult<(tempfile::TempDir, FlureeBackend)> {
    let tmp = tempfile::tempdir()?;
    let b = FlureeBackend::create(options(tmp.path())).await?;
    b.admit(&key("data"), &batch(resource())?).await?;
    Ok((tmp, b))
}
#[tokio::test]
async fn default_deny_and_inactive_roles() -> NativeResult<()> {
    let (_tmp, b) = setup().await?;
    assert!(b.issue_principal(principal()).await.is_err());
    let mut s = state("")?;
    b.set_policy_state(&key("empty"), &s).await?;
    let p = b.issue_principal(principal()).await?;
    assert!(!b.resource_allowed(&b.current(&p).await?, &resource())?);
    s.policy = state(&rule("", true))?.policy;
    s.principals.get_mut(&principal()).unwrap().1.clear();
    b.set_policy_state(&key("inactive"), &s).await?;
    assert!(!b.resource_allowed(&b.current(&p).await?, &resource())?);
    Ok(())
}
#[tokio::test]
async fn roles_classes_and_property_narrowing() -> NativeResult<()> {
    let (_tmp, b) = setup().await?;
    let mut s = state(&format!(
        "{},{}",
        rule(
            r#", "https://ns.flur.ee/db#onClass":"https://test.example/Thing""#,
            true
        ),
        rule(
            r#", "https://ns.flur.ee/db#onProperty":"https://test.example/secret""#,
            false
        )
    ))?;
    b.set_policy_state(&key("untyped"), &s).await?;
    let p = b.issue_principal(principal()).await?;
    assert!(!b.resource_allowed(&b.current(&p).await?, &resource())?);
    s.classes.insert(resource(), BTreeSet::from([iri("Thing")]));
    b.set_policy_state(&key("typed"), &s).await?;
    let c = b.current(&p).await?;
    assert!(b.resource_allowed(&c, &resource())?);
    assert!(!b.fact_allowed(&c, &resource(), &iri("secret"))?);
    assert!(!b.resource_allowed(&c, &ResourceId::new("missing")?)?);
    Ok(())
}
#[tokio::test]
async fn foreign_issuer_and_principal_mismatch() -> NativeResult<()> {
    let (_t, a) = setup().await?;
    let (_u, b) = setup().await?;
    let mut s = state(&rule("", true))?;
    s.principals.insert(
        PrincipalId::new("bob")?,
        (true, BTreeSet::from([iri("Reader")])),
    );
    a.set_policy_state(&key("p"), &s).await?;
    b.set_policy_state(&key("p"), &s).await?;
    let p = a.issue_principal(principal()).await?;
    let c = a.current(&p).await?;
    assert_eq!(b.current(&p).await.err().unwrap().kind, ErrorKind::Denied);
    assert_eq!(
        b.resource_allowed(&c, &resource()).unwrap_err().kind,
        ErrorKind::Denied
    );
    let bob = a.issue_principal(PrincipalId::new("bob")?).await?;
    let mut called = false;
    let mut sink = || {
        called = true;
        Ok(())
    };
    assert!(a.publish(&bob, &c, &mut sink).await.is_err());
    assert!(!called);
    Ok(())
}
#[tokio::test]
async fn revocation_governs_old_data() -> NativeResult<()> {
    let (_tmp, b) = setup().await?;
    let old = b.head().await?;
    let mut s = state(&rule("", true))?;
    b.set_policy_state(&key("allow"), &s).await?;
    let p = b.issue_principal(principal()).await?;
    let c = b.current(&p).await?;
    assert!(b.resource_allowed(&c, &resource())?);
    s.principals.get_mut(&principal()).unwrap().0 = false;
    b.set_policy_state(&key("revoke"), &s).await?;
    b.validate_snapshot(&old).await?;
    assert_eq!(b.current(&p).await.err().unwrap().kind, ErrorKind::Denied);
    let mut called = false;
    let mut sink = || {
        called = true;
        Ok(())
    };
    assert!(b.publish(&p, &c, &mut sink).await.is_err());
    assert!(!called);
    Ok(())
}
#[tokio::test]
async fn every_head_invalidates_context() -> NativeResult<()> {
    let (_tmp, b) = setup().await?;
    b.set_policy_state(&key("allow"), &state(&rule("", true))?)
        .await?;
    let p = b.issue_principal(principal()).await?;
    let c = b.current(&p).await?;
    b.capture(None).await?;
    assert_eq!(
        b.resource_allowed(&c, &resource()).unwrap_err().kind,
        ErrorKind::PolicyChanged
    );
    let c = b.current(&p).await?;
    b.admit(&key("other"), &batch(ResourceId::new("other")?)?)
        .await?;
    assert_eq!(
        b.resource_allowed(&c, &resource()).unwrap_err().kind,
        ErrorKind::PolicyChanged
    );
    Ok(())
}
#[tokio::test]
async fn reopen_state_and_idempotent_admin_journal() -> NativeResult<()> {
    let (tmp, b) = setup().await?;
    let s = state(&rule("", true))?;
    let receipt = b.set_policy_state(&key("allow"), &s).await?;
    let p = b.issue_principal(principal()).await?;
    let c = b.current(&p).await?;
    b.capture(None).await?;
    drop(b);
    let b = FlureeBackend::open(options(tmp.path())).await?;
    assert_eq!(b.policy_state().await?, s);
    let head = b.head().await?;
    assert_eq!(b.set_policy_state(&key("allow"), &s).await?, receipt);
    assert_eq!(b.head().await?, head);
    assert!(b
        .set_policy_state(&key("allow"), &state("")?)
        .await
        .is_err());
    assert!(b.current(&p).await.is_err());
    assert!(b.resource_allowed(&c, &resource()).is_err());
    let fresh = b.issue_principal(principal()).await?;
    assert!(b.resource_allowed(&b.current(&fresh).await?, &resource())?);
    Ok(())
}
#[tokio::test]
async fn ordinary_admission_cannot_forge_policy_or_admin_retry() -> NativeResult<()> {
    let (_tmp, b) = setup().await?;
    let s = state(&rule("", true))?;
    b.set_policy_state(&key("allow"), &s).await?;
    let head = b.head().await?;
    assert!(b
        .admit(
            &key("forge"),
            &batch(ResourceId::new(format!("{INTERNAL_PREFIX}policy/state"))?)?
        )
        .await
        .is_err());
    assert!(b
        .admit(
            &key(&format!("{INTERNAL_PREFIX}policy/admin/allow")),
            &batch(ResourceId::new("other")?)?
        )
        .await
        .is_err());
    assert_eq!(b.head().await?, head);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_holds_mutation_gate() -> NativeResult<()> {
    let (_tmp, b) = setup().await?;
    b.set_policy_state(&key("allow"), &state(&rule("", true))?)
        .await?;
    let b = std::sync::Arc::new(b);
    let p = b.issue_principal(principal()).await?;
    let c = b.current(&p).await?;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let publisher = b.clone();
    let task = tokio::spawn(async move {
        let mut tx = Some(started_tx);
        let mut sink = move || {
            tx.take().unwrap().send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        };
        publisher.publish(&p, &c, &mut sink).await
    });
    started_rx.await?;
    // Poll mutation while sink is active: it must park on the SAME gate.
    let mut capture = Box::pin(b.capture(None));
    let parked = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(matches!(
            capture.as_mut().poll(cx),
            std::task::Poll::Pending
        ))
    })
    .await;
    release_tx.send(())?;
    task.await??;
    assert!(parked);
    capture.await?;
    Ok(())
}
