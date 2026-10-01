//! Additional native seam evidence; deliberately no dependency on cdb-service.
use super::*;

#[test]
fn retained_context_and_cumulative_lazy_budgets_fail_closed() {
    native_test(|| async {
        let (_dir, b, _) = setup().await;
        let (p, basis) = prepared(&b, "retained-budget").await;
        assert_eq!(
            retained_context_budget(&basis.original, 0, MAX_BYTES)
                .unwrap_err()
                .kind,
            ErrorKind::Limit
        );
        let existence_bytes = basis.original.existing.iter().map(String::len).sum();
        assert_eq!(
            retained_context_budget(&basis.original, 4096, existence_bytes)
                .unwrap_err()
                .kind,
            ErrorKind::Limit
        );
        let stale = required(&basis);
        for i in 0..=MAX_DEPS {
            assert!(basis.visible(&Need(
                view("seed").0,
                Iri::http(format!("https://gate.example/lazy/{i}")).unwrap()
            )));
        }
        assert!(basis.observed.lock().unwrap().len() <= MAX_DEPS);
        assert_eq!(
            release(b, p, basis, stale, Box::new(OpenFence), || panic!(
                "overflow cannot become a truncated successful footprint"
            ))
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Limit
        );
    });
}

// Test-only expiry-capable publication fence, NOT the service's SessionLease.
struct ExpiringFence {
    deadline: Instant,
    entered: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}
impl ExternalPublicationFence for ExpiringFence {
    fn check(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(denied_probe());
        }
        if let Some(tx) = self.entered.lock().unwrap().take() {
            let _ = tx.send(());
        }
        Ok(())
    }
}

#[test]
fn live_fence_expires_while_authority_gate_is_blocked() {
    native_test(|| async {
        let (_dir, b, _) = setup().await;
        let (p, basis) = prepared(&b, "live-expiry").await;
        let gate = b.mutation_gate.clone().lock_owned().await;
        let (entered, entered_rx) = oneshot::channel();
        let deadline = Instant::now() + Duration::from_millis(250);
        let fence = ExpiringFence {
            deadline,
            entered: std::sync::Mutex::new(Some(entered)),
        };
        let owner = b.clone();
        let frozen = basis.clone();
        let task = tokio::spawn(async move {
            release(
                owner,
                p,
                frozen.clone(),
                required(&frozen),
                Box::new(fence),
                || panic!("expired fence must not enqueue"),
            )
            .await
        });
        // A successful live check has occurred with the gate unavailable. Wait for
        // the actual deadline, not a sleep used to guess which task won a race.
        tokio::time::timeout(WAIT, entered_rx)
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        assert!(Instant::now() < basis.deadline, "only the fence expired");
        drop(gate);
        assert_eq!(
            tokio::time::timeout(WAIT, task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .kind,
            ErrorKind::Denied
        );
        assert!(stored(&b, &basis.run).await.unwrap().is_none());
    });
}

#[test]
fn lazy_positive_omission_and_typed_false_or_operation_forgery_refuse() {
    native_test(|| async {
        let (_dir, b, _) = setup().await;
        b.admit(
            &IdempotencyKey::new("lazy-positive-seed").unwrap(),
            &batch("https://gate.example/lazy-state"),
        )
        .await
        .unwrap();
        let (p, basis) = prepared(&b, "lazy-binding").await;
        let stale = required(&basis);
        // First encounter occurs after descriptor preparation, even on rejected work.
        assert!(basis.visible(&view("https://gate.example/lazy-state")));
        assert_eq!(
            release(
                b.clone(),
                p.clone(),
                basis.clone(),
                stale,
                Box::new(OpenFence),
                || panic!("omitted lazy state")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        let complete = || {
            basis
                .footprint(
                    basis
                        .required
                        .iter()
                        .cloned()
                        .chain([view("https://gate.example/lazy-state")]),
                )
                .unwrap()
        };
        release(
            b.clone(),
            p.clone(),
            basis.clone(),
            complete(),
            Box::new(OpenFence),
            || Ok(()),
        )
        .await
        .unwrap();
        let mut wrong_operation = complete();
        wrong_operation.operation = Operation::Read;
        let mut false_grant = complete();
        assert!(!basis.visible(&view("not-in-original")));
        false_grant.needs.insert(view("not-in-original"));
        for forged in [wrong_operation, false_grant] {
            assert_eq!(
                release(
                    b.clone(),
                    p.clone(),
                    basis.clone(),
                    forged,
                    Box::new(OpenFence),
                    || panic!("typed forgery")
                )
                .await
                .unwrap_err()
                .kind,
                ErrorKind::Denied
            );
        }
        let mut incomplete = complete();
        incomplete
            .needs
            .remove(&view("https://gate.example/lazy-state"));
        assert_eq!(
            commit(
                b.clone(),
                p,
                basis.clone(),
                incomplete,
                Box::new(OpenFence),
                |_, _| panic!("incomplete final footprint")
            )
            .await
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        assert!(stored(&b, &basis.run).await.unwrap().is_none());
    });
}

#[test]
fn full_mutations_order_before_validation_or_after_enqueue_and_callback() {
    native_test(|| async {
        for after_enqueue in [false, true] {
            for mode in [
                "resource",
                "fact",
                "scope",
                "function",
                "provider",
                "class",
                "principal",
            ] {
                let (_dir, b, mut state) = setup().await;
                let support = "https://gate.example/race-support";
                let function = "https://gate.example/race-function";
                let provider = "https://gate.example/race-provider";
                for id in [support, function, provider] {
                    b.admit(
                        &IdempotencyKey::new(format!("race-{id}")).unwrap(),
                        &batch(id),
                    )
                    .await
                    .unwrap();
                }
                if mode == "class" {
                    targeted_deny(&mut state, "onClass", "https://gate.example/revoked");
                    b.set_policy_state(&IdempotencyKey::new("race-class-rule").unwrap(), &state)
                        .await
                        .unwrap();
                }
                let (p, mut basis) = prepared(&b, "race").await;
                let fact = Need(
                    view(support).0,
                    Iri::http("https://gate.example/state-property").unwrap(),
                );
                Arc::get_mut(&mut basis).unwrap().required.extend([
                    view(support),
                    fact.clone(),
                    view(function),
                    view(provider),
                ]);
                let original_policy = state.policy.clone();
                match mode {
                    "resource" => targeted_deny(&mut state, "onSubject", support),
                    "fact" => targeted_deny(&mut state, "onProperty", fact.1.as_str()),
                    "scope" => targeted_deny(&mut state, "onSubject", REQUIRED_SCOPES[0]),
                    "function" => targeted_deny(&mut state, "onSubject", function),
                    "provider" => targeted_deny(&mut state, "onSubject", provider),
                    "class" => {
                        state.classes.insert(
                            view(support).0,
                            [Iri::http("https://gate.example/revoked").unwrap()]
                                .into_iter()
                                .collect(),
                        );
                    }
                    "principal" => state.principals.get_mut(p.id()).unwrap().0 = false,
                    _ => unreachable!(),
                }
                let footprint = || basis.footprint(basis.required.iter().cloned()).unwrap();
                let (enqueued, enqueued_rx) = oneshot::channel();
                let (mutated, mutated_rx) = oneshot::channel();
                let writer = b.clone();
                let administrator = tokio::spawn(async move {
                    enqueued_rx.await.unwrap();
                    writer
                        .set_policy_state(&IdempotencyKey::new("race-revoke").unwrap(), &state)
                        .await
                        .unwrap();
                    mutated.send(()).unwrap();
                });
                if after_enqueue {
                    let owner = b.clone();
                    release(
                        b.clone(),
                        p.clone(),
                        basis.clone(),
                        footprint(),
                        Box::new(OpenFence),
                        move || {
                            assert!(owner.mutation_gate.try_lock().is_err());
                            enqueued.send(()).unwrap();
                            Ok(())
                        },
                    )
                    .await
                    .unwrap();
                } else {
                    enqueued.send(()).unwrap();
                }
                // The actual administrator commit completes, not just a flag flip.
                tokio::time::timeout(WAIT * 4, mutated_rx)
                    .await
                    .unwrap()
                    .unwrap();
                administrator.await.unwrap();
                if mode == "class" {
                    assert_eq!(original_policy, b.policy_state().await.unwrap().policy);
                }
                // Represents callback return held outside authority ownership. Its
                // result must not influence authorized work before this new check.
                let (callback, callback_rx) = oneshot::channel();
                callback.send(17usize).unwrap();
                let result = callback_rx.await.unwrap();
                assert_eq!(result, 17);
                for _attempt in 0..2 {
                    assert_eq!(
                        release(
                            b.clone(),
                            p.clone(),
                            basis.clone(),
                            footprint(),
                            Box::new(OpenFence),
                            || panic!("revoked callback consumption/retry")
                        )
                        .await
                        .unwrap_err()
                        .kind,
                        ErrorKind::Denied,
                        "{mode}/{after_enqueue}"
                    );
                }
                assert_eq!(
                    commit(
                        b.clone(),
                        p,
                        basis.clone(),
                        footprint(),
                        Box::new(OpenFence),
                        |_, _| panic!("revoked publication")
                    )
                    .await
                    .unwrap_err()
                    .kind,
                    ErrorKind::Denied
                );
                assert!(stored(&b, &basis.run).await.unwrap().is_none());
            }
        }
    });
}
