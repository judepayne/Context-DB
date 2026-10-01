use super::*;

fn logical() -> LogicalLimiter {
    let mut limits = BrokerLimits::default();
    limits.global.max_queued_bytes = 10;
    limits.per_request_bytes = 10;
    limits.max_logical_calls = 2;
    LogicalLimiter::new(limits)
}
#[test]
fn global_bytes_cover_all_requests_and_retained_physical_owners() {
    let limiter = logical();
    let first = limiter.reserve("one", 6).unwrap();
    let physical = first.clone();
    drop(first);
    assert!(limiter.reserve("two", 5).is_err());
    let second = limiter.reserve("two", 4).unwrap();
    drop(physical);
    let third = limiter.reserve("three", 6).unwrap();
    assert_eq!(limiter.state.lock().unwrap().held_bytes, 10);
    drop((second, third));
    assert_eq!(limiter.state.lock().unwrap().held_bytes, 0);
}
#[test]
fn logical_call_counts_survive_consumption_but_finished_requests_are_reclaimed() {
    let limiter = logical();
    drop(limiter.reserve("one", 1).unwrap());
    drop(limiter.reserve("one", 1).unwrap());
    assert!(limiter.reserve("one", 1).is_err());
    limiter.finish_request("one");
    assert!(limiter.state.lock().unwrap().requests.is_empty());
    let held = limiter.reserve("two", 1).unwrap();
    limiter.finish_request("two");
    assert!(limiter.reserve("two", 1).is_err());
    assert_eq!(limiter.state.lock().unwrap().held_bytes, 1);
    drop(held);
    assert!(limiter.state.lock().unwrap().requests.is_empty());
}
#[test]
fn stop_all_closes_admission_but_retains_live_reservations() {
    let limiter = logical();
    let live = limiter.reserve("live", 4).unwrap();
    drop(limiter.reserve("idle", 1).unwrap());
    limiter.stop_all();
    assert!(limiter.reserve("live", 1).is_err());
    assert!(
        limiter.reserve("idle", 1).is_ok(),
        "closed idle IDs are reclaimed"
    );
    assert_eq!(limiter.state.lock().unwrap().held_bytes, 4);
    drop(live);
    assert_eq!(limiter.state.lock().unwrap().held_bytes, 0);
}
#[test]
fn identity_and_abandoned_request_bookkeeping_are_bounded() {
    let limiter = logical();
    assert!(limiter.reserve("", 1).is_err());
    assert!(limiter
        .reserve(&"x".repeat(MAX_REQUEST_ID_BYTES + 1), 1)
        .is_err());
    for n in 0..MAX_TRACKED_REQUESTS {
        drop(limiter.reserve(&n.to_string(), 1).unwrap());
    }
    assert!(limiter.reserve("overflow", 1).is_err());
    limiter.finish_request("0");
    assert!(limiter.reserve("replacement", 1).is_ok());
}
#[test]
fn fairness_rotates_three_requests_and_prioritizes_the_earliest_lane() {
    let gate = FairGate::new(BrokerLimits::default().global);
    let mut state = gate.state.lock().unwrap();
    for (id, request, lane) in [
        (1, "B", 1),
        (2, "A", 2),
        (3, "A", 1),
        (4, "C", 3),
        (5, "B", 0),
    ] {
        state.queue.push_back(Waiter {
            id,
            request: request.into(),
            lane,
            bytes: 1,
        });
    }
    let mut selected = Vec::new();
    while let Some(id) = choose(&state) {
        let pos = state.queue.iter().position(|w| w.id == id).unwrap();
        let waiter = state.queue.remove(pos).unwrap();
        state.last_request = Some(waiter.request);
        selected.push(id);
    }
    assert_eq!(selected, [3, 5, 4, 2, 1]);
}
#[tokio::test]
async fn cancelled_waiters_release_queue_bytes_and_counter_overflow_is_atomic() {
    let mut limits = BrokerLimits::default().global;
    limits.max_in_flight = 1;
    let gate = FairGate::new(limits);
    let first = gate.acquire("one", 0, 1).await.unwrap();
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(10),
        gate.acquire("two", 0, 8)
    )
    .await
    .is_err());
    assert_eq!(gate.state.lock().unwrap().queued_bytes, 0);
    assert!(gate.state.lock().unwrap().queue.is_empty());
    drop(first);
    gate.state.lock().unwrap().next = u64::MAX;
    assert!(gate.acquire("overflow", 0, 8).await.is_err());
    assert_eq!(gate.state.lock().unwrap().queued_bytes, 0);
    assert!(gate.state.lock().unwrap().queue.is_empty());
}
