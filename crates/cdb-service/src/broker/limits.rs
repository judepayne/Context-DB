use cdb_core::{Error, Result};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    pub max_in_flight: usize,
    pub max_queued_bytes: usize,
    pub requests_per_second: u32,
    pub burst_requests: u32,
}
impl ResourceLimits {
    pub fn validate(self) -> Result<Self> {
        if self.max_in_flight == 0
            || self.max_queued_bytes == 0
            || self.requests_per_second == 0
            || self.burst_requests == 0
        {
            return Err(Error::limit());
        }
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct BrokerLimits {
    pub global: ResourceLimits,
    pub per_request_pending: usize,
    pub per_request_bytes: usize,
    pub max_logical_calls: u64,
    pub max_argument_bytes: usize,
    pub max_result_bytes: usize,
    pub call_timeout_ms: u64,
    pub max_attempts: u8,
}
impl Default for BrokerLimits {
    fn default() -> Self {
        Self {
            global: ResourceLimits {
                max_in_flight: 32,
                max_queued_bytes: 64 * 1024 * 1024,
                requests_per_second: 10_000,
                burst_requests: 10_000,
            },
            per_request_pending: 64,
            per_request_bytes: 64 * 1024 * 1024,
            max_logical_calls: 250_000,
            max_argument_bytes: 256 * 1024,
            max_result_bytes: 1024 * 1024,
            call_timeout_ms: 30_000,
            max_attempts: 2,
        }
    }
}
impl BrokerLimits {
    pub fn validate(self) -> Result<Self> {
        self.global.validate()?;
        if self.per_request_pending == 0
            || self.per_request_bytes == 0
            || self.max_logical_calls == 0
            || self.max_argument_bytes == 0
            || self.max_result_bytes == 0
            || self.call_timeout_ms == 0
            || self.max_attempts == 0
            || self.max_attempts > 8
        {
            return Err(Error::limit());
        }
        Ok(self)
    }
}

#[derive(Default)]
struct RequestUse {
    closed: bool,
    pending: usize,
    bytes: usize,
    calls: u64,
}
#[derive(Default)]
struct LogicalState {
    requests: BTreeMap<String, RequestUse>,
    held_bytes: usize,
}
// Bound bookkeeping as well as payloads. A controller explicitly finishes each
// request; outstanding native/completed-unreduced work retains its reservation.
const MAX_TRACKED_REQUESTS: usize = 4096;
const MAX_REQUEST_ID_BYTES: usize = 1024;
pub(crate) type LogicalAdmission = Arc<LogicalReservation>;
pub(crate) struct LogicalReservation {
    state: Arc<Mutex<LogicalState>>,
    request: String,
    bytes: usize,
}
impl Drop for LogicalReservation {
    fn drop(&mut self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.held_bytes -= self.bytes;
        if let Some(v) = s.requests.get_mut(&self.request) {
            v.pending -= 1;
            v.bytes -= self.bytes;
            if v.closed && v.pending == 0 {
                s.requests.remove(&self.request);
            }
        }
    }
}
pub(crate) struct LogicalLimiter {
    state: Arc<Mutex<LogicalState>>,
    limits: BrokerLimits,
}
impl LogicalLimiter {
    pub fn new(limits: BrokerLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(LogicalState::default())),
            limits,
        }
    }
    pub fn reserve(&self, request: &str, bytes: usize) -> Result<LogicalAdmission> {
        self.reserve_inner(request, bytes, true)
    }
    pub fn reserve_evaluation(&self, request: &str, bytes: usize) -> Result<LogicalAdmission> {
        self.reserve_inner(request, bytes, false)
    }
    fn reserve_inner(&self, request: &str, bytes: usize, call: bool) -> Result<LogicalAdmission> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if request.is_empty() || request.len() > MAX_REQUEST_ID_BYTES {
            return Err(Error::limit());
        }
        let held_bytes = s.held_bytes.checked_add(bytes).ok_or_else(Error::limit)?;
        if held_bytes > self.limits.global.max_queued_bytes
            || (!s.requests.contains_key(request) && s.requests.len() >= MAX_TRACKED_REQUESTS)
        {
            return Err(Error::limit());
        }
        let v = s.requests.entry(request.into()).or_default();
        if v.closed {
            return Err(Error::limit());
        }
        let pending = v.pending.checked_add(1).ok_or_else(Error::limit)?;
        let total = v.bytes.checked_add(bytes).ok_or_else(Error::limit)?;
        let calls = v
            .calls
            .checked_add(u64::from(call))
            .ok_or_else(Error::limit)?;
        if pending > self.limits.per_request_pending
            || total > self.limits.per_request_bytes
            || calls > self.limits.max_logical_calls
        {
            return Err(Error::limit());
        }
        v.pending = pending;
        v.bytes = total;
        v.calls = calls;
        s.held_bytes = held_bytes;
        Ok(Arc::new(LogicalReservation {
            state: self.state.clone(),
            request: request.into(),
            bytes,
        }))
    }
    /// Called once the trusted controller has stopped all request admission.
    /// Never use this as an automatic retry/reset of a live logical call budget.
    pub fn finish_request(&self, request: &str) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = s.requests.get_mut(request) {
            v.closed = true;
            if v.pending == 0 {
                s.requests.remove(request);
            }
        }
    }
    pub fn stop_all(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.requests.retain(|_, use_| {
            use_.closed = true;
            use_.pending != 0
        });
    }
}

#[derive(Clone)]
struct Waiter {
    id: u64,
    request: String,
    lane: u64,
    bytes: usize,
}
struct GateState {
    active: usize,
    queued_bytes: usize,
    next: u64,
    last_request: Option<String>,
    queue: VecDeque<Waiter>,
    tokens: f64,
    refilled: Instant,
}
pub(crate) struct FairGate {
    limits: ResourceLimits,
    state: Mutex<GateState>,
    notify: Notify,
}
pub(crate) struct GatePermit {
    gate: Arc<FairGate>,
}
impl Drop for GatePermit {
    fn drop(&mut self) {
        let mut s = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        s.active -= 1;
        drop(s);
        self.gate.notify.notify_waiters();
    }
}
struct QueueTicket {
    gate: Arc<FairGate>,
    id: u64,
    granted: bool,
}
impl Drop for QueueTicket {
    fn drop(&mut self) {
        if self.granted {
            return;
        }
        let mut s = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = s.queue.iter().position(|w| w.id == self.id) {
            if let Some(w) = s.queue.remove(pos) {
                s.queued_bytes -= w.bytes;
            }
        }
        drop(s);
        self.gate.notify.notify_waiters();
    }
}
impl FairGate {
    pub fn new(limits: ResourceLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            state: Mutex::new(GateState {
                active: 0,
                queued_bytes: 0,
                next: 0,
                last_request: None,
                queue: VecDeque::new(),
                tokens: f64::from(limits.burst_requests),
                refilled: Instant::now(),
            }),
            notify: Notify::new(),
        })
    }
    pub async fn acquire(
        self: &Arc<Self>,
        request: &str,
        lane: u64,
        bytes: usize,
    ) -> Result<GatePermit> {
        let id = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let q = s.queued_bytes.checked_add(bytes).ok_or_else(Error::limit)?;
            if q > self.limits.max_queued_bytes {
                return Err(Error::limit());
            }
            let id = s.next.checked_add(1).ok_or_else(Error::limit)?;
            s.queued_bytes = q;
            s.next = id;
            s.queue.push_back(Waiter {
                id,
                request: request.into(),
                lane,
                bytes,
            });
            id
        };
        let mut ticket = QueueTicket {
            gate: self.clone(),
            id,
            granted: false,
        };
        loop {
            let notified = self.notify.notified();
            let granted = {
                let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                let elapsed = now.duration_since(s.refilled).as_secs_f64();
                s.tokens = (s.tokens + elapsed * f64::from(self.limits.requests_per_second))
                    .min(f64::from(self.limits.burst_requests));
                s.refilled = now;
                if s.active >= self.limits.max_in_flight || s.tokens < 1.0 {
                    false
                } else if choose(&s) == Some(id) {
                    let pos = s
                        .queue
                        .iter()
                        .position(|w| w.id == id)
                        .expect("queued waiter");
                    let w = s.queue.remove(pos).expect("position");
                    s.queued_bytes -= w.bytes;
                    s.active += 1;
                    s.tokens -= 1.0;
                    s.last_request = Some(w.request);
                    true
                } else {
                    false
                }
            };
            if granted {
                ticket.granted = true;
                return Ok(GatePermit { gate: self.clone() });
            }
            tokio::select! {_=notified=>{},_=tokio::time::sleep(std::time::Duration::from_millis(1))=>{}}
        }
    }
}
fn choose(s: &GateState) -> Option<u64> {
    let mut earliest: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for w in &s.queue {
        let e = earliest.entry(&w.request).or_insert((w.lane, w.id));
        if (w.lane, w.id) < *e {
            *e = (w.lane, w.id)
        }
    }
    if earliest.is_empty() {
        return None;
    }
    let keys = earliest.keys().copied().collect::<Vec<_>>();
    let key = match &s.last_request {
        Some(last) => keys
            .iter()
            .copied()
            .find(|k| *k > last.as_str())
            .unwrap_or(keys[0]),
        None => keys[0],
    };
    Some(earliest[key].1)
}

#[cfg(test)]
mod tests;
