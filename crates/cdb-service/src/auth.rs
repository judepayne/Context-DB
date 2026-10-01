//! Node-local authentication, not graph authorization.
//!
//! Lock order: owned session lease BEFORE the authority gate. Transfer the lease
//! with detached recording work and check it inside the final publication fence.
use cdb_core::id::{ContentHash, PrincipalId};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

pub const MAX_CREDENTIALS: usize = 1024;
/// Absolute v2 ceiling. V1 configuration continues to enforce its 300-second cap.
pub const MAX_SESSION_TTL: Duration = Duration::from_secs(86_400);
const PREFIX: &str = "ctxql1_";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Denied;
impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("denied")
    }
}
impl std::error::Error for Denied {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Query,
    Read,
    Replay,
    Publish,
    Admin,
}

/// An upper bound, never an authorization grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities(u8);
impl Capabilities {
    pub fn all() -> Self {
        Self(31)
    }
    pub fn only(operations: &[Operation]) -> Self {
        Self(
            operations
                .iter()
                .fold(0, |mask, op| mask | (1 << *op as u8)),
        )
    }
    fn permits(self, operation: Operation) -> bool {
        self.0 & (1 << operation as u8) != 0
    }
}

/// Deliberately has no Debug, Display, Clone or serialization implementation.
pub struct SecretToken(String);
impl SecretToken {
    /// Trusted provisioning only: the caller must protect the returned secret.
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Digest-only credential configuration. No roles or graph grants are stored.
pub struct CredentialRecord {
    digest: ContentHash,
    principal: PrincipalId,
    enabled: bool,
    expires_at: Option<SystemTime>,
    narrowing: Capabilities,
}
impl CredentialRecord {
    pub fn new(
        digest: &str,
        principal: PrincipalId,
        enabled: bool,
        expires_at: Option<SystemTime>,
        narrowing: Capabilities,
    ) -> Result<Self, Denied> {
        Ok(Self {
            digest: ContentHash::parse(digest).map_err(|_| Denied)?,
            principal,
            enabled,
            expires_at,
            narrowing,
        })
    }
}

/// Explicit trusted provisioning; the store never retains the bearer secret.
pub fn provision(
    principal: PrincipalId,
    expires_at: Option<SystemTime>,
    narrowing: Capabilities,
) -> Result<(SecretToken, CredentialRecord), Denied> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| Denied)?;
    let mut token = String::with_capacity(PREFIX.len() + 64);
    token.push_str(PREFIX);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in random {
        token.push(HEX[(byte >> 4) as usize] as char);
        token.push(HEX[(byte & 15) as usize] as char);
    }
    let digest = ContentHash::of_bytes(token.as_bytes());
    Ok((
        SecretToken(token),
        CredentialRecord {
            digest,
            principal,
            enabled: true,
            expires_at,
            narrowing,
        },
    ))
}

struct State {
    generation: u64,
    enabled: bool,
    records: Vec<CredentialRecord>,
}
struct Issuer {
    admitting: AtomicBool,
    state: Arc<RwLock<State>>,
    ttl: Duration,
}
#[derive(Clone)]
pub struct AuthStore {
    issuer: Arc<Issuer>,
}
/// Private issuer-bound handle; clones retain the same issuer and expiry.
/// Not constructible from client data.
#[derive(Clone)]
pub struct AuthSession {
    issuer: Arc<Issuer>,
    generation: u64,
    index: usize,
    deadline: Instant,
}
/// Owned and transferable with cancellation-surviving native recording work.
pub struct SessionLease {
    issuer: Arc<Issuer>,
    state: OwnedRwLockReadGuard<State>,
    generation: u64,
    index: usize,
    deadline: Instant,
}
impl AuthStore {
    pub fn new(records: Vec<CredentialRecord>, session_ttl: Duration) -> Result<Self, Denied> {
        if records.is_empty()
            || records.len() > MAX_CREDENTIALS
            || session_ttl.is_zero()
            || session_ttl > MAX_SESSION_TTL
        {
            return Err(Denied);
        }
        let mut duplicate = false;
        for (i, record) in records.iter().enumerate() {
            for other in &records[..i] {
                duplicate |= bool::from(
                    record
                        .digest
                        .as_str()
                        .as_bytes()
                        .ct_eq(other.digest.as_str().as_bytes()),
                );
            }
        }
        if duplicate {
            return Err(Denied);
        }
        Ok(Self {
            issuer: Arc::new(Issuer {
                admitting: AtomicBool::new(true),
                state: Arc::new(RwLock::new(State {
                    generation: 0,
                    enabled: true,
                    records,
                })),
                ttl: session_ttl,
            }),
        })
    }

    pub async fn authenticate(&self, token: &str) -> Result<AuthSession, Denied> {
        if !self.issuer.admitting.load(Ordering::SeqCst)
            || token.len() != PREFIX.len() + 64
            || !token.starts_with(PREFIX)
            || !token.as_bytes()[PREFIX.len()..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(Denied);
        }
        let digest = ContentHash::of_bytes(token.as_bytes());
        let state = self.issuer.state.read().await;
        let mut found = None;
        // Scan the entire bounded table, including disabled/expired records.
        for (index, record) in state.records.iter().enumerate() {
            if bool::from(
                record
                    .digest
                    .as_str()
                    .as_bytes()
                    .ct_eq(digest.as_str().as_bytes()),
            ) {
                found = Some(index);
            }
        }
        let index = found.ok_or(Denied)?;
        let session = AuthSession {
            issuer: self.issuer.clone(),
            generation: state.generation,
            index,
            deadline: Instant::now() + self.issuer.ttl,
        };
        check(
            &self.issuer,
            &state,
            session.generation,
            index,
            session.deadline,
        )?;
        Ok(session)
    }

    /// Resolve only the authenticated identity, before parsing semantic input.
    /// This is not an operation grant or a publication lease.
    pub(crate) async fn principal(&self, session: &AuthSession) -> Result<PrincipalId, Denied> {
        if !Arc::ptr_eq(&self.issuer, &session.issuer) {
            return Err(Denied);
        }
        let state = self.issuer.state.read().await;
        check(
            &self.issuer,
            &state,
            session.generation,
            session.index,
            session.deadline,
        )?;
        Ok(state.records[session.index].principal.clone())
    }

    pub async fn lease(
        &self,
        session: &AuthSession,
        operation: Operation,
    ) -> Result<SessionLease, Denied> {
        if !Arc::ptr_eq(&self.issuer, &session.issuer)
            || !self.issuer.admitting.load(Ordering::SeqCst)
        {
            return Err(Denied);
        }
        let state = self.issuer.state.clone().read_owned().await;
        let lease = SessionLease {
            issuer: self.issuer.clone(),
            state,
            generation: session.generation,
            index: session.index,
            deadline: session.deadline,
        };
        lease.check()?;
        if !lease.state.records[lease.index]
            .narrowing
            .permits(operation)
        {
            return Err(Denied);
        }
        Ok(lease)
    }

    /// Nonblocking; use before awaiting the exclusive drain.
    pub fn stop_admitting(&self) {
        self.issuer.admitting.store(false, Ordering::SeqCst);
    }
    /// Never call while holding a lease or authority gate. Cancellation leaves
    /// admission closed even if the exclusive drain has not completed.
    pub async fn shutdown(&self) {
        self.stop_admitting();
        let mut state = self.issuer.state.write().await;
        if state.enabled {
            state.enabled = false;
            state.generation += 1;
        }
    }
}
impl SessionLease {
    /// Conservative monotonic ceiling for an owned operation. Fresh lease checks
    /// still enforce credential expiry (including later wall-clock changes).
    pub(crate) fn deadline(&self) -> Result<Instant, Denied> {
        self.check()?;
        let now = Instant::now();
        let wall = SystemTime::now();
        let credential = self.state.records[self.index]
            .expires_at
            .map(|expiry| expiry.duration_since(wall).map_err(|_| Denied))
            .transpose()?;
        match credential {
            Some(remaining) => Ok(self.deadline.min(now.checked_add(remaining).ok_or(Denied)?)),
            None => Ok(self.deadline),
        }
    }
    pub fn principal(&self) -> &PrincipalId {
        &self.state.records[self.index].principal
    }
    /// Invoke inside the final authority publication fence, immediately before enqueue.
    /// Current graph operation/resource authorization is separately mandatory.
    pub fn check(&self) -> Result<(), Denied> {
        check(
            &self.issuer,
            &self.state,
            self.generation,
            self.index,
            self.deadline,
        )
    }
}
fn check(
    issuer: &Issuer,
    state: &State,
    generation: u64,
    index: usize,
    deadline: Instant,
) -> Result<(), Denied> {
    let record = state.records.get(index).ok_or(Denied)?;
    if !issuer.admitting.load(Ordering::SeqCst)
        || !state.enabled
        || state.generation != generation
        || !record.enabled
        || Instant::now() >= deadline
        || record
            .expires_at
            .is_some_and(|expiry| SystemTime::now() >= expiry)
    {
        return Err(Denied);
    }
    Ok(())
}
