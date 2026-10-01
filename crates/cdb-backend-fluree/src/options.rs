use crate::native::{NativeLimits, NativeResult};
use cdb_core::{
    id::{AuthorityId, BackendId, GraphId},
    Limits, Timestamp,
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// Trusted host clock, never supplied through admission data.
pub trait WallClock: Send + Sync {
    fn now(&self) -> NativeResult<Timestamp>;
}
pub struct SystemClock;
impl WallClock for SystemClock {
    fn now(&self) -> NativeResult<Timestamp> {
        let ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis())?,
            Err(e) => -i64::try_from(e.duration().as_millis())?,
        };
        Ok(Timestamp::from_millis(ms)?)
    }
}
#[derive(Clone)]
pub struct AuthorityOptions {
    pub path: PathBuf,
    pub ledger: String,
    pub backend: BackendId,
    pub authority: AuthorityId,
    pub graph: GraphId,
    pub clock: Arc<dyn WallClock>,
    pub native_limits: NativeLimits,
    pub codec_limits: Limits,
    pub max_changes: usize,
    pub max_history_commits: usize,
}
impl AuthorityOptions {
    pub fn new(
        path: PathBuf,
        ledger: String,
        backend: BackendId,
        authority: AuthorityId,
        graph: GraphId,
    ) -> Self {
        Self {
            path,
            ledger,
            backend,
            authority,
            graph,
            clock: Arc::new(SystemClock),
            native_limits: NativeLimits::default(),
            codec_limits: Limits::default(),
            max_changes: 1000,
            max_history_commits: 100_000,
        }
    }
}
