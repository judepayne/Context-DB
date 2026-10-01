use crate::{backend::map, history, native::*, options::AuthorityOptions};
use cdb_core::contracts::*;
use fluree_db_nameservice::NameServiceEvent;
pub(crate) struct Hints {
    native: NativeStore,
    options: AuthorityOptions,
    receiver: tokio::sync::broadcast::Receiver<NameServiceEvent>,
}
impl Hints {
    pub fn new(native: NativeStore, options: AuthorityOptions) -> Self {
        let receiver = native.event_receiver();
        Self {
            native,
            options,
            receiver,
        }
    }
}
impl ChangeHintSource for Hints {
    fn next(&mut self) -> IoFuture<'_, ChangeHint> {
        Box::pin(async move {
            loop {
                match self.receiver.recv().await {
                    Ok(NameServiceEvent::LedgerCommitPublished {
                        ledger_id,
                        commit_id,
                        commit_t,
                        ..
                    }) if ledger_id == self.native.ledger_id() => {
                        let p = NativePin {
                            t: commit_t,
                            cid: commit_id.to_string(),
                        };
                        if p.t < 2 {
                            continue;
                        }
                        history::audit(&self.native, &self.options, &p)
                            .await
                            .map_err(map)?;
                        return Ok(ChangeHint::Head(
                            history::snapshot(&self.options, p).map_err(map)?,
                        ));
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        return Ok(ChangeHint::Lagged);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Ok(ChangeHint::Closed);
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_core::id::*;
    #[tokio::test]
    async fn actual_receiver_lag_close_and_unrelated_filter() -> NativeResult<()> {
        let tmp = tempfile::tempdir()?;
        let o = AuthorityOptions::new(
            tmp.path().join("db"),
            "hint:main".into(),
            BackendId::new("b")?,
            AuthorityId::new("a")?,
            GraphId::new("g")?,
        );
        let b = crate::FlureeBackend::create(o.clone()).await?;
        let mut real = b.native.event_receiver();
        b.capture(None).await?;
        let event = real.recv().await?;
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        let mut hints = Hints {
            native: b.native.clone(),
            options: o,
            receiver: rx,
        };
        tx.send(event.clone())?;
        tx.send(event.clone())?;
        assert_eq!(hints.next().await?, ChangeHint::Lagged);
        assert!(matches!(hints.next().await?, ChangeHint::Head(_)));
        let mut unrelated = event;
        if let NameServiceEvent::LedgerCommitPublished { ledger_id, .. } = &mut unrelated {
            *ledger_id = "other:main".into();
        }
        tx.send(unrelated)?;
        drop(tx);
        assert_eq!(hints.next().await?, ChangeHint::Closed);
        Ok(())
    }
}
