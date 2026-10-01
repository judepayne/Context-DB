// Behavioral adaptation of hmem-runtime/src/worker.rs batching: ordered
// same-document batches of two, successful sibling isolation, and one immediate
// individual fallback. CTXQL adds an admission-safety check before fallback and
// never couples extraction to hmem persistence.

use crate::contracts::{ExtractionProvider, ProviderItemOutcome, ProviderWindow};
use crate::state::{Failure, FailureClass};
use cdb_core::acquisition::{AdmissionRecovery, BundlePrepared};
use cdb_core::semantic_admission::SemanticAdmissionReceipt;
use cdb_core::{Error, Result};

pub trait RetrySafety {
    /// True only while no prepared/unknown admission can cause repeated work.
    fn provider_retry_allowed(&self, window_id: &str) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowOutcome {
    pub window_id: String,
    pub outcome: ProviderItemOutcome,
    pub attempts: usize,
}

pub fn extract_batch_two<P: ExtractionProvider, S: RetrySafety>(
    provider: &mut P,
    windows: &[ProviderWindow],
    safety: &S,
) -> Result<Vec<WindowOutcome>> {
    if windows
        .windows(2)
        .any(|pair| pair[0].document_id != pair[1].document_id)
    {
        return Err(Error::invalid("provider batch must contain one document"));
    }
    let mut all = Vec::with_capacity(windows.len());
    for batch in windows.chunks(2) {
        let first = provider.extract(batch);
        let outcomes = match first {
            Ok(items) if items.len() == batch.len() => items,
            _ => batch
                .iter()
                .map(|_| ProviderItemOutcome::Failed(provider_failure("batch_failure")))
                .collect(),
        };
        for (window, outcome) in batch.iter().zip(outcomes) {
            if !matches!(outcome, ProviderItemOutcome::Failed(_)) {
                all.push(WindowOutcome {
                    window_id: window.window_id.clone(),
                    outcome,
                    attempts: 1,
                });
                continue;
            }
            if !safety.provider_retry_allowed(&window.window_id) {
                all.push(WindowOutcome {
                    window_id: window.window_id.clone(),
                    outcome: ProviderItemOutcome::Failed(provider_failure(
                        "retry_blocked_by_admission_state",
                    )),
                    attempts: 1,
                });
                continue;
            }
            let retry = provider.extract(std::slice::from_ref(window));
            let outcome = match retry {
                Ok(mut item) if item.len() == 1 => item.remove(0),
                _ => ProviderItemOutcome::Failed(provider_failure("individual_fallback_failed")),
            };
            all.push(WindowOutcome {
                window_id: window.window_id.clone(),
                outcome,
                attempts: 2,
            });
        }
    }
    Ok(all)
}

fn provider_failure(code: &str) -> Failure {
    Failure::new(FailureClass::ProviderTransport, code).expect("static failure code is valid")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    ReturnReceipt(SemanticAdmissionReceipt),
    ReconstructAndAdmit { provider_rerun_permitted: bool },
    ReconstructReceipt(SemanticAdmissionReceipt),
    Conflict,
    NothingPrepared,
}

/// Mandatory receipt-first recovery ordering. The caller performs history
/// lookup only after checking the final receipt and prepared commitment.
pub fn choose_recovery(
    final_receipt: Option<SemanticAdmissionReceipt>,
    prepared: Option<&BundlePrepared>,
    observation: Option<AdmissionRecovery>,
    validated_payload_available: bool,
) -> Result<RecoveryAction> {
    if let Some(receipt) = final_receipt {
        return Ok(RecoveryAction::ReturnReceipt(receipt));
    }
    if prepared.is_none() {
        if observation.is_some() {
            return Err(Error::invalid(
                "history observation without prepared record",
            ));
        }
        return Ok(RecoveryAction::NothingPrepared);
    }
    match observation
        .ok_or_else(|| Error::invalid("prepared recovery requires history observation"))?
    {
        AdmissionRecovery::Absent => Ok(RecoveryAction::ReconstructAndAdmit {
            provider_rerun_permitted: !validated_payload_available,
        }),
        AdmissionRecovery::Exact(receipt) => Ok(RecoveryAction::ReconstructReceipt(*receipt)),
        AdmissionRecovery::Conflict => Ok(RecoveryAction::Conflict),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::ProviderItemOutcome;
    use cdb_core::id::{ContentHash, Iri};

    struct Safe;
    impl RetrySafety for Safe {
        fn provider_retry_allowed(&self, _: &str) -> bool {
            true
        }
    }
    struct Mock {
        calls: Vec<Vec<String>>,
    }
    impl ExtractionProvider for Mock {
        fn extract(&mut self, windows: &[ProviderWindow]) -> Result<Vec<ProviderItemOutcome>> {
            self.calls
                .push(windows.iter().map(|w| w.window_id.clone()).collect());
            if windows.len() == 2 {
                Ok(vec![
                    ProviderItemOutcome::NoClaims,
                    ProviderItemOutcome::Failed(provider_failure("one")),
                ])
            } else {
                Ok(vec![ProviderItemOutcome::NoClaims])
            }
        }
    }
    fn window(id: &str) -> ProviderWindow {
        ProviderWindow {
            document_id: "doc".into(),
            window_id: id.into(),
            locator: Iri::new("file:///x").unwrap(),
            text_version: ContentHash::of_bytes(b"x"),
            text: "x".into(),
        }
    }

    #[test]
    fn retains_successful_sibling_and_falls_back_once() {
        let mut provider = Mock { calls: vec![] };
        let result = extract_batch_two(&mut provider, &[window("a"), window("b")], &Safe).unwrap();
        assert_eq!(
            provider.calls,
            vec![
                vec![String::from("a"), String::from("b")],
                vec![String::from("b")]
            ]
        );
        assert_eq!(result[0].attempts, 1);
        assert_eq!(result[1].attempts, 2);
    }

    #[test]
    fn recovery_rejects_history_without_a_canonical_prepared_record() {
        assert_eq!(
            choose_recovery(None, None, None, false).unwrap(),
            RecoveryAction::NothingPrepared
        );
        assert!(choose_recovery(None, None, Some(AdmissionRecovery::Absent), false).is_err());
    }
}
