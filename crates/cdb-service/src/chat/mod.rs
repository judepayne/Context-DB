mod bridge;
mod contracts;
mod coordinator;
mod direct_projection;
mod inventory;
#[cfg(test)]
mod quality_fixture;
mod reads;
mod state;
mod terminal;

pub use contracts::{
    ArtifactBinding, ChatCapabilities, ChatClaim, ChatDiagnostic, ChatLabel, ChatNode, ChatObject,
    ChatOntologyRequest, ChatQueryOutcome, ChatQueryRequest, ChatQueryResult, ChatSourceDescriptor,
    ChatSourceOutcome, ChatSourceRequest, ChatSourceResult, SnapshotBinding,
};
pub use coordinator::run_chat;
pub use reads::ChatReadResources;
