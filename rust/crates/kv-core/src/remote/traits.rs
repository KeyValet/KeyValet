use super::*;
pub use kv_ipc::remote::{PresenceProbe, PresenceSignals, PresenceState};
use std::future::Future;

pub trait Approver {
    fn approver_kind(&self) -> ApproverKind;
    fn approve(
        &self,
        request: &ApprovalRequest,
    ) -> impl Future<Output = Result<ApprovalDecision>> + Send;
}

pub trait Executor {
    fn protection(&self) -> Protection;
    fn execute(
        &self,
        request: &super::canonical::CanonicalRequest,
    ) -> impl Future<Output = Result<serde_json::Value>> + Send;
}
