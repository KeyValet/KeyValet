//! The continuation tool has a small schema; dispatch also restores local tool postprocessing.

use crate::server::Server;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResponse;
use rmcp::service::RequestContext;
use rmcp::RoleServer;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
pub struct WaitArgs {
    pub approval_id: String,
    #[serde(default, deserialize_with = "deserialize_wait")]
    #[schemars(range(min = 5, max = 600))]
    pub max_wait_s: Option<u64>,
}

fn deserialize_wait<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    u64::deserialize(deserializer).map(Some)
}

#[tool_router(router = approval_tool_router, vis = "pub")]
impl Server {
    #[tool(description = kv_i18n::t(
        "等待一条待批准的 KeyValet 请求。批准后直接返回该请求的执行结果；不要重复发起原请求。每次只等一个 approval_id；还未决定时可以继续其他工作或再调用本工具。",
        "Wait for one pending KeyValet approval. After approval, return the original request's execution result directly; do not repeat the original request. Wait for one approval_id at a time; while pending, continue other work or call this tool again.",
    ))]
    async fn credential_wait_approval(
        &self,
        Parameters(a): Parameters<WaitArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        self.resume_approval(a, context).await
    }
}
