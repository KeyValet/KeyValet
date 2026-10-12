use super::{Error, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preference {
    #[default]
    Auto,
    Local,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalConfig {
    pub prefer: Preference,
    pub wait_in_call_s: u64,
    pub wait_tool_max_s: u64,
    pub default_exp_s: u64,
    pub http_wait_s: u64,
    pub stop_hook_max_blocks: u32,
    pub progress_interval_s: u64,
    pub unlock_ttl_s: u64,
    pub class: Vec<ApprovalClass>,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            prefer: Preference::Auto,
            wait_in_call_s: 60,
            wait_tool_max_s: 600,
            default_exp_s: 600,
            http_wait_s: 540,
            stop_hook_max_blocks: 3,
            progress_interval_s: 15,
            unlock_ttl_s: 43200,
            class: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalClass {
    pub name: String,
    pub r#match: ClassMatch,
    pub exp_s: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClassMatch {
    pub credential: Option<String>,
    pub host: Option<String>,
}

impl ApprovalConfig {
    pub fn from_toml(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct File {
            #[serde(default)]
            approval: ApprovalConfig,
        }
        let config = toml::from_str::<File>(text)
            .map_err(|_| Error("invalid_approval_config"))?
            .approval;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.default_exp_s == 0
            || self.default_exp_s > 86400
            || self.unlock_ttl_s == 0
            || self.unlock_ttl_s > 86400
            || self.progress_interval_s == 0
            || self.wait_tool_max_s > 86400
            || self.wait_in_call_s > 86400
            || self.http_wait_s > 86400
            || self.stop_hook_max_blocks > 100
        {
            return Err(Error("invalid_approval_config"));
        }
        let mut names = std::collections::HashSet::new();
        for class in &self.class {
            if class.name.is_empty()
                || !names.insert(&class.name)
                || class.exp_s == 0
                || class.exp_s > 86400
                || (class.r#match.credential.is_none() && class.r#match.host.is_none())
            {
                return Err(Error("invalid_approval_class"));
            }
        }
        Ok(())
    }

    pub fn call_budget_s(&self, runtime_budget_s: u64) -> u64 {
        self.wait_in_call_s.min(runtime_budget_s.saturating_sub(10))
    }

    pub fn wait_budget_ms(&self, requested_ms: u64, runtime_budget_s: u64) -> u64 {
        requested_ms
            .min(self.wait_tool_max_s.saturating_mul(1000))
            .min(runtime_budget_s.saturating_sub(10).saturating_mul(1000))
    }

    pub fn http_budget_s(&self, host_hint_s: Option<u64>) -> u64 {
        self.http_wait_s
            .min(host_hint_s.map_or(55, |hint| hint.saturating_sub(60)))
    }
}
