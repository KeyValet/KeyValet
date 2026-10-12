//! Optional template hints for how long an HTTP client will wait for a response.
//! The overlay changes only this field; the shared template catalog is otherwise untouched.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TemplateTimeout {
    pub client_timeout_hint_s: Option<u64>,
}

pub static TEMPLATE_TIMEOUTS: LazyLock<HashMap<String, TemplateTimeout>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../templates/client-timeouts.json"))
        .expect("bundled template timeout hints must be valid")
});

/// Read the template field before using a bundled fallback, including caller-provided templates.
pub fn client_timeout_hint(template: &serde_json::Value) -> Result<Option<u64>, serde_json::Error> {
    let hint: TemplateTimeout = serde_json::from_value(template.clone())?;
    Ok(hint.client_timeout_hint_s.or_else(|| {
        TEMPLATE_TIMEOUTS
            .get(template["id"].as_str()?)
            .and_then(|v| v.client_timeout_hint_s)
    }))
}

/// Hosts are read from repository templates, so this lookup never relies on a local installation.
pub fn host_timeout_hint(host: &str) -> Option<u64> {
    static CATALOG: LazyLock<serde_json::Value> = LazyLock::new(|| {
        serde_json::from_str(include_str!("../../../../templates/catalog.json"))
            .expect("bundled template catalog must be valid")
    });
    CATALOG["templates"]
        .as_array()?
        .iter()
        .find_map(|template| {
            template["hosts"]
                .as_array()?
                .iter()
                .any(|value| value.as_str().is_some_and(|h| h.eq_ignore_ascii_case(host)))
                .then(|| client_timeout_hint(template).ok().flatten())
                .flatten()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_openai_and_anthropic_have_bundled_hints() {
        assert_eq!(TEMPLATE_TIMEOUTS.len(), 2);
        for id in ["openai", "anthropic"] {
            assert_eq!(client_timeout_hint(&json!({"id": id})).unwrap(), Some(600));
        }
        assert_eq!(client_timeout_hint(&json!({"id": "github"})).unwrap(), None);
        assert_eq!(
            client_timeout_hint(&json!({"id": "openai", "client_timeout_hint_s": 42})).unwrap(),
            Some(42)
        );
        for invalid in [json!(-1), json!(1.5), json!("600")] {
            assert!(client_timeout_hint(&json!({"client_timeout_hint_s": invalid})).is_err());
        }
        assert_eq!(host_timeout_hint("api.openai.com"), Some(600));
        assert_eq!(host_timeout_hint("api.anthropic.com"), Some(600));
        assert_eq!(host_timeout_hint("api.example.com"), None);
    }
}
