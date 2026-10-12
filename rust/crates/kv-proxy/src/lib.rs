//! Proxy calls (credential injection into HTTP requests, made from inside the root helper) and the
//! local gateway (for SDKs/CLIs that can't speak MCP). Direct port of src/helper/http-proxy.ts,
//! http-config.ts, http-manage.ts, and gateway.ts.

pub mod approval;
/// Explicit loopback-only test switch for cross-crate fixtures using synthetic credentials.
pub use kv_protocols::http::allow_insecure_loopback_for_tests;
pub mod certificates;
pub mod config;
pub mod gateway;
pub mod manage;
pub mod proxy;
pub mod redact;
pub mod run;
pub mod transparent;
