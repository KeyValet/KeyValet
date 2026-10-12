//! The user proxy forwards through an authenticated helper route, never through a secret.

use super::{Backend, BoxFuture, Bytes, HeaderMap, HttpBody, Response};
use futures_util::StreamExt;
use http_body_util::{BodyExt, StreamBody};
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

pub struct Binding {
    pub credential_type: String,
    pub name: String,
    pub host: String,
    pub base: String,
    pub token: Zeroizing<String>,
}

pub trait LeafSigner: Send + Sync {
    fn sign(
        &self,
        ty: String,
        name: String,
        host: String,
        csr: String,
    ) -> BoxFuture<'_, Result<Vec<u8>, String>>;
}

pub struct GatewayBackend {
    bindings: HashMap<String, Binding>,
    signer: Arc<dyn LeafSigner>,
    client: reqwest::Client,
}

impl GatewayBackend {
    pub fn new(bindings: Vec<Binding>, signer: Arc<dyn LeafSigner>) -> Result<Self, String> {
        let mut routes = HashMap::new();
        for binding in bindings {
            let base =
                url::Url::parse(&binding.base).map_err(|_| "Invalid helper gateway address")?;
            if base.scheme() != "http"
                || base.host_str() != Some("127.0.0.1")
                || base.port().is_none()
                || base.path() != "/"
                || base.query().is_some()
                || base.fragment().is_some()
                || !base.username().is_empty()
                || base.password().is_some()
                || !crate::certificates::valid_host(&binding.host)
                || !binding.token.starts_with("kv_")
                || binding.token.len() > 100
                || routes.contains_key(&binding.host)
            {
                return Err(
                    "Proxy bindings must use a unique host and a loopback helper route".into(),
                );
            }
            routes.insert(binding.host.clone(), binding);
        }
        if routes.is_empty() {
            return Err("At least one explicit proxy binding is required".into());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(600))
            .build()
            .map_err(|_| "Cannot create the gateway client")?;
        Ok(Self {
            bindings: routes,
            signer,
            client,
        })
    }
}

impl Backend for GatewayBackend {
    fn leaf(&self, host: String, csr: String) -> BoxFuture<'_, Result<Vec<u8>, String>> {
        Box::pin(async move {
            let binding = self.bindings.get(&host).ok_or("Unbound proxy host")?;
            self.signer
                .sign(
                    binding.credential_type.clone(),
                    binding.name.clone(),
                    host,
                    csr,
                )
                .await
        })
    }
    fn send(
        &self,
        host: String,
        method: String,
        path: String,
        mut headers: HeaderMap,
        body: Bytes,
    ) -> BoxFuture<'_, Result<Response<HttpBody>, String>> {
        Box::pin(async move {
            let binding = self.bindings.get(&host).ok_or("Unbound proxy host")?;
            if !path.starts_with('/') || path.contains('#') {
                return Err("Invalid proxy request path".into());
            }
            let method = reqwest::Method::from_bytes(method.as_bytes())
                .map_err(|_| "Invalid HTTP method")?;
            for name in [
                "host",
                "authorization",
                "x-api-key",
                "api-key",
                "x-goog-api-key",
                "cookie",
                "proxy-authorization",
                "connection",
                "transfer-encoding",
                "content-length",
            ] {
                headers.remove(name);
            }
            let response = self
                .client
                .request(
                    method,
                    format!("{}/{host}{path}", binding.base.trim_end_matches('/')),
                )
                .headers(headers)
                .bearer_auth(binding.token.as_str())
                .body(body)
                .send()
                .await
                .map_err(|_| "Helper gateway request failed")?;
            let status = response.status();
            let headers = response.headers().clone();
            let stream = response.bytes_stream().map(|chunk| {
                chunk
                    .map(hyper::body::Frame::data)
                    .map_err(|_| std::io::Error::other("Helper gateway response interrupted"))
            });
            let mut reply = Response::new(BodyExt::boxed(StreamBody::new(stream)));
            *reply.status_mut() = status;
            *reply.headers_mut() = headers;
            Ok(reply)
        })
    }
}
