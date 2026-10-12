//! Deployment assets and the public relay-client configuration; no secret fields are accepted.

use super::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SERVICE: &str = include_str!("../../../../../deploy/relay/keyvalet-relay.service");
const NGINX: &str = include_str!("../../../../../deploy/relay/nginx.conf.template");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Health {
    pub ok: bool,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Installed {
    pub service: PathBuf,
    pub nginx: PathBuf,
    pub listen: String,
    pub data: PathBuf,
    pub public_url: String,
    pub cloudflare_steps: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct RelayUrl {
    pub scheme: String,
    pub authority: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl RelayUrl {
    pub fn parse(text: &str) -> Result<Self> {
        let error = || {
            Error::argument("relay URL 需要 HTTPS，且不能含用户信息、查询或片段；HTTP 仅允许回环 IP", "The relay URL requires HTTPS without user info, query or fragment; HTTP is allowed only for loopback IPs")
        };
        if !text.is_ascii()
            || text
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            || text.contains(['@', '?', '#', '\\', '"', '\''])
        {
            return Err(error());
        }
        let (scheme, rest) = text.split_once("://").ok_or_else(error)?;
        if !matches!(scheme, "https" | "http") {
            return Err(error());
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() {
            return Err(error());
        }
        let (host, port) = if authority.starts_with('[') {
            let end = authority.find(']').ok_or_else(error)?;
            let host = &authority[1..end];
            host.parse::<std::net::Ipv6Addr>().map_err(|_| error())?;
            let tail = &authority[end + 1..];
            (
                host,
                if tail.is_empty() {
                    None
                } else {
                    Some(tail.strip_prefix(':').ok_or_else(error)?)
                },
            )
        } else {
            let (host, port) = authority
                .split_once(':')
                .map_or((authority, None), |(h, p)| (h, Some(p)));
            if host.is_empty()
                || host.len() > 253
                || host.split('.').any(|part| {
                    part.is_empty()
                        || part.len() > 63
                        || part.starts_with('-')
                        || part.ends_with('-')
                        || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err(error());
            }
            (host, port)
        };
        let port = port
            .map(|p| p.parse::<u16>().ok().filter(|n| *n > 0).ok_or_else(error))
            .transpose()?
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        if scheme == "http"
            && !host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        {
            return Err(error());
        }
        if path.contains([';', '{', '}']) || path.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(error());
        }
        Ok(Self {
            scheme: scheme.into(),
            authority: authority.into(),
            host: host.into(),
            port,
            path: path.trim_end_matches('/').into(),
        })
    }

    pub fn health_url(&self) -> String {
        let base = format!("{}://{}", self.scheme, self.authority);
        if self.path.is_empty() {
            format!("{base}/v1/health")
        } else {
            format!("{base}/{}/v1/health", self.path)
        }
    }
}

pub(super) fn io_error(_: std::io::Error) -> Error {
    Error::new(
        "local_io_error",
        "无法读写配置；请检查路径与权限",
        "Cannot read or write configuration; check paths and permissions",
    )
}

pub(super) fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::argument(
            "配置路径缺少父目录",
            "The configuration path has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent).map_err(io_error)?;
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink() || !m.is_file()) {
        return Err(Error::new(
            "unsafe_path",
            "配置目标必须为普通文件，不能为符号链接",
            "The configuration target must be a regular file, not a symlink",
        ));
    }
    let temporary = parent.join(format!(
        ".keyvalet-write-{}-{}",
        std::process::id(),
        std::sync::atomic::AtomicU64::fetch_add(
            &WRITE_SEQUENCE,
            1,
            std::sync::atomic::Ordering::Relaxed
        )
    ));
    write_file(path, content, &temporary)
}

fn write_file(path: &Path, content: &str, temporary: &Path) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    // Only clean up a temporary file created by this invocation. A collision belongs
    // to another writer and must survive a failed create_new call.
    let mut file = options.open(temporary).map_err(io_error)?;
    let result = (|| {
        file.write_all(content.as_bytes()).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        std::fs::rename(temporary, path).map_err(io_error)
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

static WRITE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct Config {
    pub relay_url: String,
    pub device_id: Option<String>,
    pub account_id: Option<String>,
}

impl Config {
    pub fn set_binding(path: &Path, binding: &kv_core::remote::ipc::RelayBinding) -> Result<()> {
        RelayUrl::parse(&binding.relay_url)?;
        if [&binding.device_id, &binding.account_id]
            .iter()
            .any(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        {
            return Err(Error::protocol());
        }
        if path.exists() {
            Self::read(path)?;
        }
        atomic_write(
            path,
            &format!(
                "relay_url = {}\ndevice_id = {}\naccount_id = {}\n",
                Value::String(binding.relay_url.clone()),
                Value::String(binding.device_id.clone()),
                Value::String(binding.account_id.clone())
            ),
        )
    }
    pub fn read(path: &Path) -> Result<Self> {
        let mut content = String::new();
        std::fs::File::open(path)
            .map_err(io_error)?
            .take(16 * 1024 + 1)
            .read_to_string(&mut content)
            .map_err(io_error)?;
        Self::parse(&content)
    }

    fn parse(content: &str) -> Result<Self> {
        let invalid = || {
            Error::new(
                "invalid_config",
                "relay-client 配置格式不支持；请保留原文件并检查配置",
                "Unsupported relay-client configuration; preserve the file and check it",
            )
        };
        if content.len() > 16 * 1024 {
            return Err(invalid());
        }
        let mut values = std::collections::BTreeMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(invalid)?;
            let key = key.trim();
            if !matches!(key, "relay_url" | "device_id" | "account_id") || values.contains_key(key)
            {
                return Err(invalid());
            }
            let value = value.trim();
            let (text, remainder) = if let Some(value) = value.strip_prefix('\'') {
                let end = value.find('\'').ok_or_else(invalid)?;
                (value[..end].to_owned(), &value[end + 1..])
            } else if value.starts_with('"') {
                let mut end = None;
                let mut escaped = false;
                for (i, c) in value.char_indices().skip(1) {
                    if c == '"' && !escaped {
                        end = Some(i + 1);
                        break;
                    }
                    escaped = c == '\\' && !escaped;
                }
                let end = end.ok_or_else(invalid)?;
                (
                    serde_json::from_str::<String>(&value[..end]).map_err(|_| invalid())?,
                    &value[end..],
                )
            } else {
                return Err(invalid());
            };
            if !remainder.trim().is_empty() && !remainder.trim().starts_with('#') {
                return Err(invalid());
            }
            if text.is_empty()
                || text.chars().any(char::is_control)
                || (key != "relay_url" && text.len() > 256)
            {
                return Err(invalid());
            }
            values.insert(key, text);
        }
        let relay_url = values.remove("relay_url").ok_or_else(invalid)?;
        RelayUrl::parse(&relay_url)?;
        Ok(Self {
            relay_url,
            device_id: values.remove("device_id"),
            account_id: values.remove("account_id"),
        })
    }

    pub fn set_url(path: &Path, url: &str) -> Result<()> {
        RelayUrl::parse(url)?;
        let mut config = if path.exists() {
            Self::read(path)?
        } else {
            Self::default()
        };
        config.relay_url = url.to_owned();
        let mut content = format!(
            "relay_url = {}\n",
            serde_json::Value::String(config.relay_url)
        );
        for (key, value) in [
            ("device_id", config.device_id),
            ("account_id", config.account_id),
        ] {
            if let Some(value) = value {
                content.push_str(&format!("{key} = {}\n", serde_json::Value::String(value)));
            }
        }
        atomic_write(path, &content)
    }
}

pub(super) fn install(
    root: &Path,
    listen: &str,
    data: &Path,
    public_url: &str,
) -> Result<Installed> {
    let url = RelayUrl::parse(public_url)?;
    if data.starts_with("/var/lib/keyvalet-relay") {
        return Err(Error::argument(
            "relay server 数据目录不能与 relay-client 共用；请使用 /var/lib/keyvalet-relay-server",
            "The relay server must not share relay-client state; use /var/lib/keyvalet-relay-server",
        ));
    }
    let service = root.join("etc/systemd/system/keyvalet-relay-server.service");
    let nginx = root.join("etc/nginx/conf.d/keyvalet-relay.conf");
    // systemd expands percent specifiers even inside quotes; escape them in the data path.
    let data_arg = data
        .to_str()
        .ok_or_else(|| Error::argument("--data 必须为 UTF-8 路径", "--data must be a UTF-8 path"))?
        .replace('%', "%%")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let mut unit = SERVICE.replace(
        "--listen 127.0.0.1:8787 --data /var/lib/keyvalet-relay",
        &format!(
            "--listen {listen} --data \"{}\"",
            data_arg.replace('$', "$$")
        ),
    );
    unit = unit.replace(
        "StateDirectory=keyvalet-relay\n",
        &format!(
            "StateDirectory=keyvalet-relay-server\nReadWritePaths=\"{}\"\n",
            data_arg
        ),
    );
    let proxy = NGINX
        .replace("relay.example.com", &url.host)
        .replace("127.0.0.1:8787", listen);
    atomic_write(&service, &unit)?;
    atomic_write(&nginx, &proxy)?;
    Ok(describe_install(root, listen, data, public_url))
}

pub(super) fn describe_install(
    root: &Path,
    listen: &str,
    data: &Path,
    public_url: &str,
) -> Installed {
    Installed {
        service: root.join("etc/systemd/system/keyvalet-relay-server.service"),
        nginx: root.join("etc/nginx/conf.d/keyvalet-relay.conf"),
        listen: listen.into(),
        data: data.into(),
        public_url: public_url.into(),
        cloudflare_steps: vec![
            "dns_orange_cloud".into(),
            "ssl_full_strict_origin_ca".into(),
            "firewall_cloudflare_only".into(),
        ],
    }
}

pub(super) fn parse_health(bytes: &[u8]) -> Result<Health> {
    if bytes.len() > 64 * 1024 {
        return Err(health_error());
    }
    let health: Health = serde_json::from_slice(bytes).map_err(|_| health_error())?;
    if !health.ok
        || health.version.is_empty()
        || health.version.len() > 128
        || health.version.chars().any(char::is_control)
    {
        return Err(Error::new(
            "relay_unreachable",
            "relay 健康检查失败",
            "The relay health check failed",
        ));
    }
    Ok(health)
}

pub(super) fn health_error() -> Error {
    Error::new(
        "relay_unreachable",
        "relay 健康检查失败",
        "The relay health check failed",
    )
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
