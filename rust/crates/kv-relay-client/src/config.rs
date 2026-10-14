use std::{fs::File, io::Read, net::IpAddr, path::Path};

use reqwest::Url;
use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub relay_url: String,
    pub device_id: String,
    pub account_id: String,
}

impl Config {
    #[cfg(any(windows, test))]
    pub(crate) async fn load_with_presence_probe<F, P>(
        path: &Path,
        probe_path: &Path,
        metadata: std::io::Result<()>,
        probe: F,
    ) -> Result<Option<Self>>
    where
        F: FnOnce() -> P,
        P: std::future::Future<Output = Result<bool>>,
    {
        match metadata {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // The helper proves absence only for its fixed installed path.
                if path != probe_path {
                    return Err(Error::Config);
                }
                if probe().await? {
                    Err(Error::Config)
                } else {
                    Ok(None)
                }
            }
            Err(_) => Err(Error::Config),
            Ok(()) => Self::load_optional(path),
        }
    }

    pub(crate) async fn load_for_service(
        path: &Path,
        helper: &crate::helper::Helper,
    ) -> Result<Option<Self>> {
        #[cfg(windows)]
        {
            Self::load_with_presence_probe(
                path,
                Path::new(kv_platform::paths::RELAY_CONFIG),
                std::fs::metadata(path).map(|_| ()),
                || helper.config_exists(),
            )
            .await
        }
        #[cfg(not(windows))]
        {
            let _ = helper;
            Self::load_optional(path)
        }
    }

    pub fn load_optional(path: &Path) -> Result<Option<Self>> {
        match std::fs::metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Config),
            Ok(_) => {}
        }
        if let Ok(config) = Self::load(path) {
            return Ok(Some(config));
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unbound {
            relay_url: String,
        }
        let mut text = String::new();
        File::open(path)
            .map_err(|_| Error::Config)?
            .take(16 * 1024 + 1)
            .read_to_string(&mut text)
            .map_err(|_| Error::Config)?;
        if text.len() > 16 * 1024 {
            return Err(Error::Config);
        }
        let unbound: Unbound = toml::from_str(&text).map_err(|_| Error::Config)?;
        Self {
            relay_url: unbound.relay_url,
            device_id: String::new(),
            account_id: String::new(),
        }
        .base_url()?;
        Ok(None)
    }
    pub fn load(path: &Path) -> Result<Self> {
        let mut text = String::new();
        File::open(path)
            .map_err(|_| Error::Config)?
            .take(16 * 1024 + 1)
            .read_to_string(&mut text)
            .map_err(|_| Error::Config)?;
        if text.len() > 16 * 1024 {
            return Err(Error::Config);
        }
        let config: Self = toml::from_str(&text).map_err(|_| Error::Config)?;
        config.base_url()?;
        for id in [&config.device_id, &config.account_id] {
            if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
                return Err(Error::Config);
            }
        }
        Ok(config)
    }

    pub fn base_url(&self) -> Result<Url> {
        let mut url = Url::parse(&self.relay_url).map_err(|_| Error::Config)?;
        let loopback = url
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Config);
        }
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }
        Ok(url)
    }
}
