//! Authentication of real helper connections, outside the fake IPC transport used by tests.

#[cfg(windows)]
use std::path::Path;

use crate::error::{Error, Result};

use super::Stream;

#[cfg(unix)]
pub(super) async fn verify(
    stream: tokio::net::UnixStream,
    #[cfg(test)] fake_peer: bool,
) -> Result<Box<dyn Stream>> {
    #[cfg(test)]
    if fake_peer {
        return Ok(Box::new(stream));
    }
    // Signature checks may block; only a real helper connection reaches this adapter.
    tokio::task::spawn_blocking(move || {
        crate::platform::verify_helper(&stream)?;
        Ok(Box::new(stream) as Box<dyn Stream>)
    })
    .await
    .map_err(|_| Error::HelperUntrusted)?
}

#[cfg(windows)]
pub(super) async fn connect(
    endpoint: &Path,
    #[cfg(test)] fake_peer: bool,
) -> Result<Box<dyn Stream>> {
    let name = endpoint.to_str().ok_or(Error::HelperUnavailable)?;
    #[cfg(test)]
    if fake_peer {
        return kv_platform::pipe::open_client(name)
            .map(|pipe| Box::new(pipe) as Box<dyn Stream>)
            .map_err(|_| Error::HelperUnavailable);
    }
    kv_platform::pipe::connect_service(name)
        .await
        .map(|pipe| Box::new(pipe) as Box<dyn Stream>)
        .map_err(|_| Error::HelperUntrusted)
}
