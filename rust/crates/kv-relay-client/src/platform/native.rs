//! Real account lookup and kernel peer/code-signing checks. Tests use an explicit fake connector.

#[cfg(target_os = "macos")]
use std::path::PathBuf;

use crate::error::{Error, Result};
use kv_platform::paths;

#[cfg(target_os = "linux")]
fn uid_by_name(name: &str) -> Result<u32> {
    let name = std::ffi::CString::new(name).map_err(|_| Error::HelperUntrusted)?;
    let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 65536];
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(Error::HelperUntrusted);
    }
    Ok(unsafe { passwd.assume_init() }.pw_uid)
}

#[cfg(target_os = "linux")]
pub fn verify_runtime_account() -> Result<()> {
    let expected = uid_by_name(paths::RELAY_SERVICE_USER)?;
    if unsafe { libc::geteuid() } == expected {
        Ok(())
    } else {
        Err(Error::HelperUntrusted)
    }
}

#[cfg(target_os = "macos")]
pub(super) fn user_home() -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 65536];
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(Error::Config);
    }
    let passwd = unsafe { passwd.assume_init() };
    if passwd.pw_dir.is_null() {
        return Err(Error::Config);
    }
    let home = unsafe { std::ffi::CStr::from_ptr(passwd.pw_dir) };
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(home.to_bytes())))
}

#[cfg(unix)]
pub fn verify_helper(stream: &tokio::net::UnixStream) -> Result<()> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let uid = kv_platform::peer::peer_uid(fd).map_err(|_| Error::HelperUntrusted)?;
    #[cfg(target_os = "linux")]
    if uid != uid_by_name(paths::SERVICE_USER)? {
        return Err(Error::HelperUntrusted);
    }
    #[cfg(target_os = "macos")]
    {
        if uid != 0 {
            return Err(Error::HelperUntrusted);
        }
        let token = kv_platform::peer::peer_audit_token(fd).map_err(|_| Error::HelperUntrusted)?;
        let requirement = format!(
            "identifier \"{}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\"",
            paths::DAEMON_LABEL,
            paths::TEAM_ID
        );
        kv_platform::peer::verify_peer_code(&token, &requirement, paths::HELPER_BIN)
            .map_err(|_| Error::HelperUntrusted)?;
    }
    Ok(())
}
