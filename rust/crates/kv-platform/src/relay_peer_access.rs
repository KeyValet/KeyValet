//! The relay account reads only the helper's OS identity metadata. No SeDebugPrivilege,
//! credential memory, token duplication/impersonation, default-token or worker ACL changes.
use std::io;
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    SE_KERNEL_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

struct Local(*mut std::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0)));
        }
    }
}
fn merged_acl(sid: &[u8], access: u32, existing: *const ACL) -> io::Result<Local> {
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: ACE_FLAGS(0),
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: windows::core::PWSTR(sid.as_ptr() as _),
            ..Default::default()
        },
    };
    let mut acl = std::ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(Some(&[entry]), Some(existing), &mut acl) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.0 as i32));
    }
    Ok(Local(acl.cast()))
}
fn grant(handle: HANDLE, sid: &[u8], access: u32) -> io::Result<()> {
    let mut acl = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.0 as i32));
    }
    let _descriptor = Local(descriptor.0);
    if acl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper identity DACL missing",
        ));
    }
    let merged = merged_acl(sid, access, acl)?;
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(merged.0.cast()),
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.0 as i32));
    }
    Ok(())
}

/// Call from the LocalSystem service before accepting clients. The SID is resolved from the
/// fixed installed service account, never supplied by an IPC client or environment variable.
pub fn enable() -> io::Result<()> {
    let me = crate::peer::self_identity().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper identity unavailable",
        )
    })?;
    if crate::peer::sid_to_string(&me.sid).as_deref() != Some("S-1-5-18") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "LocalSystem required",
        ));
    }
    let sid = match crate::peer::account_sid(crate::paths::RELAY_SERVICE_ACCOUNT) {
        Ok(sid) => sid,
        // A standalone helper may have no installed relay service yet.
        Err(_) => return Ok(()),
    };
    let process = unsafe { GetCurrentProcess() };
    // Access is added only to this process object and its actual primary token object.
    grant(process, &sid, PROCESS_QUERY_LIMITED_INFORMATION.0)?;
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            process,
            TOKEN_QUERY | windows::Win32::Security::TOKEN_ACCESS_MASK(0x0004_0000 | 0x0002_0000),
            &mut token,
        )
    }
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper token DACL unavailable",
        )
    })?;
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    let token = Token(token);
    grant(token.0, &sid, TOKEN_QUERY.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::Authorization::*;
    use windows::Win32::Security::{
        InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SetSecurityDescriptorGroup,
        SetSecurityDescriptorOwner, PSID, SECURITY_DESCRIPTOR,
    };

    #[test]
    fn relay_can_query_only_metadata_and_cannot_read_memory_or_duplicate_a_token() {
        unsafe {
            let relay = crate::peer::sid_from_string("S-1-5-80-1-2-3-4-5").unwrap();
            let other = crate::peer::sid_from_string("S-1-5-80-6-7-8-9-10").unwrap();
            let system = crate::peer::sid_from_string("S-1-5-18").unwrap();
            let mut manager = AUTHZ_RESOURCE_MANAGER_HANDLE::default();
            AuthzInitializeResourceManager(
                1,
                None,
                None,
                None,
                windows::core::PCWSTR::null(),
                &mut manager,
            )
            .unwrap();
            for sid in [&relay, &other] {
                let mut context = AUTHZ_CLIENT_CONTEXT_HANDLE::default();
                AuthzInitializeContextFromSid(
                    AUTHZ_SKIP_TOKEN_GROUPS,
                    PSID(sid.as_ptr() as _),
                    manager,
                    None,
                    Default::default(),
                    None,
                    &mut context,
                )
                .unwrap();
                for (mask, denied) in [
                    (
                        PROCESS_QUERY_LIMITED_INFORMATION.0,
                        vec![0x10, 0x20, 0x8, 0x2, 0x40, 0x200, 0x40000, 0x80000],
                    ),
                    (TOKEN_QUERY.0, vec![0x2, 0x4, 0x20, 0x80, 0x40000, 0x80000]),
                ] {
                    // An empty ACL denies all before the exact metadata-only grant is added.
                    let mut empty = ACL::default();
                    windows::Win32::Security::InitializeAcl(
                        &mut empty,
                        std::mem::size_of::<ACL>() as u32,
                        windows::Win32::Security::ACL_REVISION,
                    )
                    .unwrap();
                    let acl = merged_acl(&relay, mask, &empty).unwrap();
                    let mut descriptor = SECURITY_DESCRIPTOR::default();
                    InitializeSecurityDescriptor(
                        PSECURITY_DESCRIPTOR(&mut descriptor as *mut _ as _),
                        1,
                    )
                    .unwrap();
                    SetSecurityDescriptorOwner(
                        PSECURITY_DESCRIPTOR(&mut descriptor as *mut _ as _),
                        Some(PSID(system.as_ptr() as _)),
                        false,
                    )
                    .unwrap();
                    SetSecurityDescriptorGroup(
                        PSECURITY_DESCRIPTOR(&mut descriptor as *mut _ as _),
                        Some(PSID(system.as_ptr() as _)),
                        false,
                    )
                    .unwrap();
                    SetSecurityDescriptorDacl(
                        PSECURITY_DESCRIPTOR(&mut descriptor as *mut _ as _),
                        true,
                        Some(acl.0.cast()),
                        false,
                    )
                    .unwrap();
                    for access in std::iter::once(mask).chain(denied) {
                        let request = AUTHZ_ACCESS_REQUEST {
                            DesiredAccess: access,
                            ..Default::default()
                        };
                        let mut granted = 0;
                        let mut error = 0;
                        let mut reply = AUTHZ_ACCESS_REPLY {
                            ResultListLength: 1,
                            GrantedAccessMask: &mut granted,
                            Error: &mut error,
                            ..Default::default()
                        };
                        AuthzAccessCheck(
                            AUTHZ_ACCESS_CHECK_FLAGS(0),
                            context,
                            &request,
                            None,
                            PSECURITY_DESCRIPTOR(&descriptor as *const _ as _),
                            None,
                            &mut reply,
                            None,
                        )
                        .unwrap();
                        let expected = sid == &relay && access == mask;
                        assert_eq!(
                            error == 0 && granted & access == access,
                            expected,
                            "unexpected access for metadata mask {mask:#x}, requested {access:#x}"
                        );
                    }
                }
                AuthzFreeContext(context).unwrap();
            }
            AuthzFreeResourceManager(manager).unwrap();
        }
    }
}
