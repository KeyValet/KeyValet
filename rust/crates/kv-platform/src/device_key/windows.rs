//! LocalSystem PCP identity/Quick keys and explicitly selected DPAPI software keys.
use super::{
    decode_b64, encode_b64, key_name_valid, p256_jwk, DeviceKeyError, DeviceKeyProvider, KeyRole,
    Result, SignatureAlgorithm,
};
use serde_json::{json, Value};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::*;
use zeroize::{Zeroize, Zeroizing};

struct Provider(NCRYPT_PROV_HANDLE);
impl Drop for Provider {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.0 .0));
        }
    }
}
struct Key(NCRYPT_KEY_HANDLE);
impl Drop for Key {
    fn drop(&mut self) {
        if self.0 .0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.0 .0));
            }
        }
    }
}
impl Key {
    fn delete(&mut self) -> Result<()> {
        // PCP rejects NCRYPT_SILENT_FLAG for deletion, including keys without a UI policy.
        unsafe { NCryptDeleteKey(self.0, 0) }.map_err(failure)?;
        self.0 = NCRYPT_KEY_HANDLE::default();
        Ok(())
    }
}
struct Secret(NCRYPT_SECRET_HANDLE);
impl Drop for Secret {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.0 .0));
        }
    }
}
fn failure(_: windows::core::Error) -> DeviceKeyError {
    DeviceKeyError::OperationFailed
}
fn system_context() -> Result<()> {
    let me = crate::peer::self_identity().ok_or(DeviceKeyError::Unavailable)?;
    if crate::peer::sid_to_string(&me.sid).as_deref() != Some("S-1-5-18") {
        return Err(DeviceKeyError::Unavailable);
    }
    Ok(())
}
fn provider(name: PCWSTR) -> Result<Provider> {
    let mut handle = NCRYPT_PROV_HANDLE::default();
    unsafe { NCryptOpenStorageProvider(&mut handle, name, 0) }.map_err(failure)?;
    Ok(Provider(handle))
}
fn hardware_provider() -> Result<Provider> {
    let provider = provider(MS_PLATFORM_CRYPTO_PROVIDER)?;
    let mut flags = [0u8; 4];
    let mut length = 0;
    unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(provider.0 .0),
            NCRYPT_IMPL_TYPE_PROPERTY,
            Some(&mut flags),
            &mut length,
            windows::Win32::Security::OBJECT_SECURITY_INFORMATION(0),
        )
    }
    .map_err(failure)?;
    if length != 4 || u32::from_le_bytes(flags) & NCRYPT_IMPL_HARDWARE_FLAG == 0 {
        return Err(DeviceKeyError::Unavailable);
    }
    Ok(provider)
}
fn system_key_permissions(key: &Key) -> Result<()> {
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)"),
            1,
            &mut descriptor,
            None,
        )
    }
    .map_err(failure)?;
    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
    let descriptor = Descriptor(descriptor);
    let length = unsafe { GetSecurityDescriptorLength(descriptor.0) };
    if length == 0 || length > 4096 {
        return Err(DeviceKeyError::OperationFailed);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(descriptor.0 .0 as *const u8, length as usize) };
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0 .0),
            NCRYPT_SECURITY_DESCR_PROPERTY,
            bytes,
            NCRYPT_FLAGS(4) | NCRYPT_PERSIST_FLAG | NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(failure)
}
fn export(key: &Key, kind: PCWSTR) -> Result<Zeroizing<Vec<u8>>> {
    let mut length = 0;
    unsafe {
        NCryptExportKey(
            key.0,
            None,
            kind,
            None,
            None,
            &mut length,
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(failure)?;
    if length == 0 || length > 1024 {
        return Err(DeviceKeyError::InvalidKey);
    }
    let mut bytes = Zeroizing::new(vec![0; length as usize]);
    unsafe {
        NCryptExportKey(
            key.0,
            None,
            kind,
            None,
            Some(&mut bytes),
            &mut length,
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(failure)?;
    if length as usize != bytes.len() {
        return Err(DeviceKeyError::InvalidKey);
    }
    Ok(bytes)
}
fn import(provider: &Provider, bytes: &[u8], kind: PCWSTR) -> Result<Key> {
    let mut key = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptImportKey(
            provider.0,
            None,
            kind,
            None,
            &mut key,
            bytes,
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(failure)?;
    Ok(Key(key))
}
fn public(key: &Key) -> Result<Value> {
    let blob = export(key, BCRYPT_ECCPUBLIC_BLOB)?;
    if blob.len() != 72
        || u32::from_le_bytes(blob[4..8].try_into().unwrap()) != 32
        || ![
            BCRYPT_ECDH_PUBLIC_P256_MAGIC,
            BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        ]
        .contains(&u32::from_le_bytes(blob[..4].try_into().unwrap()))
    {
        return Err(DeviceKeyError::InvalidKey);
    }
    let mut point = vec![4];
    point.extend_from_slice(&blob[8..]);
    p256_jwk(&point)
}
fn sign(key: &Key, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>> {
    if alg != SignatureAlgorithm::ES256 {
        return Err(DeviceKeyError::UnsupportedAlgorithm);
    }
    if payload.len() > 128 * 1024 {
        return Err(DeviceKeyError::OperationFailed);
    }
    let mut hash = [0u8; 32];
    unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, payload, &mut hash) }
        .ok()
        .map_err(failure)?;
    let mut signature = vec![0; 64];
    let mut length = 0;
    unsafe {
        NCryptSignHash(
            key.0,
            None,
            &hash,
            Some(&mut signature),
            &mut length,
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(failure)?;
    if length != 64 {
        return Err(DeviceKeyError::OperationFailed);
    }
    Ok(signature)
}
fn ecdh(provider: &Provider, key: &Key, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if peer.len() != 65 || peer[0] != 4 {
        return Err(DeviceKeyError::InvalidKey);
    }
    let mut blob = BCRYPT_ECDH_PUBLIC_P256_MAGIC.to_le_bytes().to_vec();
    blob.extend_from_slice(&32u32.to_le_bytes());
    blob.extend_from_slice(&peer[1..]);
    let peer = import(provider, &blob, BCRYPT_ECCPUBLIC_BLOB)?;
    let mut secret = NCRYPT_SECRET_HANDLE::default();
    unsafe { NCryptSecretAgreement(key.0, peer.0, &mut secret, NCRYPT_SILENT_FLAG) }
        .map_err(failure)?;
    let secret = Secret(secret);
    let mut raw = Zeroizing::new([0u8; 32]);
    let mut length = 0;
    // CONTRACT: §3.1 / A.1: CNG RAW_SECRET is little-endian; W0 requires a padded big-endian x coordinate.
    unsafe {
        NCryptDeriveKey(
            secret.0,
            BCRYPT_KDF_RAW_SECRET,
            None,
            Some(raw.as_mut_slice()),
            &mut length,
            0,
        )
    }
    .map_err(failure)?;
    if length != 32 {
        return Err(DeviceKeyError::OperationFailed);
    }
    raw.reverse();
    Ok(raw)
}
/// Newly created persisted keys are deleted unless the complete provider passes its self-tests.
struct PendingKey(Option<Key>);
impl PendingKey {
    fn key(&self) -> &Key {
        self.0.as_ref().expect("pending PCP key")
    }
    fn commit(mut self) -> Key {
        self.0.take().expect("pending PCP key")
    }
}
impl Drop for PendingKey {
    fn drop(&mut self) {
        if let Some(key) = &mut self.0 {
            let _ = key.delete();
        }
    }
}

fn typed_public(key: &Key, magic: u32) -> Result<Value> {
    let blob = export(key, BCRYPT_ECCPUBLIC_BLOB)?;
    if blob.len() != 72 || blob[..4] != magic.to_le_bytes() {
        return Err(DeviceKeyError::InvalidKey);
    }
    public(key)
}

fn create_pcp_key(
    provider: &Provider,
    role: KeyRole,
    algorithm: PCWSTR,
) -> Result<(PendingKey, String)> {
    let mut id = [0u8; 16];
    unsafe { BCryptGenRandom(None, &mut id, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
        .ok()
        .map_err(failure)?;
    let name = format!(
        "keyvalet.remote.{}.{}",
        role.as_str(),
        id.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut key = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut key,
            algorithm,
            PCWSTR(wide.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(failure)?;
    let pending = PendingKey(Some(Key(key)));
    // PCP determines usage from the algorithm. Setting KEY_USAGE is unsupported on the tested TPM.
    unsafe { NCryptFinalizeKey(pending.key().0, NCRYPT_SILENT_FLAG) }.map_err(failure)?;
    system_key_permissions(pending.key())?;
    Ok((pending, name))
}

fn open_pcp_key(provider: &Provider, name: &str, role: KeyRole) -> Result<Key> {
    if !key_name_valid(name, role) {
        return Err(DeviceKeyError::InvalidKey);
    }
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut key = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptOpenKey(
            provider.0,
            &mut key,
            PCWSTR(wide.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(failure)?;
    Ok(Key(key))
}

pub struct PcpDeviceKey {
    signing: Key,
    agreement: Option<Key>,
    provider: Provider,
    role: KeyRole,
    metadata: Value,
}
impl PcpDeviceKey {
    // Invoke after service startup, from LocalSystem's worker context, never StartService.
    pub fn create(role: KeyRole) -> Result<Self> {
        Self::create_with(role, create_pcp_key)
    }

    fn create_with(
        role: KeyRole,
        mut create_key: impl FnMut(&Provider, KeyRole, PCWSTR) -> Result<(PendingKey, String)>,
    ) -> Result<Self> {
        system_context()?;
        if role == KeyRole::Strong {
            return Err(DeviceKeyError::UnsupportedAlgorithm);
        }
        let provider = hardware_provider()?;
        let agreement = if role == KeyRole::Identity {
            Some(create_key(&provider, role, BCRYPT_ECDH_P256_ALGORITHM)?)
        } else {
            None
        };
        let (signing, signing_name) = create_key(&provider, role, BCRYPT_ECDSA_P256_ALGORITHM)?;
        let signing_public = typed_public(signing.key(), BCRYPT_ECDSA_PUBLIC_P256_MAGIC)?;
        sign(
            signing.key(),
            SignatureAlgorithm::ES256,
            b"keyvalet/device-key/self-test",
        )?;
        let metadata = if let Some((key, name)) = &agreement {
            let public = typed_public(key.key(), BCRYPT_ECDH_PUBLIC_P256_MAGIC)?;
            if public == signing_public {
                return Err(DeviceKeyError::InvalidKey);
            }
            ecdh(&provider, key.key(), &super::jwk_point(&public)?)?;
            json!({"version":2,"role":role.as_str(),"key_kind":"pcp_tpm",
                "key_name":name,"public_jwk":public,"signing_key_name":signing_name,
                "identity_sign_jwk":signing_public})
        } else {
            json!({"version":2,"role":role.as_str(),"key_kind":"pcp_tpm",
                "key_name":signing_name,"public_jwk":signing_public})
        };
        Ok(Self {
            signing: signing.commit(),
            agreement: agreement.map(|(key, _)| key.commit()),
            provider,
            role,
            metadata,
        })
    }
    pub fn from_authenticated_metadata(metadata: Value) -> Result<Self> {
        system_context()?;
        let role = KeyRole::parse(
            metadata["role"]
                .as_str()
                .ok_or(DeviceKeyError::InvalidKey)?,
        )?;
        let name = metadata["key_name"]
            .as_str()
            .ok_or(DeviceKeyError::InvalidKey)?;
        if metadata["version"] != 2 || metadata["key_kind"] != "pcp_tpm" || role == KeyRole::Strong
        {
            return Err(DeviceKeyError::InvalidKey);
        }
        let provider = hardware_provider()?;
        let (agreement, signing) = if role == KeyRole::Identity {
            let signing_name = metadata["signing_key_name"]
                .as_str()
                .ok_or(DeviceKeyError::InvalidKey)?;
            if name == signing_name || metadata["public_jwk"] == metadata["identity_sign_jwk"] {
                return Err(DeviceKeyError::InvalidKey);
            }
            let agreement = open_pcp_key(&provider, name, role)?;
            let signing = open_pcp_key(&provider, signing_name, role)?;
            if typed_public(&agreement, BCRYPT_ECDH_PUBLIC_P256_MAGIC)? != metadata["public_jwk"]
                || typed_public(&signing, BCRYPT_ECDSA_PUBLIC_P256_MAGIC)?
                    != metadata["identity_sign_jwk"]
            {
                return Err(DeviceKeyError::InvalidKey);
            }
            (Some(agreement), signing)
        } else {
            if metadata.get("signing_key_name").is_some()
                || metadata.get("identity_sign_jwk").is_some()
            {
                return Err(DeviceKeyError::InvalidKey);
            }
            let signing = open_pcp_key(&provider, name, role)?;
            if typed_public(&signing, BCRYPT_ECDSA_PUBLIC_P256_MAGIC)? != metadata["public_jwk"] {
                return Err(DeviceKeyError::InvalidKey);
            }
            (None, signing)
        };
        Ok(Self {
            signing,
            agreement,
            provider,
            role,
            metadata,
        })
    }
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }

    pub fn delete(mut self) -> Result<()> {
        system_context()?;
        // Attempt both deletions even if one fails. PCP requires flags=0 for NCryptDeleteKey.
        let signing = self.signing.delete();
        let agreement = self.agreement.as_mut().map_or(Ok(()), Key::delete);
        signing.and(agreement)
    }
}
impl DeviceKeyProvider for PcpDeviceKey {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>> {
        sign(&self.signing, alg, payload)
    }
    fn ecdh(&self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        ecdh(
            &self.provider,
            self.agreement
                .as_ref()
                .ok_or(DeviceKeyError::UnsupportedAlgorithm)?,
            peer,
        )
    }
    fn public_jwk(&self) -> Result<Value> {
        Ok(self.metadata["public_jwk"].clone())
    }
    fn identity_sign_jwk(&self) -> Result<Option<Value>> {
        Ok((self.role == KeyRole::Identity).then(|| self.metadata["identity_sign_jwk"].clone()))
    }
    fn key_kind(&self) -> &str {
        "pcp_tpm"
    }
    fn presence_kind(&self) -> &str {
        self.role.presence_kind()
    }
}

/// Read-only inventory of persisted KeyValet identity keys, queried by the SYSTEM service.
/// This reports key existence, separately from authenticated enrollment and physical TPM evidence.
pub fn identity_key_status() -> Value {
    fn inventory() -> Result<(bool, bool)> {
        system_context()?;
        let provider = hardware_provider()?;
        struct Buffer(*mut std::ffi::c_void);
        impl Drop for Buffer {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        let _ = NCryptFreeBuffer(self.0);
                    }
                }
            }
        }
        let mut state = Buffer(std::ptr::null_mut());
        let mut ecdh = false;
        let mut ecdsa = false;
        for _ in 0..4096 {
            let mut name = std::ptr::null_mut();
            let result = unsafe {
                NCryptEnumKeys(
                    provider.0,
                    PCWSTR::null(),
                    &mut name,
                    &mut state.0,
                    NCRYPT_MACHINE_KEY_FLAG,
                )
            };
            let _name = Buffer(name.cast());
            if let Err(error) = result {
                if error.code() == windows::Win32::Foundation::NTE_NO_MORE_ITEMS {
                    return Ok((ecdh, ecdsa));
                }
                return Err(failure(error));
            }
            if name.is_null() {
                return Err(DeviceKeyError::OperationFailed);
            }
            let entry = unsafe { &*name };
            let text =
                unsafe { entry.pszName.to_string() }.map_err(|_| DeviceKeyError::InvalidKey)?;
            if key_name_valid(&text, KeyRole::Identity) {
                // PCP enumeration can return generic algorithm names. Check the actual P-256 blob.
                let key = open_pcp_key(&provider, &text, KeyRole::Identity)?;
                let blob = export(&key, BCRYPT_ECCPUBLIC_BLOB)?;
                public(&key)?;
                match u32::from_le_bytes(blob[..4].try_into().unwrap()) {
                    BCRYPT_ECDH_PUBLIC_P256_MAGIC => ecdh = true,
                    BCRYPT_ECDSA_PUBLIC_P256_MAGIC => ecdsa = true,
                    _ => {}
                }
            }
        }
        Err(DeviceKeyError::OperationFailed)
    }
    let (ecdh, ecdsa) = match inventory() {
        Ok((ecdh, ecdsa)) => (Some(ecdh), Some(ecdsa)),
        Err(_) => (None, None),
    };
    json!({"pcp_ecdh":ecdh,"pcp_ecdsa":ecdsa,
        "ready":ecdh == Some(true) && ecdsa == Some(true),
        "evidence":"pcp_machine_key_inventory"})
}

fn dpapi(input: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: input
            .len()
            .try_into()
            .map_err(|_| DeviceKeyError::InvalidKey)?,
        pbData: input.as_ptr() as _,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    if protect {
        unsafe {
            CryptProtectData(
                &input,
                w!("KeyValet remote software device key"),
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
        .map_err(failure)?;
    } else {
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
        .map_err(failure)?;
    }
    struct Allocation(CRYPT_INTEGER_BLOB);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                if !self.0.pbData.is_null() {
                    std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                    let _ = LocalFree(Some(HLOCAL(self.0.pbData as _)));
                }
            }
        }
    }
    let output = Allocation(output);
    if output.0.pbData.is_null() || output.0.cbData == 0 || output.0.cbData > 4096 {
        return Err(DeviceKeyError::InvalidKey);
    }
    Ok(Zeroizing::new(
        unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }.to_vec(),
    ))
}

pub struct DpapiDeviceKey {
    signing: Key,
    agreement: Key,
    provider: Provider,
    metadata: Value,
}
impl DpapiDeviceKey {
    // CONTRACT: §3.1: the caller explicitly selects software and stores the DPAPI blob in authenticated vault metadata.
    pub fn create(role: KeyRole) -> Result<Self> {
        system_context()?;
        if role == KeyRole::Strong {
            return Err(DeviceKeyError::UnsupportedAlgorithm);
        }
        let provider = provider(MS_KEY_STORAGE_PROVIDER)?;
        let mut key = NCRYPT_KEY_HANDLE::default();
        unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key,
                BCRYPT_ECDH_P256_ALGORITHM,
                PCWSTR::null(),
                CERT_KEY_SPEC(0),
                NCRYPT_SILENT_FLAG,
            )
        }
        .map_err(failure)?;
        let key = Key(key);
        unsafe {
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0 .0),
                NCRYPT_EXPORT_POLICY_PROPERTY,
                &NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG.to_le_bytes(),
                NCRYPT_SILENT_FLAG,
            )
        }
        .map_err(failure)?;
        unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) }.map_err(failure)?;
        let private = export(&key, BCRYPT_ECCPRIVATE_BLOB)?;
        let protected = dpapi(&private, true)?;
        let metadata = json!({"version":1,"role":role.as_str(),"key_kind":"software","protected_blob":encode_b64(&protected),"public_jwk":public(&key)?});
        Self::from_authenticated_metadata(metadata)
    }
    pub fn from_authenticated_metadata(metadata: Value) -> Result<Self> {
        system_context()?;
        Self::open(metadata)
    }

    fn open(metadata: Value) -> Result<Self> {
        let role = KeyRole::parse(
            metadata["role"]
                .as_str()
                .ok_or(DeviceKeyError::InvalidKey)?,
        )?;
        if metadata["version"] != 1 || metadata["key_kind"] != "software" || role == KeyRole::Strong
        {
            return Err(DeviceKeyError::InvalidKey);
        }
        let protected = decode_b64(
            metadata["protected_blob"]
                .as_str()
                .ok_or(DeviceKeyError::InvalidKey)?,
        )?;
        if protected.len() > 4096 {
            return Err(DeviceKeyError::InvalidKey);
        }
        let mut private = dpapi(&protected, false)?;
        if private.len() != 104
            || private[..4] != BCRYPT_ECDH_PRIVATE_P256_MAGIC.to_le_bytes()
            || private[4..8] != 32u32.to_le_bytes()
        {
            return Err(DeviceKeyError::InvalidKey);
        }
        let provider = provider(MS_KEY_STORAGE_PROVIDER)?;
        let agreement = import(&provider, &private, BCRYPT_ECCPRIVATE_BLOB)?;
        // CNG software keys need separate typed handles for the same scalar, not separate keypairs.
        private[..4].copy_from_slice(&BCRYPT_ECDSA_PRIVATE_P256_MAGIC.to_le_bytes());
        let signing = import(&provider, &private, BCRYPT_ECCPRIVATE_BLOB)?;
        if public(&agreement)? != metadata["public_jwk"]
            || public(&signing)? != metadata["public_jwk"]
        {
            return Err(DeviceKeyError::InvalidKey);
        }
        Ok(Self {
            signing,
            agreement,
            provider,
            metadata,
        })
    }
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }
}
impl DeviceKeyProvider for DpapiDeviceKey {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>> {
        sign(&self.signing, alg, payload)
    }
    fn ecdh(&self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        ecdh(&self.provider, &self.agreement, peer)
    }
    fn public_jwk(&self) -> Result<Value> {
        Ok(self.metadata["public_jwk"].clone())
    }
    fn key_kind(&self) -> &str {
        "software"
    }
    fn presence_kind(&self) -> &str {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn dpapi_software_uses_w0_scalar_and_returns_raw_p256_x() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../kv-core/testdata/remote/test_keys.json");
        let vector: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let point = super::super::jwk_point(&vector["sender"]["public_jwk"]).unwrap();
        let mut private = Zeroizing::new(BCRYPT_ECDH_PRIVATE_P256_MAGIC.to_le_bytes().to_vec());
        private.extend_from_slice(&32u32.to_le_bytes());
        private.extend_from_slice(&point[1..]);
        private.extend_from_slice(
            &decode_b64(vector["sender"]["private_scalar"].as_str().unwrap()).unwrap(),
        );
        let protected = dpapi(&private, true).unwrap();
        let metadata = json!({"version":1,"role":"identity","key_kind":"software","public_jwk":vector["sender"]["public_jwk"],"protected_blob":encode_b64(&protected)});
        // Exercise software CNG/DPAPI in CI's ordinary user token; production constructors require SYSTEM.
        let key = DpapiDeviceKey::open(metadata).unwrap();
        assert_eq!(key.key_kind(), "software");
        let peer = super::super::jwk_point(&vector["recipient"]["public_jwk"]).unwrap();
        let raw = key.ecdh(&peer).unwrap();
        assert!(
            raw.as_slice()
                == decode_b64(vector["recipient"]["public_jwk"]["x"].as_str().unwrap())
                    .unwrap()
                    .as_slice()
        );
        let payload = b"W0 software compatibility";
        let signature = key.sign(SignatureAlgorithm::ES256, payload).unwrap();
        let mut hash = [0; 32];
        unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, payload, &mut hash) }
            .ok()
            .unwrap();
        unsafe {
            NCryptVerifySignature(key.signing.0, None, &hash, &signature, NCRYPT_SILENT_FLAG)
        }
        .unwrap();
    }
    /// LocalSystem on Windows 11 + TPM 2.0:
    /// CARGO_TARGET_DIR=target-r2b cargo test -p kv-platform pcp_identity_dual_key_roundtrip -- --ignored --nocapture
    #[test]
    #[ignore = "Requires Windows 11, TPM 2.0 and a LocalSystem worker context"]
    fn pcp_identity_dual_key_roundtrip() {
        struct Cleanup(Option<PcpDeviceKey>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Some(key) = self.0.take() {
                    let _ = key.delete();
                }
            }
        }
        let mut left = Cleanup(Some(PcpDeviceKey::create(KeyRole::Identity).unwrap()));
        let mut right = Cleanup(Some(PcpDeviceKey::create(KeyRole::Identity).unwrap()));
        let mut quick = Cleanup(Some(PcpDeviceKey::create(KeyRole::Quick).unwrap()));
        let metadata = left.0.as_ref().unwrap().metadata().clone();
        let loaded = PcpDeviceKey::from_authenticated_metadata(metadata.clone()).unwrap();
        assert_ne!(
            loaded.public_jwk().unwrap(),
            loaded.identity_sign_jwk().unwrap().unwrap()
        );
        let a = loaded
            .ecdh(
                &super::super::jwk_point(&right.0.as_ref().unwrap().public_jwk().unwrap()).unwrap(),
            )
            .unwrap();
        let b = right
            .0
            .as_ref()
            .unwrap()
            .ecdh(&super::super::jwk_point(&loaded.public_jwk().unwrap()).unwrap())
            .unwrap();
        assert_eq!(*a, *b);
        let payload = b"K1 identity signature";
        let signature = loaded.sign(SignatureAlgorithm::ES256, payload).unwrap();
        let mut hash = [0u8; 32];
        unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, payload, &mut hash) }
            .ok()
            .unwrap();
        unsafe {
            NCryptVerifySignature(
                loaded.signing.0,
                None,
                &hash,
                &signature,
                NCRYPT_SILENT_FLAG,
            )
        }
        .unwrap();
        assert!(unsafe {
            NCryptVerifySignature(
                loaded.agreement.as_ref().unwrap().0,
                None,
                &hash,
                &signature,
                NCRYPT_SILENT_FLAG,
            )
        }
        .is_err());
        assert!(quick
            .0
            .as_ref()
            .unwrap()
            .ecdh(&super::super::jwk_point(&loaded.public_jwk().unwrap()).unwrap())
            .is_err());
        let mut swapped = metadata.clone();
        swapped["key_name"] = metadata["signing_key_name"].clone();
        swapped["signing_key_name"] = metadata["key_name"].clone();
        swapped["public_jwk"] = metadata["identity_sign_jwk"].clone();
        swapped["identity_sign_jwk"] = metadata["public_jwk"].clone();
        assert!(PcpDeviceKey::from_authenticated_metadata(swapped).is_err());
        drop(loaded);
        left.0.take().unwrap().delete().unwrap();
        assert!(PcpDeviceKey::from_authenticated_metadata(metadata.clone()).is_err());
        // Check each name separately so a remaining half cannot be hidden by failed pair reopen.
        let provider = hardware_provider().unwrap();
        for field in ["key_name", "signing_key_name"] {
            assert!(open_pcp_key(
                &provider,
                metadata[field].as_str().unwrap(),
                KeyRole::Identity
            )
            .is_err());
        }
        right.0.take().unwrap().delete().unwrap();
        quick.0.take().unwrap().delete().unwrap();
        // right/quick cleanup is guarded through every assertion above.
        println!("pcp_ecdh=pass; pcp_ecdsa=pass signature_length=64; raw_secret=pass length=32; reopen=pass; cleanup=pass");
    }
    /// Run from LocalSystem on any Windows 11 test machine:
    /// CARGO_TARGET_DIR=target-w1 cargo test -p kv-platform dpapi_device_roundtrip -- --ignored
    #[test]
    #[ignore = "Requires Windows DPAPI in LocalSystem context"]
    fn dpapi_device_roundtrip() {
        let key = DpapiDeviceKey::create(KeyRole::Identity).unwrap();
        let loaded = DpapiDeviceKey::from_authenticated_metadata(key.metadata().clone()).unwrap();
        assert_eq!(key.public_jwk().unwrap(), loaded.public_jwk().unwrap());
        assert_eq!(loaded.key_kind(), "software");
        assert_eq!(
            loaded
                .sign(SignatureAlgorithm::ES256, b"remote test")
                .unwrap()
                .len(),
            64
        );
    }

    /// LocalSystem TPM VM: verifies rollback of a real first key if the second creation fails.
    #[test]
    #[ignore = "Requires Windows 11 TPM 2.0 and LocalSystem; creates/deletes a disposable PCP key"]
    fn pcp_partial_creation_cleans_up_without_fallback() {
        let mut names = Vec::new();
        let result = PcpDeviceKey::create_with(KeyRole::Identity, |provider, role, algorithm| {
            if !names.is_empty() {
                return Err(DeviceKeyError::OperationFailed);
            }
            let (key, name) = create_pcp_key(provider, role, algorithm)?;
            names.push(name.clone());
            Ok((key, name))
        });
        match result {
            Err(error) => assert_eq!(error, DeviceKeyError::OperationFailed),
            Ok(key) => {
                key.delete().unwrap();
                panic!("Failed PCP creation returned a provider");
            }
        }
        assert_eq!(names.len(), 1);
        let provider = hardware_provider().unwrap();
        if let Ok(mut key) = open_pcp_key(&provider, &names[0], KeyRole::Identity) {
            key.delete().unwrap();
            panic!("The first PCP key remained after second-key creation failure");
        }
        println!("partial_creation=error; software_fallback=false; first_key_cleanup=pass");
    }

    /// Run from LocalSystem on Windows 11 + TPM 2.0 with --ignored --exact.
    #[test]
    #[ignore = "Requires Windows 11, TPM 2.0 and a LocalSystem context"]
    fn pcp_single_purpose_key_cleanup() {
        system_context().unwrap();
        let provider = hardware_provider().unwrap();
        let mut id = [0u8; 16];
        unsafe { BCryptGenRandom(None, &mut id, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
            .ok()
            .unwrap();
        let name = format!(
            "keyvalet.test.pcp.cleanup.{}",
            id.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut handle = NCRYPT_KEY_HANDLE::default();
        unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut handle,
                BCRYPT_ECDSA_P256_ALGORITHM,
                PCWSTR(wide.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
            )
        }
        .unwrap();
        struct Cleanup(Key);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if self.0 .0 .0 != 0 {
                    let _ = self.0.delete();
                }
            }
        }
        let mut key = Cleanup(Key(handle));
        unsafe { NCryptFinalizeKey(key.0 .0, NCRYPT_SILENT_FLAG) }.unwrap();
        system_key_permissions(&key.0).unwrap();
        assert_eq!(
            sign(&key.0, SignatureAlgorithm::ES256, b"PCP cleanup fixture")
                .unwrap()
                .len(),
            64
        );
        key.0.delete().unwrap();
        let mut reopened = NCRYPT_KEY_HANDLE::default();
        let result = unsafe {
            NCryptOpenKey(
                provider.0,
                &mut reopened,
                PCWSTR(wide.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
            )
        };
        if result.is_ok() {
            let _unexpected = Cleanup(Key(reopened));
            panic!("Deleted PCP fixture remained available");
        }
    }
}
