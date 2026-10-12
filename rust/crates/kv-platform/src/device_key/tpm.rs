use super::{
    decode_b64, encode_b64, p256_jwk, DeviceKeyError, DeviceKeyProvider, Result, SignatureAlgorithm,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub trait TpmCommands {
    fn run(&self, name: &str, args: &[&str], directory: &Path) -> Result<Zeroizing<Vec<u8>>>;
}
pub struct TrustedTpm;
impl TpmCommands for TrustedTpm {
    fn run(&self, name: &str, args: &[&str], directory: &Path) -> Result<Zeroizing<Vec<u8>>> {
        run_tool(
            name,
            args,
            directory,
            tpm_present(
                Path::new("/sys/class/tpm/tpm0/tpm_version_major"),
                Path::new("/dev/tpmrm0"),
            ),
            crate::linux::trusted_command,
        )
    }
}
fn tpm_present(version: &Path, device: &Path) -> bool {
    std::fs::read_to_string(version)
        .ok()
        .as_deref()
        .map(str::trim)
        == Some("2")
        && device.exists()
}
fn run_tool<E: std::fmt::Display>(
    name: &str,
    args: &[&str],
    directory: &Path,
    available: bool,
    command: impl FnOnce(&str) -> std::result::Result<std::process::Command, E>,
) -> Result<Zeroizing<Vec<u8>>> {
    if !["createprimary", "create", "load", "sign", "ecdhzgen"].contains(&name) {
        return Err(DeviceKeyError::OperationFailed);
    }
    if !available {
        return Err(DeviceKeyError::Unavailable);
    }
    let mut command =
        command(&format!("/usr/bin/tpm2_{name}")).map_err(|_| DeviceKeyError::Unavailable)?;
    command
        .current_dir(directory)
        .args(["-T", "device:/dev/tpmrm0", "-Q"])
        .args(args);
    crate::remote_process::bounded_output(&mut command, 4096, Duration::from_secs(30))
        .map_err(|_| DeviceKeyError::OperationFailed)
}

pub struct TpmDeviceKey<T = TrustedTpm> {
    backend: T,
    directory: PathBuf,
    metadata: Value,
    public_blob: Vec<u8>,
    private_blob: Zeroizing<Vec<u8>>,
}
impl<T: TpmCommands> TpmDeviceKey<T> {
    pub fn create(directory: PathBuf, backend: T) -> Result<Self> {
        let temp = workspace(&directory)?;
        let dir = temp.path();
        primary(&backend, dir)?;
        // CONTRACT: §3.1: an unrestricted dual-use object needs a NULL scheme, not ECDSA/ECDH fixed at creation.
        backend.run(
            "create",
            &[
                "-C",
                "parent.ctx",
                "-G",
                "ecc256:null",
                "-g",
                "sha256",
                "-u",
                "identity.pub",
                "-r",
                "identity.priv",
                "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|decrypt|noda",
            ],
            dir,
        )?;
        let public =
            std::fs::read(dir.join("identity.pub")).map_err(|_| DeviceKeyError::OperationFailed)?;
        let private = Zeroizing::new(
            std::fs::read(dir.join("identity.priv"))
                .map_err(|_| DeviceKeyError::OperationFailed)?,
        );
        if private.is_empty() || private.len() > 2048 {
            return Err(DeviceKeyError::InvalidKey);
        }
        let metadata = json!({"version":1,"role":"identity","key_kind":"tpm2",
            "public_blob":encode_b64(&public), "private_blob":encode_b64(&private),
            "public_jwk":p256_jwk(&public_point(&public)?)?});
        Ok(Self {
            backend,
            directory,
            metadata,
            public_blob: public,
            private_blob: private,
        })
    }
    // CONTRACT: §3.2: blobs are returned for vault AEAD storage, never written as long-lived plaintext metadata.
    pub fn from_authenticated_metadata(
        directory: PathBuf,
        backend: T,
        metadata: Value,
    ) -> Result<Self> {
        if metadata["version"] != 1
            || metadata["role"] != "identity"
            || metadata["key_kind"] != "tpm2"
        {
            return Err(DeviceKeyError::InvalidKey);
        }
        let public = decode_b64(
            metadata["public_blob"]
                .as_str()
                .ok_or(DeviceKeyError::InvalidKey)?,
        )?;
        let private = decode_b64(
            metadata["private_blob"]
                .as_str()
                .ok_or(DeviceKeyError::InvalidKey)?,
        )?;
        if public.len() > 2048
            || private.is_empty()
            || private.len() > 2048
            || p256_jwk(&public_point(&public)?)? != metadata["public_jwk"]
        {
            return Err(DeviceKeyError::InvalidKey);
        }
        Ok(Self {
            backend,
            directory,
            metadata,
            public_blob: public.to_vec(),
            private_blob: private,
        })
    }
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }
    fn loaded(&self) -> Result<tempfile::TempDir> {
        let temp = workspace(&self.directory)?;
        let dir = temp.path();
        for (file, blob) in [
            ("identity.pub", self.public_blob.as_slice()),
            ("identity.priv", self.private_blob.as_slice()),
        ] {
            write_private(&dir.join(file), blob)?;
        }
        primary(&self.backend, dir)?;
        self.backend.run(
            "load",
            &[
                "-C",
                "parent.ctx",
                "-u",
                "identity.pub",
                "-r",
                "identity.priv",
                "-c",
                "identity.ctx",
            ],
            dir,
        )?;
        Ok(temp)
    }
}
fn primary(tpm: &impl TpmCommands, dir: &Path) -> Result<()> {
    tpm.run(
        "createprimary",
        &["-C", "o", "-G", "ecc", "-g", "sha256", "-c", "parent.ctx"],
        dir,
    )
    .map(|_| ())
}
fn workspace(directory: &Path) -> Result<tempfile::TempDir> {
    let meta = std::fs::symlink_metadata(directory).map_err(|_| DeviceKeyError::Unavailable)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { libc::geteuid() }
    {
        return Err(DeviceKeyError::InvalidKey);
    }
    let temp = tempfile::Builder::new()
        .prefix(".remote-tpm-")
        .tempdir_in(directory)
        .map_err(|_| DeviceKeyError::OperationFailed)?;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .map_err(|_| DeviceKeyError::OperationFailed)?;
    Ok(temp)
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|_| DeviceKeyError::OperationFailed)
}

fn public_point(blob: &[u8]) -> Result<Vec<u8>> {
    struct Reader<'a>(&'a [u8]);
    impl Reader<'_> {
        fn take(&mut self, n: usize) -> Result<&[u8]> {
            if n > self.0.len() {
                return Err(DeviceKeyError::InvalidKey);
            }
            let (bytes, rest) = self.0.split_at(n);
            self.0 = rest;
            Ok(bytes)
        }
        fn word(&mut self) -> Result<u16> {
            Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
        }
        fn sized(&mut self) -> Result<&[u8]> {
            let n = self.word()? as usize;
            self.take(n)
        }
    }
    let mut input = Reader(blob);
    if input.word()? as usize != input.0.len() || input.word()? != 0x23 || input.word()? != 0xb {
        return Err(DeviceKeyError::InvalidKey);
    }
    let attributes = u32::from_be_bytes(input.take(4)?.try_into().unwrap());
    // CONTRACT: §3.1: authenticate the exact unrestricted identity template created here.
    if attributes != 0x60472 {
        return Err(DeviceKeyError::InvalidKey);
    }
    if !input.sized()?.is_empty()
        || input.word()? != 0x10
        || input.word()? != 0x10
        || input.word()? != 3
        || input.word()? != 0x10
    {
        return Err(DeviceKeyError::InvalidKey);
    }
    let mut point = vec![4];
    for _ in 0..2 {
        let coordinate = input.sized()?;
        if coordinate.is_empty() || coordinate.len() > 32 {
            return Err(DeviceKeyError::InvalidKey);
        }
        point.extend(std::iter::repeat_n(0, 32 - coordinate.len()));
        point.extend_from_slice(coordinate);
    }
    if !input.0.is_empty() {
        return Err(DeviceKeyError::InvalidKey);
    }
    Ok(point)
}

fn der_signature(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 8 || bytes[0] != 0x30 || bytes[1] as usize + 2 != bytes.len() {
        return Err(DeviceKeyError::OperationFailed);
    }
    let mut input = &bytes[2..];
    let mut output = Vec::with_capacity(64);
    for _ in 0..2 {
        if input.len() < 3 || input[0] != 2 {
            return Err(DeviceKeyError::OperationFailed);
        }
        let n = input[1] as usize;
        if n == 0 || n > 33 || input.len() < n + 2 {
            return Err(DeviceKeyError::OperationFailed);
        }
        let mut value = &input[2..2 + n];
        if value[0] & 0x80 != 0 || (n > 1 && value[0] == 0 && value[1] & 0x80 == 0) {
            return Err(DeviceKeyError::OperationFailed);
        }
        if value[0] == 0 && n > 1 {
            value = &value[1..];
        }
        if value.len() > 32 || value.iter().all(|b| *b == 0) {
            return Err(DeviceKeyError::OperationFailed);
        }
        output.extend(std::iter::repeat_n(0, 32 - value.len()));
        output.extend_from_slice(value);
        input = &input[2 + n..];
    }
    if !input.is_empty() {
        return Err(DeviceKeyError::OperationFailed);
    }
    Ok(output)
}

fn ecdh_x(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if bytes.len() < 8
        || u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize != bytes.len() - 2
    {
        return Err(DeviceKeyError::OperationFailed);
    }
    let x_len = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
    if !(1..=32).contains(&x_len) || bytes.len() < x_len + 6 {
        return Err(DeviceKeyError::OperationFailed);
    }
    let y_len = u16::from_be_bytes(bytes[4 + x_len..6 + x_len].try_into().unwrap()) as usize;
    if !(1..=32).contains(&y_len) || bytes.len() != x_len + y_len + 6 {
        return Err(DeviceKeyError::OperationFailed);
    }
    let mut x = Zeroizing::new([0; 32]);
    x[32 - x_len..].copy_from_slice(&bytes[4..4 + x_len]);
    Ok(x)
}

impl<T: TpmCommands> DeviceKeyProvider for TpmDeviceKey<T> {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>> {
        if alg != SignatureAlgorithm::ES256 {
            return Err(DeviceKeyError::UnsupportedAlgorithm);
        }
        if payload.len() > 128 * 1024 {
            return Err(DeviceKeyError::OperationFailed);
        }
        let temp = self.loaded()?;
        write_private(&temp.path().join("digest.bin"), &Sha256::digest(payload))?;
        let signature = self.backend.run(
            "sign",
            &[
                "-c",
                "identity.ctx",
                "-g",
                "sha256",
                "-s",
                "ecdsa",
                "-d",
                "-f",
                "plain",
                "-o",
                "/dev/stdout",
                "digest.bin",
            ],
            temp.path(),
        )?;
        der_signature(&signature)
    }
    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        if peer_pub.len() != 65 || peer_pub[0] != 4 {
            return Err(DeviceKeyError::InvalidKey);
        }
        let temp = self.loaded()?;
        let mut peer = vec![0, 68, 0, 32];
        peer.extend_from_slice(&peer_pub[1..33]);
        peer.extend_from_slice(&[0, 32]);
        peer.extend_from_slice(&peer_pub[33..]);
        write_private(&temp.path().join("peer.point"), &peer)?;
        let secret = self.backend.run(
            "ecdhzgen",
            &[
                "-c",
                "identity.ctx",
                "-u",
                "peer.point",
                "-o",
                "/dev/stdout",
            ],
            temp.path(),
        )?;
        ecdh_x(&secret)
    }
    fn public_jwk(&self) -> Result<Value> {
        Ok(self.metadata["public_jwk"].clone())
    }
    fn presence_kind(&self) -> &str {
        "none"
    }
    fn key_kind(&self) -> &str {
        "tpm2"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_blob() -> Vec<u8> {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../kv-core/testdata/remote/test_keys.json");
        let vector: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let point = super::super::jwk_point(&vector["sender"]["public_jwk"]).unwrap();
        let mut body = vec![0, 0x23, 0, 0xb];
        body.extend_from_slice(&0x60472u32.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 0x10, 0, 0x10, 0, 3, 0, 0x10, 0, 32]);
        body.extend_from_slice(&point[1..33]);
        body.extend_from_slice(&[0, 32]);
        body.extend_from_slice(&point[33..]);
        let mut blob = (body.len() as u16).to_be_bytes().to_vec();
        blob.extend(body);
        blob
    }

    struct Fake {
        fail: Option<&'static str>,
        public: Vec<u8>,
        private: Vec<u8>,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                fail: None,
                public: public_blob(),
                private: vec![1],
            }
        }
    }
    impl TpmCommands for Fake {
        fn run(&self, name: &str, args: &[&str], directory: &Path) -> Result<Zeroizing<Vec<u8>>> {
            assert_eq!(std::fs::metadata(directory).unwrap().mode() & 0o777, 0o700);
            if self.fail == Some(name) {
                return Err(DeviceKeyError::OperationFailed);
            }
            match name {
                "createprimary" => {}
                "create" => {
                    assert!(args.windows(2).any(|v| v == ["-G", "ecc256:null"]));
                    assert!(args.windows(2).any(|v| v == ["-a","fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|decrypt|noda"]));
                    std::fs::write(directory.join("identity.pub"), &self.public).unwrap();
                    std::fs::write(directory.join("identity.priv"), &self.private).unwrap();
                }
                "load" => {
                    for (name, expected) in [
                        ("identity.pub", &self.public),
                        ("identity.priv", &self.private),
                    ] {
                        let path = directory.join(name);
                        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
                        assert!(std::fs::read(path).unwrap() == *expected);
                    }
                }
                "sign" => {
                    assert!(args.contains(&"-d") && args.contains(&"ecdsa"));
                    assert!(
                        std::fs::read(directory.join("digest.bin")).unwrap()
                            == [
                                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
                            ]
                    );
                    return Ok(Zeroizing::new(vec![0x30, 6, 2, 1, 1, 2, 1, 2]));
                }
                "ecdhzgen" => {
                    let peer = std::fs::read(directory.join("peer.point")).unwrap();
                    assert_eq!(peer.len(), 70);
                    assert_eq!(&peer[..4], &[0, 68, 0, 32]);
                    return Ok(Zeroizing::new(vec![0, 6, 0, 1, 1, 0, 1, 2]));
                }
                _ => panic!("unexpected TPM command"),
            }
            Ok(Zeroizing::new(Vec::new()))
        }
    }

    fn directory() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn trusted_tool_policy_and_bounded_process_failures_use_injected_commands() {
        let dir = directory();
        let version = dir.path().join("version");
        let device = dir.path().join("device");
        assert!(!tpm_present(&version, &device));
        std::fs::write(&version, "1\n").unwrap();
        std::fs::write(&device, b"").unwrap();
        assert!(!tpm_present(&version, &device));
        std::fs::write(&version, "2\n").unwrap();
        assert!(tpm_present(&version, &device));
        std::fs::remove_file(&device).unwrap();
        assert!(!tpm_present(&version, &device));
        assert_eq!(
            TrustedTpm.run("unknown", &[], dir.path()),
            Err(DeviceKeyError::OperationFailed)
        );
        assert_eq!(
            run_tool("sign", &[], dir.path(), false, |_| Err::<
                std::process::Command,
                _,
            >(
                "not called"
            )),
            Err(DeviceKeyError::Unavailable)
        );
        assert_eq!(
            run_tool("sign", &[], dir.path(), true, |_| Err::<
                std::process::Command,
                _,
            >("untrusted")),
            Err(DeviceKeyError::Unavailable)
        );
        for (script, succeeds) in [
            ("printf abcd", true),
            ("exit 1", false),
            (
                "i=0; while [ $i -lt 4097 ]; do printf x; i=$((i + 1)); done",
                false,
            ),
        ] {
            let result = run_tool("sign", &["digest.bin"], dir.path(), true, |path| {
                assert_eq!(path, "/usr/bin/tpm2_sign");
                let mut command = std::process::Command::new("/bin/sh");
                command
                    .args(["-c", script])
                    .env_clear()
                    .stdin(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                Ok::<_, &str>(command)
            });
            if succeeds {
                assert_eq!(result.unwrap().as_slice(), b"abcd");
            } else {
                assert_eq!(result, Err(DeviceKeyError::OperationFailed));
            }
        }
    }

    #[test]
    fn injected_tpm_creates_loads_signs_and_derives_without_persistent_plaintext() {
        let dir = directory();
        let key = TpmDeviceKey::create(dir.path().into(), Fake::default()).unwrap();
        let reopened = TpmDeviceKey::from_authenticated_metadata(
            dir.path().into(),
            Fake::default(),
            key.metadata().clone(),
        )
        .unwrap();
        assert_eq!(key.public_jwk().unwrap(), reopened.public_jwk().unwrap());
        assert_eq!(key.key_kind(), "tpm2");
        assert_eq!(key.presence_kind(), "none");
        let signature = reopened.sign(SignatureAlgorithm::ES256, b"abc").unwrap();
        assert_eq!(signature[31], 1);
        assert_eq!(signature[63], 2);
        let peer = super::super::jwk_point(&key.public_jwk().unwrap()).unwrap();
        let raw = reopened.ecdh(&peer).unwrap();
        assert_eq!(raw[31], 1);
        assert!(raw[..31].iter().all(|b| *b == 0));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        assert_eq!(
            key.sign(SignatureAlgorithm::RS256, b"abc"),
            Err(DeviceKeyError::UnsupportedAlgorithm)
        );
        assert_eq!(
            key.sign(SignatureAlgorithm::ES256, &vec![0; 128 * 1024 + 1]),
            Err(DeviceKeyError::OperationFailed)
        );
        for invalid in [vec![], vec![3; 65], vec![4; 64]] {
            assert_eq!(key.ecdh(&invalid), Err(DeviceKeyError::InvalidKey));
        }
        for command in ["createprimary", "load", "sign", "ecdhzgen"] {
            let key = TpmDeviceKey::from_authenticated_metadata(
                dir.path().into(),
                Fake {
                    fail: Some(command),
                    ..Fake::default()
                },
                key.metadata().clone(),
            )
            .unwrap();
            assert!(key.sign(SignatureAlgorithm::ES256, b"abc").is_err() || command == "ecdhzgen");
            assert!(key.ecdh(&peer).is_err() || command == "sign");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn creation_and_metadata_fail_closed_on_invalid_objects_and_backend_errors() {
        let dir = directory();
        for command in ["createprimary", "create"] {
            assert!(TpmDeviceKey::create(
                dir.path().into(),
                Fake {
                    fail: Some(command),
                    ..Fake::default()
                }
            )
            .is_err());
        }
        for private in [vec![], vec![0; 2049]] {
            assert!(TpmDeviceKey::create(
                dir.path().into(),
                Fake {
                    private,
                    ..Fake::default()
                }
            )
            .is_err());
        }
        assert!(TpmDeviceKey::create(
            dir.path().into(),
            Fake {
                public: vec![],
                ..Fake::default()
            }
        )
        .is_err());
        let key = TpmDeviceKey::create(dir.path().into(), Fake::default()).unwrap();
        for (field, value) in [
            ("version", json!(2)),
            ("role", json!("strong")),
            ("key_kind", json!("software")),
            ("public_blob", Value::Null),
            ("public_blob", json!("!")),
            ("public_blob", json!(encode_b64(&[0; 2049]))),
            ("private_blob", Value::Null),
            ("private_blob", json!("!")),
            ("private_blob", json!("")),
            ("private_blob", json!(encode_b64(&[0; 2049]))),
            ("public_jwk", json!({})),
        ] {
            let mut invalid = key.metadata().clone();
            invalid[field] = value;
            assert!(TpmDeviceKey::from_authenticated_metadata(
                dir.path().into(),
                Fake::default(),
                invalid
            )
            .is_err());
        }
        assert!(workspace(&dir.path().join("missing")).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(workspace(&link).is_err());
        let file = dir.path().join("file");
        std::fs::write(&file, []).unwrap();
        assert!(workspace(&file).is_err());
        write_private(&dir.path().join("once"), &[1]).unwrap();
        assert!(write_private(&dir.path().join("once"), &[2]).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(workspace(dir.path()).is_err());
        assert!(TrustedTpm.run("not-allowed", &[], dir.path()).is_err());
    }

    #[test]
    fn public_object_parser_enforces_unrestricted_dual_use_p256_and_consumes_all_bytes() {
        let blob = public_blob();
        assert_eq!(public_point(&blob).unwrap().len(), 65);
        for length in 0..blob.len() {
            assert!(public_point(&blob[..length]).is_err());
        }
        for offset in [0, 2, 4, 6, 10, 12, 14, 16, 18, 20, 54] {
            let mut invalid = blob.clone();
            invalid[offset] ^= 0x80;
            assert!(public_point(&invalid).is_err());
        }
        let mut restricted = blob.clone();
        restricted[7] |= 1;
        assert!(public_point(&restricted).is_err());
        let mut trailing = blob.clone();
        trailing.push(0);
        let length = trailing.len() - 2;
        trailing[..2].copy_from_slice(&(length as u16).to_be_bytes());
        assert!(public_point(&trailing).is_err());
        let mut empty = blob.clone();
        empty.splice(20..54, [0, 0]);
        let length = empty.len() - 2;
        empty[..2].copy_from_slice(&(length as u16).to_be_bytes());
        assert!(public_point(&empty).is_err());
    }

    #[test]
    fn tpm_shared_points_are_padded_and_strictly_bounded() {
        let secret = ecdh_x(&[0, 6, 0, 1, 1, 0, 1, 2]).unwrap();
        assert!(secret[..31].iter().all(|b| *b == 0) && secret[31] == 1);
        for invalid in [
            vec![],
            vec![0, 6, 0, 0, 1, 0, 1, 2],
            vec![0, 7, 0, 1, 1, 0, 1, 2],
            vec![0, 6, 0, 1, 1, 0, 0, 2],
        ] {
            assert!(ecdh_x(&invalid).is_err());
        }
    }
    #[test]
    fn canonical_ecdsa_der_is_converted_to_p1363() {
        let result = der_signature(&[0x30, 6, 2, 1, 1, 2, 1, 2]).unwrap();
        assert_eq!(result.len(), 64);
        assert_eq!(result[31], 1);
        assert_eq!(result[63], 2);
        for bad in [
            vec![],
            vec![0x30, 6, 2, 1, 0, 2, 1, 2],
            vec![0x30, 7, 2, 2, 0, 1, 2, 1, 2],
            vec![0x30, 6, 2, 1, 0x80, 2, 1, 2],
            vec![0x30, 6, 3, 1, 1, 2, 1, 2],
            vec![0x30, 6, 2, 0, 1, 2, 1, 2],
            vec![0x30, 6, 2, 34, 1, 2, 1, 2],
            vec![0x30, 6, 2, 3, 1, 2, 1, 2],
            vec![0x30, 7, 2, 1, 1, 2, 1, 2, 0],
        ] {
            assert!(der_signature(&bad).is_err());
        }
        let mut padded = vec![0x30, 39, 2, 33, 0];
        padded.extend_from_slice(&[0x80; 32]);
        padded.extend_from_slice(&[2, 2, 0, 0x80]);
        let raw = der_signature(&padded).unwrap();
        assert_eq!(&raw[..32], &[0x80; 32]);
        assert_eq!(raw[63], 0x80);
        let mut oversized = vec![0x30, 38, 2, 33];
        oversized.extend_from_slice(&[1; 33]);
        oversized.extend_from_slice(&[2, 1, 2]);
        assert!(der_signature(&oversized).is_err());
    }
    /// Run as the KeyValet service uid on a TPM 2.0 Linux machine with trusted tpm2-tools:
    /// CARGO_TARGET_DIR=target-w1 cargo test -p kv-platform remote_tpm_roundtrip -- --ignored
    #[test]
    #[ignore = "Requires TPM 2.0, /dev/tpmrm0 access and trusted tpm2-tools"]
    fn remote_tpm_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let left = TpmDeviceKey::create(dir.path().into(), TrustedTpm).unwrap();
        let right = TpmDeviceKey::create(dir.path().into(), TrustedTpm).unwrap();
        let a = left
            .ecdh(&super::super::jwk_point(&right.public_jwk().unwrap()).unwrap())
            .unwrap();
        let b = right
            .ecdh(&super::super::jwk_point(&left.public_jwk().unwrap()).unwrap())
            .unwrap();
        assert!(*a == *b);
        assert_eq!(
            left.sign(SignatureAlgorithm::ES256, b"remote test")
                .unwrap()
                .len(),
            64
        );
    }
}
