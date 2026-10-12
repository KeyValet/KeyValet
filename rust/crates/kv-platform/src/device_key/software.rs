//! Explicit software storage; the caller supplies W0's cryptographic implementation.
use super::{DeviceKeyError, DeviceKeyProvider, Result, SignatureAlgorithm};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

pub struct SoftwareFileKey<P> {
    key: P,
}

impl<P: DeviceKeyProvider> SoftwareFileKey<P> {
    // CONTRACT: §3.1 / §13.1: software selection is explicit; storage never chooses a fallback.
    pub fn create(path: &Path, factory: impl Fn(&[u8; 32]) -> Result<P>) -> Result<Self> {
        private_parent(path)?;
        let mut bytes = Zeroizing::new([0u8; 32]);
        let mut random = File::open("/dev/urandom").map_err(|_| DeviceKeyError::Unavailable)?;
        let mut key = None;
        for _ in 0..128 {
            random
                .read_exact(bytes.as_mut())
                .map_err(|_| DeviceKeyError::OperationFailed)?;
            match factory(&bytes) {
                Ok(candidate) => {
                    key = Some(candidate);
                    break;
                }
                Err(DeviceKeyError::InvalidKey) => continue,
                Err(error) => return Err(error),
            }
        }
        let key = key.ok_or(DeviceKeyError::InvalidKey)?;
        store(path, bytes.as_ref(), |file, bytes| {
            persist(file, bytes, |file| file.sync_all())
        })?;
        Ok(Self { key })
    }

    pub fn open(path: &Path, factory: impl Fn(&[u8; 32]) -> Result<P>) -> Result<Self> {
        private_parent(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| DeviceKeyError::Unavailable)?;
        let meta = file.metadata().map_err(|_| DeviceKeyError::InvalidKey)?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o777 != 0o600
            || meta.len() != 32
        {
            return Err(DeviceKeyError::InvalidKey);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        file.read_exact(bytes.as_mut())
            .map_err(|_| DeviceKeyError::InvalidKey)?;
        Ok(Self {
            key: factory(&bytes)?,
        })
    }
}

fn store(
    path: &Path,
    bytes: &[u8],
    save: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| DeviceKeyError::OperationFailed)?;
    let persisted = file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .and_then(|_| save(&mut file, bytes));
    if persisted.is_err() {
        let _ = std::fs::remove_file(path);
        return Err(DeviceKeyError::OperationFailed);
    }
    Ok(())
}

fn persist<W: Write>(
    writer: &mut W,
    bytes: &[u8],
    sync: impl FnOnce(&mut W) -> std::io::Result<()>,
) -> std::io::Result<()> {
    writer.write_all(bytes)?;
    sync(writer)
}

fn private_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(DeviceKeyError::InvalidKey)?;
    let meta = std::fs::symlink_metadata(parent).map_err(|_| DeviceKeyError::Unavailable)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err(DeviceKeyError::InvalidKey);
    }
    Ok(())
}

impl<P: DeviceKeyProvider> DeviceKeyProvider for SoftwareFileKey<P> {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>> {
        self.key.sign(alg, payload)
    }
    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        self.key.ecdh(peer_pub)
    }
    fn public_jwk(&self) -> Result<Value> {
        self.key.public_jwk()
    }
    fn presence_kind(&self) -> &str {
        "none"
    }
    fn key_kind(&self) -> &str {
        "software"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fake;
    impl DeviceKeyProvider for Fake {
        fn sign(&self, _: SignatureAlgorithm, _: &[u8]) -> Result<Vec<u8>> {
            Err(DeviceKeyError::OperationFailed)
        }
        fn ecdh(&self, _: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
            Err(DeviceKeyError::OperationFailed)
        }
        fn public_jwk(&self) -> Result<Value> {
            Ok(Value::Null)
        }
        fn presence_kind(&self) -> &str {
            "unlocked"
        }
        fn key_kind(&self) -> &str {
            "tpm2"
        }
    }

    #[test]
    fn private_file_reopen_and_fail_closed_permissions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("device.key");
        let factory = |_: &[u8; 32]| Ok(Fake);
        let key = SoftwareFileKey::create(&path, factory).unwrap();
        assert_eq!(key.key_kind(), "software");
        assert_eq!(key.presence_kind(), "none");
        assert!(SoftwareFileKey::create(&path, factory).is_err());
        assert!(SoftwareFileKey::open(&path, factory).is_ok());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SoftwareFileKey::open(&path, factory).is_err());
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(SoftwareFileKey::open(&link, factory).is_err());
        let invalid = dir.path().join("invalid.key");
        assert!(
            SoftwareFileKey::<Fake>::create(&invalid, |_| Err(DeviceKeyError::InvalidKey)).is_err()
        );
        assert!(!invalid.exists());
        assert!(
            SoftwareFileKey::<Fake>::create(&invalid, |_| Err(DeviceKeyError::Unavailable))
                .is_err()
        );
        assert!(!invalid.exists());
        assert_eq!(
            key.sign(SignatureAlgorithm::ES256, b"payload"),
            Err(DeviceKeyError::OperationFailed)
        );
        assert_eq!(key.ecdh(&[4; 65]), Err(DeviceKeyError::OperationFailed));
        assert_eq!(key.public_jwk().unwrap(), Value::Null);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SoftwareFileKey::create(&dir.path().join("other"), factory).is_err());
    }

    #[test]
    fn missing_invalid_and_symlinked_storage_never_creates_or_loads_a_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let factory = |_: &[u8; 32]| Ok(Fake);
        assert!(SoftwareFileKey::create(Path::new("/"), factory).is_err());
        assert!(SoftwareFileKey::create(&dir.path().join("absent/key"), factory).is_err());
        assert!(SoftwareFileKey::open(&dir.path().join("absent.key"), factory).is_err());
        let directory = dir.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(SoftwareFileKey::open(&directory, factory).is_err());
        assert!(SoftwareFileKey::create(&directory, factory).is_err());
        let link = dir.path().join("linked-dir");
        symlink(&directory, &link).unwrap();
        assert!(SoftwareFileKey::create(&link.join("key"), factory).is_err());
        let short = dir.path().join("short");
        std::fs::write(&short, [0; 31]).unwrap();
        std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(SoftwareFileKey::open(&short, factory).is_err());
        let path = dir.path().join("key");
        SoftwareFileKey::create(&path, factory).unwrap();
        assert!(SoftwareFileKey::<Fake>::open(&path, |_| Err(DeviceKeyError::InvalidKey)).is_err());
    }

    #[test]
    fn persistence_propagates_write_and_sync_failures() {
        struct Failure;
        impl Write for Failure {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("write failed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(persist(&mut Failure, &[1; 32], |_| panic!(
            "sync after failed write"
        ))
        .is_err());
        let mut output = Vec::new();
        assert!(
            persist(&mut output, &[1; 32], |_| Err(std::io::Error::other(
                "sync failed"
            )))
            .is_err()
        );
        assert_eq!(output.len(), 32);
        output.clear();
        persist(&mut output, &[2; 32], |_| Ok(())).unwrap();
        assert!(output == [2; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("failed.key");
        assert_eq!(
            store(&path, &[3; 32], |file, _| {
                assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
                Err(std::io::Error::other("persistence failed"))
            }),
            Err(DeviceKeyError::OperationFailed)
        );
        assert!(!path.exists());
    }
}
