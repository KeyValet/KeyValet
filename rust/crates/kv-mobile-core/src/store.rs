//! WAL plus a cross-process lock; each logical record is independently AEAD authenticated.
use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand_core::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub struct Store {
    db: Mutex<Connection>,
    lock: File,
    key: Zeroizing<[u8; 32]>,
}

impl Store {
    pub fn open(directory: &Path, key: Zeroizing<[u8; 32]>) -> Result<Self> {
        std::fs::create_dir_all(directory)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            if std::fs::symlink_metadata(directory)?
                .file_type()
                .is_symlink()
            {
                return Err(Error("unsafe_storage"));
            }
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = options.open(directory.join("mobile.lock"))?;
        let db_path = directory.join("mobile.sqlite3");
        if db_path.exists()
            && std::fs::symlink_metadata(&db_path)?
                .file_type()
                .is_symlink()
        {
            return Err(Error("unsafe_storage"));
        }
        let _initialization_lock = FileLock::acquire(&lock)?;
        let db = Connection::open(&db_path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS records(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket TEXT NOT NULL, key TEXT NOT NULL, value BLOB NOT NULL, exp INTEGER NOT NULL,
                UNIQUE(bucket,key));",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600))?;
        }
        drop(_initialization_lock);
        Ok(Self {
            db: Mutex::new(db),
            lock,
            key,
        })
    }

    pub(crate) fn transaction<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let mut db = self.db.lock().map_err(|_| Error("storage_unavailable"))?;
        let _lock = FileLock::acquire(&self.lock)?;
        let tx = db.transaction()?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }

    fn aad(bucket: &str, key: &str) -> Vec<u8> {
        format!("keyvalet/mobile/record/v1\0{bucket}\0{key}").into_bytes()
    }

    pub(crate) fn put<T: Serialize>(
        &self,
        db: &Connection,
        bucket: &str,
        key: &str,
        value: &T,
        exp: i64,
    ) -> Result<()> {
        let plaintext = Zeroizing::new(serde_json::to_vec(value)?);
        if plaintext.len() > 128 * 1024 {
            return Err(Error("record_too_large"));
        }
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| Error("invalid_key"))?;
        let mut nonce = [0; 12];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &Self::aad(bucket, key),
                },
            )
            .map_err(|_| Error("storage_unavailable"))?;
        let mut bytes = nonce.to_vec();
        bytes.extend(encrypted);
        db.execute(
            "INSERT INTO records(bucket,key,value,exp) VALUES(?1,?2,?3,?4)
            ON CONFLICT(bucket,key) DO UPDATE SET value=excluded.value,exp=excluded.exp",
            params![bucket, key, bytes, exp],
        )?;
        // Retain the newest audit entries. Transport/state buckets must never be silently
        // truncated: dropping a pending object or a durable outbox row changes semantics.
        if bucket == "activity" {
            db.execute(
                "DELETE FROM records WHERE bucket='activity' AND sequence NOT IN
                (SELECT sequence FROM records WHERE bucket='activity' ORDER BY sequence DESC LIMIT 200)",
                [],
            )?;
        }
        Ok(())
    }

    fn decode<T: DeserializeOwned>(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<T> {
        if bytes.len() < 28 || bytes.len() > 128 * 1024 + 28 {
            return Err(Error("storage_integrity"));
        }
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| Error("invalid_key"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&bytes[..12]),
                    Payload {
                        msg: &bytes[12..],
                        aad: &Self::aad(bucket, key),
                    },
                )
                .map_err(|_| Error("storage_integrity"))?,
        );
        kv_core::remote::canonical::from_json(&plaintext).map_err(|_| Error("storage_integrity"))
    }

    pub(crate) fn get<T: DeserializeOwned>(
        &self,
        db: &Connection,
        bucket: &str,
        key: &str,
    ) -> Result<Option<T>> {
        let bytes: Option<Vec<u8>> = db
            .query_row(
                "SELECT value FROM records WHERE bucket=?1 AND key=?2",
                params![bucket, key],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| self.decode(bucket, key, &bytes))
            .transpose()
    }

    pub(crate) fn list<T: DeserializeOwned>(
        &self,
        db: &Connection,
        bucket: &str,
    ) -> Result<Vec<(String, T)>> {
        let mut statement =
            db.prepare("SELECT key,value FROM records WHERE bucket=?1 ORDER BY sequence")?;
        let rows = statement.query_map([bucket], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|row| {
            let (key, value) = row?;
            Ok((key.clone(), self.decode(bucket, &key, &value)?))
        })
        .collect()
    }

    pub(crate) fn delete(db: &Connection, bucket: &str, key: &str) -> Result<()> {
        db.execute(
            "DELETE FROM records WHERE bucket=?1 AND key=?2",
            params![bucket, key],
        )?;
        Ok(())
    }

    pub(crate) fn expire(db: &Connection, now: i64) -> Result<()> {
        // Peers and issued history have exp=0. Expired outbound objects must never be sent.
        db.execute("DELETE FROM records WHERE exp>0 AND exp<=?1", [now])?;
        Ok(())
    }
}

struct FileLock<'a>(&'a File);
impl<'a> FileLock<'a> {
    fn acquire(file: &'a File) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                // SAFETY: the file descriptor remains owned by Store for the guard lifetime.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(Error("storage_busy"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        #[cfg(not(unix))]
        {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match file.try_lock() {
                    Ok(()) => break,
                    Err(std::fs::TryLockError::WouldBlock) => {
                        if Instant::now() >= deadline {
                            return Err(Error("storage_busy"));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(std::fs::TryLockError::Error(_)) => {
                        return Err(Error("storage_unavailable"));
                    }
                }
            }
        }
        Ok(Self(file))
    }
}
impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: the descriptor is still alive and this guard acquired its lock.
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.0.unlock();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn independent_handles_wait_until_the_lock_guard_is_dropped() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let first = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary.path())
            .unwrap();
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary.path())
            .unwrap();
        let guard = FileLock::acquire(&first).unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let _guard = FileLock::acquire(&second).unwrap();
                sender.send(()).unwrap();
            });
            assert!(matches!(
                receiver.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            drop(guard);
            receiver.recv_timeout(Duration::from_secs(5)).unwrap();
            worker.join().unwrap();
        });
    }
}
