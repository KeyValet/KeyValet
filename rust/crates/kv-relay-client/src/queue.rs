//! An exclusive FIFO spool. Each committed file contains only an array of encrypted envelopes.
//! Writes and partial-batch completion use file sync + atomic rename + directory sync on Unix.

use std::{
    collections::{HashSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use tokio::sync::Notify;

use crate::{
    envelope::Envelope,
    error::{Error, Result},
};

#[cfg(unix)]
mod native;

pub struct Batch {
    pub sequence: u64,
    pub envelopes: Vec<Envelope>,
}

#[cfg(test)]
#[path = "tests/queue.rs"]
mod coverage_tests;

struct DiskQueue {
    directory: PathBuf,
    sequences: VecDeque<u64>,
    next: u64,
    _lock: File,
}

#[derive(Clone)]
pub struct Queue {
    disk: Arc<Mutex<DiskQueue>>,
    pub changed: Arc<Notify>,
}

impl Queue {
    pub fn open(directory: &Path) -> Result<Self> {
        fs::create_dir_all(directory)?;
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::QueueCorrupt);
        }
        #[cfg(unix)]
        native::secure_directory(directory, &metadata)?;
        let mut options = secure_options();
        options.read(true).write(true).create(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let lock = options
            .open(directory.join("queue.lock"))
            .map_err(lock_error)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(Error::QueueBusy);
            }
        }
        let mut sequences = Vec::new();
        // Recover a completely written append interrupted before rename. A corrupt committed
        // file is never discarded. An interrupted rewrite can safely replay the committed prefix.
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "tmp") {
                let sequence = sequence_of(&path)?;
                let committed = file_path(directory, sequence, "json");
                if committed.exists() {
                    fs::remove_file(&path)?;
                } else {
                    read_batch(&path)?;
                    fs::rename(&path, committed)?;
                }
            }
        }
        sync_directory(directory)?;
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.file_name().is_some_and(|name| name == "queue.lock") {
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "json") {
                return Err(Error::QueueCorrupt);
            }
            let sequence = sequence_of(&path)?;
            read_batch(&path)?;
            sequences.push(sequence);
        }
        sequences.sort_unstable();
        let next = sequences
            .last()
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::QueueCorrupt)?;
        Ok(Self {
            disk: Arc::new(Mutex::new(DiskQueue {
                directory: directory.into(),
                sequences: sequences.into(),
                next,
                _lock: lock,
            })),
            changed: Arc::new(Notify::new()),
        })
    }

    async fn access<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut DiskQueue) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let disk = self.disk.clone();
        tokio::task::spawn_blocking(move || {
            let mut disk = disk.lock().map_err(|_| Error::QueueCorrupt)?;
            operation(&mut disk)
        })
        .await
        .map_err(|_| Error::QueueCorrupt)?
    }

    pub async fn append(&self, mut envelopes: Vec<Envelope>) -> Result<()> {
        if envelopes.is_empty() {
            return Ok(());
        }
        // Apply the input bound before deduplication; repeated ciphertext cannot make an
        // oversized helper batch admissible or allocate an unbounded deduplication set.
        let bytes = envelopes
            .iter()
            .fold(envelopes.len().saturating_add(1), |bytes, envelope| {
                bytes.saturating_add(envelope.0.get().len())
            });
        if bytes > kv_ipc::MAX_LINE_BYTES {
            return Err(Error::HelperProtocol);
        }
        self.access(move |disk| {
            // A crash after file commit but before the helper's spool receipt replays a batch.
            // Deduplicate complete ciphertext bytes; never infer equality from an ID alone.
            let mut known = HashSet::new();
            for sequence in &disk.sequences {
                for envelope in read_batch(&file_path(&disk.directory, *sequence, "json"))? {
                    known.insert(envelope.0.get().to_owned());
                }
            }
            envelopes.retain(|envelope| known.insert(envelope.0.get().to_owned()));
            if envelopes.is_empty() {
                return Ok(());
            }
            let next = disk.next.checked_add(1).ok_or(Error::QueueCorrupt)?;
            write_batch(&disk.directory, disk.next, &envelopes)?;
            disk.sequences.push_back(disk.next);
            disk.next = next;
            Ok(())
        })
        .await?;
        self.changed.notify_one();
        Ok(())
    }

    pub async fn front(&self) -> Result<Option<Batch>> {
        self.access(|disk| {
            disk.sequences
                .front()
                .copied()
                .map(|sequence| {
                    Ok(Batch {
                        sequence,
                        envelopes: read_batch(&file_path(&disk.directory, sequence, "json"))?,
                    })
                })
                .transpose()
        })
        .await
    }

    pub async fn complete_prefix(&self, sequence: u64, count: usize) -> Result<()> {
        self.access(move |disk| {
            if disk.sequences.front().copied() != Some(sequence) || count == 0 {
                return Err(Error::QueueCorrupt);
            }
            let path = file_path(&disk.directory, sequence, "json");
            let mut envelopes = read_batch(&path)?;
            if count > envelopes.len() {
                return Err(Error::QueueCorrupt);
            }
            envelopes.drain(..count);
            if envelopes.is_empty() {
                fs::remove_file(path)?;
                sync_directory(&disk.directory)?;
                disk.sequences.pop_front();
            } else {
                write_batch(&disk.directory, sequence, &envelopes)?;
            }
            Ok(())
        })
        .await
    }
}

fn file_path(directory: &Path, sequence: u64, extension: &str) -> PathBuf {
    directory.join(format!("{sequence:020}.{extension}"))
}

fn lock_error(error: std::io::Error) -> Error {
    #[cfg(windows)]
    let busy = matches!(error.raw_os_error(), Some(32 | 33));
    #[cfg(not(windows))]
    let busy = error.kind() == std::io::ErrorKind::PermissionDenied;
    if busy {
        Error::QueueBusy
    } else {
        Error::Queue(error)
    }
}

fn sequence_of(path: &Path) -> Result<u64> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or(Error::QueueCorrupt)?;
    if stem.len() != 20 || !stem.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::QueueCorrupt);
    }
    stem.parse().map_err(|_| Error::QueueCorrupt)
}

fn secure_options() -> OpenOptions {
    #[allow(unused_mut)]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x8000_0000); // FILE_FLAG_WRITE_THROUGH
    }
    options
}

fn read_batch(path: &Path) -> Result<Vec<Envelope>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(Error::QueueCorrupt);
    }
    let mut bytes = Vec::new();
    secure_options()
        .read(true)
        .open(path)?
        .take(kv_ipc::MAX_LINE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > kv_ipc::MAX_LINE_BYTES {
        return Err(Error::QueueCorrupt);
    }
    let envelopes: Vec<Envelope> =
        serde_json::from_slice(&bytes).map_err(|_| Error::QueueCorrupt)?;
    if envelopes.is_empty() {
        return Err(Error::QueueCorrupt);
    }
    for envelope in &envelopes {
        envelope
            .validate_for_queue()
            .map_err(|_| Error::QueueCorrupt)?;
    }
    Ok(envelopes)
}

fn write_batch(directory: &Path, sequence: u64, envelopes: &[Envelope]) -> Result<()> {
    for envelope in envelopes {
        envelope.validate_for_queue()?;
    }
    let bytes = serde_json::to_vec(envelopes).map_err(|_| Error::HelperProtocol)?;
    if bytes.len() > kv_ipc::MAX_LINE_BYTES {
        return Err(Error::HelperProtocol);
    }
    let temporary = file_path(directory, sequence, "tmp");
    let mut file = secure_options()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, file_path(directory, sequence, "json"))?;
    sync_directory(directory)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<()> {
    // Windows does not expose directory fsync through std. Files use WRITE_THROUGH and sync_all;
    // atomic rename and crash durability must also be exercised on the supported NTFS deployment.
    Ok(())
}
