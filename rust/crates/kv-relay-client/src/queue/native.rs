//! Native ownership validation. Filesystem framing and durable FIFO logic live in queue.rs.

#[cfg(unix)]
pub(super) fn secure_directory(
    directory: &std::path::Path,
    metadata: &std::fs::Metadata,
) -> crate::error::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(crate::error::Error::QueueCorrupt);
    }
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
