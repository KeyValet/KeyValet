//! Root-only Linux broker. It inspects caller processes; it never opens a vault or a network
//! socket, signs, decrypts, authorizes an operation, or executes caller-supplied commands.
use kv_platform::{linux::LinuxHost, paths, peer_broker::Policy};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub fn run() -> Result<(), String> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return Err("peer broker requires root".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    kv_platform::trust::verify_root_environment(&exe, Path::new(paths::HELPER_BIN), &[])?;
    let path = Path::new(paths::PEER_BROKER_SOCKET);
    let parent = path.parent().ok_or("missing broker directory")?;
    if let Some(reason) = kv_platform::trust::untrusted_reason(parent) {
        return Err(reason);
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == 0 => {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        Ok(_) => return Err("untrusted broker socket path".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let listener = UnixListener::bind(path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| e.to_string())?;
    let clients = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        if clients.fetch_add(1, Ordering::SeqCst) >= 32 {
            clients.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let clients = clients.clone();
        std::thread::spawn(move || {
            let host = LinuxHost::system();
            if let (Ok((helper_uid, _)), Ok(owner_uid)) =
                (host.service_identity(), host.owner_uid())
            {
                let policy = Policy {
                    helper_uid,
                    owner_uid,
                    relay_uid: host.relay_identity().ok().map(|identity| identity.0),
                    install: Path::new(paths::INSTALL_DIR).join("bin"),
                };
                let _ = kv_platform::peer_broker::serve_one(stream, &policy);
            }
            clients.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}
