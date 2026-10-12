#[path = "main.rs"]
mod existing;
#[cfg(target_os = "macos")]
mod remote_agent;

#[cfg(target_os = "macos")]
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--remote-dialog") | Some("--remote-preview") => {
            if let Err(error) = remote_dialog() {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        Some("--agent") => {
            if let Err(error) = user_session() {
                eprintln!("{error}");
                std::process::exit(1);
            }
            std::process::exit(remote_agent::run());
        }
        _ => existing::run_existing(),
    }
}

#[cfg(target_os = "macos")]
fn user_session() -> kv_touchid::remote::Result<()> {
    if unsafe {
        libc::getuid() == 0 || libc::geteuid() == 0 || libc::getgid() == 0 || libc::getegid() == 0
    } {
        return Err(kv_touchid::remote::Error::UiUnavailable);
    }
    unsafe {
        libc::umask(0o077);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn remote_dialog() -> kv_touchid::remote::Result<()> {
    use kv_touchid::{
        remote::{
            stdio::{self, Mode},
            Error, Platform,
        },
        remote_dialog::NativeDialog,
    };
    user_session()?;
    let path = std::env::args().nth(2).map(std::path::PathBuf::from);
    let mode = if std::env::args().nth(1).as_deref() == Some("--remote-preview") {
        Mode::Preview(path.as_deref().ok_or(Error::InvalidRequest)?)
    } else {
        Mode::Dialog
    };
    stdio::run(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        mode,
        Platform::Macos,
        &mut NativeDialog::default(),
    )
}

#[cfg(not(target_os = "macos"))]
fn main() {
    existing::run_existing();
}
