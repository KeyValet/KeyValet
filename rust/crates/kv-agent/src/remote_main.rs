// The unchanged W1 entry uses crate-local modules; retain those names in the additive wrapper.
#![allow(clippy::duplicate_mod)]

#[allow(dead_code)]
#[path = "main.rs"]
mod existing;
#[cfg(any(windows, test))]
#[path = "hello_crypto.rs"]
mod hello_crypto;
#[cfg(any(windows, test))]
#[path = "hello_logic.rs"]
mod hello_logic;
#[cfg(windows)]
mod remote_agent;

fn main() {
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("--remote-window") {
        if let Err(error) = kv_agent::remote::windows::run_window() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("--serve") {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("agent runtime unavailable");
        // Keep the process MTA alive across blocking-worker replacement. SDK factory
        // caches outlive any one Hello request or Tokio pool worker.
        if let Err(error) =
            kv_agent::presence::windows::with_winrt(|| runtime.block_on(remote_agent::run()))
        {
            eprintln!("Windows Runtime initialization failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    existing::run_existing();
}
