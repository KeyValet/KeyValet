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
    if std::env::args().nth(1).as_deref() == Some("--serve") {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("agent runtime unavailable");
        runtime.block_on(remote_agent::run());
        return;
    }
    existing::run_existing();
}
