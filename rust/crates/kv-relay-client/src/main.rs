//! An unprivileged transport for helper-owned remote approval envelopes.

mod app;
mod backoff;
mod client;
mod config;
mod control;
#[cfg(test)]
pub(crate) use kv_relay_client::control_transport;
mod envelope;
mod error;
mod helper;
mod platform;
mod process;
mod queue;
#[cfg(test)]
mod tests;
mod transport;
#[cfg(windows)]
mod windows;

fn main() {
    if let Err(error) = process::entry() {
        eprintln!("kv-relay-client: {error}");
        std::process::exit(1);
    }
}
