// Compile the Linux signal logic on macOS CI; only injected sources run in these tests.
#[cfg(target_os = "macos")]
mod linux {
    pub fn trusted_command(_: &str) -> std::io::Result<std::process::Command> {
        Err(std::io::Error::other("Linux command runner unavailable"))
    }
}

#[cfg(target_os = "macos")]
mod remote_process {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/remote_process.rs"
    ));
}

#[cfg(target_os = "macos")]
mod presence {
    pub use kv_platform::presence::*;

    pub mod linux {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/presence/linux.rs"
        ));
    }
}
