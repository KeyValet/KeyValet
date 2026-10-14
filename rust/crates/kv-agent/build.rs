mod metadata {
    include!("../../windows-build.rs");
    pub fn emit() {
        main();
    }
}

fn main() {
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("--stage-winui") {
        windows_reactor_setup::as_self_contained();
        return;
    }
    metadata::emit();
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // The SDK extraction cache must be architecture-specific. Use an isolated
        // setup subprocess so the normal compiler/SDK environment remains intact.
        let cache = std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("KeyValet")
            .join("winui-build")
            .join(std::env::var("CARGO_CFG_TARGET_ARCH").unwrap());
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--stage-winui")
            .env("LOCALAPPDATA", cache)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "WinUI runtime staging failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        print!("{}", String::from_utf8(result.stdout).unwrap());
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        let profile = std::env::var_os("PROFILE").unwrap();
        let bin = out
            .ancestors()
            .find(|p| p.file_name() == Some(profile.as_os_str()))
            .unwrap();
        for name in [
            "Microsoft.UI.Xaml.dll",
            "Microsoft.UI.Xaml.Controls.dll",
            "Microsoft.WindowsAppRuntime.dll",
            "resources.pri",
        ] {
            assert!(
                bin.join(name).is_file(),
                "WinUI runtime is incomplete: {name}"
            );
        }
    }
}
