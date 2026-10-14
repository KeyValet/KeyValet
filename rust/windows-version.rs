// Shared by the seven native executables. No resource helper dependency is required.
fn emit_windows_version() {
    println!("cargo:rerun-if-changed=../../windows-version.rs");
    println!("cargo:rerun-if-env-changed=RC");
    if !std::env::var("TARGET")
        .unwrap_or_default()
        .ends_with("windows-msvc")
    {
        return;
    }
    let name = std::env::var("CARGO_PKG_NAME").expect("package name");
    let version = std::env::var("CARGO_PKG_VERSION").expect("package version");
    let components = version
        .split(['-', '+'])
        .next()
        .unwrap()
        .split('.')
        .map(|part| part.parse::<u16>().expect("Windows version component"))
        .collect::<Vec<_>>();
    assert_eq!(components.len(), 3, "expected a semantic package version");
    let numbers = format!("{},{},{},0", components[0], components[1], components[2]);
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("output directory"));
    let resource = output.join("keyvalet-version.rc");
    let compiled = output.join("keyvalet-version.res");
    std::fs::write(
        &resource,
        format!(
            r#"
1 VERSIONINFO
FILEVERSION {numbers}
PRODUCTVERSION {numbers}
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Simvito Limited\0"
      VALUE "ProductName", "KeyValet\0"
      VALUE "FileDescription", "KeyValet {name}\0"
      VALUE "FileVersion", "{version}\0"
      VALUE "ProductVersion", "{version}\0"
      VALUE "OriginalFilename", "{name}.exe\0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#
        ),
    )
    .expect("write Windows version resource");
    let compiler = if let Some(path) = std::env::var_os("RC") {
        std::path::PathBuf::from(path)
    } else {
        let root = std::path::PathBuf::from(
            std::env::var_os("ProgramFiles(x86)").expect("Windows SDK requires ProgramFiles(x86)"),
        )
        .join("Windows Kits/10/bin");
        let mut versions = std::fs::read_dir(root)
            .expect("Windows SDK resource compiler")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect::<Vec<_>>();
        versions.sort();
        let host = std::env::var("HOST").unwrap_or_default();
        let architecture = if host.starts_with("aarch64") {
            "arm64"
        } else {
            "x64"
        };
        versions
            .into_iter()
            .rev()
            .map(|path| path.join(architecture).join("rc.exe"))
            .find(|path| path.is_file())
            .expect("install the native Windows SDK rc.exe")
    };
    let status = std::process::Command::new(compiler)
        .arg("/nologo")
        .arg("/fo")
        .arg(&compiled)
        .arg(&resource)
        .status()
        .expect("run Windows resource compiler");
    assert!(
        status.success(),
        "Windows version resource compilation failed"
    );
    println!("cargo:rustc-link-arg-bins={}", compiled.display());
}
