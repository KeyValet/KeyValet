# Build a Windows x64/arm64 release package. Authenticode signing is optional.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^v\d+\.\d+\.\d+$')][string]$Tag,
    [ValidateSet('x64', 'arm64')][string]$Architecture = 'x64',
    [string]$SigningCertificateThumbprint,
    [switch]$AllowUnsigned, # Compatibility option; unsigned releases are the default.
    [string]$BinaryDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path $PSScriptRoot -Parent
if ($env:OS -ne 'Windows_NT') { throw 'Build the Windows package on Windows with the MSVC toolchain.' }
$version = [regex]::Match((Get-Content "$repo/rust/crates/kv-cli/Cargo.toml" -Raw), '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
if ($Tag -ne "v$version") { throw "Tag must be v$version." }
if ($BinaryDirectory -and $SigningCertificateThumbprint) { throw 'Build signed packages from source; prebuilt binaries are supported for unsigned packages.' }
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
if (!$BinaryDirectory) {
    Push-Location "$repo/rust"
    try {
        & cargo build --release --locked --target $target -p kv-helper -p kv-agent -p kv-cli -p kv-mcp -p kv-hook -p kv-server -p kv-relay-client
        if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed.' }
    } finally { Pop-Location }
    $buildTarget = "$repo/rust/target"
    if ($env:CARGO_TARGET_DIR) {
        $buildTarget = if ([IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) { $env:CARGO_TARGET_DIR }
            else { Join-Path "$repo/rust" $env:CARGO_TARGET_DIR }
    }
    $BinaryDirectory = Join-Path $buildTarget "$target/release"
}
$BinaryDirectory = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$name = "keyvalet-$Tag-windows-$Architecture"
$stage = Join-Path "$repo/dist" $name
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item "$stage/bin", "$stage/templates", "$stage/scripts", "$stage/docs", "$stage/wsl" -ItemType Directory -Force | Out-Null
foreach ($binary in 'kv-helper', 'kv-agent', 'kv-cli', 'kv-mcp', 'kv-hook', 'kv-server', 'kv-relay-client') {
    Copy-Item -LiteralPath "$BinaryDirectory/$binary.exe" "$stage/bin/"
}
# WinUI is self-contained: copy only the pinned SDK files, not the rest of a Cargo
# target directory. Microsoft runtime DLLs keep their original Microsoft signatures.
foreach ($required in 'Microsoft.UI.Xaml.dll','Microsoft.UI.Xaml.Controls.dll','Microsoft.WindowsAppRuntime.dll','resources.pri') {
    if (!(Test-Path -LiteralPath "$BinaryDirectory/$required" -PathType Leaf)) {
        throw "Missing WinUI runtime: $required. Rebuild kv-agent before packaging."
    }
}
$runtimeFiles = @()
$runtimeList = Get-Content "$repo/rust/crates/kv-agent/winui-runtime.txt" | Where-Object { $_ -and !$_.StartsWith('#') }
foreach ($entry in $runtimeList) {
    $source = Join-Path $BinaryDirectory $entry
    if (!(Test-Path -LiteralPath $source)) { continue }
    $files = if (Test-Path -LiteralPath $source -PathType Container) {
        @(Get-ChildItem -LiteralPath $source -Recurse -File)
    } else { @(Get-Item -LiteralPath $source) }
    foreach ($file in $files) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'WinUI runtime cannot contain reparse points.' }
        $relative = $file.FullName.Substring($BinaryDirectory.Length + 1).Replace('\','/')
        $destination = Join-Path "$stage/bin" $relative
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination
        if ($file.Extension -ieq '.dll') {
            $signature = Get-AuthenticodeSignature -LiteralPath $destination
            $publisher = if ($signature.SignerCertificate) {
                $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
            } else { '' }
            if ($signature.Status -ne 'Valid' -or $publisher -notin @('Microsoft Corporation','Microsoft Windows')) {
                throw "Untrusted WinUI runtime DLL: $relative"
            }
        }
        $runtimeFiles += @{path=$relative;sha256=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
}
$runtimeManifest = @{schema=1;sdk_version='2.5.1';files=$runtimeFiles} | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText("$stage/bin/native-ui-runtime.json",$runtimeManifest,[Text.UTF8Encoding]::new($false))
if ($SigningCertificateThumbprint) {
    $certificate = Get-Item "Cert:/CurrentUser/My/$SigningCertificateThumbprint"
    if ($certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Simvito Limited') {
        throw 'The signing certificate must belong to Simvito Limited.'
    }
    $signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($signTool) { $signTool = $signTool.Source }
    else {
        $signTool = Get-ChildItem "${env:ProgramFiles(x86)}/Windows Kits/10/bin/*/x64/signtool.exe" |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    if (!$signTool) { throw 'Install the Windows SDK signing tools.' }
    foreach ($file in Get-ChildItem "$stage/bin/*.exe") {
        & $signTool sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $file.FullName
        if ($LASTEXITCODE -ne 0) { throw "Signing failed: $($file.Name)" }
        $signature = Get-AuthenticodeSignature $file.FullName
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Simvito Limited') {
            throw "Signature verification failed: $($file.Name)"
        }
    }
} else {
    Set-Content "$stage/WINDOWS-RELEASE.txt" 'This Windows release has no Authenticode signature. Install with scripts/install.ps1. Signing is not required for local or remote KeyValet features. Windows application control policies may still affect execution.'
}
Copy-Item "$repo/templates/catalog.json" "$stage/templates/"
Copy-Item "$repo/scripts/install.ps1", "$repo/scripts/uninstall.ps1" "$stage/scripts/"
New-Item "$stage/service/relay-client" -ItemType Directory -Force | Out-Null
Copy-Item "$repo/rust/crates/kv-relay-client/service/*" "$stage/service/relay-client/"
foreach ($file in 'bridge.sh', 'install.sh', 'uninstall.sh', 'configure.py', 'verify.py') {
    Copy-Item -LiteralPath "$repo/scripts/wsl/$file" "$stage/wsl/"
}
Copy-Item "$repo/LICENSE", "$repo/README.md", "$repo/SECURITY.md" $stage
Copy-Item "$repo/docs/windows.md", "$repo/docs/wsl.md" "$stage/docs/"
$archive = "$repo/dist/$name.zip"
if (Test-Path $archive) { Remove-Item $archive -Force }
Compress-Archive -Path $stage -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
# Separate per-architecture files avoid concurrent package jobs overwriting one another.
Set-Content "$repo/dist/SHA256SUMS-windows-$Architecture" "$hash  $name.zip" -Encoding ascii
Write-Host "Built $archive"
