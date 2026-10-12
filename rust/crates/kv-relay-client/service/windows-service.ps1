# W9 integration template. Run from an elevated PowerShell after installing signed binaries.
param([ValidateSet("Install", "Uninstall")][string]$Action = "Install")
$ErrorActionPreference = "Stop"
$relayBinary = Join-Path $env:ProgramFiles "KeyValet\bin\kv-relay-client.exe"
if ($Action -eq "Uninstall") {
    & $relayBinary service uninstall
    if ($LASTEXITCODE -ne 0) { throw "KeyValetRelay uninstall failed" }
    return
}

# Provision relay configuration separately. The service never receives the helper vault ACL.
$relayDirectory = Join-Path $env:ProgramData "KeyValet\Relay"
& $relayBinary service install
if ($LASTEXITCODE -ne 0) { throw "KeyValetRelay install failed" }
New-Item -ItemType Directory -Force -Path $relayDirectory | Out-Null
& icacls.exe $relayDirectory /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'NT SERVICE\KeyValetRelay:(OI)(CI)M'
if ($LASTEXITCODE -ne 0) { throw "KeyValetRelay queue ACL failed" }
$relayConfig = Join-Path $env:ProgramData "KeyValet\relay-client.toml"
# The authenticated control worker runs before pairing provisions the binding file.
& icacls.exe $relayConfig /inheritance:r /grant:r 'SYSTEM:F' 'BUILTIN\Administrators:F' 'NT SERVICE\KeyValetRelay:R'
if ($LASTEXITCODE -ne 0) { throw "KeyValetRelay configuration ACL failed" }
Start-Service KeyValetRelay
