[CmdletBinding()]
param([switch]$RemoveVault)
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$admin) { throw 'Run uninstall.ps1 in an elevated PowerShell terminal.' }
$install = 'C:\Program Files\KeyValet'
$relay = Get-Service KeyValetRelay -ErrorAction SilentlyContinue
if ($relay) {
    $configuration = Get-CimInstance Win32_Service -Filter "Name='KeyValetRelay'"
    if ($configuration.PathName.Trim() -ine ('"' + "$install\bin\kv-relay-client.exe" + '" --service') -or
        $configuration.StartName -ine 'NT SERVICE\KeyValetRelay') { throw 'Unexpected relay service configuration.' }
    $relayProcess = $null
    if ($configuration.ProcessId -gt 0) {
        $relayProcess = [Diagnostics.Process]::GetProcessById($configuration.ProcessId)
        [void]$relayProcess.Handle
    }
    if ($relay.Status -ne 'Stopped') {
        Stop-Service KeyValetRelay -Force
        $relay.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
    if ($relayProcess) {
        try { if (!$relayProcess.WaitForExit(20000)) { throw 'The stopped relay process has not exited; installation files were not removed.' } }
        finally { $relayProcess.Dispose() }
    }
    $relay.Dispose()
    & 'C:\Windows\System32\sc.exe' delete KeyValetRelay | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Relay service removal failed.' }
}
$service = Get-Service KeyValetHelper -ErrorAction SilentlyContinue
if ($service) {
    $configuration = Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'"
    $process = $null
    if ($configuration.ProcessId -gt 0) {
        $process = [Diagnostics.Process]::GetProcessById($configuration.ProcessId)
        [void]$process.Handle
    }
    Stop-Service KeyValetHelper -Force
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    if ($process) {
        try { if (!$process.WaitForExit(20000)) { throw 'The stopped helper process has not exited; installation files were not removed.' } }
        finally { $process.Dispose() }
    }
    # Release the controller handle before deleting so an immediate reinstall can succeed.
    $service.Dispose()
    & 'C:\Windows\System32\sc.exe' delete KeyValetHelper | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service removal failed.' }
}
Unregister-ScheduledTask -TaskName KeyValetAgent -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='kv-agent.exe' OR Name='kv-mcp.exe'" | Where-Object { $_.ExecutablePath -in @("$install\bin\kv-agent.exe", "$install\bin\kv-mcp.exe") } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
if (Test-Path $install) { Remove-Item $install -Recurse -Force }
if ($RemoveVault -and (Test-Path 'C:\ProgramData\KeyValet')) {
    Remove-Item 'C:\ProgramData\KeyValet' -Recurse -Force
}
Write-Host 'KeyValet removed. The vault is retained unless -RemoveVault was explicitly supplied.'
Write-Host 'Remove the keyvalet MCP/hook entries from your AI clients and the install bin directory from your user PATH.'
