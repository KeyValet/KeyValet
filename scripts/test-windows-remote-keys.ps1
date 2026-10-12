# K1 hardware acceptance on a disposable Windows 11 TPM VM. Explicitly opt in to SYSTEM keys.
[CmdletBinding()]
param(
    [switch]$AllowSystemChanges,
    [Parameter(Mandatory=$true)][string]$TargetDirectory,
    [Parameter(Mandatory=$true)][string]$ResultDirectory,
    [string]$InstalledCli,
    [switch]$Worker
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
if (!$AllowSystemChanges) { throw 'Use -AllowSystemChanges on the authorized disposable TPM VM.' }
$TargetDirectory = (Resolve-Path -LiteralPath $TargetDirectory).Path
New-Item -ItemType Directory -Path $ResultDirectory -Force | Out-Null
$ResultDirectory = (Resolve-Path -LiteralPath $ResultDirectory).Path
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($Worker) {
    if ($sid -ne 'S-1-5-18') { throw 'The worker must run as LocalSystem.' }
    $env:R2B_NATIVE_REPORT = Join-Path $ResultDirectory 'native-keys.json'
    if ($InstalledCli) { $env:R2B_INSTALLED_CLI = $InstalledCli }
    try {
        $specs = @(
            @{ prefix='kv_platform'; test='device_key::windows::tests::pcp_identity_dual_key_roundtrip' },
            @{ prefix='kv_agent'; test='remote::windows::pcp_acceptance::windows_pcp_k1_native_acceptance' }
        )
        $results = @()
        foreach ($spec in $specs) {
            $binary = $null
            foreach ($candidate in Get-ChildItem -LiteralPath (Join-Path $TargetDirectory 'debug/deps') -Filter ($spec.prefix + '-*.exe')) {
                $listing = & $candidate.FullName --list 2>$null
                if ($LASTEXITCODE -eq 0 -and ($listing -contains ($spec.test + ': test'))) {
                    $binary = $candidate.FullName; break
                }
            }
            if (!$binary) { throw ('Build the native test executable for ' + $spec.prefix + ' first.') }
            $start = [DateTime]::UtcNow
            & $binary $spec.test --ignored --exact --nocapture *> (Join-Path $ResultDirectory ($spec.prefix + '.log'))
            $exitCode = $LASTEXITCODE
            $results += @{test=$spec.test; binary=$binary; exit_code=$exitCode; passed=($exitCode -eq 0); seconds=([DateTime]::UtcNow-$start).TotalSeconds}
            if ($exitCode -ne 0) { throw ('Native PCP test failed: ' + $spec.test) }
        }
        @{sid=$sid; passed=$true; tests=$results} | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath (Join-Path $ResultDirectory 'system-result.json') -Encoding UTF8
    } catch {
        @{sid=$sid; passed=$false; error=$_.Exception.Message} | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $ResultDirectory 'system-result.json') -Encoding UTF8
        exit 1
    } finally {
        Remove-Item Env:R2B_NATIVE_REPORT -ErrorAction SilentlyContinue
        Remove-Item Env:R2B_INSTALLED_CLI -ErrorAction SilentlyContinue
    }
    exit 0
}
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The task launcher requires an elevated administrator token.'
}
$taskName = 'KeyValetR2BKeys-' + [guid]::NewGuid().ToString('N')
$arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath +
    '" -AllowSystemChanges -Worker -TargetDirectory "' + $TargetDirectory + '" -ResultDirectory "' + $ResultDirectory + '"'
if ($InstalledCli) { $arguments += ' -InstalledCli "' + $InstalledCli + '"' }
$action = New-ScheduledTaskAction -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' -Argument $arguments
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(3)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$registered = $false
$resultPath = Join-Path $ResultDirectory 'system-result.json'
if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath }
try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered = $true
    Start-ScheduledTask -TaskName $taskName
    $deadline = [DateTime]::UtcNow.AddMinutes(3)
    while (!(Test-Path -LiteralPath $resultPath)) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'SYSTEM PCP acceptance timed out.' }
        Start-Sleep -Seconds 1
    }
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if (!$result.passed) { throw ('SYSTEM PCP acceptance failed: ' + $result.error) }
    Get-Content -LiteralPath $resultPath -Raw
} finally {
    if ($registered) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}
