# Opt-in Windows 11 TPM + owner desktop Hello acceptance. Uses temporary test keys only.
# The SYSTEM input/executables are protected; the owner can write only public result files.
[CmdletBinding()]
param(
    [switch]$AllowSystemChanges,
    [Parameter(Mandatory=$true)][string]$SystemTestBinary,
    [Parameter(Mandatory=$true)][string]$OwnerTestBinary,
    [Parameter(Mandatory=$true)][string]$ResultDirectory,
    [string]$OwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
    [string]$InstalledCli
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (!$AllowSystemChanges) { throw 'Explicit -AllowSystemChanges and an interactive owner are required.' }
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Launch from an elevated administrator; Hello runs in the limited owner task.' }
if ($OwnerSid -notmatch '^S-1-(5-21-\d+-\d+-\d+-\d+|12-1-\d+-\d+-\d+-\d+)$') { throw 'An interactive owner SID is required.' }
foreach ($path in $ResultDirectory,$InstalledCli) {
    if ($path -match "['`r`n]") { throw 'Use fixture paths without quotes or newline characters.' }
}
foreach ($binary in $SystemTestBinary,$OwnerTestBinary) {
    $item = Get-Item -LiteralPath $binary -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Expected a regular native test executable.' }
}
$run = [guid]::NewGuid().ToString('N')
$runtime = Join-Path $env:ProgramData ('KeyValet-Backups\r3b-hello-runtime-' + $run)
New-Item -ItemType Directory -Path $runtime | Out-Null
$owner = [Security.Principal.SecurityIdentifier]::new($OwnerSid)
function Protect-Path([string]$Path,[bool]$Directory) {
    $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in 'S-1-5-18','S-1-5-32-544') {
        if ($Directory) { $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow') }
        else { $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow') }
        $acl.AddAccessRule($rule)
    }
    if ($Directory) { $rule=[Security.AccessControl.FileSystemAccessRule]::new($owner,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow') }
    else { $rule=[Security.AccessControl.FileSystemAccessRule]::new($owner,'ReadAndExecute','Allow') }
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}
Protect-Path $runtime $true
$inputDirectory = Join-Path $runtime 'input'
New-Item -ItemType Directory -Path $inputDirectory | Out-Null
Protect-Path $inputDirectory $true
if (Test-Path -LiteralPath $ResultDirectory) { throw 'Use a fresh result directory; do not overwrite earlier evidence.' }
New-Item -ItemType Directory -Path $ResultDirectory | Out-Null
$outputDirectory = Join-Path $ResultDirectory 'owner-output'
New-Item -ItemType Directory -Path $outputDirectory | Out-Null
# No SYSTEM writes occur under the owner-writable output directory.
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in 'S-1-5-18','S-1-5-32-544') { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')) }
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($owner,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath $outputDirectory -AclObject $acl
Copy-Item -LiteralPath $SystemTestBinary -Destination (Join-Path $runtime 'system-tests.exe')
Copy-Item -LiteralPath $OwnerTestBinary -Destination (Join-Path $runtime 'owner-tests.exe')
foreach ($name in 'system-tests.exe','owner-tests.exe') { Protect-Path (Join-Path $runtime $name) $false }
$systemTask = 'KeyValetR3BHelloSystem-' + $run
$ownerTask = 'KeyValetR3BHelloOwner-' + $run
$ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$systemScript = @"
`$ErrorActionPreference='Continue'
`$env:R3B_STRONG_EXCHANGE='$inputDirectory'
`$env:R3B_STRONG_OUTPUT='$outputDirectory'
`$env:R2B_NATIVE_REPORT='$runtime\native-keys.json'
"@
if ($InstalledCli) { $systemScript += "`n`$env:R2B_INSTALLED_CLI='$InstalledCli'`n" }
$systemScript += @"
& '$runtime\system-tests.exe' remote::windows::pcp_acceptance::windows_pcp_k1_native_acceptance --ignored --exact --nocapture *> '$runtime\system.log'
`$code=`$LASTEXITCODE
@{exit_code=`$code;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value} | ConvertTo-Json | Set-Content '$runtime\system-result.json' -Encoding UTF8
exit `$code
"@
$ownerScript = @"
`$ErrorActionPreference='Continue'
`$env:R3B_STRONG_EXCHANGE='$inputDirectory'
`$env:R3B_STRONG_OUTPUT='$outputDirectory'
& '$runtime\owner-tests.exe' existing::hello::remote_key::tests::remote_hello_t2_software_executor --ignored --exact --nocapture *> '$outputDirectory\owner.log'
`$code=`$LASTEXITCODE
@{exit_code=`$code;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value} | ConvertTo-Json | Set-Content '$outputDirectory\owner-task-result.json' -Encoding UTF8
exit `$code
"@
foreach ($entry in @(@{name='system.ps1';text=$systemScript},@{name='owner.ps1';text=$ownerScript})) {
    $path=Join-Path $runtime $entry.name
    [IO.File]::WriteAllText($path,$entry.text,[Text.UTF8Encoding]::new($true))
    Protect-Path $path $false
}
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(16)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
try {
    foreach ($entry in @(@{name=$systemTask;script='system.ps1';sid='SYSTEM';logon='ServiceAccount';level='Highest'},@{name=$ownerTask;script='owner.ps1';sid=$OwnerSid;logon='Interactive';level='Limited'})) {
        $action=New-ScheduledTaskAction -Execute $ps -Argument ('-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $runtime $entry.script)+'"')
        $principal=New-ScheduledTaskPrincipal -UserId $entry.sid -LogonType $entry.logon -RunLevel $entry.level
        Register-ScheduledTask -TaskName $entry.name -Action $action -Principal $principal -Settings $settings | Out-Null
    }
    $launch=@{utc=[DateTime]::UtcNow.ToString('o');runtime=$runtime;input=$inputDirectory;output=$outputDirectory;system_task=$systemTask;owner_task=$ownerTask;owner_sid=$OwnerSid;
        system_sha256=(Get-FileHash "$runtime\system-tests.exe" -Algorithm SHA256).Hash.ToLowerInvariant();owner_sha256=(Get-FileHash "$runtime\owner-tests.exe" -Algorithm SHA256).Hash.ToLowerInvariant()}
    $launch | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $ResultDirectory 'launch.json') -Encoding UTF8
    Start-ScheduledTask -TaskName $systemTask
    Start-ScheduledTask -TaskName $ownerTask
    $launch | ConvertTo-Json -Depth 4
    Write-Host 'Approve AK_s creation and the T2/Hello signatures. Read owner-progress.json; at waiting_cancel_signal, write input/continue-cancel and cancel only the new Hello sign. Wait for both result JSON files before removing the two tasks. Preserve runtime and result evidence.'
} catch {
    foreach ($task in $systemTask,$ownerTask) { Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue }
    throw
}
