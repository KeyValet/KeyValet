param([switch]$VerifyRestoration)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root='C:\kv-r3b-unsigned-20261014'
$repo="$root\repo"
$backup=(Get-Content "$root\pre-service-backup.json" -Raw | ConvertFrom-Json).backup
$retained=Join-Path $backup 'retained-original-data'
$moved=$false
$failure=$null
function Restore-OriginalInstall {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & "$repo\scripts\install.ps1" -InstallSystem -PackagePath "$repo\dist\keyvalet-v0.3.0-windows-x64.zip" `
        -OwnerSid $sid -OwnerProfile 'C:\Users\win' -AllowUnsignedAgent -SkipSetup *> "$root\vm-restored-upgrade.log"
    $helper=Get-Service KeyValetHelper
    try { $helper.WaitForStatus('Running',[TimeSpan]::FromSeconds(20)) }
    finally { $helper.Dispose() }
    @{restored=$true;original_backup=$backup;helper=(Get-Service KeyValetHelper).Status.ToString();
      relay=(Get-Service KeyValetRelay).Status.ToString();failure=$failure;system_phase=$true} |
        ConvertTo-Json -Depth 4 | Set-Content "$root\service-restoration.json" -Encoding UTF8
}
if($VerifyRestoration){
    if(!(Test-Path 'C:\ProgramData\KeyValet\owner.sid')){throw 'Original data must already be restored.'}
    Restore-OriginalInstall
    return
}
try {
    # Keep CI independent of installation changes, even though it must not use the daemon.
    $deadline=[DateTime]::UtcNow.AddMinutes(20)
    while (!(Test-Path "$root\ci-result.json")) {
        if([DateTime]::UtcNow -gt $deadline){throw 'CI did not finish; original installation left intact.'}
        Start-Sleep -Seconds 1
    }
    if(!((Get-Content "$root\ci-result.json" -Raw | ConvertFrom-Json).passed)){throw 'CI failed; original installation left intact.'}
    & "$repo\scripts\uninstall.ps1" *> "$root\vm-original-uninstall.log"
    if(Test-Path -LiteralPath $retained){throw 'Retained data destination already exists.'}
    Move-Item -LiteralPath 'C:\ProgramData\KeyValet' -Destination $retained
    $moved=$true
    & "$repo\scripts\test-windows-service.ps1" -AllowSystemChanges -DeferProfileCleanup `
        -BinaryDirectory 'C:\kv-r2b-20261012\target\debug' -ResultPath "$root\service-regression.json" `
        *> "$root\service-regression.log"
} catch {$failure=$_.Exception.Message}
finally {
    if($moved){
        # Only the disposable fixture's data may be removed. Original data stays in backup.
        if(Test-Path 'C:\Program Files\KeyValet'){
            & "$repo\scripts\uninstall.ps1" -RemoveVault *> "$root\service-fixture-cleanup.log"
        }
        if(Test-Path 'C:\ProgramData\KeyValet'){
            throw 'Fixture vault remains; original data was retained and not overwritten.'
        }
        Move-Item -LiteralPath $retained -Destination 'C:\ProgramData\KeyValet'
        Restore-OriginalInstall
    }
}
if($failure){exit 1}
