$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$base='C:\Users\11516\KeyValet-Test-20261013\r3b'
$zip=Join-Path $base 'cancel-only-bundle.zip'
if((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne '51982534a32d6966390d67de391d3b5ddd381636d0e6d3cfea9c8dddfe9ffb4d'){throw 'Diagnostic archive checksum mismatch'}
$bundle=Join-Path $base 'cancel-only-bundle'
if(Test-Path $bundle){throw 'Preserve earlier diagnostic artifacts'}
Expand-Archive -LiteralPath $zip -DestinationPath $bundle
$binary=Join-Path $bundle 'owner-cancel-only.exe'
if((Get-FileHash $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne '1c54039a8a9506c564b39b4b47b438b0d0f38cd70f4a022061d8aa14af9a268c'){throw 'Diagnostic executable checksum mismatch'}
$ownerSid='S-1-5-21-3389053113-2113560702-4064643913-1001'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $ownerSid){throw 'Unexpected owner'}
if(!(Get-Process explorer -ErrorAction SilentlyContinue)){throw 'Interactive desktop required'}
$run=[guid]::NewGuid().ToString('N')
$runtime=Join-Path $env:ProgramData ('KeyValet-Backups\r3b-cancel-only-'+$run)
$result=Join-Path $base 'cancel-only-round1'
if(Test-Path $result){throw 'Use a fresh result directory'}
New-Item -ItemType Directory -Path $runtime,$result | Out-Null
$owner=[Security.Principal.SecurityIdentifier]::new($ownerSid)
function Protect-Directory([string]$path,[string]$ownerAccess){
 $acl=[Security.AccessControl.DirectorySecurity]::new()
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
 $acl.SetAccessRuleProtection($true,$false)
 foreach($sid in 'S-1-5-18','S-1-5-32-544'){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($owner,$ownerAccess,'ContainerInherit,ObjectInherit','None','Allow'))
 Set-Acl -LiteralPath $path -AclObject $acl
}
Protect-Directory $runtime 'ReadAndExecute'
Protect-Directory $result 'ReadAndExecute'
$output=Join-Path $result 'owner-output'
New-Item -ItemType Directory -Path $output | Out-Null
Protect-Directory $output 'Modify'
Copy-Item $binary "$runtime\owner-cancel-only.exe"
$script=@"
`$ErrorActionPreference='Continue'
`$ProgressPreference='SilentlyContinue'
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class NativeWake { [DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint flags); }'
[NativeWake]::SetThreadExecutionState(0x80000003) | Out-Null
`$env:R3B_CANCEL_ONLY_OPT_IN='1'
`$env:R3B_CANCEL_ONLY_OUTPUT='$output'
`$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
@{sid=`$identity.User.Value;session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId;elevated=([Security.Principal.WindowsPrincipal]`$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)} | ConvertTo-Json | Set-Content '$output\identity.json' -Encoding UTF8
try {
 & '$runtime\owner-cancel-only.exe' existing::hello::remote_key::r3b_cancel_only_diagnostic::cancellation_started_on_desktop --ignored --exact --nocapture *> '$output\owner.log'
 `$code=`$LASTEXITCODE
 @{exit_code=`$code;finished_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content '$output\task-result.json' -Encoding UTF8
} finally {[NativeWake]::SetThreadExecutionState(0x80000000) | Out-Null}
exit `$code
"@
[IO.File]::WriteAllText("$runtime\owner.ps1",$script,[Text.UTF8Encoding]::new($true))
$task='KeyValetR3BCancelOnly-'+$run
$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$runtime+'\owner.ps1"')
$principal=New-ScheduledTaskPrincipal -UserId $ownerSid -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(10)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null
$launch=@{utc=[DateTime]::UtcNow.ToString('o');task=$task;runtime=$runtime;output=$output;owner_sha256='1c54039a8a9506c564b39b4b47b438b0d0f38cd70f4a022061d8aa14af9a268c';base_tested_source='fbf22e994313d82d246b96ccc8e480441f4c048b4ad715f8f8c5bd828f87bf0b';no_t2_or_repeat_retest=$true;production_sign_budget_unchanged=$true;uses_installed_worker=$false}
$launch | ConvertTo-Json | Set-Content "$result\launch.json" -Encoding UTF8
Start-ScheduledTask -TaskName $task
$launch | ConvertTo-Json
