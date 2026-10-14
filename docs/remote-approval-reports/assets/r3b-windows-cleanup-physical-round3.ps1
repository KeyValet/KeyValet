$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root='C:\Users\11516\KeyValet-Test-20261013\r3b\hello-round3'
$launch=Get-Content "$root\launch.json" -Raw | ConvertFrom-Json
foreach ($name in $launch.system_task,$launch.owner_task) {
  if ((Get-ScheduledTask -TaskName $name).State -eq 'Running') { throw 'Wait for the native key guards to finish before deleting the task.' }
}
$worker=Join-Path $launch.runtime 'inventory.ps1'
$text=@'
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class R3BInventory {
 [StructLayout(LayoutKind.Sequential)] struct KeyName { public IntPtr name; public IntPtr algorithm; public uint legacy; public uint flags; }
 [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptOpenStorageProvider(out IntPtr p,string name,uint flags);
 [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptEnumKeys(IntPtr p,string scope,out IntPtr name,ref IntPtr state,uint flags);
 [DllImport("ncrypt.dll")] static extern int NCryptFreeBuffer(IntPtr p);
 [DllImport("ncrypt.dll")] static extern int NCryptFreeObject(IntPtr p);
 public static int Count() {
  IntPtr p,state=IntPtr.Zero; int count=0;
  int r=NCryptOpenStorageProvider(out p,"Microsoft Platform Crypto Provider",0);
  if(r!=0) throw new Exception("PCP provider unavailable");
  try { for(int i=0;i<4096;i++) {
   IntPtr entry; r=NCryptEnumKeys(p,null,out entry,ref state,32);
   if(unchecked((uint)r)==0x8009002a) return count;
   if(r!=0) throw new Exception("PCP inventory unavailable");
   try { string name=Marshal.PtrToStringUni(((KeyName)Marshal.PtrToStructure(entry,typeof(KeyName))).name);
    if(name.StartsWith("keyvalet.remote.identity.")||name.StartsWith("keyvalet.remote.quick.")) count++;
   } finally {NCryptFreeBuffer(entry);}
  } throw new Exception("PCP inventory limit");
  } finally {if(state!=IntPtr.Zero)NCryptFreeBuffer(state);NCryptFreeObject(p);}
 }
}
"@
$count=[R3BInventory]::Count()
@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;pcp_remote_keys=$count} | ConvertTo-Json | Set-Content (Join-Path $PSScriptRoot 'cleanup-inventory.json') -Encoding UTF8
if($count -ne 0){exit 1}
'@
[IO.File]::WriteAllText($worker,$text,[Text.UTF8Encoding]::new($true))
$task='KeyValetR3BInventory-'+[guid]::NewGuid().ToString('N')
$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$worker+'"')
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(1)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
try {
 Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null
 Start-ScheduledTask -TaskName $task
 $until=[DateTime]::UtcNow.AddSeconds(45);$result=Join-Path $launch.runtime 'cleanup-inventory.json'
 while (!(Test-Path $result)) {if([DateTime]::UtcNow -ge $until){throw 'Inventory timed out'};Start-Sleep -Milliseconds 250}
 $inventory=Get-Content $result -Raw | ConvertFrom-Json
 if($inventory.sid -ne 'S-1-5-18' -or $inventory.pcp_remote_keys -ne 0){throw 'PCP cleanup not verified'}
 foreach($name in $launch.system_task,$launch.owner_task){Unregister-ScheduledTask -TaskName $name -Confirm:$false}
 $summary=@{utc=[DateTime]::UtcNow.ToString('o');pcp_remote_keys=0;temporary_tasks_removed=$true;formal_agent_preserved=!!(Get-ScheduledTask -TaskName 'KeyValetAgent');hello_creation_completed=$true;hello_guard_delete_requested=$false;hello_delete_independently_checked=$false;hello_signing_started=$true;hello_cancel_receipt=$false;owner_exit_hex="0xc000013a";runtime_preserved=$launch.runtime}
 $summary | ConvertTo-Json | Set-Content "$root\cleanup.json" -Encoding UTF8
 $summary | ConvertTo-Json
} finally {Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue}
