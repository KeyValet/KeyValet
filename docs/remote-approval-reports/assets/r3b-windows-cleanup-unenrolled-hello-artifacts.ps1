$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class HelloAliasInventory {
 [StructLayout(LayoutKind.Sequential)] struct KeyName { public IntPtr name; public IntPtr algorithm; public uint legacy; public uint flags; }
 [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptOpenStorageProvider(out IntPtr p,string name,uint flags);
 [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptEnumKeys(IntPtr p,string scope,out IntPtr name,ref IntPtr state,uint flags);
 [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptOpenKey(IntPtr p,out IntPtr key,string name,uint legacy,uint flags);
 [DllImport("ncrypt.dll")] static extern int NCryptDeleteKey(IntPtr key,uint flags);
 [DllImport("ncrypt.dll")] static extern int NCryptFreeBuffer(IntPtr p);
 [DllImport("ncrypt.dll")] static extern int NCryptFreeObject(IntPtr p);
 public static string DeleteExact(string alias) {
  string[] allowed={"keyvalet.remote.strong.7a845fb472b366906eb122a60e855a40","keyvalet.remote.strong.0ce9ad63e6c98a51336141c53161801a"};
  if(Array.IndexOf(allowed,alias)<0)throw new Exception("Alias is outside this cleanup ledger");
  IntPtr p,key=IntPtr.Zero,state=IntPtr.Zero; int r=NCryptOpenStorageProvider(out p,"Microsoft Passport Key Storage Provider",0);
  if(r!=0)throw new Exception("Provider unavailable");
  try {
   string exact=null;
   for(int i=0;i<4096;i++) {
    IntPtr entry;r=NCryptEnumKeys(p,null,out entry,ref state,0);
    if(unchecked((uint)r)==0x8009002a)break;
    if(r!=0)throw new Exception("Enumeration failed");
    try {
     var info=(KeyName)Marshal.PtrToStructure(entry,typeof(KeyName));string name=Marshal.PtrToStringUni(info.name);
     if(name.EndsWith("//"+alias,StringComparison.Ordinal) && (info.flags & 32)==0){
      if(exact!=null)throw new Exception("Ambiguous alias");exact=name;
     }
    }finally{NCryptFreeBuffer(entry);}
   }
   if(exact==null)return "already_absent";
   r=NCryptOpenKey(p,out key,exact,0,64);
   if(r!=0) return "silent_open_status="+unchecked((uint)r).ToString("x8");
   r=NCryptDeleteKey(key,64);
   if(r!=0)return "silent_delete_status="+unchecked((uint)r).ToString("x8");
   key=IntPtr.Zero;return "deleted_without_ui";
  }finally{if(key!=IntPtr.Zero)NCryptFreeObject(key);if(state!=IntPtr.Zero)NCryptFreeBuffer(state);NCryptFreeObject(p);}
 }
 public static string[] List() {
  IntPtr p,state=IntPtr.Zero; var names=new List<string>();
  int r=NCryptOpenStorageProvider(out p,"Microsoft Passport Key Storage Provider",0);
  if(r!=0) throw new Exception("Provider status="+unchecked((uint)r).ToString("x8"));
  try { for(int i=0;i<4096;i++) {
   IntPtr entry; r=NCryptEnumKeys(p,null,out entry,ref state,0);
   if(unchecked((uint)r)==0x8009002a) return names.ToArray();
   if(r!=0) throw new Exception("Enumeration status="+unchecked((uint)r).ToString("x8"));
   try { string name=Marshal.PtrToStringUni(((KeyName)Marshal.PtrToStructure(entry,typeof(KeyName))).name);
    foreach(System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(name,"keyvalet\\.remote\\.strong\\.[0-9a-f]{32}")) names.Add(m.Value);
   } finally {NCryptFreeBuffer(entry);}
  } throw new Exception("Enumeration limit");
  } finally {if(state!=IntPtr.Zero)NCryptFreeBuffer(state);NCryptFreeObject(p);}
 }
}
"@
$base='C:\ProgramData\KeyValet'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-21-3389053113-2113560702-4064643913-1001'){throw 'Wrong owner'}
if((Test-Path "$base\remote\vault.enc") -or (Test-Path "$base\remote\master.key") -or (Test-Path "$base\relay-client.toml")){throw 'Preserve enrolled remote keys; no cleanup performed'}
if(@(Get-ScheduledTask | Where-Object {$_.TaskName -match '^KeyValetR3BHello' -and $_.State -eq 'Running'}).Count){throw 'A native fixture is still running'}
$beforeHash=(Get-FileHash "$base\vault.enc" -Algorithm SHA256).Hash.ToLowerInvariant()
$beforeSddl=(Get-Acl $base).Sddl
$results=@()
foreach($alias in 'keyvalet.remote.strong.7a845fb472b366906eb122a60e855a40','keyvalet.remote.strong.0ce9ad63e6c98a51336141c53161801a'){
 $results+=@{alias=$alias;result=[HelloAliasInventory]::DeleteExact($alias)}
}
$remaining=@([HelloAliasInventory]::List())
$result=@{utc=[DateTime]::UtcNow.ToString('o');silent_flag=64;results=$results;remaining_remote_strong_aliases=$remaining;remote_identity_was_unenrolled=$true;vault_hash_unchanged=((Get-FileHash "$base\vault.enc" -Algorithm SHA256).Hash.ToLowerInvariant() -eq $beforeHash);vault_dacl_unchanged=((Get-Acl $base).Sddl -eq $beforeSddl);formal_agent_preserved=!!(Get-ScheduledTask -TaskName 'KeyValetAgent');private_keys_exported=$false}
$result | ConvertTo-Json -Depth 5 | Set-Content 'C:\Users\11516\KeyValet-Test-20261013\r3b\hello-artifact-cleanup.json' -Encoding UTF8
$result | ConvertTo-Json -Depth 5
if($remaining.Count){exit 1}
