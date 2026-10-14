param([Parameter(Mandatory=$true)][string]$ResultPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$backup='C:\ProgramData\KeyValet-Backups\pre-r3b-unsigned-'+$stamp
if(Test-Path -LiteralPath $backup){throw 'Backup already exists.'}
New-Item -ItemType Directory -Path $backup | Out-Null
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in 'S-1-5-18','S-1-5-32-544'){
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $backup -AclObject $acl
$helper=Get-Service KeyValetHelper
$running=$helper.Status -eq 'Running'
Stop-ScheduledTask -TaskName KeyValetAgent -ErrorAction SilentlyContinue
Stop-Service KeyValetHelper
$helper.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
try{
    Copy-Item -LiteralPath 'C:\Program Files\KeyValet' -Destination (Join-Path $backup 'install') -Recurse
    Copy-Item -LiteralPath 'C:\ProgramData\KeyValet' -Destination (Join-Path $backup 'data') -Recurse
    $vault=Get-ChildItem -LiteralPath 'C:\ProgramData\KeyValet' -File | Where-Object Name -match '^vault'
    $hashes=@($vault | ForEach-Object{@{name=$_.Name;sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
    $result=@{backup=$backup;vault_hashes=$hashes;vault_dacl=(Get-Acl -LiteralPath 'C:\ProgramData\KeyValet').Sddl;
        install_dacl=(Get-Acl -LiteralPath 'C:\Program Files\KeyValet').Sddl;consistent=$true;
        utc=[DateTime]::UtcNow.ToString('o')}
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}finally{
    if($running){Start-Service KeyValetHelper}
    Start-ScheduledTask -TaskName KeyValetAgent
}
