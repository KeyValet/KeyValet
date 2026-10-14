# Official native Codex client; discovery only, no model, auth or credential call.
param(
    [Parameter(Mandatory=$true)][string]$CodexExecutable,
    [Parameter(Mandatory=$true)][string]$ResultDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Use the limited installation owner.'
}
if(Test-Path -LiteralPath $ResultDirectory){throw 'Fresh output directory required.'}
if((Get-FileHash -LiteralPath $CodexExecutable).Hash.ToLowerInvariant() -cne
   'dd13bdb162a184fa04039488b234a8258ef9b76f84e926c505d5742b19249a6a'){
    throw 'Official Codex executable checksum mismatch.'
}
New-Item -ItemType Directory -Path $ResultDirectory|Out-Null
$start=[DateTime]::UtcNow
$baseline=@(Get-CimInstance Win32_Process -Filter "Name='kv-mcp.exe'"|ForEach-Object{[int]$_.ProcessId})
$helperPid=[int](Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId
$process=$null;$started=$false;$failure=$null;$workerIds=@();$names=@();$frames=0
$initialized=$false;$discovered=$false;$clientExited=$false;$workersExited=$false
function Property($Object,[string]$Name){
    if($null -eq $Object){return $null}
    $property=$Object.PSObject.Properties[$Name]
    if($property){return $property.Value}
    return $null
}
function Assert([bool]$Condition,[string]$Message){if(!$Condition){throw $Message}}
function Send($Message){
    $process.StandardInput.WriteLine((ConvertTo-Json -InputObject $Message -Depth 12 -Compress))
    $process.StandardInput.Flush()
}
function Receive([int]$Id){
    $deadline=[DateTime]::UtcNow.AddSeconds(90)
    while([DateTime]::UtcNow -lt $deadline){
        $read=$process.StandardOutput.ReadLineAsync()
        while(!$read.IsCompleted -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 40}
        Assert $read.IsCompleted 'Codex response timed out.'
        $line=$read.GetAwaiter().GetResult()
        Assert ($null -ne $line) 'Codex stdout ended before its response.'
        $frame=$line|ConvertFrom-Json
        $script:frames++
        if((Property $frame 'id') -eq $Id){return $frame}
    }
    throw 'Codex response timed out.'
}
try{
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$CodexExecutable
    # A process-only TOML override preserves all installed client configuration.
    $info.Arguments='-c "mcp_servers.keyvalet.command=''C:/Program Files/KeyValet/bin/kv-mcp.exe''" app-server'
    $info.WorkingDirectory=$ResultDirectory
    $info.UseShellExecute=$false
    $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
    $info.EnvironmentVariables['CODEX_NON_INTERACTIVE']='1'
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    $started=$process.Start()
    Assert $started 'Codex did not start.'
    $stderr=$process.StandardError.ReadToEndAsync()
    Send @{id=1;method='initialize';params=@{clientInfo=@{name='KeyValet Windows acceptance';version='0.3.0'};capabilities=@{experimentalApi=$true}}}
    $reply=Receive 1
    Assert ($null -ne (Property $reply 'result') -and $null -eq (Property $reply 'error')) 'Codex initialize failed.'
    $initialized=$true
    Send @{method='initialized';params=@{}}
    Send @{id=2;method='mcpServerStatus/list';params=@{serverName='keyvalet'}}
    $reply=Receive 2
    Assert ($null -eq (Property $reply 'error')) 'Codex MCP discovery failed.'
    $entries=@(Property (Property $reply 'result') 'data')
    $server=@($entries|Where-Object{(Property $_ 'name') -eq 'keyvalet'})
    Assert ($server.Count -eq 1) 'Codex omitted the KeyValet server.'
    $tools=Property $server[0] 'tools'
    if($tools){
        $names=@($tools.PSObject.Properties|ForEach-Object{
            $name=Property $_.Value 'name'
            if($name){$name}else{$_.Name}
        }|Where-Object{$_ -match '^(?:mcp__keyvalet__)?credential_[a-z_]+$'}|Sort-Object -Unique)
    }
    Assert (@($names|Where-Object{$_ -match 'credential_unlock$'}).Count -eq 1 -and
            @($names|Where-Object{$_ -match 'credential_status$'}).Count -eq 1) 'Codex did not discover the expected KeyValet tools.'
    $discovered=$true
    $workerIds=@(Get-CimInstance Win32_Process -Filter "Name='kv-mcp.exe'"|
        Where-Object{[int]$_.ParentProcessId -eq $helperPid -and [int]$_.ProcessId -notin $baseline}|
        ForEach-Object{[int]$_.ProcessId})
    Assert ($workerIds.Count -ge 1) 'Codex discovery did not create a protected MCP worker.'
    $process.StandardInput.Close()
    $clientExited=$process.WaitForExit(15000)
    Assert $clientExited 'Codex did not exit after stdin EOF.'
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    do{
        $remaining=@(Get-CimInstance Win32_Process -Filter "Name='kv-mcp.exe'"|
            Where-Object{[int]$_.ProcessId -in $workerIds})
        if(!$remaining.Count){$workersExited=$true;break}
        Start-Sleep -Milliseconds 100
    }while([DateTime]::UtcNow -lt $deadline)
    Assert $workersExited 'Codex left a protected MCP worker running.'
}catch{
    $fixed=@('Codex response timed out.','Codex stdout ended before its response.','Codex did not start.',
        'Codex initialize failed.','Codex MCP discovery failed.','Codex omitted the KeyValet server.',
        'Codex did not discover the expected KeyValet tools.','Codex discovery did not create a protected MCP worker.',
        'Codex did not exit after stdin EOF.','Codex left a protected MCP worker running.')
    $failure=if($fixed -contains $_.Exception.Message){$_.Exception.Message}else{'codex_probe_exception'}
}finally{
    if($process -and $started){if(!$process.HasExited){$process.Kill();[void]$process.WaitForExit(5000)};$process.Dispose()}
    @{passed=($null -eq $failure);failure=$failure;codex_version='0.162.1';
      owner_sid=$identity.User.Value;elevated=$false;initialized=$initialized;tools_discovered=$discovered;
      tool_names=$names;valid_client_frames=$frames;protected_workers_observed=$workerIds.Count;
      client_eof_exit=$clientExited;protected_worker_exit=$workersExited;
      seconds=([DateTime]::UtcNow-$start).TotalSeconds;model_called=$false;login_attempted=$false;
      credential_tool_called=$false;credential_values_logged=$false}|
        ConvertTo-Json -Depth 6|Set-Content -LiteralPath "$ResultDirectory\result.json" -Encoding UTF8
}
if($failure){exit 1}
