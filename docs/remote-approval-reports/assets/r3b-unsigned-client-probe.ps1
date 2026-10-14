param([Parameter(Mandatory=$true)][string]$ResultDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or (Get-Process -Id $PID).SessionId -eq 0){throw 'Use the limited desktop owner.'}
if(Test-Path $ResultDirectory){throw 'Fresh output directory required.'}
New-Item -ItemType Directory $ResultDirectory|Out-Null
$baseline=@(Get-CimInstance Win32_Process -Filter "Name='kv-mcp.exe'"|ForEach-Object{[int]$_.ProcessId})
function Run([string]$File,[string]$Arguments){
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$File;$info.Arguments=$Arguments
    $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.WorkingDirectory=$ResultDirectory
    $child=[Diagnostics.Process]::new();$child.StartInfo=$info
    try{
        if(!$child.Start()){throw 'Client did not start.'}
        $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
        if(!$child.WaitForExit(60000)){$child.Kill();return @{exit=$null;timed_out=$true;text=''}}
        return @{exit=$child.ExitCode;timed_out=$false;text=($stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult())}
    }finally{$child.Dispose()}
}
$results=@()
$cursor="$env:LOCALAPPDATA\cursor-agent\agent.cmd"
if(Test-Path $cursor){
    foreach($arguments in @('--version','mcp --help','mcp list-tools keyvalet')){
        @{phase='cursor_probe';command=$arguments}|ConvertTo-Json|Set-Content "$ResultDirectory\progress.json" -Encoding UTF8
        $output=Run 'C:\Windows\System32\cmd.exe' ('/d /s /c ""'+$cursor+'" '+$arguments+'"')
        $tools=@([regex]::Matches($output.text,'\bcredential_[a-z_]+\b')|ForEach-Object{$_.Value}|Sort-Object -Unique)
        $results+=@{client='cursor';command=$arguments;exit=$output.exit;timed_out=$output.timed_out;
            version=([regex]::Match($output.text,'\b(?:\d{4}\.\d{2}\.\d{2}-[a-f0-9]+|\d+\.\d+\.\d+)\b')).Value;
            tool_names=$tools;auth_required=($output.text -match '(?i)(not authenticated|not logged in|log in|sign in|login required|please login|requires authentication|missing api key)');
            diagnostic_markers=@(@('server not found','unknown server','failed to connect','not logged in','not authenticated','missing api key','requires authentication','approval','trust','not configured','not connected','MCP error','connection closed','ENOENT','EPIPE','EINVAL','ENOTDIR','SyntaxError','Unexpected token','spawn','stdin','stdout','helper_server_binary_untrusted')|Where-Object{$output.text.IndexOf($_,[StringComparison]::OrdinalIgnoreCase) -ge 0});
            keyvalet_disabled=($output.text -match '(?i)(disabled|not enabled)');
            expected_tools_present=($tools -contains 'credential_unlock' -and $tools -contains 'credential_status')}
    }
}
$deadline=[DateTime]::UtcNow.AddSeconds(10)
do{$remaining=@(Get-CimInstance Win32_Process -Filter "Name='kv-mcp.exe'"|Where-Object{[int]$_.ProcessId -notin $baseline});if(!$remaining.Count){break};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $deadline)
@{owner_sid=$identity.User.Value;session=(Get-Process -Id $PID).SessionId;commands=$results;
  protected_workers_remaining=$remaining.Count;login_attempted=$false;credential_values_logged=$false}|
    ConvertTo-Json -Depth 7|Set-Content "$ResultDirectory\result.json" -Encoding UTF8
@{phase='complete'}|ConvertTo-Json|Set-Content "$ResultDirectory\progress.json" -Encoding UTF8
