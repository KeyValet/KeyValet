$ErrorActionPreference='Stop'
$root='C:\Users\win\KeyValet-Test-20261014'
$binary='C:\Users\win\AppData\Local\Programs\OpenAI\Codex-0.162.1\bin\codex.exe'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$report=@{owner_sid=$identity.User.Value;session=(Get-Process -Id $PID).SessionId;
    elevated=([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
try{
    $report['checksum_matches']=((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant() -ceq
        'dd13bdb162a184fa04039488b234a8258ef9b76f84e926c505d5742b19249a6a')
    & "$root\codex-mcp-probe.ps1" -CodexExecutable $binary -ResultDirectory "$root\codex-mcp-desktop"
    $report['exit']=$LASTEXITCODE
}catch{
    $report['exit']=1
    $report['error_type']=$_.Exception.GetType().FullName
    $fixed=@('Use the limited installation owner.','Fresh output directory required.',
        'Official Codex executable checksum mismatch.')
    $report['failure']=if($fixed -contains $_.Exception.Message){$_.Exception.Message}else{'codex_probe_precondition_or_parse_error'}
}finally{
    $report|ConvertTo-Json|Set-Content "$root\codex-mcp-run-result.json" -Encoding UTF8
}
if($report['exit'] -ne 0){exit 1}
