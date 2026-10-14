param([Parameter(Mandatory=$true)][string]$ResultDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Install clients as the limited desktop owner.'
}
if(Test-Path $ResultDirectory){throw 'Fresh output directory required.'}
New-Item -ItemType Directory $ResultDirectory|Out-Null
$apps=@(
    @{name='codex';url='https://chatgpt.com/codex/install.ps1';binary="$env:LOCALAPPDATA\Programs\OpenAI\Codex\bin\codex.exe"},
    @{name='claude';url='https://claude.ai/install.ps1';binary="$env:USERPROFILE\.local\bin\claude.exe"},
    @{name='cursor-agent';url='https://cursor.com/install?win32=true';binary="$env:LOCALAPPDATA\cursor-agent\agent.cmd"}
)
$results=@()
foreach($app in $apps){
    @{app=$app.name;phase='download_install';utc=[DateTime]::UtcNow.ToString('o')}|
        ConvertTo-Json|Set-Content "$ResultDirectory\progress.json" -Encoding UTF8
    $row=@{name=$app.name;source=$app.url;installed=$false;login_attempted=$false}
    try{
        $installer=Join-Path $ResultDirectory ($app.name+'-installer.ps1')
        Invoke-WebRequest $app.url -UseBasicParsing -TimeoutSec 30 -OutFile $installer
        $row.installer_sha256=(Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant()
        $source=[IO.File]::ReadAllText($installer)
        if($source.TrimStart().StartsWith('<')){
            $row.html_instead_of_installer=$true
            $row.region_unavailable=$source.Contains('App unavailable in region')
            throw 'Expected a PowerShell installer, received HTML.'
        }
        $tokens=$null;$parseErrors=$null
        [void][Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$parseErrors)
        if($parseErrors.Count){throw 'Installer did not parse as PowerShell.'}
        if($app.name -eq 'codex'){$env:CODEX_NON_INTERACTIVE='1'}
        $info=[Diagnostics.ProcessStartInfo]::new()
        $info.FileName='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$installer+'"'
        $info.UseShellExecute=$false
        $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $child=[Diagnostics.Process]::new();$child.StartInfo=$info
        try{
            if(!$child.Start()){throw 'Client installer did not start.'}
            $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
            if(!$child.WaitForExit(240000)){$child.Kill();throw 'Client installer timed out.'}
            $row.installer_exit=$child.ExitCode
            # Installer and client output stay in memory; never collect authentication data.
        }finally{$child.Dispose()}
        if(Test-Path $app.binary){
            $version=@(& $app.binary --version 2>$null)|Out-String
            $row.installed=($LASTEXITCODE -eq 0)
            $row.version=([regex]::Match($version,'\b\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.]+)?\b')).Value
            $row.binary=$app.binary
        }
    }catch{$row.error_type=$_.Exception.GetType().Name}
    finally{if($app.name -eq 'codex'){Remove-Item Env:CODEX_NON_INTERACTIVE -ErrorAction SilentlyContinue}}
    $results+=,$row
    @{apps=$results;login_attempted=$false;credentials_read=$false}|
        ConvertTo-Json -Depth 5|Set-Content "$ResultDirectory\result.json" -Encoding UTF8
}
@{phase='complete';utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|
    Set-Content "$ResultDirectory\progress.json" -Encoding UTF8
