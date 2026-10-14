param([Parameter(Mandatory=$true)][string]$ResultDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Use the limited desktop owner.'}
if(Test-Path $ResultDirectory){throw 'Fresh output directory required.'}
New-Item -ItemType Directory $ResultDirectory|Out-Null
$url='https://github.com/openai/codex/releases/download/rust-v0.162.1/codex-x86_64-pc-windows-msvc.exe.tar.gz'
$expected='a97c427a033b08d58902af3e52e8586ad2013267212112d306100223e2b12ec7'
$row=@{source=$url;expected_sha256=$expected;installed=$false;login_attempted=$false;credentials_read=$false}
try{
    $archive=Join-Path $ResultDirectory 'codex.tar.gz'
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName='C:\Windows\System32\curl.exe'
    $info.Arguments='--fail --location --connect-timeout 10 --max-time 240 --output "'+$archive+'" "'+$url+'"'
    $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $child=[Diagnostics.Process]::new();$child.StartInfo=$info
    try{
        if(!$child.Start()){throw 'Download did not start.'}
        $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
        if(!$child.WaitForExit(250000)){$child.Kill();throw 'Download timed out.'}
        $row.download_exit=$child.ExitCode
        if($child.ExitCode -ne 0){throw 'Official release download failed.'}
    }finally{$child.Dispose()}
    $row.actual_sha256=(Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if($row.actual_sha256 -cne $expected){throw 'Official release checksum mismatch.'}
    $extract=Join-Path $ResultDirectory 'extracted';New-Item -ItemType Directory $extract|Out-Null
    & C:\Windows\System32\tar.exe -xzf $archive -C $extract
    if($LASTEXITCODE -ne 0){throw 'Archive extraction failed.'}
    $binaries=@(Get-ChildItem $extract -Recurse -File -Filter 'codex-x86_64-pc-windows-msvc.exe')
    if($binaries.Count -ne 1){throw 'Unexpected release layout.'}
    $bin="$env:LOCALAPPDATA\Programs\OpenAI\Codex\bin";New-Item -ItemType Directory -Force $bin|Out-Null
    if(Test-Path "$bin\codex.exe"){throw 'An existing Codex installation must not be overwritten.'}
    Copy-Item $binaries[0].FullName "$bin\codex.exe"
    $version=@(& "$bin\codex.exe" --version 2>$null)|Out-String
    $row.installed=($LASTEXITCODE -eq 0);$row.version=([regex]::Match($version,'\b\d+\.\d+\.\d+\b')).Value
    $row.binary="$bin\codex.exe"
}catch{$row.error_type=$_.Exception.GetType().Name}
finally{
    $row|ConvertTo-Json -Depth 4|Set-Content "$ResultDirectory\result.json" -Encoding UTF8
}
