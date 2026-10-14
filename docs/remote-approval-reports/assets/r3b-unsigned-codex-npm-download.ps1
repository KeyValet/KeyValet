param([Parameter(Mandatory=$true)][string]$ResultDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(Test-Path $ResultDirectory){throw 'Fresh output directory required.'}
New-Item -ItemType Directory $ResultDirectory|Out-Null
$url='https://registry.npmjs.org/@openai/codex/-/codex-0.162.1-win32-x64.tgz'
$integrity='dfl4MhHuEi0ARKyNmrTxk+RQmsWNCQAoVLUtrYq+yrW1C8P2sg5ziwgHUUACHjYLKuACV7ARH5Nq5pnCz3GlaQ=='
$expectedExe='dd13bdb162a184fa04039488b234a8258ef9b76f84e926c505d5742b19249a6a'
$row=@{source=$url;version='0.162.1';verified=$false;login_attempted=$false}
try{
    $archive=Join-Path $ResultDirectory 'codex.tgz'
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName='C:\Windows\System32\curl.exe'
    $info.Arguments='--fail --location --connect-timeout 10 --max-time 180 --output "'+$archive+'" "'+$url+'"'
    $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $child=[Diagnostics.Process]::new();$child.StartInfo=$info
    try{
        if(!$child.Start()){throw 'Download did not start.'}
        $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
        if(!$child.WaitForExit(190000)){$child.Kill();throw 'Download timed out.'}
        $row.download_exit=$child.ExitCode
        if($child.ExitCode -ne 0){throw 'Download failed.'}
    }finally{$child.Dispose()}
    $hash=[Security.Cryptography.SHA512]::Create();$stream=[IO.File]::OpenRead($archive)
    try{$row.sha512=[Convert]::ToBase64String($hash.ComputeHash($stream))}finally{$stream.Dispose();$hash.Dispose()}
    if($row.sha512 -cne $integrity){throw 'NPM integrity mismatch.'}
    $extract=Join-Path $ResultDirectory 'extracted';New-Item -ItemType Directory $extract|Out-Null
    & C:\Windows\System32\tar.exe -xzf $archive -C $extract
    if($LASTEXITCODE -ne 0){throw 'Archive extraction failed.'}
    $exe=@(Get-ChildItem $extract -Recurse -File -Filter 'codex.exe')
    if($exe.Count -ne 1){throw 'Unexpected release layout.'}
    $row.binary=$exe[0].FullName
    $row.sha256=(Get-FileHash $row.binary -Algorithm SHA256).Hash.ToLowerInvariant()
    if($row.sha256 -cne $expectedExe){throw 'GitHub executable checksum mismatch.'}
    $row.archive_sha256=(Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $row.verified=$true
}catch{$row.error_type=$_.Exception.GetType().Name}
finally{$row|ConvertTo-Json -Depth 4|Set-Content "$ResultDirectory\result.json" -Encoding UTF8}
