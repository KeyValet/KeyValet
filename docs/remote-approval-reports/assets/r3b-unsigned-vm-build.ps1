$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root='C:\kv-r3b-unsigned-20261014'
$env:PATH='C:\Users\win\.cargo\bin;'+$env:PATH
$env:CARGO_TARGET_DIR='C:\kv-r2b-20261012\target'
$env:CARGO_INCREMENTAL='0'
$env:CARGO_PROFILE_DEV_DEBUG='0'
$env:CARGO_PROFILE_TEST_DEBUG='0'
$commands=@(
    @('test','-p','kv-core','-p','kv-helper','-p','kv-cli','-p','kv-agent','-p','kv-platform','--locked'),
    @('build','--locked','-p','kv-helper','-p','kv-agent','-p','kv-cli','-p','kv-mcp','-p','kv-hook','-p','kv-server','-p','kv-relay-client')
)
$results=@()
$failure=$null
Push-Location "$root\repo\rust"
try {
    $index=0
    foreach ($arguments in $commands) {
        $index++
        @{phase='cargo';command=$index;utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json |
            Set-Content "$root\build-progress.json" -Encoding UTF8
        $started=[DateTime]::UtcNow
        & cargo @arguments *> "$root\build-$index.log"
        $code=$LASTEXITCODE
        $results+=@{command=('cargo '+($arguments -join ' '));exit_code=$code;seconds=([DateTime]::UtcNow-$started).TotalSeconds}
        if ($code -ne 0) { throw "Cargo command $index failed." }
    }
    $metadata=@()
    foreach ($name in 'kv-helper','kv-agent','kv-cli','kv-mcp','kv-hook','kv-server','kv-relay-client') {
        $file=Get-Item "$env:CARGO_TARGET_DIR\debug\$name.exe"
        if ($file.VersionInfo.ProductName -cne 'KeyValet' -or $file.VersionInfo.OriginalFilename -cne "$name.exe") {
            throw "PE version resource missing for $name."
        }
        $metadata+=@{name=$name;sha256=(Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant();
            product=$file.VersionInfo.ProductName;version=$file.VersionInfo.ProductVersion;original=$file.VersionInfo.OriginalFilename}
    }
    $metadata | ConvertTo-Json -Depth 4 | Set-Content "$root\pe-metadata.json" -Encoding UTF8
} catch { $failure=$_.Exception.Message }
finally {
    Pop-Location
    @{passed=($null -eq $failure);failure=$failure;commands=$results;finished_utc=[DateTime]::UtcNow.ToString('o')} |
        ConvertTo-Json -Depth 6 | Set-Content "$root\build-result.json" -Encoding UTF8
}
if ($failure) { exit 1 }
