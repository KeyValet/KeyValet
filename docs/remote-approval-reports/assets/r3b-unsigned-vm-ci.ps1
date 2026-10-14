param([string]$ResultPrefix='ci')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root='C:\kv-r3b-unsigned-20261014'
$env:PATH='C:\Users\win\.cargo\bin;'+$env:PATH
$env:CARGO_TARGET_DIR='C:\kv-r2b-20261012\target'
$env:CARGO_INCREMENTAL='0'
$env:CARGO_PROFILE_DEV_DEBUG='0'
$env:CARGO_PROFILE_TEST_DEBUG='0'
$commands=@(
    @('fmt','--all','--','--check'),
    @('clippy','--workspace','--all-targets','--','-D','warnings'),
    @('build','--workspace','--locked'),
    @('test','--workspace','--locked')
)
$results=@(); $failure=$null
Push-Location "$root\repo\rust"
try {
    $index=0
    foreach($arguments in $commands) {
        $index++
        @{phase='ci';command=$index;utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json |
            Set-Content "$root\$ResultPrefix-progress.json" -Encoding UTF8
        $start=[DateTime]::UtcNow
        # Windows PowerShell 5.1 wraps successful native stderr (Cargo progress)
        # in ErrorRecord objects. Decide success from the process exit code.
        $savedPreference=$ErrorActionPreference
        try {
            $ErrorActionPreference='Continue'
            & cargo @arguments *> "$root\$ResultPrefix-$index.log"
            $code=$LASTEXITCODE
        } finally { $ErrorActionPreference=$savedPreference }
        $results+=@{command=('cargo '+($arguments -join ' '));exit_code=$code;seconds=([DateTime]::UtcNow-$start).TotalSeconds}
        if($code -ne 0){throw "CI command $index failed."}
    }
} catch {$failure=$_.Exception.Message}
finally {
    Pop-Location
    @{passed=($null -eq $failure);failure=$failure;commands=$results;finished_utc=[DateTime]::UtcNow.ToString('o')} |
        ConvertTo-Json -Depth 6 | Set-Content "$root\$ResultPrefix-result.json" -Encoding UTF8
}
if($failure){exit 1}
