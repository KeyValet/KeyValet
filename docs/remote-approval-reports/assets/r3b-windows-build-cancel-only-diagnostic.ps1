$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root='C:\kv-r3b-windows-20261013'
$source=Join-Path $root 'repo'
$copy=Join-Path $root 'cancel-only-source'
if(Test-Path $copy){throw 'Preserve previous diagnostic source; no overwrite'}
$manifest=Get-Content "$root\source-closure-manifest.json" -Raw | ConvertFrom-Json
if($manifest.fingerprint -ne 'fbf22e994313d82d246b96ccc8e480441f4c048b4ad715f8f8c5bd828f87bf0b'){throw 'Unexpected tested production source'}
foreach($file in $manifest.files){
 $original=Join-Path $source $file.path
 if((Get-FileHash $original -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256){throw 'Production source checksum changed'}
 $destination=Join-Path $copy $file.path
 New-Item -ItemType Directory -Path (Split-Path $destination) -Force | Out-Null
 Copy-Item $original $destination
}
$utf8=[Text.UTF8Encoding]::new($false)
$key=Join-Path $copy 'rust\crates\kv-agent\src\hello\remote_key.rs'
[IO.File]::AppendAllText($key,[IO.File]::ReadAllText("$root\cancel-only-diagnostic.rs",$utf8),$utf8)
$hello=Join-Path $copy 'rust\crates\kv-agent\src\hello.rs'
$text=[IO.File]::ReadAllText($hello,$utf8)
$find='move |sender, status| {'
$replace=@'
move |sender, status| {
                #[cfg(test)]
                eprintln!("HELLO_DIAG completion_status={} sender_present={}", status.0, sender.ok().is_ok());
'@
$text=$text.Replace($find,$replace)
[IO.File]::WriteAllText($hello,$text,$utf8)
$env:CARGO_TARGET_DIR='C:\kv-r2b-20261012\target'
$env:CARGO_INCREMENTAL='0';$env:CARGO_PROFILE_DEV_DEBUG='0';$env:CARGO_PROFILE_TEST_DEBUG='0'
$env:PATH='C:\Users\win\.cargo\bin;'+$env:PATH
Set-Location "$copy\rust"
$ErrorActionPreference='Continue'
& 'C:\Users\win\.cargo\bin\cargo.exe' test -p kv-agent --bin kv-agent --locked --no-run --message-format=json > "$root\logs\cancel-only-build.jsonl" 2> "$root\logs\cancel-only-build.log"
$code=$LASTEXITCODE
$ErrorActionPreference='Stop'
if($code -ne 0){Get-Content "$root\logs\cancel-only-build.log" -Tail 30;throw 'Diagnostic build failed'}
$artifacts=@(Get-Content "$root\logs\cancel-only-build.jsonl" | ForEach-Object {$_ | ConvertFrom-Json} | Where-Object {$_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.executable})
if($artifacts.Count -ne 1){throw 'Expected one owner test executable'}
$binary=$artifacts[0].executable
$test='existing::hello::remote_key::r3b_cancel_only_diagnostic::cancellation_started_on_desktop'
if(!(& $binary --list | Select-String -SimpleMatch ($test+': test'))){throw 'Diagnostic test not found'}
$bundle=Join-Path $root 'logs\cancel-only-bundle'
New-Item -ItemType Directory -Path $bundle -Force | Out-Null
Copy-Item $binary "$bundle\owner-cancel-only.exe"
Compress-Archive -Path "$bundle\*" -DestinationPath "$root\logs\cancel-only-bundle.zip"
$result=@{base_tested_source=$manifest.fingerprint;production_wait_and_sign_unchanged=$true;temporary_source_copy=$copy;diagnostic_test=$test;diagnostic_source_sha256=(Get-FileHash "$root\cancel-only-diagnostic.rs" -Algorithm SHA256).Hash.ToLowerInvariant();callback_logging_only=$true;owner_sha256=(Get-FileHash "$bundle\owner-cancel-only.exe" -Algorithm SHA256).Hash.ToLowerInvariant();archive_sha256=(Get-FileHash "$root\logs\cancel-only-bundle.zip" -Algorithm SHA256).Hash.ToLowerInvariant();interactive_run_performed=$false}
$result | ConvertTo-Json -Depth 5 | Set-Content "$root\logs\cancel-only-bundle.json" -Encoding UTF8
$result | ConvertTo-Json -Depth 5
