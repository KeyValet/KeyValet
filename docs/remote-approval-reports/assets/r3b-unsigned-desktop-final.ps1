param([Parameter(Mandatory=$true)][string]$ResultDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Windows.Forms
if(Test-Path $ResultDirectory){throw 'Fresh output directory required.'}
New-Item -ItemType Directory $ResultDirectory|Out-Null
function Ready([string]$Text,[string]$Title){
    $owner=[Windows.Forms.Form]::new();$owner.ShowInTaskbar=$false;$owner.TopMost=$true
    $owner.Width=1;$owner.Height=1;$owner.Show();[void]$owner.Activate()
    try{[void][Windows.Forms.MessageBox]::Show($owner,$Text,$Title,0,64)}finally{$owner.Close();$owner.Dispose()}
}
function Stage([string]$Phase){@{phase=$Phase;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content "$ResultDirectory\progress.json" -Encoding UTF8}
Stage 'waiting_crash_preparation'
Ready 'Approve this round. Click OK, then Verify and allow in the KeyValet purpose dialog, then complete Windows Hello. The test reads vault metadata only and terminates only its own MCP client to check cleanup.' 'KeyValet - 1 of 2: crash cleanup'
Stage 'running_crash'
& 'C:\KeyValet-R3B-Unsigned-20261014T052816Z\test-windows-desktop.ps1' -AllowSystemChanges -Mode Crash -ResultDirectory "$ResultDirectory\crash"
if(!(Get-Content "$ResultDirectory\crash\result.json" -Raw|ConvertFrom-Json).passed){Stage 'crash_failed';exit 1}
Stage 'waiting_presence_preparation'
Ready 'No KeyValet approval is needed for this step. Move the mouse or type on this Windows computer, then click OK. Press Win+L, wait at least 15 seconds, unlock normally, and move the mouse again. Leave Windows awake for two minutes while the read-only capture finishes.' 'KeyValet - 2 of 2: lock and unlock'
$env:R3B_PRESENCE_REPORT="$ResultDirectory\presence.json"
$env:R3B_PRESENCE_SECONDS='120'
Stage 'running_presence'
& 'C:\KeyValet-R3B-Unsigned-20261014T052816Z\native\debug\deps\kv_agent-d6155e4a924ef552.exe' --exact existing::presence::windows::tests::windows_presence_native_transitions --ignored --nocapture *> "$ResultDirectory\presence-test.log"
$code=$LASTEXITCODE
@{crash_passed=$true;presence_exit=$code;presence_passed=($code -eq 0);credential_values_logged=$false}|
    ConvertTo-Json|Set-Content "$ResultDirectory\result.json" -Encoding UTF8
Stage 'complete'
exit $code
