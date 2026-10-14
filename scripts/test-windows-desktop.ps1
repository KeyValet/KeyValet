# Installed acceptance. Run as the limited owner in the real desktop, never from CI.
[CmdletBinding()]
param(
    [switch]$AllowSystemChanges,
    [ValidateSet('Preflight','PreflightCrash','Success','Cancel','Crash')][string]$Mode = 'Success',
    [Parameter(Mandatory=$true)][string]$ResultDirectory,
    [string]$InstallDirectory = 'C:\Program Files\KeyValet'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (!$AllowSystemChanges) { throw 'Use -AllowSystemChanges for installed interactive acceptance.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ((Get-Process -Id $PID).SessionId -eq 0 -or
    ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run as the unelevated owner in a desktop session.'
}
if (Test-Path -LiteralPath $ResultDirectory) { throw 'Use a new result directory.' }
New-Item -ItemType Directory -Path $ResultDirectory | Out-Null
$project=Join-Path $ResultDirectory 'project-工作目录'
New-Item -ItemType Directory -Path $project | Out-Null
$start=[DateTime]::UtcNow
$checks=[Collections.Generic.List[string]]::new()
$process=$null
$started=$false
$stderr=$null
$failure=$null
$frames=0
$workerIds=@()
$baselineMcpIds=@(Get-CimInstance Win32_Process -Filter "Name='kv-mcp.exe'" | ForEach-Object { [int]$_.ProcessId })
$helperPid=[int](Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId
$helloRequested=$Mode -notin @('Preflight','PreflightCrash')
$crashRequested=$Mode -in @('Crash','PreflightCrash')
$operatorCancellationConfirmed=$false
function Property($Object,[string]$Name) {
    if ($null -eq $Object) { return $null }
    $property=$Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}
function Stage([string]$Name) {
    @{phase=$Name;mode=$Mode;utc=[DateTime]::UtcNow.ToString('o');owner_sid=$identity.User.Value;
      session=(Get-Process -Id $PID).SessionId} | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $ResultDirectory 'progress.json') -Encoding UTF8
}
function Assert([bool]$Condition,[string]$Message) {
    if (!$Condition) { throw $Message }
}
function Send($Message) {
    $line=ConvertTo-Json -InputObject $Message -Depth 15 -Compress
    $process.StandardInput.WriteLine($line)
    $process.StandardInput.Flush()
}
function Receive([int]$Id) {
    $deadline=[DateTime]::UtcNow.AddSeconds(120)
    while ([DateTime]::UtcNow -lt $deadline) {
        $read=$process.StandardOutput.ReadLineAsync()
        while (!$read.IsCompleted -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 40 }
        Assert $read.IsCompleted 'MCP response timed out.'
        $line=$read.GetAwaiter().GetResult()
        Assert ($null -ne $line) 'MCP stdout ended before the response.'
        $frame=$line | ConvertFrom-Json
        Assert ((Property $frame 'jsonrpc') -eq '2.0') 'Non-MCP worker handshake leaked to stdout.'
        $script:frames++
        if ((Property $frame 'id') -eq $Id) { return $frame }
    }
    throw 'MCP response timed out.'
}
function Call([int]$Id,[string]$Name,$Arguments) {
    Send @{jsonrpc='2.0';id=$Id;method='tools/call';params=@{name=$Name;arguments=$Arguments}}
    Receive $Id
}
function Read-ToolData($Reply) {
    $result=Property $Reply 'result'
    Assert ($null -ne $result -and !(Property $result 'isError')) 'MCP tool rejected the operation.'
    foreach ($content in (Property $result 'content')) {
        $text=Property $content 'text'
        if ($text) {
            $begin=$text.IndexOf('{')
            if ($begin -ge 0) { return ($text.Substring($begin) | ConvertFrom-Json) }
        }
    }
    throw 'MCP tool omitted structured status.'
}
function Assert-CancelEvidence($Reply,$Status,$Receipt) {
    Assert ([bool](Property (Property $Reply 'result') 'isError')) 'Cancelled authentication unexpectedly succeeded.'
    Assert ((Property $Status 'state') -eq 'locked') 'Cancellation left the client unlocked.'
    $observed=Property $Receipt 'windows_security_cancelled'
    Assert ($observed -is [bool] -and $observed) 'Windows Security cancellation was not observed by the operator.'
}
try {
    Stage 'starting_installed_mcp'
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=Join-Path $InstallDirectory 'bin\kv-mcp.exe'
    $info.WorkingDirectory=$project
    $info.UseShellExecute=$false
    $info.RedirectStandardInput=$true
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    $info.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
    $info.EnvironmentVariables['KEYVALET_LANG']='en'
    $info.EnvironmentVariables['KEYVALET_GRANT_MODE']='per_use'
    $info.EnvironmentVariables['KEYVALET_SESSION_TTL_MINUTES']='5'
    $process=[Diagnostics.Process]::new()
    $process.StartInfo=$info
    $started=$process.Start()
    Assert $started 'MCP launcher did not start.'
    $stderr=$process.StandardError.ReadToEndAsync()
    Send @{jsonrpc='2.0';id=1;method='initialize';params=@{protocolVersion='2024-11-05';capabilities=@{};clientInfo=@{name='KeyValet Windows acceptance';version='0.3.0'}}}
    $initialize=Receive 1
    Assert ($null -ne (Property $initialize 'result')) 'MCP initialization failed.'
    Send @{jsonrpc='2.0';method='notifications/initialized'}
    Send @{jsonrpc='2.0';id=2;method='tools/list';params=@{}}
    $tools=Receive 2
    $names=@((Property (Property $tools 'result') 'tools') | ForEach-Object { $_.name })
    Assert ($names -contains 'credential_unlock' -and $names -contains 'credential_status') 'Expected native tools missing.'
    $checks.Add('initialize_tools_jsonrpc_no_handshake_leak')
    $status=Read-ToolData (Call 3 'credential_status' @{})
    Assert ((Property $status 'state') -eq 'locked') 'Fresh client unexpectedly unlocked.'
    $checks.Add('fresh_session_locked_status_without_authentication')
    $workerIds=@(Get-CimInstance Win32_Process -Filter "Name='kv-mcp.exe'" |
        Where-Object { [int]$_.ParentProcessId -eq $helperPid -and [int]$_.ProcessId -notin $baselineMcpIds } |
        ForEach-Object { [int]$_.ProcessId })
    Assert ($workerIds.Count -eq 1) 'Expected one new helper-owned protected worker.'
    $checks.Add('helper_owned_protected_worker_observed')
    if ($helloRequested) {
        Stage $(if($Mode -eq 'Cancel'){'waiting_hello_cancel'}else{'waiting_hello_approve'})
        $reply=Call 4 'credential_unlock' @{purpose="Windows native acceptance: $Mode; no existing credential values are read"}
        if ($Mode -eq 'Cancel') {
            Assert ([bool](Property (Property $reply 'result') 'isError')) 'Cancelled authentication unexpectedly succeeded.'
            $status=Read-ToolData (Call 5 'credential_status' @{})
            Assert ((Property $status 'state') -eq 'locked') 'Cancellation left the client unlocked.'
            Stage 'waiting_operator_cancel_receipt'
            $receiptPath=Join-Path $ResultDirectory 'operator-cancel.json'
            $receiptDeadline=[DateTime]::UtcNow.AddSeconds(180)
            while (!(Test-Path -LiteralPath $receiptPath) -and [DateTime]::UtcNow -lt $receiptDeadline) {
                Start-Sleep -Milliseconds 100
            }
            $receipt=if(Test-Path -LiteralPath $receiptPath){Get-Content -LiteralPath $receiptPath -Raw|ConvertFrom-Json}else{$null}
            Assert-CancelEvidence $reply $status $receipt
            $operatorCancellationConfirmed=$true
            $checks.Add('hello_cancel_rejected_no_unlocked_session')
            $checks.Add('operator_confirmed_windows_security_cancel')
        } else {
            Assert (!(Property (Property $reply 'result') 'isError')) 'Hello unlock failed.'
            $status=Read-ToolData (Call 5 'credential_status' @{})
            Assert ((Property $status 'state') -eq 'unlocked') 'Approved Hello did not unlock the real session.'
            $checks.Add('installed_protected_worker_hello_unlock')
            $types=Call 6 'credential_list_types' @{purpose='Windows acceptance: counts only, never credential values'}
            Assert (!(Property (Property $types 'result') 'isError')) 'Unlocked vault query failed.'
            $checks.Add('existing_vault_metadata_query')
            if ($Mode -ne 'Crash') {
                $locked=Call 7 'credential_lock' @{}
                Assert (!(Property (Property $locked 'result') 'isError')) 'Explicit lock failed.'
                $status=Read-ToolData (Call 8 'credential_status' @{})
                Assert ((Property $status 'state') -eq 'locked') 'Explicit lock left the session active.'
                $checks.Add('explicit_lock_revokes_session')
            }
        }
    }
    Stage 'closing_test_client'
    if ($crashRequested) { $process.Kill() } else { $process.StandardInput.Close() }
    Assert ($process.WaitForExit(10000)) 'Client did not exit after EOF/crash.'
    $checks.Add($(if($crashRequested){'client_crash_exits'}else{'client_eof_exits'}))
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    do {
        $remaining=@(Get-CimInstance Win32_Process -Filter "Name='kv-mcp.exe'" |
            Where-Object { [int]$_.ProcessId -in $workerIds })
        if (!$remaining.Count) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    Assert (!$remaining.Count) 'Protected worker remained after client EOF/crash.'
    $checks.Add('protected_worker_exits_after_client')
} catch {
    # Parser errors can quote input. Preserve only our fixed assertions, never tool bodies.
    $fixed=@('MCP response timed out.','MCP stdout ended before the response.',
        'Non-MCP worker handshake leaked to stdout.','MCP tool rejected the operation.',
        'MCP tool omitted structured status.','MCP launcher did not start.',
        'MCP initialization failed.','Expected native tools missing.',
        'Fresh client unexpectedly unlocked.','Cancelled authentication unexpectedly succeeded.',
        'Cancellation left the client unlocked.','Hello unlock failed.',
        'Approved Hello did not unlock the real session.','Unlocked vault query failed.',
        'Explicit lock failed.','Explicit lock left the session active.',
        'Client did not exit after EOF/crash.','Expected one new helper-owned protected worker.',
        'Protected worker remained after client EOF/crash.',
        'Windows Security cancellation was not observed by the operator.')
    $failure=if($fixed -contains $_.Exception.Message){$_.Exception.Message}else{'native_desktop_test_exception'}
} finally {
    if ($process -and $started) {
        if (!$process.HasExited) { $process.Kill(); [void]$process.WaitForExit(5000) }
        $process.Dispose()
    }
    $result=@{passed=($null -eq $failure);mode=$Mode;hello_tested=$helloRequested;checks=@($checks.ToArray());failure=$failure;
        protected_workers_observed=$workerIds.Count;
        operator_cancellation_confirmed=$operatorCancellationConfirmed;
        valid_mcp_frames=$frames;owner_sid=$identity.User.Value;session=(Get-Process -Id $PID).SessionId;
        seconds=([DateTime]::UtcNow-$start).TotalSeconds;credential_values_logged=$false;
        mcp_sha256=(Get-FileHash (Join-Path $InstallDirectory 'bin\kv-mcp.exe') -Algorithm SHA256).Hash.ToLowerInvariant()}
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ResultDirectory 'result.json') -Encoding UTF8
    Stage 'complete'
}
if ($failure) { exit 1 }
