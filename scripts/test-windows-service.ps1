# Installed integration test for a disposable Windows machine. No Hello, GUI or secrets.
# Ordinary unit tests do not invoke this script. It refuses an existing installation/vault.
[CmdletBinding()]
param([switch]$AllowSystemChanges, [switch]$DeferProfileCleanup, [string]$BinaryDirectory, [string]$ResultPath,
      [string]$WslDistribution, [string]$WslUser = 'kvwsltest')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
if (!$AllowSystemChanges) { throw 'This test installs/removes a SYSTEM service. Use -AllowSystemChanges on a disposable clean Windows machine.' }
if ($env:OS -ne 'Windows_NT') { throw 'Run this integration test on Windows.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (!([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use an elevated PowerShell terminal.' }
$install = 'C:\Program Files\KeyValet'; $vault = 'C:\ProgramData\KeyValet'
if ((Test-Path -LiteralPath $install) -or (Test-Path -LiteralPath $vault) -or
    (Get-Service KeyValetHelper -ErrorAction SilentlyContinue) -or
    (Get-Service KeyValetRelay -ErrorAction SilentlyContinue) -or
    (Get-ScheduledTask -TaskName KeyValetAgent -ErrorAction SilentlyContinue)) {
    throw 'This test requires a clean machine with no KeyValet installation, task, service or retained vault.'
}
$repo = Split-Path $PSScriptRoot -Parent
if (!$BinaryDirectory) { $BinaryDirectory = "$repo/rust/target/debug" }
$BinaryDirectory = (Resolve-Path -LiteralPath $BinaryDirectory).Path
if (!$ResultPath) { $ResultPath = "$repo/dist/windows-service-test.json" }
$version = [regex]::Match((Get-Content "$repo/rust/crates/kv-cli/Cargo.toml" -Raw), '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
$architecture = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'x64' }
$owner = $null
$testUser = $null
$testPassword = $null
$checks = [Collections.Generic.List[string]]::new()
$failure = $null
$pendingProfiles = [Collections.Generic.List[object]]::new()
function Assert([bool]$Condition, [string]$Message) { if (!$Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    Assert $threw $Message
}
function Wait-Service([string]$State) {
    $controller = Get-Service KeyValetHelper
    try { $controller.WaitForStatus($State, [TimeSpan]::FromSeconds(20)) } finally { $controller.Dispose() }
}
Add-Type @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class KeyValetSmokePipe {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
}
public static class KeyValetSmokeAccountRights {
    [StructLayout(LayoutKind.Sequential)] struct Attributes {
        public uint Length; public IntPtr RootDirectory; public IntPtr ObjectName;
        public uint Flags; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)] struct UnicodeString {
        public ushort Length; public ushort MaximumLength; public IntPtr Buffer;
    }
    [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref Attributes attributes, uint access, out IntPtr policy);
    [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr policy, IntPtr sid, UnicodeString[] rights, uint count);
    [DllImport("advapi32.dll")] static extern uint LsaRemoveAccountRights(IntPtr policy, IntPtr sid, [MarshalAs(UnmanagedType.U1)] bool all, UnicodeString[] rights, uint count);
    [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr policy);
    [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
    public static void SetBatchLogon(string sidText, bool grant) {
        var sid = new System.Security.Principal.SecurityIdentifier(sidText);
        var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
        var buffer = Marshal.AllocHGlobal(bytes.Length);
        var right = Marshal.StringToHGlobalUni("SeBatchLogonRight");
        IntPtr policy = IntPtr.Zero;
        try {
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            var attributes = new Attributes(); attributes.Length = (uint)Marshal.SizeOf(attributes);
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x810, out policy);
            if (status != 0) throw new System.ComponentModel.Win32Exception((int)LsaNtStatusToWinError(status));
            var rights = new[]{new UnicodeString{Length=34, MaximumLength=36, Buffer=right}};
            status = grant ? LsaAddAccountRights(policy, buffer, rights, 1) : LsaRemoveAccountRights(policy, buffer, false, rights, 1);
            if (status != 0) throw new System.ComponentModel.Win32Exception((int)LsaNtStatusToWinError(status));
        } finally {
            if (policy != IntPtr.Zero) LsaClose(policy);
            Marshal.FreeHGlobal(right); Marshal.FreeHGlobal(buffer);
        }
    }
}
'@
function Test-ServicePipe {
    $configuration = Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'"
    Assert ($configuration.State -eq 'Running' -and $configuration.StartName -eq 'LocalSystem') 'Helper must run under SCM as SYSTEM.'
    Assert ($configuration.PathName -ieq ('"' + "$install\bin\kv-helper.exe" + '" --service')) 'Service command line must preserve the quoted executable path and --service argument.'
    Assert ($configuration.StartMode -eq 'Auto') 'Helper must be configured for automatic startup.'
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($configuration.ProcessId)"
    Assert ($process.ExecutablePath -ieq "$install\bin\kv-helper.exe") 'Service executable path differs.'
    Assert ((Invoke-CimMethod $process -MethodName GetOwnerSid).Sid -eq 'S-1-5-18') 'Service process token must belong to SYSTEM.'
    $channel = [IO.Pipes.NamedPipeClientStream]::new('.', 'keyvalet-helper', [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Identification)
    try {
        $channel.Connect(5000)
        [uint32]$pidValue = 0
        Assert ([KeyValetSmokePipe]::GetNamedPipeServerProcessId($channel.SafePipeHandle, [ref]$pidValue)) 'Cannot query kernel pipe peer.'
        Assert ($pidValue -eq $configuration.ProcessId) 'Named-pipe server is not the SCM service process.'
        $writer = [IO.StreamWriter]::new($channel, [Text.UTF8Encoding]::new($false), 1024, $true)
        $reader = [IO.StreamReader]::new($channel, [Text.UTF8Encoding]::new($false), $false, 1024, $true)
        try {
            $writer.AutoFlush = $true
            $writer.WriteLine('{"op":"control","command":"sessions"}')
            $read = $reader.ReadLineAsync()
            Assert ($read.Wait(5000)) 'Control response timed out.'
            $reply = $read.Result | ConvertFrom-Json
            Assert ($reply.sessions -eq 0) 'Public/control probes must not open credential sessions.'
        } finally { $writer.Dispose(); $reader.Dispose() }
    } finally { $channel.Dispose() }
}
function Test-StandardOwnerStatus {
    # Task Scheduler supplies the standard user's own noninteractive window station. An SSH
    # logon desktop cannot be inherited by a newly created user (STATUS_DLL_INIT_FAILED).
    $probeName = 'KeyValetOwnerProbe-' + [guid]::NewGuid().ToString('N')
    $probeRoot = Join-Path 'C:\Windows\Temp' $probeName
    $probeTask = $false
    $probeBatchRight = $false
    New-Item -Path $probeRoot -ItemType Directory | Out-Null
    try {
        $probeAcl = [Security.AccessControl.DirectorySecurity]::new()
        $probeAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $probeAcl.SetAccessRuleProtection($true, $false)
        foreach ($probeSid in 'S-1-5-18','S-1-5-32-544',$owner) {
            $probeAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($probeSid), 'FullControl',
                'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        Set-Acl -LiteralPath $probeRoot $probeAcl
        $probeScript = Join-Path $probeRoot 'probe.ps1'
        $probeResult = Join-Path $probeRoot 'result.json'
        $probeCode = @'
$ErrorActionPreference = 'Stop'
$probeProcess = $null
try {
$probeIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$probeStart = [Diagnostics.ProcessStartInfo]::new()
$probeStart.FileName = 'C:\Program Files\KeyValet\bin\kv-cli.exe'
$probeStart.Arguments = 'status --json'
$probeStart.WorkingDirectory = 'C:\Windows\System32'
$probeStart.UseShellExecute = $false; $probeStart.CreateNoWindow = $true
$probeStart.RedirectStandardOutput = $true; $probeStart.RedirectStandardError = $true
$probeStart.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
$probeStart.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
$probeProcess = [Diagnostics.Process]::Start($probeStart)
    $probeOutput = $probeProcess.StandardOutput.ReadToEndAsync()
    $probeError = $probeProcess.StandardError.ReadToEndAsync()
    if (!$probeProcess.WaitForExit(15000)) { $probeProcess.Kill(); throw 'Standard-owner CLI timed out.' }
    $probeReport = @{ sid=$probeIdentity.User.Value;
        elevated=([Security.Principal.WindowsPrincipal]$probeIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
        exit_code=$probeProcess.ExitCode; stdout=$probeOutput.Result; stderr=$probeError.Result }
    [IO.File]::WriteAllText('__KV_PROBE_RESULT__', ($probeReport | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
} catch {
    $probeReport = @{ error=$_.Exception.Message; error_type=$_.Exception.GetType().FullName }
    [IO.File]::WriteAllText('__KV_PROBE_RESULT__', ($probeReport | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
} finally { if ($probeProcess) { $probeProcess.Dispose() } }
'@
        [IO.File]::WriteAllText($probeScript, $probeCode.Replace('__KV_PROBE_RESULT__', $probeResult), [Text.UTF8Encoding]::new($false))
        $probeAction = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $probeScript + '"')
        $probeSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(1)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $probeCredential = [Management.Automation.PSCredential]::new(($env:COMPUTERNAME + '\' + $testName), $testPassword)
        [KeyValetSmokeAccountRights]::SetBatchLogon($owner, $true)
        $probeBatchRight = $true
        $probePrincipal = New-ScheduledTaskPrincipal -UserId $probeCredential.UserName -LogonType Password -RunLevel Limited
        $probeDefinition = New-ScheduledTask -Action $probeAction -Settings $probeSettings -Principal $probePrincipal
        Register-ScheduledTask -TaskName $probeName -InputObject $probeDefinition -User $probeCredential.UserName -Password $probeCredential.GetNetworkCredential().Password | Out-Null
        $probeTask = $true
        Start-ScheduledTask -TaskName $probeName
        $probeDeadline = [DateTime]::UtcNow.AddSeconds(30)
        while (!(Test-Path -LiteralPath $probeResult)) {
            if ([DateTime]::UtcNow -gt $probeDeadline) {
                $probeInfo = Get-ScheduledTaskInfo -TaskName $probeName
                $probeDetails = Get-ScheduledTask -TaskName $probeName
                Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue |
                    Where-Object { $_.ToXml().Contains($probeName) } | Select-Object TimeCreated, Id, Message | Format-List | Out-Host
                throw ('Standard-owner scheduled probe timed out; task result: ' + $probeInfo.LastTaskResult + '; state: ' + $probeDetails.State + '; logon: ' + $probeDetails.Principal.LogonType)
            }
            Start-Sleep -Milliseconds 100
        }
        $probe = Get-Content -LiteralPath $probeResult -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($probe.PSObject.Properties.Name -contains 'error') { throw ('Standard-owner scheduled probe failed: ' + $probe.error) }
        Assert ($probe.sid -eq $owner -and !$probe.elevated) 'The status probe must run as the real unelevated owner.'
        Assert ($probe.exit_code -eq 0) ("Standard-owner status probe failed (exit " + $probe.exit_code + "): " + $probe.stderr + $probe.stdout)
        $ordinaryStatus = $probe.stdout | ConvertFrom-Json
        Assert ($ordinaryStatus.ok -and $ordinaryStatus.result.protection.provider -eq 'uninitialized') 'Standard owner must read authenticated public status without elevation or Hello.'
        Assert ($ordinaryStatus.result.remote_error.code -eq 'remote_unavailable') 'An unpaired owner must receive the structured remote-unavailable reply.'
    } finally {
        if ($probeTask) {
            Stop-ScheduledTask -TaskName $probeName -ErrorAction SilentlyContinue
            $probeStopDeadline = [DateTime]::UtcNow.AddSeconds(15)
            while ((Get-ScheduledTask -TaskName $probeName).State -eq 'Running') {
                if ([DateTime]::UtcNow -gt $probeStopDeadline) { throw 'Standard-owner task did not stop.' }
                Start-Sleep -Milliseconds 100
            }
            Unregister-ScheduledTask -TaskName $probeName -Confirm:$false -ErrorAction SilentlyContinue
        }
        if ($probeBatchRight) { [KeyValetSmokeAccountRights]::SetBatchLogon($owner, $false) }
        Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Assert-NoKeys {
    Assert (!(Test-Path "$vault/master.key")) 'No-Hello installation must not create a software master key.'
    Assert (!(Test-Path "$vault/vault.enc")) 'Public status must not initialize an encrypted vault.'
    Assert (@(Get-ChildItem $vault -Force -Filter 'device-binding*.key').Count -eq 0) 'Public status must not create binding secrets.'
}
function Test-BadPermissions([string]$Path, [Security.AccessControl.FileSystemRights]$Rights) {
    $original = Get-Acl -LiteralPath $Path
    $bad = Get-Acl -LiteralPath $Path
    $bad.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), $Rights, 'Allow'))
    $pidBefore = (Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId
    try {
        Set-Acl -LiteralPath $Path $bad
        Assert-Throws { & "$repo/scripts/install.ps1" @options } 'Installer accepted an untrusted existing file DACL.'
        Assert ((Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId -eq $pidBefore) 'Rejected upgrade must leave the running service intact.'
    } finally { Set-Acl -LiteralPath $Path $original }
}
try {
    # Exercise the actual ordinary-owner path, with no Administrators group or SeDebug
    # authority. An elevated runner alone can hide broken service/token/marker permissions.
    $testName = 'KVSmoke' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $random = [byte[]]::new(32)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($random) } finally { $generator.Dispose() }
    $testPassword = ConvertTo-SecureString ('Kv9!' + [Convert]::ToBase64String($random)) -AsPlainText -Force
    $testUser = New-LocalUser -Name $testName -Password $testPassword -Description 'Disposable KeyValet integration test owner' -PasswordNeverExpires
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $users.Name -Member $testUser
    $owner = $testUser.SID.Value
    & "$repo/scripts/package-windows.ps1" -Tag "v$version" -Architecture $architecture -AllowUnsigned -BinaryDirectory $BinaryDirectory
    $options = @{ InstallSystem = $true; OwnerSid = $owner; OwnerProfile = "C:\Users\$testName";
        PackagePath = "$repo/dist/keyvalet-v$version-windows-$architecture.zip"; AllowUnsignedAgent = $true }
    & "$repo/scripts/install.ps1" @options
    Wait-Service 'Running'
    Test-ServicePipe
    $checks.Add('fresh install, SYSTEM identity and authenticated pipe control')
    foreach ($binary in 'kv-helper', 'kv-agent', 'kv-cli', 'kv-mcp', 'kv-hook', 'kv-server', 'kv-relay-client') {
        Assert ((Get-FileHash "$BinaryDirectory/$binary.exe").Hash -eq (Get-FileHash "$install/bin/$binary.exe").Hash) 'Installed executable differs from package input.'
    }
    $relay = Get-CimInstance Win32_Service -Filter "Name='KeyValetRelay'"
    Assert ($null -ne $relay -and $relay.StartName -ieq 'NT SERVICE\KeyValetRelay') 'Relay must use its dedicated virtual service account.'
    Assert ($relay.PathName -ieq ('"' + "$install\bin\kv-relay-client.exe" + '" --service')) 'Relay service executable differs from the package.'
    Assert ($relay.State -eq 'Stopped' -and $relay.StartMode -eq 'Manual') 'An unpaired relay must remain stopped with manual startup.'
    $checks.Add('complete remote binaries and unpaired relay virtual service account')
    foreach ($file in 'bridge.sh', 'install.sh', 'uninstall.sh', 'configure.py', 'verify.py') {
        Assert ((Get-FileHash "$repo/scripts/wsl/$file").Hash -eq (Get-FileHash "$install/wsl/$file").Hash) 'Installed WSL bridge differs from package input.'
    }
    $checks.Add('complete WSL bridge assets installed from the tested package')
    $task = Get-ScheduledTask -TaskName KeyValetAgent
    $taskSid = if ($task.Principal.UserId -match '^S-1-') { $task.Principal.UserId }
        else { [Security.Principal.NTAccount]::new($task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value }
    Assert ($taskSid -eq $owner -and $task.Principal.RunLevel -eq 'Limited') 'Login launcher must use the installing owner without elevation.'
    $cli = "$install/bin/kv-cli.exe"
    $output = & $cli status --json
    Assert ($LASTEXITCODE -eq 3) 'Another administrator must not obtain the owner remote status.'
    $rejected = ($output | Out-String) | ConvertFrom-Json
    Assert (!$rejected.ok -and $rejected.error.code -eq 'forbidden') 'Cross-account remote status must be rejected explicitly.'
    $checks.Add('cross-account remote status rejection for another administrator')
    $output = & $cli status --summary --json
    Assert ($LASTEXITCODE -eq 0) 'Installed CLI cannot read public protection status.'
    $status = ($output | Out-String) | ConvertFrom-Json
    Assert ($status.ok -and $status.result.protection.provider -eq 'uninitialized') 'A clean no-Hello machine must report an uninitialized vault.'
    Test-StandardOwnerStatus
    Test-ServicePipe
    Assert-NoKeys
    $checks.Add('real standard-owner authenticated public status without Hello; no fallback or binding keys')

    if ($WslDistribution) {
        $wslRepo = (& 'C:\Windows\System32\wsl.exe' --distribution $WslDistribution --user $WslUser --exec wslpath -u $repo | Out-String).Trim()
        Assert ($LASTEXITCODE -eq 0 -and $wslRepo.StartsWith('/')) 'Cannot access the repository from the disposable WSL distribution.'
        & 'C:\Windows\System32\wsl.exe' --distribution $WslDistribution --user $WslUser --cd '~' --exec python3 "$wslRepo/scripts/test-wsl-live.py"
        Assert ($LASTEXITCODE -eq 0) 'Live WSL interop/client adapter test failed.'
        Assert-NoKeys
        $checks.Add('live WSL native CLI/hooks/WSLENV/TTL and per-user client installation; no Hello or desktop MCP')
    }

    Test-BadPermissions "$vault/owner.sid" ([Security.AccessControl.FileSystemRights]::Read)
    Test-BadPermissions "$install/bin/kv-agent.exe" ([Security.AccessControl.FileSystemRights]::WriteData)
    Test-BadPermissions "$install/wsl/bridge.sh" ([Security.AccessControl.FileSystemRights]::WriteData)
    $checks.Add('untrusted owner record, binary and WSL bridge DACL rejection before service stop')
    $pidBefore = (Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId
    $wrongOwner = @{} + $options; $wrongOwner.OwnerSid = ($owner -replace '-\d+$', '-999999')
    Assert-Throws { & "$repo/scripts/install.ps1" @wrongOwner } 'Upgrade must not retarget a vault to another owner.'
    Assert ((Get-CimInstance Win32_Service -Filter "Name='KeyValetHelper'").ProcessId -eq $pidBefore) 'Wrong-owner rejection stopped the service.'
    Assert ((Get-Content "$vault/owner.sid" -Raw).Trim() -eq $owner) 'Wrong-owner upgrade changed owner.sid.'
    $checks.Add('wrong-owner upgrade rejection')
    & "$repo/scripts/install.ps1" @options
    Wait-Service 'Running'
    Test-ServicePipe
    Assert-NoKeys
    $checks.Add('same-owner upgrade')
    Stop-Service KeyValetHelper
    Wait-Service 'Stopped'
    Start-Service KeyValetHelper
    Wait-Service 'Running'
    Test-ServicePipe
    $checks.Add('SCM stop and restart')

    & "$repo/scripts/uninstall.ps1"
    Assert (!(Get-Service KeyValetHelper -ErrorAction SilentlyContinue)) 'Uninstall left its service registered.'
    Assert (!(Get-Service KeyValetRelay -ErrorAction SilentlyContinue)) 'Uninstall left its relay service registered.'
    Assert (!(Get-ScheduledTask -TaskName KeyValetAgent -ErrorAction SilentlyContinue)) 'Uninstall left its login task.'
    Assert (!(Test-Path $install) -and (Test-Path "$vault/owner.sid")) 'Default uninstall must retain the vault and remove executables.'
    $checks.Add('uninstall retains the vault by default')
} catch {
    $failure = $_.Exception.Message
    Write-Host $_.InvocationInfo.PositionMessage
    Write-Host $_.ScriptStackTrace
} finally {
    # The precondition established these paths belong solely to this test. Explicitly remove
    # that test-created vault after verifying the production default preserves it.
    try {
        & "$repo/scripts/uninstall.ps1" -RemoveVault
        Assert (!(Test-Path $install) -and !(Test-Path $vault)) 'Integration cleanup left installation data.'
        $checks.Add('explicit removal and integration cleanup')
    } catch { $failure = "${failure} Cleanup failed: $($_.Exception.Message)" }
    if ($testUser) {
        try {
            $profileDeadline = [DateTime]::UtcNow.AddSeconds(15)
            while (@(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $testUser.SID.Value -and $_.Loaded }).Count) {
                if ([DateTime]::UtcNow -gt $profileDeadline) {
                    if (!$DeferProfileCleanup) { throw 'Test-user profile did not unload.' }
                    $pendingProfiles.Add(@{ sid=$testUser.SID.Value; path="C:\Users\$testName" })
                    break
                }
                Start-Sleep -Milliseconds 100
            }
            if (!$pendingProfiles.Count) {
                Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $testUser.SID.Value -and !$_.Special } | Remove-CimInstance
            }
        } catch { $failure = "${failure} Test-user cleanup failed: $($_.Exception.Message)" }
        finally { Remove-LocalUser -SID $testUser.SID }
    }
    if ($testPassword) { $testPassword.Dispose() }
    $report = @{ windows_build = [Environment]::OSVersion.Version.ToString(); architecture = $architecture;
        hello_tested = $false; signing = 'unsigned development'; checks = @($checks.ToArray());
        wsl_interop_tested = ($checks -contains 'live WSL native CLI/hooks/WSLENV/TTL and per-user client installation; no Hello or desktop MCP');
        profile_cleanup_pending_reboot = @($pendingProfiles.ToArray());
        passed = !$failure; error = $failure; timestamp_utc = [DateTime]::UtcNow.ToString('o') }
    New-Item (Split-Path $ResultPath -Parent) -ItemType Directory -Force | Out-Null
    [IO.File]::WriteAllText($ResultPath, ($report | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}
if ($failure) { throw $failure }
Write-Host "Windows service integration checks passed. Report: $ResultPath"
