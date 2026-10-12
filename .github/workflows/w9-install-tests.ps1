param([switch]$Portable)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$path = Join-Path $root 'scripts/install.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'W9 PowerShell installer has parse errors.' }
$functions = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($name in 'Set-KeyValetToolTimeout','Remove-KeyValetMcpTable','Assert-RelayDescriptor') {
    $definition = @($functions | Where-Object { $_.Name -eq $name })
    if ($definition.Count -ne 1) { throw "Missing installer function: $name" }
    Invoke-Expression $definition[0].Extent.Text
}
$mcp = 'C:\Program Files\KeyValet\bin\kv-mcp.exe'
$original = "# Keep comment`nmodel = 'custom'`n[mcp_servers.other]`ncommand = 'keep'`n[mcp_servers.keyvalet]`ncommand = 'custom'`ntool_timeout_sec = 41`n[mcp_servers.keyvalet.env]`nLANG = 'zh'`n"
$updated = Set-KeyValetToolTimeout $original $mcp
if ($updated -notmatch 'tool_timeout_sec = 900' -or $updated -notmatch "LANG = 'zh'" -or $updated -notmatch "command = 'custom'" -or $updated -notmatch '# Keep comment') { throw 'TOML update lost user configuration.' }
if ((Set-KeyValetToolTimeout $updated $mcp) -cne $updated) { throw 'TOML update is not idempotent.' }
$new = Set-KeyValetToolTimeout "[mcp_servers.other]`ncommand = 'keep'`n" $mcp
if ($new -notmatch 'tool_timeout_sec = 900' -or $new -notmatch [regex]::Escape($mcp)) { throw 'Missing new KeyValet timeout.' }
$quoted = "[mcp_servers.`"keyvalet`"]`ncommand = 'remove'`n[mcp_servers.keyvalet.env]`nLANG = 'zh'`n[mcp_servers.other]`ncommand = 'keep'`n"
$removed = Remove-KeyValetMcpTable $quoted
if ($removed -match 'remove|LANG' -or $removed -notmatch "command = 'keep'") { throw 'Removal lost another server or retained KeyValet fields.' }
if ((Remove-KeyValetMcpTable $removed) -cne $removed) { throw 'Removal is not idempotent.' }
if ($Portable) { Write-Host 'W9 PowerShell syntax and TOML preservation tests passed; native ACL tests require Windows.'; return }
$sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')
$read = [Security.AccessControl.RawSecurityDescriptor]::new('O:BAG:BAD:P(A;;FA;;;SY)(A;;FR;;;S-1-5-80-1-2-3-4-5)')
Assert-RelayDescriptor $read $sid $true
$write = [Security.AccessControl.RawSecurityDescriptor]::new('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;S-1-5-80-1-2-3-4-5)')
$rejected = $false
try { Assert-RelayDescriptor $write $sid $true } catch { $rejected = $true }
if (!$rejected) { throw 'Relay received write access to configuration.' }
$foreign = [Security.AccessControl.RawSecurityDescriptor]::new('O:BAG:BAD:P(A;;FA;;;WD)')
$rejected = $false
try { Assert-RelayDescriptor $foreign $sid $false } catch { $rejected = $true }
if (!$rejected) { throw 'Foreign access to the queue was accepted.' }
Write-Host 'W9 PowerShell syntax, TOML preservation and relay ACL tests passed.'
