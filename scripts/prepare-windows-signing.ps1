# Produces reviewable unsigned signing inputs. It never changes publisher trust or signs files.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BinaryDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateSet('x64','arm64')][string]$Architecture='x64'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'Inspect native PE resources on Windows.' }
$repo=Split-Path $PSScriptRoot -Parent
$version=[regex]::Match((Get-Content "$repo/rust/crates/kv-cli/Cargo.toml" -Raw),'(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new signing input directory.' }
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile("$repo/scripts/install.ps1",[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Installer architecture validator did not parse.' }
$validator=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) |
    Where-Object Name -eq 'Assert-BinaryArchitecture' | Select-Object -First 1
if (!$validator) { throw 'Architecture validator missing.' }
Invoke-Expression $validator.Extent.Text
$rows=@()
foreach ($name in 'kv-helper','kv-agent','kv-cli','kv-mcp','kv-hook','kv-server','kv-relay-client') {
    $path=Join-Path $BinaryDirectory "$name.exe"
    $file=Get-Item -LiteralPath $path
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Refusing a non-file signing input.' }
    Assert-BinaryArchitecture $path $Architecture
    if ($file.VersionInfo.ProductName -cne 'KeyValet' -or $file.VersionInfo.ProductVersion -cne $version -or
        $file.VersionInfo.OriginalFilename -cne "$name.exe") { throw "Unexpected PE identity: $name." }
    if ((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'NotSigned') { throw 'Signing inputs must be unsigned build outputs.' }
    $rows+=@{name="$name.exe";sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();
        bytes=$file.Length;product='KeyValet';version=$version;architecture=$Architecture}
}
New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'bin') | Out-Null
foreach ($row in $rows) { Copy-Item -LiteralPath (Join-Path $BinaryDirectory $row.name) -Destination (Join-Path $OutputDirectory ('bin/'+$row.name)) }
@{version=$version;architecture=$Architecture;files=$rows;signing_complete=$false;
  source_commit=$env:GITHUB_SHA;workflow_run=$env:GITHUB_RUN_ID} | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'input-manifest.json') -Encoding UTF8
Copy-Item -LiteralPath "$repo/.github/signpath/windows-artifact.xml" -Destination $OutputDirectory
Set-Content -LiteralPath (Join-Path $OutputDirectory 'INTEGRATION-PENDING.txt') -Encoding UTF8 -Value (
    'Unsigned input for optional signing only. Windows releases do not require Authenticode; installed process authentication uses service/owner identity and protected paths. No signing service is enabled.')
Write-Host 'Seven native unsigned signing inputs validated.'
