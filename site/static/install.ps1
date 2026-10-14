# Windows release installer. Authenticode signing is optional.
# Run a saved copy to select -Tag or a local -PackagePath.
[CmdletBinding()]
param([string]$Tag, [string]$PackagePath, [switch]$AllowUnsignedAgent, [switch]$SkipSetup)
$ErrorActionPreference = 'Stop'
$installer = Join-Path ([IO.Path]::GetTempPath()) ('keyvalet-install-' + [guid]::NewGuid().ToString('N') + '.ps1')
try {
    Invoke-WebRequest 'https://raw.githubusercontent.com/KeyValet/KeyValet/main/scripts/install.ps1' -UseBasicParsing -OutFile $installer
    & $installer @PSBoundParameters
} finally { Remove-Item $installer -Force -ErrorAction SilentlyContinue }
