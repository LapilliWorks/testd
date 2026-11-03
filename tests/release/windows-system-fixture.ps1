# windows-system-fixture.ps1: install what `doctor --fix` would install on
# Windows, for the restore self-test only.
#
# The self-test needs a machine that differs from its snapshot; this is the
# smallest change with the same shape as the real one: an NRPT rule scoped to
# the throwaway TLD and a machine-root certificate named "testd root testing".
# `windows-system-state.ps1 -Action Restore` must then remove both.

[CmdletBinding()]
param(
	[string]$Tld = 'testdrestore'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# The runner captures this script through pipes and decodes UTF-8, as do the
# native tools whose output the checks read.
. "$PSScriptRoot\utf8-output.ps1"

# -Command does not load Microsoft.PowerShell.Security, which owns the Cert:
# drive that -CertStoreLocation resolves, so import it first.
Import-Module Microsoft.PowerShell.Security -ErrorAction Stop

# The TLD is one DNS label, and the self-test's throwaway zone is longer than
# ten characters, so bound it only by the label limit.
if ($Tld -notmatch '^[a-z0-9]{1,63}$') { throw 'invalid TLD' }
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	throw 'The restore self-test needs an elevated shell'
}

$certificate = New-SelfSignedCertificate -Subject 'CN=testd root testing' `
	-CertStoreLocation 'Cert:\LocalMachine\Root' -NotAfter (Get-Date).AddDays(1) `
	-KeyExportPolicy Exportable
Add-DnsClientNrptRule -Namespace ('.' + $Tld) -NameServers '127.0.0.1' | Out-Null
Write-Host "Installed fixture root $($certificate.Thumbprint) and NRPT rule for .$Tld"
