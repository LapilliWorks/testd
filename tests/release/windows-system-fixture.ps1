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

# The TLD is one DNS label, and the self-test's throwaway zone is longer than
# ten characters, so bound it only by the label limit.
if ($Tld -notmatch '^[a-z0-9]{1,63}$') { throw 'invalid TLD' }
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	throw 'The restore self-test needs an elevated shell'
}

# Build and store the root through .NET rather than New-SelfSignedCertificate:
# importing Microsoft.PowerShell.Security for the Cert: drive collides with the
# Security snap-in Windows PowerShell already has loaded, which reports its type
# data as a duplicate and stops the import. The state script opens the store
# the same direct way.
$key = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
	'CN=testd root testing', $key,
	[System.Security.Cryptography.HashAlgorithmName]::SHA256,
	[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$selfSigned = $request.CreateSelfSigned(
	[DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(1))
# Add the public part only, so nothing depends on the ephemeral key container.
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
	$selfSigned.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
$name = [System.Security.Cryptography.X509Certificates.StoreName]::Root
$location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new($name, $location)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
	$store.Add($certificate)
} finally {
	$store.Close()
}
Add-DnsClientNrptRule -Namespace ('.' + $Tld) -NameServers '127.0.0.1' | Out-Null
Write-Host "Installed fixture root $($certificate.Thumbprint) and NRPT rule for .$Tld"
