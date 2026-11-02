# testd-elevated.ps1: audited helper for Windows privileged actions.
#
# Invoked only by testd-setup. It accepts a closed set of actions and validates
# every argument before touching the machine. There is no dynamic code, no
# Invoke-Expression, and no arbitrary command execution.
#
# Actions:
#   InstallRoot  -CertPath <file> -Thumbprint <sha1-hex>
#   RemoveRoot   -Thumbprint <sha1-hex>
#   InstallNrpt  -Tld <label> -NameServer <ipv4>
#   RemoveNrpt   -Tld <label>

[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[ValidateSet('InstallRoot', 'RemoveRoot', 'InstallNrpt', 'RemoveNrpt')]
	[string]$Action,

	[string]$CertPath,
	[string]$Thumbprint,
	[string]$Tld,
	[string]$NameServer
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# The caller waits for this helper without an operator at the keyboard, so never
# ask: a confirmation on a redirected stdin would hang it.
$ConfirmPreference = 'None'

function Assert-Tld([string]$value) {
	# `test` is the product TLD; `testdcheck` is the throwaway release-test
	# zone. Refuse arbitrary TLDs such as .com, which would redirect unrelated
	# DNS through this helper.
	if ($value -notin @('test', 'testdcheck')) {
		throw "invalid TLD"
	}
}

function Assert-IPv4([string]$value) {
	if ($value -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
		throw "invalid IPv4 address"
	}
	foreach ($octet in $value.Split('.')) {
		if ([int]$octet -lt 0 -or [int]$octet -gt 255) {
			throw "invalid IPv4 address"
		}
	}
	if ($value -ne '127.0.0.1') {
		throw "name server must be the loopback DNS server"
	}
}

function Assert-Thumbprint([string]$value) {
	if ($value -notmatch '^[0-9A-Fa-f]{40,64}$') {
		throw "invalid certificate thumbprint"
	}
}

switch ($Action) {
	'InstallRoot' {
		if ([string]::IsNullOrWhiteSpace($CertPath)) { throw "missing -CertPath" }
		Assert-Thumbprint $Thumbprint
		if (-not (Test-Path -LiteralPath $CertPath -PathType Leaf)) { throw "certificate file not found" }

		$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
		if ($cert.Thumbprint -ne $Thumbprint) { throw "certificate thumbprint mismatch" }
		if ($cert.Subject -ne $cert.Issuer) { throw "certificate is not self-signed" }
		if (-not ($cert.Subject -match '(^|,\s*)CN=testd root(\s|,|$)')) { throw "certificate is not a testd root" }

		$basic = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
		if (-not $basic) { throw "certificate is not a CA" }
		$constraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$basic
		if (-not $constraints.CertificateAuthority) { throw "certificate is not a CA" }

		# The Cert: provider is not guaranteed to exist in a reduced elevated
		# session, so use certutil for the store operation.
		& certutil.exe -addstore -f Root $CertPath | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "certutil -addstore failed" }
	}

	'RemoveRoot' {
		Assert-Thumbprint $Thumbprint
		& certutil.exe -delstore -f Root $Thumbprint | Out-Null
		if ($LASTEXITCODE -ne 0) { throw "certutil -delstore failed" }
	}

	'InstallNrpt' {
		Assert-Tld $Tld
		Assert-IPv4 $NameServer
		$namespace = "." + $Tld
		$existing = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
			Where-Object { $_.Namespace -eq $namespace })
		$correct = $existing | Where-Object { $_.NameServers -contains $NameServer }
		if (-not $correct) {
			foreach ($rule in $existing) {
				# Only the cmdlet's own -Force suppresses its confirmation. Let a
				# failure stop the action: a stale rule must not survive.
				Remove-DnsClientNrptRule -Name $rule.Name -Force -Confirm:$false
			}
			Add-DnsClientNrptRule -Namespace $namespace -NameServers $NameServer | Out-Null
		}
	}

	'RemoveNrpt' {
		Assert-Tld $Tld
		$namespace = "." + $Tld
		Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
			Where-Object { $_.Namespace -eq $namespace } |
			ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -Confirm:$false }
	}
}
