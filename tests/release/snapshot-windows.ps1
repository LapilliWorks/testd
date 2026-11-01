param(
	[Parameter(Mandatory = $true)] [string]$Destination,
	[switch]$RequireAdministrator
)
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
	[Security.Principal.WindowsBuiltInRole]::Administrator)
if ($RequireAdministrator -and -not $isAdmin) {
	throw 'Open PowerShell as Administrator for resolver and machine-trust checks'
}
$rules = @(Get-DnsClientNrptRule -ErrorAction Stop)
ConvertTo-Json -InputObject $rules -Depth 10 | Set-Content (Join-Path $Destination 'nrpt-before.json')
& certutil.exe -store Root | Set-Content (Join-Path $Destination 'root-store-before.txt')
if ($LASTEXITCODE -ne 0) { throw 'Could not snapshot the machine root store' }
$roots = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -eq 'CN=testd root' })
foreach ($root in $roots) {
	[IO.File]::WriteAllBytes((Join-Path $Destination ($root.Thumbprint + '.cer')),
		$root.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
}
if ($roots.Count -gt 0 -or ($rules | Where-Object { $_.Namespace -eq '.testdcheck' })) {
	throw 'Existing testd integration was backed up, but will not be replaced. Use a clean disposable VM'
}
Write-Host "Saved system inventory: $Destination"
