# Windows tray diagnostics: which build is built, installed, and running.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\tray-debug.ps1

$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent

# The crate binary name has changed over time and the bundled app may be renamed
# to the product name. Older Windows builds also produced an underscore name.
# Match all of them so old installs are still reported.
# Case-sensitive: testd.exe is the CLI, Testd.exe is the product.
$binaryPattern = '^(Testd|testd[-_](host|gui))\.exe$'
$processPattern = '^(Testd|testd[-_](host|gui))$'

function Section($name) { Write-Host "`n== $name" -ForegroundColor Cyan }

function Show-Binary($path) {
	$file = Get-Item -LiteralPath $path
	$hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
	Write-Host $file.FullName
	Write-Host "  version  $($file.VersionInfo.FileVersion)   written $($file.LastWriteTime.ToString('s'))"
	Write-Host "  sha256   $hash"
	return $hash
}

function Find-Binaries($dir) {
	if (-not $dir -or -not (Test-Path -LiteralPath $dir)) {
		return @()
	}
	return @(Get-ChildItem -LiteralPath $dir -Filter *.exe -ErrorAction SilentlyContinue |
		Where-Object { $_.Name -cmatch $binaryPattern })
}

Section 'repository'
git -C $root log --oneline -1
git -C $root status --short -- Cargo.lock src-tauri/Cargo.toml

Section 'locked dependencies'
cargo tree --manifest-path "$root/Cargo.toml" -p testd-gui -i tray-icon
cargo tree --manifest-path "$root/Cargo.toml" -p testd-gui -i tauri

Section 'built binaries'
$builtHashes = @()
foreach ($binary in (Find-Binaries "$root\target\release")) {
	$builtHashes += Show-Binary $binary.FullName
}
if ($builtHashes.Count -eq 0) {
	Write-Host "no GUI binary under $root\target\release"
}

Section 'bundles'
$bundles = @(Get-ChildItem -Path "$root\target\release\bundle\nsis\*.exe" -ErrorAction SilentlyContinue |
	Sort-Object LastWriteTime)
foreach ($bundle in $bundles) {
	Write-Host "$($bundle.FullName)  written $($bundle.LastWriteTime.ToString('s'))"
}
if ($bundles.Count -eq 0) {
	Write-Host 'no NSIS installer under target\release\bundle\nsis'
}

Section 'running processes'
$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -cmatch $processPattern })
if ($running.Count -eq 0) {
	Write-Host 'none'
}
foreach ($p in $running) {
	$start = '?'
	try { $start = $p.StartTime.ToString('s') } catch {}
	$procPath = '?'
	try { $procPath = $p.Path } catch {}
	Write-Host "pid $($p.Id)  started $start  $procPath"
}

Section 'uninstall entries'
$uninstallPaths = @(
	'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
	'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$entries = @(Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue |
	Where-Object { $_.DisplayName -like 'Testd*' })
foreach ($entry in $entries) {
	Write-Host "$($entry.DisplayName)  version $($entry.DisplayVersion)  $($entry.InstallLocation)"
}

Section 'installed binaries'
$dirs = @(
	"$env:ProgramFiles\Testd",
	"${env:ProgramFiles(x86)}\Testd",
	"$env:LOCALAPPDATA\Testd",
	"$env:LOCALAPPDATA\Programs\Testd"
) + @($entries | ForEach-Object { $_.InstallLocation })

$installedHashes = @()
foreach ($binary in ($dirs | ForEach-Object { Find-Binaries $_ } | Sort-Object FullName -Unique)) {
	$installedHashes += Show-Binary $binary.FullName
}
if ($installedHashes.Count -eq 0) {
	Write-Host 'no installed GUI binary found in the usual locations'
}

Section 'tray trace'
$trace = Join-Path $env:TEMP 'testd-tray.log'
if (Test-Path -LiteralPath $trace) {
	# First line names the binary and tauri version that produced the trace.
	Get-Content -LiteralPath $trace -TotalCount 3
	Write-Host '...'
	Get-Content -LiteralPath $trace -Tail 40
} else {
	Write-Host "no trace at $trace"
}

Section 'verdict'
if ($installedHashes.Count -eq 0) {
	Write-Host 'not installed; run the build from target\release to test it directly'
} elseif (@($installedHashes | Where-Object { $builtHashes -notcontains $_ }).Count -eq 0) {
	Write-Host 'the installed binary matches target\release'
} else {
	Write-Host 'the installed binary differs from target\release, which is expected: cargo tauri build'
	Write-Host 'adds tauri/custom-protocol and patches target\release in place with bundle type'
	Write-Host 'information after bundling. Use the trace start line to identify the running build.'
}
