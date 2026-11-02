# Windows host checks: NRPT, trust, edge, DNS, registration, sharing, quick launches.
#
# Run on the target host, not in the dev container:
#   cargo build --release -p testd
#   powershell -ExecutionPolicy Bypass -File tests\host\windows.ps1
#
# The script uses a throwaway %APPDATA% and a high edge port. NRPT and trust
# checks need a snapshot, so they only run through the runner, which restores the
# integration afterwards:
#   python tests\release\run.py host --system   # from an elevated shell

$ErrorActionPreference = 'Stop'
# The runner captures this script through pipes and decodes UTF-8, as do the
# native tools whose output the checks read.
. "$PSScriptRoot\..\release\utf8-output.ps1"
if ($env:TESTD_HOST_TEST_SYSTEM -eq '1' -and
	-not ($env:TESTD_HOST_SNAPSHOT -and (Test-Path (Join-Path $env:TESTD_HOST_SNAPSHOT 'manifest.json')))) {
	throw 'Run system checks through tests/release/run.py host --system so the integration is snapshotted first'
}
$Root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $Root

$Tld = if ($env:TESTD_HOST_TLD) { $env:TESTD_HOST_TLD } else { 'testdcheck' }
$env:TESTD_HOST_TLD = $Tld
$EdgePort = if ($env:TESTD_HOST_EDGE_PORT) { [int]$env:TESTD_HOST_EDGE_PORT } else { 8443 }
$AppPort = if ($env:TESTD_HOST_APP_PORT) { [int]$env:TESTD_HOST_APP_PORT } else { 18080 }
$LaunchPort = if ($env:TESTD_HOST_LAUNCH_PORT) { [int]$env:TESTD_HOST_LAUNCH_PORT } else { 18081 }
$TestdBin = if ($env:TESTD_BIN) { $env:TESTD_BIN } else { Join-Path $Root 'target\release\testd.exe' }

$Passed = 0; $Failed = 0; $Skipped = 0
function Pass($msg) { $script:Passed++; Write-Host "ok    $msg" }
function Fail($msg) { $script:Failed++; Write-Host "FAIL  $msg" -ForegroundColor Red }
function Skip($msg) { $script:Skipped++; Write-Host "skip  $msg" }
function Section($msg) { Write-Host "`n== $msg ==" }

function Wait-Tcp([string]$HostName, [int]$Port, [int]$Seconds = 30) {
	for ($i = 0; $i -lt $Seconds; $i++) {
		$client = New-Object System.Net.Sockets.TcpClient
		try {
			$async = $client.ConnectAsync($HostName, $Port)
			if ($async.Wait(1000) -and $client.Connected) { $client.Close(); return $true }
		} catch { }
		$client.Close()
		Start-Sleep -Seconds 1
	}
	return $false
}

function Wait-Log([string]$Pattern, [string]$Path, [int]$Seconds = 30) {
	for ($i = 0; $i -lt $Seconds; $i++) {
		if (Test-Path $Path) {
			$text = Get-Content $Path -Raw -Encoding utf8 -ErrorAction SilentlyContinue
			if ($text -and $text -match $Pattern) { return $true }
		}
		Start-Sleep -Seconds 1
	}
	return $false
}

function Ensure-Daemon {
	if ($script:Daemon -and -not $script:Daemon.HasExited) { return $true }
	Write-Host '      daemon is not running; restarting it for the system checks'
	$script:Daemon = Start-Process -FilePath $TestdBin -ArgumentList 'host' -PassThru -NoNewWindow `
		-RedirectStandardOutput $DaemonLog -RedirectStandardError $DaemonErr
	return (Wait-Tcp '127.0.0.1' 7737 30)
}

function Curl-Get([string]$HostName, [string]$Path = '/') {
	$url = "https://${HostName}:$EdgePort$Path"
	& curl.exe --silent --show-error --fail --max-time 10 --noproxy '*' --insecure --ssl-no-revoke `
		--resolve "${HostName}:${EdgePort}:127.0.0.1" $url
}

function Curl-Status([string]$HostName, [string]$Path = '/') {
	$url = "https://${HostName}:$EdgePort$Path"
	& curl.exe --silent --max-time 10 --noproxy '*' --insecure --ssl-no-revoke `
		--output NUL --write-out '%{http_code}' --resolve "${HostName}:${EdgePort}:127.0.0.1" $url
}

function System-Status([string]$HostName, [string]$Path = '/') {
	$url = "https://${HostName}:$EdgePort$Path"
	& curl.exe --silent --max-time 10 --noproxy '*' --ssl-no-revoke `
		--output NUL --write-out '%{http_code}' --resolve "${HostName}:${EdgePort}:127.0.0.1" $url
}

function Dashboard-Token {
	$path = Join-Path $AppData 'testd\control.json'
	if (-not (Test-Path $path)) { return '' }
	return (Get-Content $path -Raw | ConvertFrom-Json).token
}

function Dashboard-Get([string]$Path = '/') {
	$token = Dashboard-Token
	& curl.exe --silent --show-error --fail --max-time 10 --noproxy '*' `
		-H "X-Testd-Token: $token" "http://127.0.0.1:7737$Path"
}

function Dashboard-Post([string]$Path, [string]$Body = '') {
	if ($Body) {
		# PowerShell 5.1 does not quote an argument that holds both spaces and
		# double quotes, so a JSON body on the command line reaches curl broken.
		# Hand curl a file instead.
		$bodyFile = [IO.Path]::GetTempFileName()
		try {
			[IO.File]::WriteAllText($bodyFile, $Body, [Text.UTF8Encoding]::new($false))
			& curl.exe --silent --show-error --fail --max-time 20 --noproxy '*' `
				-H "X-Testd-Token: $(Dashboard-Token)" -H 'X-Testd-Request: 1' -H 'Content-Type: application/json' `
				--data-binary "@$bodyFile" "http://127.0.0.1:7737$Path"
		} finally {
			Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue
		}
	} else {
		& curl.exe --silent --show-error --fail --max-time 20 --noproxy '*' `
			-H "X-Testd-Token: $(Dashboard-Token)" -H 'X-Testd-Request: 1' -X POST "http://127.0.0.1:7737$Path"
	}
}

function Dashboard-Status([string]$Path = '/') {
	& curl.exe --silent --max-time 10 --noproxy '*' --output NUL --write-out '%{http_code}' "http://127.0.0.1:7737$Path"
}

# Capture a native command whose failure is part of the check. PowerShell 5.1
# turns redirected native stderr into a terminating error while the error
# preference is Stop, so relax the preference for the call itself. An optional
# stderr file keeps diagnostics out of a document that must stay parseable.
function Invoke-Captured([string]$File, [string[]]$Arguments, [string]$StderrPath = '') {
	$previous = $ErrorActionPreference
	$ErrorActionPreference = 'Continue'
	try {
		$text = if ($StderrPath) {
			(& $File @Arguments 2>$StderrPath | Out-String)
		} else {
			(& $File @Arguments 2>&1 | Out-String)
		}
		return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = $text }
	} finally {
		$ErrorActionPreference = $previous
	}
}

function OperatorSecret {
	$match = Select-String -Path $Config -Pattern '^secret\s*=\s*"(.*)"' | Select-Object -First 1
	if ($match) { $match.Matches[0].Groups[1].Value } else { '' }
}

function Invoke-Init {
	$psi = New-Object System.Diagnostics.ProcessStartInfo
	$psi.FileName = $TestdBin
	$psi.Arguments = "init --caddyfile `"`""
	$psi.UseShellExecute = $false
	$psi.RedirectStandardInput = $true
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError = $true
	$psi.StandardOutputEncoding = $Utf8
	$psi.StandardErrorEncoding = $Utf8
	$process = [System.Diagnostics.Process]::Start($psi)
	$process.StandardInput.Close()
	$stdout = $process.StandardOutput.ReadToEnd()
	$stderr = $process.StandardError.ReadToEnd()
	$process.WaitForExit()
	return @{ ExitCode = $process.ExitCode; Stderr = $stderr }
}

if (-not (Test-Path $TestdBin)) {
	Write-Error "testd binary not found: $TestdBin. Build with: cargo build --release -p testd"
	exit 2
}
$sourceDirs = @((Join-Path $Root 'src'), (Join-Path $Root 'crates'))
$newestSource = Get-ChildItem -Path $sourceDirs -Recurse -Filter *.rs -ErrorAction SilentlyContinue |
	Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($newestSource -and $newestSource.LastWriteTime -gt (Get-Item $TestdBin).LastWriteTime) {
	Write-Warning "$($newestSource.FullName) is newer than $TestdBin; rebuild with cargo build --release -p testd"
}

$OutputRoot = if ($env:TESTD_HOST_OUTPUT_DIR) { $env:TESTD_HOST_OUTPUT_DIR } else {
	Join-Path $env:LOCALAPPDATA 'testd\host-checks'
}
$TestHome = Join-Path $OutputRoot ('testd-host-' + [guid]::NewGuid().ToString('N'))
$AppData = Join-Path $TestHome 'AppData\Roaming'
New-Item -ItemType Directory -Path $AppData -Force | Out-Null
$env:APPDATA = $AppData
$env:USERPROFILE = $TestHome
$env:HOME = $TestHome
$Config = Join-Path $AppData 'testd\config.toml'
$Pki = Join-Path $AppData 'testd\pki'
$Control = Join-Path $AppData 'testd\control.json'
$Launches = Join-Path $AppData 'testd\launches.json'
$DaemonLog = Join-Path $TestHome 'daemon.log'
$DaemonErr = Join-Path $TestHome 'daemon.err'
$ClientLog = Join-Path $TestHome 'client.log'
$ClientErr = Join-Path $TestHome 'client.err'
$AppStop = Join-Path $TestHome 'app.stop'
$Daemon = $null
$AppJob = $null
$ClientProc = $null
$LaunchId = ''

Section 'host'
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os) {
	Write-Host "      $($os.Caption) $($os.Version) build $($os.BuildNumber) ($($os.OSArchitecture))"
} else {
	Write-Host "      $([System.Environment]::OSVersion.VersionString)"
}

Section 'binary'
try {
	& $TestdBin --help | Out-Null
	if ($LASTEXITCODE -eq 0) { Pass 'testd --help' } else { Fail 'testd --help' }
} catch { Fail 'testd --help' }
try {
	& $TestdBin --version | Out-Null
	if ($LASTEXITCODE -eq 0) { Pass 'testd --version' } else { Fail 'testd --version' }
} catch { Fail 'testd --version' }

Section 'init'
$first = Invoke-Init
if ($first.ExitCode -eq 0) { Pass 'init' } else { Fail "init: $($first.Stderr)" }
if (-not (Test-Path $Config)) {
	Write-Error "config missing: $Config"
	exit 2
}
$secret = OperatorSecret
if ($secret) { Pass 'init writes the operator secret' } else { Fail 'init writes the operator secret' }
if ($secret.Length -ge 16) {
	Pass 'operator secret is long enough'
} else {
	Fail "operator secret is too short: $($secret.Length)"
}
if (Test-Path (Join-Path $Pki 'root.crt')) {
	Pass 'init writes the root certificate'
} else {
	Fail 'init writes the root certificate'
}

$second = Invoke-Init
if ($second.ExitCode -eq 0 -and (OperatorSecret) -eq $secret) {
	Pass 're-init keeps the operator secret'
} else {
	Fail 're-init keeps the operator secret'
}

# Keep the daemon off privileged and public ports for the throwaway run.
$lines = Get-Content $Config -Encoding utf8
$new = New-Object System.Collections.Generic.List[string]
foreach ($line in $lines) {
	$new.Add($line)
	if ($line -match '^\[host\]') {
		$new.Add("listen_addr = `"127.0.0.1:7737`"")
		$new.Add("edge_addr = `"127.0.0.1:$EdgePort`"")
	}
}
$new | Set-Content $Config -Encoding utf8

Section 'daemon'
$Daemon = Start-Process -FilePath $TestdBin -ArgumentList 'host' -PassThru -NoNewWindow `
	-RedirectStandardOutput $DaemonLog -RedirectStandardError $DaemonErr
if (Wait-Tcp '127.0.0.1' 7737 30) {
	Pass 'testd host'
} else {
	Fail 'testd host'
	Get-Content $DaemonErr -Encoding utf8 -ErrorAction SilentlyContinue | Select-Object -First 120
}
if (Wait-Tcp '127.0.0.1' $EdgePort 30) { Pass "HTTPS listener $EdgePort" } else { Fail "HTTPS listener $EdgePort" }
if (Test-Path $Control) { Pass 'control channel file' } else { Fail 'control channel file' }

# The lock must reject a second daemon before it touches the CA or the ports.
$lockOut = Join-Path $TestHome 'second-host.out'
$lockErr = Join-Path $TestHome 'second-host.err'
$secondDaemon = Start-Process -FilePath $TestdBin -ArgumentList 'host' -PassThru -Wait -NoNewWindow `
	-RedirectStandardOutput $lockOut -RedirectStandardError $lockErr
$lockText = ''
if (Test-Path $lockOut) { $lockText += Get-Content $lockOut -Raw -Encoding utf8 }
if (Test-Path $lockErr) { $lockText += Get-Content $lockErr -Raw -Encoding utf8 }
if ($secondDaemon.ExitCode -ne 0 -and $lockText -match 'another testd daemon is already running') {
	Pass 'a second daemon is refused'
} else {
	Fail 'a second daemon is refused'
}

Section 'edge'
if ((Curl-Status "testd.$Tld" '/ok.svg') -eq '404') {
	Pass "edge terminates TLS for testd.$Tld"
} else {
	Fail "edge terminates TLS for testd.$Tld"
}
# The dashboard is loopback-only, so the edge answers 404 for its name. Check the
# status rather than letting --fail write to stderr: PowerShell 5.1 turns native
# stderr into a terminating error while the error preference is Stop.
if ((Curl-Status "testd.$Tld" '/') -eq '404') {
	Pass 'the dashboard is not served through the edge'
} else {
	Fail 'the dashboard is not served through the edge'
}
if ((Curl-Status "testd.$Tld" '/api/status') -eq '404') {
	Pass 'the dashboard is not proxied through the edge'
} else {
	Fail 'the dashboard is not proxied through the edge'
}

Section 'local dashboard'
try {
	$page = Dashboard-Get '/'
	if ($page -match 'Active domains') {
		Pass 'loopback dashboard serves the page'
	} else {
		Fail 'loopback dashboard serves the page'
	}
	if ($page -match 'Quick launches') {
		Pass 'dashboard shows quick launches'
	} else {
		Fail 'dashboard shows quick launches'
	}
} catch { Fail "loopback dashboard serves the page: $_" }
try {
	$status = (Dashboard-Get '/api/status') | ConvertFrom-Json
	$properties = $status.PSObject.Properties.Name
	if ($status.tld -and ($properties -contains 'domains') -and ($properties -contains 'shares')) {
		Pass 'loopback status document'
	} else {
		Fail 'loopback status document'
	}
} catch { Fail "loopback status document: $_" }
try {
	$ca = Dashboard-Get '/ca.crt'
	if ($ca -match 'BEGIN CERTIFICATE') {
		Pass 'CA download from the dashboard'
	} else {
		Fail 'CA download from the dashboard'
	}
} catch { Fail "CA download from the dashboard: $_" }
try {
	$launchesJson = Dashboard-Get '/api/local/launches'
	if ($launchesJson -match '^\s*\[') { Pass 'quick launch endpoint' } else { Fail 'quick launch endpoint' }
} catch { Fail "quick launch endpoint: $_" }
try {
	$certificate = (Dashboard-Get '/api/local/certificate') | ConvertFrom-Json
	if ($certificate.fingerprint_sha256 -and $certificate.summary) {
		Pass 'certificate status endpoint'
	} else {
		Fail 'certificate status endpoint'
	}
} catch { Fail "certificate status endpoint: $_" }
$mutationStatus = & curl.exe --silent --max-time 10 --noproxy '*' -X POST `
	--output NUL --write-out '%{http_code}' 'http://127.0.0.1:7737/unshare/none'
if ($mutationStatus -eq '403') {
	Pass 'dashboard mutations require the request header'
} else {
	Fail 'dashboard mutations require the request header'
}
$hostStatus = & curl.exe --silent --max-time 10 --noproxy '*' -H 'Host: example.com' `
	--output NUL --write-out '%{http_code}' 'http://127.0.0.1:7737/'
if ($hostStatus -eq '403') {
	Pass 'dashboard rejects a non-loopback Host header'
} else {
	Fail 'dashboard rejects a non-loopback Host header'
}

Section 'doctor state checks'
$doctorJson = & $TestdBin doctor --json 2>$null
try {
	$checks = @{}
	($doctorJson | ConvertFrom-Json).checks | ForEach-Object { $checks[$_.name] = $_.ok }
	if ($checks['secret'] -eq $true -and $checks['config'] -eq $true) {
		Pass 'doctor reports the operator secret'
	} else {
		Fail "doctor reports the operator secret: $($checks.GetEnumerator() | Out-String)"
	}
} catch {
	Fail "doctor reports the operator secret: $_"
}

Section 'DNS'
try {
	$answer = Resolve-DnsName -Name "testd.$Tld" -Server 127.0.0.1 -Type A -DnsOnly -ErrorAction Stop
	if ($answer.IPAddress -contains '127.0.0.1') { Pass "testd.$Tld -> 127.0.0.1" } else { Fail "testd.$Tld A record" }
} catch { Fail "testd.$Tld A record: $_" }

Section 'registration'
$AppJob = Start-Job -ScriptBlock {
	param($Port, $StopPath)
	$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
	$listener.Start()
	try {
		# Poll instead of blocking in AcceptTcpClient: a job blocked there cannot
		# be stopped, which makes cleanup hang.
		while (-not (Test-Path -LiteralPath $StopPath)) {
			if (-not $listener.Pending()) {
				Start-Sleep -Milliseconds 100
				continue
			}
			$client = $listener.AcceptTcpClient()
			try {
				$stream = $client.GetStream()
				$stream.ReadTimeout = 2000
				$reader = New-Object System.IO.StreamReader($stream)
				$null = $reader.ReadLine()
				$body = [System.Text.Encoding]::UTF8.GetBytes('hello from testd')
				$headerText = "HTTP/1.1 200 OK`r`nContent-Length: $($body.Length)`r`n" +
					"Content-Type: text/plain`r`nConnection: close`r`n`r`n"
				$header = [System.Text.Encoding]::ASCII.GetBytes($headerText)
				$stream.Write($header, 0, $header.Length)
				$stream.Write($body, 0, $body.Length)
			} catch {
				# A client that drops before the response is not a test failure.
			} finally {
				$client.Close()
			}
		}
	} finally {
		$listener.Stop()
	}
} -ArgumentList $AppPort, $AppStop
if (-not (Wait-Tcp '127.0.0.1' $AppPort 10)) { Fail 'test upstream listener' } else { Pass 'test upstream listener' }

# On the node itself the default loopback profile uses [host] secret.
Remove-Item Env:TESTD_TOKEN -ErrorAction SilentlyContinue
$ClientProc = Start-Process -FilePath $TestdBin -ArgumentList 'run', "app.testdproj:$AppPort" -PassThru `
	-NoNewWindow -RedirectStandardOutput $ClientLog -RedirectStandardError $ClientErr
if (Wait-Log '\[reg\]' $ClientErr 20) {
	Pass 'client registered with the node operator secret'
} else {
	Fail 'client registered with the node operator secret'
	if (Test-Path $ClientErr) {
		Get-Content $ClientErr -Encoding utf8 -ErrorAction SilentlyContinue | Select-Object -First 40 |
			ForEach-Object { Write-Host "      $_" }
	}
}
try {
	$body = Curl-Get "app.testdproj.$Tld" '/'
	if ($body -match 'hello from testd') { Pass 'proxied request' } else { Fail 'proxied request' }
} catch { Fail "proxied request: $_" }
try {
	$answer = Resolve-DnsName -Name "app.testdproj.$Tld" -Server 127.0.0.1 -Type A -DnsOnly -ErrorAction Stop
	if ($answer.IPAddress -contains '127.0.0.1') { Pass 'registered name in DNS' } else { Fail 'registered name in DNS' }
} catch { Fail "registered name in DNS: $_" }

# A named profile with no credential asks for a token. The loopback address
# alone must not make the node's operator secret available to that profile.
$AccessOut = Join-Path $TestHome 'access-request.out'
$AccessErr = Join-Path $TestHome 'access-request.err'
$AccessProc = Start-Process -FilePath $TestdBin -PassThru -NoNewWindow `
	-ArgumentList 'deregister', 'app.testdproj', '--host', '127.0.0.1:7737', '--token-profile', 'access-test' `
	-RedirectStandardOutput $AccessOut -RedirectStandardError $AccessErr
if (Wait-Log 'requested access' $AccessErr 10) {
	Pass 'a leaf with no credential requests a token'
} else {
	Fail 'a leaf with no credential requests a token'
	if (Test-Path $AccessErr) { Get-Content $AccessErr -Encoding utf8 -ErrorAction SilentlyContinue | Select-Object -First 40 }
}
$requestText = if (Test-Path $AccessErr) { Get-Content $AccessErr -Raw -Encoding utf8 -ErrorAction SilentlyContinue } else { '' }
$requestId = $null
if ($requestText -match '\(request ([^)]+)\)') { $requestId = $Matches[1] }
$requests = Invoke-Captured $TestdBin 'requests'
if ($requestId -and $requests.Text -match [regex]::Escape($requestId)) {
	Pass 'testd requests lists the waiting request'
} else {
	Fail "testd requests lists the waiting request: $($requests.Text)"
}
$approve = Invoke-Captured $TestdBin 'approve', $requestId
if ($approve.ExitCode -eq 0) {
	Pass 'testd approve delivers the token'
} else {
	Fail "testd approve delivers the token: $($approve.Text)"
}
for ($i = 0; $i -lt 50 -and $AccessProc -and -not $AccessProc.HasExited; $i++) { Start-Sleep -Milliseconds 200 }
if ($AccessProc -and -not $AccessProc.HasExited) { Stop-Process -Id $AccessProc.Id -Force -ErrorAction SilentlyContinue }
$credential = Join-Path $AppData 'testd\credentials\access-test'
if ((Test-Path $credential) -and (Get-Item $credential).Length -gt 0) {
	Pass 'the leaf saves the issued token'
} else {
	Fail 'the leaf saves the issued token'
}
$tokens = Invoke-Captured $TestdBin 'tokens'
$tokenLines = @($tokens.Text -split '\r?\n' | Where-Object { $_ })
if ($tokenLines.Count -gt 0 -and $tokenLines[0] -ne 'no issued tokens') {
	Pass 'testd tokens lists the issued token'
} else {
	Fail "testd tokens lists the issued token: $($tokenLines -join ' ')"
}
$tokenId = if ($tokenLines.Count -gt 0) { ($tokenLines[0] -split '\s+')[0] } else { '' }
$revoke = Invoke-Captured $TestdBin 'tokens', '--revoke', $tokenId
if ($revoke.ExitCode -eq 0) {
	Pass 'testd tokens --revoke withdraws the token'
} else {
	Fail "testd tokens --revoke withdraws the token: $($revoke.Text)"
}

if ($ClientProc) { Stop-Process -Id $ClientProc.Id -Force -ErrorAction SilentlyContinue; $ClientProc = $null }
$removed = $false
for ($i = 0; $i -lt 20; $i++) {
	if ((Curl-Status "app.testdproj.$Tld" '/') -eq '404') { $removed = $true; break }
	Start-Sleep -Seconds 1
}
if ($removed) { Pass 'disconnect removes the name' } else { Fail 'disconnect removes the name' }

Section 'sharing'
# The happy path needs a fake provider binary, which a PowerShell script cannot
# be for a native spawn; provider shapes are covered by `cargo test -p
# testd-daemon --test share` on any OS.
$share = Invoke-Captured $TestdBin 'share', 'app.testdproj'
if ($share.ExitCode -ne 0 -and $share.Text -match 'not registered') {
	Pass 'share refuses an unregistered name'
} else {
	Fail "share refuses an unregistered name: $($share.Text)"
}
$shareList = Invoke-Captured $TestdBin 'share', '--list'
if ($shareList.ExitCode -eq 0) { Pass 'share --list answers' } else { Fail "share --list answers: $($shareList.Text)" }
$unknown = Invoke-Captured $TestdBin 'share', 'app.testdproj', '--provider', 'mystery'
if ($unknown.ExitCode -ne 0 -and $unknown.Text -match 'unknown provider') {
	Pass 'an unknown provider is refused'
} else {
	Fail "an unknown provider is refused: $($unknown.Text)"
}

Section 'quick launches'
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
	Skip 'python is needed to start a quick launch in this check'
} else {
	$definition = [ordered]@{
		label = 'host check'
		program = $python.Source
		args = @('-m', 'http.server', "$LaunchPort", '--bind', '127.0.0.1')
		entries = @(@{ domain = 'launch.testdproj'; target = "127.0.0.1:$LaunchPort" })
	}
	try {
		$saveBody = $definition | ConvertTo-Json -Compress -Depth 5
		$saved = (Dashboard-Post '/api/local/launches/save' $saveBody) | ConvertFrom-Json
		$LaunchId = $saved.id
		if ($LaunchId) { Pass 'dashboard saves a quick launch' } else { Fail 'dashboard saves a quick launch' }
		if (Test-Path $Launches) { Pass 'launch definitions are stored' } else { Fail 'launch definitions are stored' }

		$null = Dashboard-Post '/api/local/launches/start' (@{ id = $LaunchId } | ConvertTo-Json -Compress)
		$started = $false
		for ($i = 0; $i -lt 30; $i++) {
			$launches = (Dashboard-Get '/api/local/launches') | ConvertFrom-Json
			$launch = $launches | Where-Object { $_.id -eq $LaunchId }
			if ($launch.running -and ($launch.states | Where-Object { $_.state -eq 'confirmed' })) {
				$started = $true
				break
			}
			Start-Sleep -Seconds 1
		}
		if ($started) { Pass 'quick launch reaches confirmed' } else { Fail 'quick launch reaches confirmed' }
		if ((Curl-Status "launch.testdproj.$Tld" '/') -eq '200') {
			Pass 'quick launch name is proxied'
		} else {
			Fail 'quick launch name is proxied'
		}
		$answer = Resolve-DnsName -Name "launch.testdproj.$Tld" -Server 127.0.0.1 -Type A -DnsOnly -ErrorAction Stop
		if ($answer.IPAddress -contains '127.0.0.1') {
			Pass 'quick launch name is in DNS'
		} else {
			Fail 'quick launch name is in DNS'
		}

		$null = Dashboard-Post '/api/local/launches/stop' (@{ id = $LaunchId } | ConvertTo-Json -Compress)
		$stopped = $false
		for ($i = 0; $i -lt 20; $i++) {
			if ((Curl-Status "launch.testdproj.$Tld" '/') -ne '200') { $stopped = $true; break }
			Start-Sleep -Seconds 1
		}
		if ($stopped) { Pass 'stopping a launch removes the name' } else { Fail 'stopping a launch removes the name' }

		$null = Dashboard-Post '/api/local/launches/delete' (@{ id = $LaunchId } | ConvertTo-Json -Compress)
		$remaining = (Dashboard-Get '/api/local/launches') | ConvertFrom-Json
		if (-not ($remaining | Where-Object { $_.id -eq $LaunchId })) {
			Pass 'dashboard deletes a quick launch'
		} else {
			Fail 'dashboard deletes a quick launch'
		}
		$LaunchId = ''
	} catch {
		Fail "quick launches: $_"
	}
}

Section 'url actions'
$url = Invoke-Captured $TestdBin 'url', 'testd://fix/unknown'
if ($url.ExitCode -ne 0 -and $url.Text -match 'unknown testd action') {
	Pass 'an unknown testd:// action is refused'
} else {
	Fail "an unknown testd:// action is refused: $($url.Text)"
}

Section 'NRPT and trust'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
	[Security.Principal.WindowsBuiltInRole]::Administrator)
$daemonUp = $true
if ($env:TESTD_HOST_TEST_SYSTEM -eq '1' -and $isAdmin) {
	$daemonUp = Ensure-Daemon
	if ($daemonUp) { Pass 'daemon running for the system checks' } else { Fail 'daemon running for the system checks' }
}
if ($env:TESTD_HOST_TEST_SYSTEM -eq '1' -and $isAdmin -and $daemonUp) {
	$curlPath = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
	if ($curlPath) {
		Write-Host "      curl: $curlPath"
		(& $curlPath --version | Select-Object -First 1) | ForEach-Object { Write-Host "      $_" }
	} else {
		Write-Host '      curl.exe not found on PATH'
	}
	# Keep the JSON document and the diagnostics apart into separate streams.
	$doctorErr = Join-Path $TestHome 'doctor.err.txt'
	$doctor = Invoke-Captured $TestdBin 'doctor', '--fix', '--json' $doctorErr
	if ($doctor.ExitCode -eq 0) {
		Pass 'doctor --fix'
	} else {
		Fail 'doctor --fix'
		Get-Content $doctorErr -Encoding utf8 -ErrorAction SilentlyContinue | Select-Object -First 80 |
			ForEach-Object { Write-Host "      $_" }
	}
	try {
		$checks = @{}
		($doctor.Text | ConvertFrom-Json).checks | ForEach-Object { $checks[$_.name] = $_.ok }
		if ($checks['resolver'] -eq $true -and $checks['resolution'] -eq $true -and $checks['edge'] -eq $true) {
			Pass 'resolver, name resolution, and edge'
		} else {
			Fail "resolver, name resolution, or edge: $($checks.GetEnumerator() | Out-String)"
		}
	} catch {
		Fail "resolver, name resolution, or edge: $_"
	}
	$rootPath = Join-Path $Pki 'root.crt'
	if (Test-Path $rootPath) {
		try {
			$pem = Get-Content $rootPath -Raw -Encoding utf8
			$pattern = '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----'
			$base64 = [regex]::Match($pem, $pattern, 'Singleline').Groups[1].Value
			$der = [Convert]::FromBase64String(($base64 -replace '\s', ''))
			$rootThumb = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der)).Thumbprint
			# Look the certificate up in the store itself: certutil's text is
			# localized and prints the hash in spaced pairs.
			$storeName = [System.Security.Cryptography.X509Certificates.StoreName]::Root
			$storePlace = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
			$store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storePlace)
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
			try {
				$installed = $store.Certificates.Find(
					[System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $rootThumb, $false)
			} finally {
				$store.Close()
			}
			if ($installed.Count -gt 0) {
				Pass "current root installed ($rootThumb)"
			} else {
				Fail "current root missing from the machine store ($rootThumb)"
			}
		} catch {
			Skip "current root thumbprint: $_"
		}
	}
	$rules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Namespace -eq ".$Tld" }
	if ($rules) {
		Pass 'NRPT rule'
	} else {
		Fail 'NRPT rule'
		Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
			Format-Table Namespace, NameServers, Name | Out-String | Write-Host
	}
	if ((certutil -store Root) -match 'testd root') { Pass 'root trust store' } else { Fail 'root trust store' }
	# No --insecure here: any HTTP status means Schannel accepted the chain from
	# the machine trust store.
	if ((System-Status "testd.$Tld" '/ok.svg') -eq '404') {
		Pass 'system trust (TLS accepted without --insecure)'
	} else {
		Fail "system trust (TLS accepted without --insecure): $((System-Status "testd.$Tld" '/ok.svg'))"
	}
	$resolverUrl = Invoke-Captured $TestdBin 'url', 'testd://fix/resolver'
	if ($resolverUrl.ExitCode -eq 0) {
		Pass 'testd url forwards the resolver repair'
	} else {
		Fail "testd url forwards the resolver repair: $($resolverUrl.Text)"
	}
	$certificateUrl = Invoke-Captured $TestdBin 'url', 'testd://fix/certificate'
	if ($certificateUrl.ExitCode -eq 0) {
		Pass 'testd url forwards the certificate repair'
	} else {
		Fail "testd url forwards the certificate repair: $($certificateUrl.Text)"
	}
} elseif ($env:TESTD_HOST_TEST_SYSTEM -eq '1') {
	Fail 'system checks requested, but this PowerShell is not elevated; open PowerShell as Administrator and rerun'
} else {
	Skip 'system checks disabled (set TESTD_HOST_TEST_SYSTEM=1 in an elevated shell to test NRPT and trust)'
}

Section 'launch at login'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runValue = (Get-ItemProperty -Path $runKey -Name 'dev.testd.host' -ErrorAction SilentlyContinue).'dev.testd.host'
if ($runValue) {
	if ($runValue -match 'testd') {
		Pass "launch-at-login entry ($runValue)"
	} else {
		Fail "launch-at-login entry points elsewhere: $runValue"
	}
} else {
	Skip 'launch at login not configured yet (start the tray once): HKCU\...\Run\dev.testd.host'
}

Section 'cleanup'
if ($env:TESTD_HOST_SNAPSHOT) {
	Write-Host "integration: restored from $env:TESTD_HOST_SNAPSHOT by tests/release/run.py after this script"
}
Write-Host "config:      $TestHome"

if ($ClientProc) { Stop-Process -Id $ClientProc.Id -Force -ErrorAction SilentlyContinue; $ClientProc = $null }
if ($AppJob) {
	Set-Content -LiteralPath $AppStop -Value 'stop' -ErrorAction SilentlyContinue
	$null = Wait-Job $AppJob -Timeout 5
	Remove-Job $AppJob -Force -ErrorAction SilentlyContinue
	$AppJob = $null
}
if ($LaunchId) {
	try { $null = Dashboard-Post '/api/local/launches/stop' (@{ id = $LaunchId } | ConvertTo-Json -Compress) } catch { }
}
if ($Daemon) { Stop-Process -Id $Daemon.Id -Force -ErrorAction SilentlyContinue }

Write-Host "`npassed $Passed, failed $Failed, skipped $Skipped"
if ($Failed -ne 0) { exit 1 }
