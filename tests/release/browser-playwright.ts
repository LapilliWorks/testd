import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { lstat, mkdir, mkdtemp, readFile, rmdir, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';
import { connect } from 'node:tls';

const AUTOMATIC_CHECKS = [
	'HTTPS and secure context',
	'WebSocket, including 60 seconds idle',
	'Streaming SSE and 100 MiB upload',
	'Cookie sharing and project isolation',
];

export function isLoopback(address: string): boolean {
	const value = address.toLowerCase();
	const family = isIP(value);
	return (family === 4 && value.startsWith('127.')) ||
		(family === 6 && (value === '::1' || value.startsWith('::ffff:127.')));
}

export function validateBrowserChecks(text: string): void {
	const checks = JSON.parse(text);
	if (!Array.isArray(checks) || checks.length !== AUTOMATIC_CHECKS.length) {
		throw new Error('the page did not return every automatic browser check');
	}
	const names = checks.map(check => check?.name);
	if (new Set(names).size !== AUTOMATIC_CHECKS.length || AUTOMATIC_CHECKS.some(name => !names.includes(name))) {
		throw new Error('the page returned unexpected or duplicate browser checks');
	}
	if (checks.some(check => check.status !== 'pass')) throw new Error('an automatic browser check failed');
}

export function validateSecurityDetails(details: any, hostname: string, now: number): void {
	if (!details || details.subjectName !== hostname || details.issuer !== 'testd intermediate') {
		throw new Error('the browser did not report the expected leaf subject and intermediate');
	}
	if (!Number.isFinite(details.validFrom) || !Number.isFinite(details.validTo)
		|| details.validFrom > now || details.validTo <= now || details.validTo > now + 25 * 60 * 60) {
		throw new Error('the browser reported an invalid or unexpectedly long leaf lifetime');
	}
}

export function isExpectedUnknownFailure(message: string): boolean {
	return [/ERR_NAME_NOT_RESOLVED/i, /ERR_SSL_UNRECOGNIZED_NAME_ALERT/i, /NS_ERROR_UNKNOWN_HOST/i,
		/SSL_ERROR_UNRECOGNIZED_NAME_ALERT/i, /NSURLErrorDomain.*-1003/i].some(pattern => pattern.test(message));
}

async function checkLoopback(hostname: string): Promise<void> {
	let timer: ReturnType<typeof setTimeout>;
	let addresses;
	try {
		addresses = await Promise.race([
			lookup(hostname, { all: true }),
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error(`${hostname} lookup timed out`)), 10000);
			}),
		]);
	} finally {
		clearTimeout(timer!);
	}
	if (!addresses.length || addresses.some(entry => !isLoopback(entry.address))) {
		throw new Error(`${hostname} resolved outside loopback; refusing to send fixture data`);
	}
}

async function waitForRoutes(hosts: string[]): Promise<void> {
	const deadline = Date.now() + 30000;
	while (true) {
		try {
			for (const host of hosts) await checkLoopback(host);
			return;
		} catch (error: any) {
			if (error?.code !== 'ENOTFOUND' && error?.code !== 'EAI_AGAIN') throw error;
			if (Date.now() >= deadline) throw error;
			await Bun.sleep(250);
		}
	}
}

async function leafFingerprint(hostname: string, port: number, root: string): Promise<string> {
	await checkLoopback(hostname);
	const ca = await readFile(root);
	return await new Promise((resolve, reject) => {
		const socket = connect({ host: hostname, port, servername: hostname, ca, rejectUnauthorized: true });
		const timer = setTimeout(() => socket.destroy(new Error('certificate probe timed out')), 10000);
		socket.once('secureConnect', () => {
			const address = socket.remoteAddress ?? '';
			const certificate = socket.getPeerCertificate();
			clearTimeout(timer);
			socket.destroy();
			if (!isLoopback(address) || !certificate.raw) {
				reject(new Error('certificate probe did not reach a loopback leaf'));
				return;
			}
			resolve(createHash('sha256').update(certificate.raw).digest('hex'));
		});
		socket.once('error', error => { clearTimeout(timer); reject(error); });
	});
}

async function responseOnLoopback(response: any, expected: number): Promise<void> {
	if (!response || response.status() !== expected) throw new Error(`expected HTTP ${expected}`);
	const address = await response.serverAddr();
	if (!address || !isLoopback(address.ipAddress)) throw new Error('the browser response was not from loopback');
}

async function runPageChecks(page: any): Promise<void> {
	await page.locator('#run').click();
	await page.waitForFunction(() => {
		try { return JSON.parse(document.querySelector('#results')?.textContent ?? '').length === 4; }
		catch { return false; }
	}, null, { timeout: 240000 });
	validateBrowserChecks(await page.locator('#results').textContent() ?? '');
}

async function checkErrorPages(context: any, base: string, port: number): Promise<void> {
	try { await checkLoopback('unregistered.releasecheck.test'); }
	catch (error: any) {
		if (error?.code !== 'ENOTFOUND' && error?.code !== 'EAI_NONAME') throw error;
	}
	const dashboard = await context.newPage();
	const dead = await context.newPage();
	const unknown = await context.newPage();
	try {
		await responseOnLoopback(await dashboard.goto(`https://testd.test:${port}/`, { timeout: 30000 }), 200);
		await responseOnLoopback(await dead.goto(`https://dead.releasecheck.test:${port}/`, { timeout: 30000 }), 502);
		let rejected = false;
		try {
			await unknown.goto(`https://unregistered.releasecheck.test:${port}/`, { timeout: 30000 });
		} catch (error) {
			rejected = isExpectedUnknownFailure(String(error));
		}
		if (!rejected) throw new Error('the unregistered name did not fail specifically at DNS or TLS');
		await responseOnLoopback(await dashboard.goto(base, { timeout: 30000 }), 200);
	} finally {
		await Promise.all([dashboard.close(), dead.close(), unknown.close()]);
	}
}

async function certificateTool(args: string[]): Promise<void> {
	const process = Bun.spawn(['certutil', ...args], { stdin: 'ignore', stdout: 'ignore', stderr: 'pipe' });
	const timer = setTimeout(() => process.kill(), 30000);
	const [code, stderr] = await Promise.all([process.exited, new Response(process.stderr).text()]);
	clearTimeout(timer);
	if (code !== 0) throw new Error(`isolated browser trust setup failed: ${stderr.trim() || `exit ${code}`}`);
}

async function prepareBrowserTrust(engine: string, home: string, profile: string, root: string): Promise<void> {
	if (process.platform !== 'linux' || !['chromium', 'firefox'].includes(engine)) return;
	const store = engine === 'firefox' ? profile : join(home, '.pki', 'nssdb');
	await mkdir(store, { recursive: true, mode: 0o700 });
	await certificateTool(['-N', '-d', `sql:${store}`, '--empty-password']);
	await certificateTool(['-A', '-d', `sql:${store}`, '-n', 'testd fixture root', '-t', 'C,,', '-i', root]);
}

export function browserLaunchOptions(engine: string, home: string, temporary: string): any {
	const contextEnv = { ...process.env, HOME: home, USERPROFILE: home,
		APPDATA: join(home, 'AppData', 'Roaming'), LOCALAPPDATA: join(home, 'AppData', 'Local'),
		XDG_CONFIG_HOME: join(home, '.config'), XDG_CACHE_HOME: join(home, '.cache'),
		XDG_DATA_HOME: join(home, '.local', 'share'), XDG_RUNTIME_DIR: join(home, '.runtime'),
		TMPDIR: temporary, TMP: temporary, TEMP: temporary };
	const blocked = new Set(['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
		'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED',
		'NODE_OPTIONS', 'SSLKEYLOGFILE', 'RES_OPTIONS', 'HOSTALIASES', 'LOCALDOMAIN', 'DBUS_SESSION_BUS_ADDRESS',
		'WAYLAND_DISPLAY', 'DISPLAY', 'XAUTHORITY', 'SSH_AUTH_SOCK', 'GPG_AGENT_INFO', 'OPENSSL_CONF',
		'OPENSSL_MODULES', 'OPENSSL_ENGINES', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES',
		'DYLD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONUSERBASE']);
	for (const name of Object.keys(contextEnv)) if (blocked.has(name.toUpperCase())) delete contextEnv[name];
	const options: any = { headless: true, env: contextEnv, acceptDownloads: false };
	if (engine === 'chromium') {
		options.channel = 'chromium';
		options.chromiumSandbox = true;
		options.args = ['--no-proxy-server', '--disable-background-networking'];
	} else if (engine === 'firefox') {
		options.firefoxUserPrefs = { 'network.proxy.type': 0, 'network.trr.mode': 5 };
	}
	return options;
}

async function browserRun(playwright: any, engine: string): Promise<void> {
	const directory = process.env.TESTD_BROWSER_REPORT;
	const root = process.env.TESTD_BROWSER_ROOT;
	const commit = process.env.TESTD_BROWSER_COMMIT;
	const candidate = process.env.TESTD_BROWSER_CANDIDATE;
	const port = Number(process.env.TESTD_BROWSER_EDGE_PORT);
	if (!directory || !root || !commit || !candidate || !Number.isInteger(port) || port < 1 || port > 65535) {
		throw new Error('missing browser report, candidate identity, root certificate, or edge port');
	}
	const hostname = 'app.releasecheck.test';
	const origin = `https://${hostname}:${port}`;
	const hosts = [hostname, 'api.releasecheck.test', 'app.othercheck.test', 'dead.releasecheck.test', 'testd.test'];
	const allowed = new Set([...hosts, 'unregistered.releasecheck.test']);
	const profile = join(directory, `playwright-${engine}-profile`);
	const browserHome = join(directory, `playwright-${engine}-home`);
	let temporary = join(browserHome, 'tmp');
	let temporaryCreated = false;
	let temporaryIdentity: { dev: number; ino: number } | undefined;
	const evidence: any = { engine, origin, commit, candidate, checks: [], status: 'fail', cleanupComplete: false };
	let context: any;
	let launchAttempted = false;
	try {
		evidence.rootSha256 = createHash('sha256').update(await readFile(root)).digest('hex');
		await mkdir(profile, { mode: 0o700 });
		await mkdir(browserHome, { mode: 0o700 });
		await mkdir(join(browserHome, '.runtime'), { mode: 0o700 });
		if (process.platform === 'win32') {
			await mkdir(temporary, { mode: 0o700 });
		} else {
			temporary = await mkdtemp('/tmp/td-browser-');
			temporaryCreated = true;
			evidence.temporary = temporary;
			temporaryIdentity = await lstat(temporary);
		}
		await waitForRoutes(hosts);
		await prepareBrowserTrust(engine, browserHome, profile, root);
		launchAttempted = true;
		context = await playwright[engine].launchPersistentContext(profile,
			browserLaunchOptions(engine, browserHome, temporary));
		await context.route('**/*', (route: any) => {
			const url = new URL(route.request().url());
			if (['https:', 'wss:'].includes(url.protocol) && allowed.has(url.hostname) && Number(url.port || 443) === port) {
				return route.continue();
			}
			return route.abort('blockedbyclient');
		});
		const page = await context.newPage();
		const response = await page.goto(origin, { timeout: 30000 });
		await responseOnLoopback(response, 200);
		evidence.firstCertificate = await response.securityDetails();
		validateSecurityDetails(evidence.firstCertificate, hostname, Date.now() / 1000);
		if (!await page.evaluate(() => window.isSecureContext && location.protocol === 'https:')) {
			throw new Error('the browser did not establish a secure HTTPS context');
		}
		evidence.userAgent = await page.evaluate(() => navigator.userAgent);
		evidence.firstFingerprint = await leafFingerprint(hostname, port, root);
		evidence.checks.push('trusted TLS and secure context');
		await runPageChecks(page);
		evidence.checks.push('automatic browser checks before restart');
		await checkErrorPages(context, origin, port);
		evidence.checks.push('dashboard and negative routing controls');
		await page.locator('#restart').click();
		await page.waitForFunction(
			() => document.querySelector('#restart-status')?.textContent?.startsWith('Host restarted.'),
			null, { timeout: 90000 });
		await waitForRoutes(hosts);
		const renewed = await page.reload({ timeout: 30000 });
		await responseOnLoopback(renewed, 200);
		evidence.secondCertificate = await renewed.securityDetails();
		validateSecurityDetails(evidence.secondCertificate, hostname, Date.now() / 1000);
		evidence.secondFingerprint = await leafFingerprint(hostname, port, root);
		if (evidence.firstFingerprint === evidence.secondFingerprint) throw new Error('the restarted host reused its leaf');
		evidence.checks.push('restart and renewed trusted TLS');
		await runPageChecks(page);
		evidence.checks.push('automatic browser checks after restart');
		evidence.status = 'pass';
	} catch (error) {
		evidence.error = String(error);
		throw error;
	} finally {
		let cleanupError;
		try {
			if (context) await context.close();
			evidence.cleanupComplete = !!context || !launchAttempted;
		} catch (error) {
			cleanupError = error;
			evidence.status = 'fail';
			evidence.cleanupError = String(error);
		}
		if (temporaryCreated && !temporaryIdentity) evidence.cleanupComplete = false;
		if (temporaryIdentity && evidence.cleanupComplete) {
			try {
				const current = await lstat(temporary);
				if (!current.isDirectory() || current.dev !== temporaryIdentity.dev || current.ino !== temporaryIdentity.ino) {
					throw new Error('the browser temporary directory changed; leaving it untouched');
				}
				await rmdir(temporary);
			} catch (error) {
				cleanupError = error;
				evidence.status = 'fail';
				evidence.cleanupComplete = false;
				evidence.cleanupError = String(error);
			}
		}
		const destination = join(directory, `playwright-${engine}.json`);
		await writeFile(destination, JSON.stringify(evidence, null, '\t') + '\n', { flag: 'wx', mode: 0o600 });
		console.log(`Playwright evidence: ${destination}`);
		if (cleanupError) throw cleanupError;
	}
}

async function main(): Promise<void> {
	const engine = process.argv[2];
	if (!['chromium', 'firefox', 'webkit'].includes(engine)) throw new Error('choose chromium, firefox, or webkit');
	let playwright: any;
	try {
		playwright = await import('playwright');
	} catch {
		console.error('Install the Playwright package and selected browser before running this check');
		process.exitCode = 2;
		return;
	}
	if (process.argv[3] === '--probe') {
		const executable = playwright[engine].executablePath();
		if (!await Bun.file(executable).exists()) {
			console.error(`Install the Playwright ${engine} browser: ${executable}`);
			process.exitCode = 2;
		}
		return;
	}
	await browserRun(playwright, engine);
}

if (import.meta.main) {
	try { await main(); }
	catch (error) { console.error(error); process.exitCode = 1; }
}
