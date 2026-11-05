import { afterAll, beforeAll, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

let child: ReturnType<typeof Bun.spawn>;
let directory: string;
let origin: string;
const appOrigin = 'https://app.releasecheck.test:8443';

async function waitForPort(path: string, fixture: ReturnType<typeof Bun.spawn>): Promise<number> {
	for (let attempt = 0; attempt < 250; attempt++) {
		if (fixture.exitCode !== null) throw new Error(`Fixture exited before binding: ${fixture.exitCode}`);
		const file = Bun.file(path);
		if (await file.exists()) {
			const port = Number(await file.text());
			if (Number.isInteger(port) && port > 0 && port <= 65535) return port;
		}
		await Bun.sleep(20);
	}
	throw new Error('Fixture did not report its bound port');
}

beforeAll(async () => {
	directory = await mkdtemp(join(tmpdir(), 'testd-browser-fixture-'));
	await Bun.write(join(directory, 'report.json'),
		JSON.stringify({ commit: 'fixture-commit', browser_host_managed: true }));
	const portFile = join(directory, 'listener-port');
	child = Bun.spawn([process.execPath, 'tests/release/browser-server.ts'], {
		env: { ...process.env, TESTD_BROWSER_REPORT: directory, TESTD_BROWSER_PORT: '0',
			TESTD_BROWSER_TLD: 'test', TESTD_BROWSER_EDGE_PORT: '8443' },
		stdout: 'inherit', stderr: 'inherit',
	});
	try {
		origin = `http://127.0.0.1:${await waitForPort(portFile, child)}`;
		if (!(await fetch(`${origin}/meta`)).ok) throw new Error('Fixture did not become ready');
	} catch (error) {
		if (child.exitCode === null) child.kill();
		await child.exited;
		throw error;
	}
}, 10_000);

afterAll(async () => {
	if (child && child.exitCode === null) child.kill();
	if (child) await child.exited;
	if (directory) await rm(directory, { recursive: true, force: true });
});

test('binds concurrent fixtures to distinct ephemeral ports', async () => {
	const directories = Array.from({ length: 4 }, (_, index) => join(directory, `concurrent-${index}`));
	await Promise.all(directories.map(async path => {
		await mkdir(path);
		await Bun.write(join(path, 'report.json'), JSON.stringify({ commit: 'fixture-commit' }));
	}));
	const children = directories.map(path => Bun.spawn([process.execPath, 'tests/release/browser-server.ts'], {
		env: { ...process.env, TESTD_BROWSER_REPORT: path, TESTD_BROWSER_PORT: '0',
			TESTD_BROWSER_TLD: 'test', TESTD_BROWSER_EDGE_PORT: '8443' },
		stdout: 'ignore', stderr: 'inherit',
	}));
	try {
		const ports = await Promise.all(children.map((fixture, index) =>
			waitForPort(join(directories[index], 'listener-port'), fixture)));
		expect(new Set(ports).size).toBe(children.length);
		for (const port of ports) expect((await fetch(`http://127.0.0.1:${port}/meta`)).ok).toBe(true);
	} finally {
		for (const fixture of children) if (fixture.exitCode === null) fixture.kill();
		await Promise.all(children.map(fixture => fixture.exited));
	}
}, 10_000);

test('serves the harness and metadata', async () => {
	expect(await (await fetch(`${origin}/`)).text()).toContain('testd browser release checks');
	expect(await (await fetch(`${origin}/meta`)).json()).toEqual({ tld: 'test', edgePort: 8443,
		commit: 'fixture-commit', hostManaged: true });
});

test('asks the operator to check the dashboard, an unregistered name, and a dead upstream', async () => {
	const page = await (await fetch(`${origin}/`)).text();
	expect(page).toContain('Dashboard: expect 200');
	expect(page).toContain('unregistered.releasecheck.${metadata.tld}');
	expect(page).toContain('Unregistered name: expect a DNS or TLS failure');
	expect(page).toContain('Registered, dead upstream: expect 502');
	expect(page).not.toContain('expect 404');
});

test('streams SSE and counts uploaded bytes', async () => {
	const response = await fetch(`${origin}/events`);
	const reader = response.body!.getReader();
	const first = await reader.read();
	expect(new TextDecoder().decode(first.value)).toContain('data: first');
	await reader.cancel();
	const upload = await fetch(`${origin}/upload`, { method: 'POST', body: new Uint8Array(1024) });
	expect(await upload.json()).toEqual({ bytes: 1024 });
});

test('sets project cookies and permits only the harness origin to read them', async () => {
	const response = await fetch(`${origin}/cookie/set`);
	expect(response.headers.get('set-cookie')).toContain('Domain=releasecheck.test');
	expect(response.headers.get('set-cookie')).toContain('Secure; HttpOnly; SameSite=Lax');
	const cookie = await fetch(`${origin}/cookie`, { headers: { Origin: appOrigin, Cookie: 'releasecheck=fixture' } });
	expect(cookie.headers.get('access-control-allow-origin')).toBe(appOrigin);
	expect(await cookie.json()).toEqual({ cookie: 'releasecheck=fixture' });
	const foreign = await fetch(`${origin}/cookie`, { headers: { Origin: 'https://foreign.example' } });
	expect(foreign.headers.get('access-control-allow-origin')).toBeNull();
});

test('refuses cross-site reports and retains passing and failing operator evidence', async () => {
	const forbidden = await fetch(`${origin}/report`, { method: 'POST', body: '{}' });
	expect(forbidden.status).toBe(403);
	const page = await (await fetch(`${origin}/`)).text();
	const names = Array.from(page.matchAll(/await check\('([^']+)'/g), match => match[1]);
	expect(names).toHaveLength(4);
	const result = { browser: 'fixture browser', notes: 'fixture OS', fingerprint: 'a'.repeat(64),
		manualConfirmed: true, checks: names.map(name => ({ name, status: 'pass' })) };
	const headers = { Origin: appOrigin, 'X-Testd-Browser-Report': '1' };
	const response = await fetch(`${origin}/report`, { method: 'POST', headers, body: JSON.stringify(result) });
	expect(response.ok).toBe(true);
	const failed = { ...result, manualConfirmed: false, fingerprint: '',
		checks: result.checks.map(check => ({ ...check, status: 'fail' })) };
	expect((await fetch(`${origin}/report`, { method: 'POST', headers, body: JSON.stringify(failed) })).ok).toBe(true);
	const incomplete = { ...result, checks: result.checks.slice(0, 3) };
	expect((await fetch(`${origin}/report`, { method: 'POST', headers, body: JSON.stringify(incomplete) })).status).toBe(400);
	const files = (await readdir(directory)).filter(file => file.startsWith('browser-'));
	expect(files).toHaveLength(2);
	const reports = await Promise.all(files.map(file => Bun.file(join(directory, file)).json()));
	expect(reports.every(report => report.commit === 'fixture-commit' && report.origin === appOrigin)).toBe(true);
	expect(reports.some(report => report.manualConfirmed === false)).toBe(true);
});

test('records restart requests and reports their result', async () => {
	const id = crypto.randomUUID();
	const forbidden = await fetch(`${origin}/restart`, { method: 'POST' });
	expect(forbidden.status).toBe(403);
	const invalid = await fetch(`${origin}/restart`, { method: 'POST', headers: { Origin: appOrigin,
		'X-Testd-Browser-Restart': '1', 'X-Testd-Browser-Restart-Id': '../etc/passwd' } });
	expect(invalid.status).toBe(400);
	const requested = await fetch(`${origin}/restart`, { method: 'POST', headers: { Origin: appOrigin,
		'X-Testd-Browser-Restart': '1', 'X-Testd-Browser-Restart-Id': id } });
	expect(requested.status).toBe(202);
	expect(await Bun.file(join(directory, `restart-request-${id}.json`)).exists()).toBe(true);
	expect(await (await fetch(`${origin}/restart/status?id=${id}`)).json()).toEqual({ status: 'pending' });
	await Bun.write(join(directory, `restart-result-${id}.json`), JSON.stringify({ status: 'ok' }));
	expect(await (await fetch(`${origin}/restart/status?id=${id}`)).json()).toEqual({ status: 'ok' });
});

test('echoes WebSocket messages through a real upgrade', async () => {
	const socket = new WebSocket(`${origin.replace('http:', 'ws:')}/ws`);
	try {
		const response = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error('WebSocket fixture timed out')), 3000);
			socket.onopen = () => socket.send('fixture');
			socket.onmessage = event => { clearTimeout(timer); resolve(String(event.data)); };
			socket.onerror = () => { clearTimeout(timer); reject(new Error('WebSocket fixture failed')); };
		});
		expect(response).toBe('fixture');
	} finally { socket.close(); }
});
