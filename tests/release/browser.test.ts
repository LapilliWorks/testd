import { afterAll, beforeAll, expect, test } from 'bun:test';
import { mkdtemp, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

let child: ReturnType<typeof Bun.spawn>;
let directory: string;
let origin: string;
const appOrigin = 'https://app.releasecheck.test:8443';

beforeAll(async () => {
	directory = await mkdtemp(join(tmpdir(), 'testd-browser-fixture-'));
	await Bun.write(join(directory, 'report.json'), JSON.stringify({ commit: 'fixture-commit' }));
	const probe = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: () => new Response('probe') });
	const port = probe.port;
	await probe.stop(true);
	origin = `http://127.0.0.1:${port}`;
	child = Bun.spawn([process.execPath, 'tests/release/browser-server.ts'], {
		env: { ...process.env, TESTD_BROWSER_REPORT: directory, TESTD_BROWSER_PORT: String(port),
			TESTD_BROWSER_TLD: 'test', TESTD_BROWSER_EDGE_PORT: '8443' },
		stdout: 'inherit', stderr: 'inherit',
	});
	for (let attempt = 0; attempt < 100; attempt++) {
		try {
			if ((await fetch(`${origin}/meta`)).ok) return;
		} catch { /* The child may not have bound its listener yet. */ }
		await Bun.sleep(20);
	}
	throw new Error('Browser fixture did not start');
});

afterAll(async () => {
	if (child) {
		child.kill();
		await child.exited;
	}
});

test('serves the harness and metadata', async () => {
	expect(await (await fetch(`${origin}/`)).text()).toContain('testd browser release checks');
	expect(await (await fetch(`${origin}/meta`)).json()).toEqual({ tld: 'test', edgePort: 8443,
		commit: 'fixture-commit' });
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

test('refuses cross-site reports and saves complete operator results', async () => {
	const forbidden = await fetch(`${origin}/report`, { method: 'POST', body: '{}' });
	expect(forbidden.status).toBe(403);
	const result = { manualConfirmed: true, checks: Array.from({ length: 4 }, (_, index) =>
		({ name: `check${index}`, status: 'pass' })) };
	const response = await fetch(`${origin}/report`, { method: 'POST',
		headers: { Origin: appOrigin, 'X-Testd-Browser-Report': '1' }, body: JSON.stringify(result) });
	expect(response.ok).toBe(true);
	const files = (await readdir(directory)).filter(file => file.startsWith('browser-'));
	expect(files).toHaveLength(1);
	expect((await Bun.file(join(directory, files[0])).json()).commit).toBe('fixture-commit');
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
