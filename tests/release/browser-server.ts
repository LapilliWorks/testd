import { hostname, platform, release } from 'node:os';
import { join } from 'node:path';

const port = Number(process.env.TESTD_BROWSER_PORT ?? '19080');
const tld = process.env.TESTD_BROWSER_TLD ?? 'test';
const edgePort = Number(process.env.TESTD_BROWSER_EDGE_PORT ?? '443');
const reportDirectory = process.env.TESTD_BROWSER_REPORT;
if (!reportDirectory) throw new Error('Run this fixture through tests/release/run.py browser');
const appOrigin = new URL(`https://app.releasecheck.${tld}:${edgePort}`).origin;
const metadata = JSON.parse(await Bun.file(join(reportDirectory, 'report.json')).text());

function cors(request: Request): HeadersInit {
	return request.headers.get('origin') === appOrigin
		? { 'Access-Control-Allow-Origin': appOrigin, 'Access-Control-Allow-Credentials': 'true', Vary: 'Origin' }
		: {};
}

function events(): Response {
	let timer: ReturnType<typeof setTimeout>;
	const stream = new ReadableStream({
		start(controller) {
			controller.enqueue(new TextEncoder().encode('data: first\n\n'));
			timer = setTimeout(() => {
				controller.enqueue(new TextEncoder().encode('data: done\n\n'));
				controller.close();
			}, 250);
		},
		cancel() { clearTimeout(timer); },
	});
	return new Response(stream, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' } });
}

async function upload(request: Request): Promise<Response> {
	let bytes = 0;
	if (request.body) {
		for await (const chunk of request.body) bytes += chunk.byteLength;
	}
	return Response.json({ bytes });
}

async function saveReport(request: Request): Promise<Response> {
	if (request.headers.get('x-testd-browser-report') !== '1'
		|| request.headers.get('origin') !== appOrigin) return new Response('Forbidden', { status: 403 });
	const text = await request.text();
	if (text.length > 64 * 1024) return new Response('Report too large', { status: 413 });
	const result = JSON.parse(text);
	if (!Array.isArray(result.checks) || result.checks.length !== 4) {
		return new Response('Incomplete results', { status: 400 });
	}
	const path = join(reportDirectory, `browser-${crypto.randomUUID()}.json`);
	await Bun.write(path, JSON.stringify({ ...result, commit: metadata.commit,
		host: { hostname: hostname(), platform: platform(), release: release() },
		origin: appOrigin, savedAt: new Date().toISOString() }, null, '\t') + '\n');
	return Response.json({ saved: path });
}

Bun.serve({
	hostname: '127.0.0.1',
	port,
	maxRequestBodySize: 128 * 1024 * 1024,
	async fetch(request, server) {
		const url = new URL(request.url);
		if (url.pathname === '/ws') {
			if (server.upgrade(request)) return;
			return new Response('WebSocket upgrade required', { status: 400 });
		}
		if (request.method === 'POST' && url.pathname === '/report') return saveReport(request);
		if (request.method === 'POST' && url.pathname === '/upload') return upload(request);
		if (request.method !== 'GET') return new Response('Method not allowed', { status: 405 });
		if (url.pathname === '/events') return events();
		if (url.pathname === '/meta') return Response.json({ tld, edgePort, commit: metadata.commit });
		if (url.pathname === '/cookie/set') {
			const nonce = crypto.randomUUID();
			return Response.json({ nonce }, { headers: {
				'Set-Cookie': `releasecheck=${nonce}; Domain=releasecheck.${tld}; Path=/; Secure; HttpOnly; SameSite=Lax`,
			} });
		}
		if (url.pathname === '/cookie') {
			return Response.json({ cookie: request.headers.get('cookie') ?? '' }, { headers: cors(request) });
		}
		if (url.pathname === '/') return new Response(Bun.file('tests/release/browser.html'));
		return new Response('Not found', { status: 404 });
	},
	websocket: {
		message(socket, message) { socket.send(message); },
	},
});
console.log(`Browser fixture: ${appOrigin}/ (keep the terminal open)`);
