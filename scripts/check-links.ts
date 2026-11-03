import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../dist', import.meta.url));

if (!existsSync(join(root, 'index.html'))) {
	console.error('check-links: dist/index.html is missing; run `bun run build` first');
	process.exit(1);
}

function walk(dir: string): string[] {
	return readdirSync(dir).flatMap((name) => {
		const path = join(dir, name);
		return statSync(path).isDirectory() ? walk(path) : [path];
	});
}

const htmlFiles = walk(root).filter((path) => path.endsWith('.html'));
const ids = new Map<string, Set<string>>();

for (const file of htmlFiles) {
	const html = readFileSync(file, 'utf8');
	const found = new Set<string>();
	for (const match of html.matchAll(/\sid="([^"]+)"/g)) found.add(match[1]);
	ids.set(file, found);
}

const broken: string[] = [];

function localTarget(from: string, value: string): string | undefined {
	const raw = value.split('?')[0].split('#')[0];
	if (!raw) return from;
	if (raw.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(raw)) return undefined;

	const path = raw.startsWith('/') ? join(root, raw) : resolve(dirname(from), raw);
	if (raw.endsWith('/')) return join(path, 'index.html');
	if (existsSync(path) && statSync(path).isFile()) return path;
	if (existsSync(`${path}.html`)) return `${path}.html`;
	if (existsSync(join(path, 'index.html'))) return join(path, 'index.html');
	return path;
}

for (const file of htmlFiles) {
	const html = readFileSync(file, 'utf8');
	for (const match of html.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
		const value = match[1].replaceAll('&amp;', '&');
		if (!value || value.startsWith('#')) {
			if (value.startsWith('#') && value.length > 1 && !ids.get(file)?.has(value.slice(1))) {
				broken.push(`${relative(root, file)} -> ${value}`);
			}
			continue;
		}
		if (value.startsWith('mailto:') || value.startsWith('tel:') || value.startsWith('data:')) continue;
		const target = localTarget(file, value);
		if (!target) continue;
		if (!existsSync(target)) {
			broken.push(`${relative(root, file)} -> ${value}`);
			continue;
		}
		const fragment = value.split('#')[1];
		if (!fragment || !target.endsWith('.html')) continue;
		if (!ids.get(target)?.has(fragment)) {
			broken.push(`${relative(root, file)} -> ${value} (missing #${fragment})`);
		}
	}
}

if (broken.length > 0) {
	console.error(`check-links: ${broken.length} broken link${broken.length === 1 ? '' : 's'}`);
	for (const line of broken) console.error(`  ${line}`);
	process.exit(1);
}

console.log(`check-links: ${htmlFiles.length} pages ok`);
