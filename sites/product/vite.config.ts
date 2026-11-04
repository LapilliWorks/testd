import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';

const host = process.env.TESTD_SITE_HOST ?? '127.0.0.1';
const docsPort = Number(process.env.TESTD_DOCS_PORT ?? 5174);
const outDir = process.env.TESTD_SITE_OUT_DIR ?? '../../dist';

const ogImagePath = fileURLToPath(new URL('../../assets/social/og.png', import.meta.url));
const assetsRoot = fileURLToPath(new URL('../../assets/', import.meta.url));

// Brand sources sit outside the Vite root. In dev, point the HTML at Vite's
// /@fs URL so the dev server can read them; the build bundles the same paths.
function devAssets(): Plugin {
	return {
		name: 'testd-dev-assets',
		apply: 'serve',
		transformIndexHtml(html) {
			return html.replaceAll('../../assets/', `/@fs${assetsRoot}`);
		},
	};
}

// Serve the canonical social card at a stable URL in dev and emit it at build.
function ogImageAsset(): Plugin {
	const image = readFileSync(ogImagePath);
	return {
		name: 'testd-og-image',
		configureServer(server) {
			server.middlewares.use('/og.png', (_req, res) => {
				res.setHeader('Content-Type', 'image/png');
				res.end(image);
			});
		},
		generateBundle() {
			this.emitFile({ type: 'asset', fileName: 'og.png', source: image });
		},
	};
}

export default defineConfig({
	base: '/',
	plugins: [devAssets(), ogImageAsset()],
	server: {
		host,
		port: 5173,
		strictPort: true,
		proxy: {
			'/docs': {
				target: `http://127.0.0.1:${docsPort}`,
				changeOrigin: true,
				ws: true,
				bypass(req, res) {
					if (req.url === '/docs') {
						res.writeHead(301, { Location: '/docs/' });
						res.end();
						return false;
					}
				},
			},
		},
	},
	preview: { host, port: 4173, strictPort: true },
	build: {
		outDir,
		emptyOutDir: true,
		target: 'es2022',
		rollupOptions: {
			input: [
				fileURLToPath(new URL('index.html', import.meta.url)),
				fileURLToPath(new URL('404.html', import.meta.url)),
			],
		},
	},
});
