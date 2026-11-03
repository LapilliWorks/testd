import { defineConfig } from 'vite';

const host = process.env.TESTD_SITE_HOST ?? '127.0.0.1';
const docsPort = Number(process.env.TESTD_DOCS_PORT ?? 5174);
const outDir = process.env.TESTD_SITE_OUT_DIR ?? '../../dist';

export default defineConfig({
	base: '/',
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
	},
});
