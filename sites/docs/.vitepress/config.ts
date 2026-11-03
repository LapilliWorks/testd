import { defineConfig } from 'vitepress';

const REPO = 'https://github.com/LapilliWorks/testd';
const SITE = 'https://testd.dev';
const outDir = process.env.TESTD_SITE_OUT_DIR
	? `${process.env.TESTD_SITE_OUT_DIR}/docs`
	: '../../dist/docs';

export default defineConfig({
	lang: 'en-US',
	title: 'testd',
	description: 'Stable HTTPS names for containers, VMs, WSL, and remote dev boxes.',
	base: '/docs/',
	outDir,
	cacheDir: process.env.TESTD_DOCS_CACHE_DIR,
	cleanUrls: false,
	lastUpdated: false,
	titleTemplate: ':title | testd docs',
	head: [
		['link', { rel: 'icon', type: 'image/svg+xml', href: '/docs/favicon.svg' }],
		['meta', { name: 'theme-color', content: '#f2eee4' }],
		['meta', { property: 'og:type', content: 'website' }],
		['meta', { property: 'og:site_name', content: 'testd docs' }],
	],
	themeConfig: {
		logo: { src: '/logo.svg', alt: 'testd', width: 24, height: 24 },
		siteTitle: 'testd docs',
		nav: [
			{ text: 'Product', link: SITE },
			{ text: 'Quickstart', link: '/quickstart' },
			{ text: 'Reference', link: '/reference' },
			{ text: 'GitHub', link: REPO },
		],
		sidebar: [
			{
				text: 'Start',
				items: [
					{ text: 'Overview', link: '/' },
					{ text: 'Quickstart', link: '/quickstart' },
				],
			},
			{
				text: 'Use',
				items: [
					{ text: 'Daily usage', link: '/usage' },
					{ text: 'Advanced usage', link: '/advanced' },
				],
			},
			{
				text: 'Reference',
				items: [
					{ text: 'Reference', link: '/reference' },
					{ text: 'Security', link: '/security' },
					{ text: 'Dependency policy', link: '/dependency-policy' },
				],
			},
		],
		socialLinks: [{ icon: 'github', link: REPO }],
		editLink: {
			pattern: `${REPO}/edit/master/sites/docs/:path`,
			text: 'Edit this page',
		},
		outline: { level: [2, 3], label: 'On this page' },
		docFooter: { prev: 'Previous', next: 'Next' },
		search: {
			provider: 'local',
			options: {
				translations: {
					button: {
						buttonText: 'Search docs',
						buttonAriaLabel: 'Search docs',
					},
					modal: {
						displayDetails: 'Display detailed list',
						resetButtonTitle: 'Reset search',
						backButtonTitle: 'Close search',
						noResultsText: 'No results for',
						footer: {
							selectText: 'to select',
							selectKeyAriaLabel: 'enter',
							navigateText: 'to navigate',
							navigateUpKeyAriaLabel: 'up arrow',
							navigateDownKeyAriaLabel: 'down arrow',
							closeText: 'to close',
							closeKeyAriaLabel: 'escape',
						},
					},
				},
			},
		},
		footer: {
			message: 'ISC licensed. No account, no telemetry.',
			copyright: '© 2026 Lapilli Works',
		},
	},
	vite: {
		server: {
			host: '127.0.0.1',
			port: Number(process.env.TESTD_DOCS_PORT ?? 5174),
			strictPort: true,
		},
	},
});
