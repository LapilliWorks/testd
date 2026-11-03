import './styles.css';

function copyText(text: string): Promise<void> {
	if (navigator.clipboard?.writeText) {
		return navigator.clipboard.writeText(text);
	}

	const field = document.createElement('textarea');
	field.value = text;
	field.setAttribute('readonly', '');
	field.style.position = 'fixed';
	field.style.opacity = '0';
	document.body.append(field);
	field.select();
	document.execCommand('copy');
	field.remove();
	return Promise.resolve();
}

for (const block of document.querySelectorAll<HTMLElement>('.code[data-copy]')) {
	const button = block.querySelector<HTMLButtonElement>('.code-copy');
	const code = block.querySelector('code');
	if (!button || !code) continue;

	button.addEventListener('click', async () => {
		const label = button.textContent ?? 'Copy';
		try {
			await copyText(code.textContent ?? '');
			button.textContent = 'Copied';
		} catch {
			button.textContent = 'Select';
		}
		window.setTimeout(() => {
			button.textContent = label;
		}, 1600);
	});
}

const navToggle = document.querySelector<HTMLButtonElement>('.nav-toggle');
const nav = document.querySelector<HTMLElement>('#site-nav');

if (navToggle && nav) {
	const setOpen = (open: boolean) => {
		nav.classList.toggle('is-open', open);
		navToggle.setAttribute('aria-expanded', String(open));
	};

	navToggle.addEventListener('click', () => {
		setOpen(navToggle.getAttribute('aria-expanded') !== 'true');
	});

	nav.addEventListener('click', (event) => {
		if ((event.target as Element).closest('a')) setOpen(false);
	});

	document.addEventListener('keydown', (event) => {
		if (event.key === 'Escape') setOpen(false);
	});

	document.addEventListener('click', (event) => {
		if (!(event.target as Element).closest('.site-header')) setOpen(false);
	});

	window.addEventListener('resize', () => {
		if (window.innerWidth > 900) setOpen(false);
	});
}

const year = document.querySelector<HTMLElement>('#year');
if (year) year.textContent = String(new Date().getFullYear());
