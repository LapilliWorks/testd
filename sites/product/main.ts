import './style.css';

document.documentElement.classList.add('js');

const toast = document.querySelector<HTMLElement>('[data-toast]');
let toastTimer: number | undefined;

function showToast(message: string): void {
	if (!toast) return;

	window.clearTimeout(toastTimer);
	toast.textContent = message;
	toast.classList.add('visible');
	toastTimer = window.setTimeout(() => toast.classList.remove('visible'), 2400);
}

function setupNavigation(): void {
	const toggle = document.querySelector<HTMLButtonElement>('[data-nav-toggle]');
	const nav = document.querySelector<HTMLElement>('[data-nav]');
	if (!toggle || !nav) return;

	const close = (): void => {
		toggle.setAttribute('aria-expanded', 'false');
		toggle.setAttribute('aria-label', 'Open navigation');
		nav.classList.remove('open');
	};

	toggle.addEventListener('click', () => {
		const isOpen = toggle.getAttribute('aria-expanded') === 'true';
		toggle.setAttribute('aria-expanded', String(!isOpen));
		toggle.setAttribute('aria-label', isOpen ? 'Open navigation' : 'Close navigation');
		nav.classList.toggle('open', !isOpen);
	});

	nav.querySelectorAll('a').forEach((link) => link.addEventListener('click', close));
	document.addEventListener('keydown', (event) => {
		if (event.key === 'Escape' && nav.classList.contains('open')) {
			close();
			toggle.focus();
		}
	});

	window.matchMedia('(min-width: 721px)').addEventListener('change', (event) => {
		if (event.matches) close();
	});
}

function copyWithFallback(text: string): boolean {
	const textarea = document.createElement('textarea');
	textarea.value = text;
	textarea.setAttribute('readonly', '');
	textarea.style.position = 'fixed';
	textarea.style.opacity = '0';
	document.body.append(textarea);
	textarea.select();
	const copied = document.execCommand('copy');
	textarea.remove();
	return copied;
}

async function copyText(text: string): Promise<void> {
	if (navigator.clipboard && window.isSecureContext) {
		await navigator.clipboard.writeText(text);
		return;
	}

	if (!copyWithFallback(text)) throw new Error('Clipboard access is unavailable');
}

function getCommandForButton(button: HTMLButtonElement): string {
	if (button.hasAttribute('data-copy-active-panel')) {
		return document.querySelector<HTMLElement>('[data-code-panel]:not([hidden])')?.textContent?.trim() ?? '';
	}

	const targetId = button.dataset.copyTarget;
	return (targetId ? document.getElementById(targetId)?.textContent : '')?.trim() ?? '';
}

const copyResetTimers = new WeakMap<HTMLButtonElement, number>();

async function handleCopy(button: HTMLButtonElement): Promise<void> {
	const command = getCommandForButton(button);
	const label = button.querySelector<HTMLElement>('.copy-label');
	if (!command) {
		showToast('No command found to copy');
		return;
	}

	window.clearTimeout(copyResetTimers.get(button));

	try {
		await copyText(command);
		if (label) label.textContent = 'Copied';
		showToast('Command copied to clipboard');
	} catch {
		if (label) label.textContent = 'Failed';
		showToast('Copy failed. Select the command manually.');
	}

	const timer = window.setTimeout(() => {
		if (label) label.textContent = 'Copy';
	}, 1800);
	copyResetTimers.set(button, timer);
}

function setupCopyButtons(): void {
	document.querySelectorAll<HTMLButtonElement>('[data-copy-target], [data-copy-active-panel]').forEach((button) => {
		button.addEventListener('click', () => void handleCopy(button));
	});
}

function setupCodeTabs(): void {
	document.querySelectorAll<HTMLElement>('.code-tabs').forEach((tablist) => {
		const tabs = Array.from(tablist.querySelectorAll<HTMLButtonElement>('[role="tab"]'));

		const activate = (selected: HTMLButtonElement): void => {
			tabs.forEach((tab) => {
				const isSelected = tab === selected;
				tab.setAttribute('aria-selected', String(isSelected));
				tab.tabIndex = isSelected ? 0 : -1;
				const panelId = tab.getAttribute('aria-controls');
				const panel = panelId ? document.getElementById(panelId) : null;
				if (panel) panel.hidden = !isSelected;
			});
		};

		tabs.forEach((tab, index) => {
			tab.addEventListener('click', () => activate(tab));
			tab.addEventListener('keydown', (event) => {
				let nextIndex: number | undefined;
				if (event.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
				if (event.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;
				if (event.key === 'Home') nextIndex = 0;
				if (event.key === 'End') nextIndex = tabs.length - 1;
				if (nextIndex === undefined) return;

				event.preventDefault();
				activate(tabs[nextIndex]);
				tabs[nextIndex].focus();
			});
		});
	});
}

function setupReveals(): void {
	const elements = document.querySelectorAll<HTMLElement>('.reveal');
	if (!('IntersectionObserver' in window) || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
		elements.forEach((element) => element.classList.add('is-visible'));
		return;
	}

	const observer = new IntersectionObserver(
		(entries) => {
			entries.forEach((entry) => {
				if (!entry.isIntersecting) return;
				entry.target.classList.add('is-visible');
				observer.unobserve(entry.target);
			});
		},
		{ threshold: 0.08, rootMargin: '0px 0px -35px' },
	);
	elements.forEach((element) => observer.observe(element));
}

setupNavigation();
setupCopyButtons();
setupCodeTabs();
setupReveals();

document.querySelectorAll<HTMLElement>('[data-year]').forEach((element) => {
	element.textContent = String(new Date().getFullYear());
});
