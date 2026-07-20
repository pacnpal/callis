<script lang="ts">
	// Cycles system → light → dark, persisting to localStorage (same behavior
	// and storage key as the pre-Svelte UI, so preferences carry over).
	const MODES = ['system', 'light', 'dark'] as const;
	type Mode = (typeof MODES)[number];

	const LABELS: Record<Mode, string> = {
		system: 'Theme: auto (system). Click for light.',
		light: 'Theme: light. Click for dark.',
		dark: 'Theme: dark. Click for auto.'
	};

	function initialMode(): Mode {
		if (typeof localStorage === 'undefined') return 'system';
		try {
			const stored = localStorage.getItem('callis-theme');
			if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
		} catch {
			// localStorage unavailable — fall through to system
		}
		return 'system';
	}

	let mode = $state<Mode>('system');

	$effect(() => {
		mode = initialMode();
	});

	function cycle() {
		mode = MODES[(MODES.indexOf(mode) + 1) % MODES.length];
		try {
			localStorage.setItem('callis-theme', mode);
		} catch {
			// best effort
		}
		if (mode === 'light' || mode === 'dark') {
			document.documentElement.setAttribute('data-theme', mode);
		} else {
			document.documentElement.removeAttribute('data-theme');
		}
	}
</script>

<button type="button" class="theme-toggle" aria-label={LABELS[mode]} onclick={cycle}>
	{#if mode === 'system'}
		<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" /></svg>
	{:else if mode === 'light'}
		<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5" /><line x1="12" y1="1" x2="12" y2="3" /><line x1="12" y1="21" x2="12" y2="23" /><line x1="4.22" y1="4.22" x2="5.64" y2="5.64" /><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" /><line x1="1" y1="12" x2="3" y2="12" /><line x1="21" y1="12" x2="23" y2="12" /><line x1="4.22" y1="19.78" x2="5.64" y2="18.36" /><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" /></svg>
	{:else}
		<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" /></svg>
	{/if}
</button>
