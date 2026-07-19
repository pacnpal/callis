<script lang="ts">
	import { enhance } from '$app/forms';
	import CopyButton from '$lib/components/CopyButton.svelte';
	import type { SettingField } from '$lib/types';
	import type { ActionData, PageData } from './$types';

	let { data, form }: { data: PageData; form: ActionData } = $props();

	// After a save, the action returns the fresh state; otherwise use the load.
	const settings = $derived((form && 'settings' in form && form.settings) || data.settings);

	const groups = $derived.by(() => {
		const grouped = new Map<string, SettingField[]>();
		for (const field of settings.fields) {
			const list = grouped.get(field.group) ?? [];
			list.push(field);
			grouped.set(field.group, list);
		}
		return [...grouped.entries()];
	});

	const installCommand = $derived(`curl -fsSL ${settings.installer_url} | sh`);
</script>

<h2>Settings</h2>

<p class="text-muted">
	Configure your Callis instance. Most changes apply immediately; session timeouts only affect new
	sessions, and read-only settings require a restart. Settings override environment variable
	defaults and persist across restarts.
</p>

{#if form && 'error' in form && form.error}
	<div class="flash flash-error" role="alert">{form.error}</div>
{/if}
{#if form && 'success' in form && form.success}
	<div class="flash flash-success" role="status">{form.success}</div>
{/if}

<form method="post" use:enhance>
	{#each groups as [groupName, fields] (groupName)}
		<article>
			<header><strong>{groupName}</strong></header>
			{#each fields as s (s.key)}
				<div class="setting-row">
					<label for={s.key}>{s.label}</label>
					{#if s.readonly}
						<input type="text" id={s.key} value={s.value} aria-describedby="{s.key}_help" disabled />
					{:else if s.type === 'choice'}
						<select id={s.key} name={s.key} aria-describedby="{s.key}_help">
							{#each s.choices ?? [] as opt (opt)}
								<option value={opt} selected={s.value === opt}>{opt}</option>
							{/each}
						</select>
					{:else if s.type === 'text'}
						<textarea id={s.key} name={s.key} rows="3" placeholder={s.help} aria-describedby="{s.key}_help" value={String(s.value ?? '')}></textarea>
					{:else if s.type === 'int'}
						<input
							type="number"
							id={s.key}
							name={s.key}
							value={s.value}
							aria-describedby="{s.key}_help"
							min={s.min ?? undefined}
							max={s.max ?? undefined}
						/>
					{:else}
						<input type="text" id={s.key} name={s.key} value={s.value} aria-describedby="{s.key}_help" />
					{/if}
					<p id="{s.key}_help" class="helper-text">{s.help}</p>
				</div>
			{/each}
		</article>
	{/each}

	<button type="submit">Save Changes</button>
</form>

<article>
	<header><strong>CLI Installer</strong></header>
	<p class="helper-text">
		Share this command with users to install the Callis CLI. The URL reflects the
		<strong>Base URL</strong> setting above.
	</p>
	<div class="ssh-config-actions">
		<CopyButton text={installCommand} />
	</div>
	<pre class="ssh-config">{installCommand}</pre>
</article>
