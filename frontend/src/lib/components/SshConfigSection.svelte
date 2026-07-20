<script lang="ts">
	import CopyButton from '$lib/components/CopyButton.svelte';
	import type { Host } from '$lib/types';

	let {
		username,
		sshHost,
		sshPort,
		assignedHosts
	}: {
		username: string;
		sshHost: string;
		sshPort: number;
		assignedHosts: Host[];
	} = $props();

	const bastionBlock = $derived(
		`Host callis\n    HostName ${sshHost}\n    Port ${sshPort}\n    User ${username}\n    IdentityFile ~/.ssh/your_ed25519_key`
	);

	function hostBlock(host: Host): string {
		return `Host ${host.alias}\n    HostName ${host.hostname}\n    Port ${host.port}\n    ProxyJump callis`;
	}

	const fullConfig = $derived(
		[bastionBlock, ...assignedHosts.map(hostBlock)].join('\n\n')
	);
</script>

{#if assignedHosts.length > 0}
	<p>
		Copy this config into your <code>~/.ssh/config</code> file to connect through Callis. On
		Windows, this file is at <code>C:\Users\&lt;you&gt;\.ssh\config</code>.
	</p>
	<p class="text-small text-muted">
		Replace <code>~/.ssh/your_ed25519_key</code> with the path to the private key matching the
		public key you uploaded above.
	</p>

	<div class="ssh-config-actions">
		<CopyButton text={fullConfig} label="Copy Full Config" />
	</div>

	<pre class="ssh-config">{fullConfig}</pre>

	<p class="text-small text-muted">
		After saving, connect with: <code>ssh {assignedHosts[0].alias}</code>
	</p>

	<h4>Individual Host Configs</h4>
	<p class="text-small text-muted">
		Need just one host? Copy its config block below. The bastion <code>Host callis</code> entry
		above is still required.
	</p>

	{#each assignedHosts as host (host.id)}
		<div class="ssh-config-host">
			<div class="ssh-config-host-header">
				<strong>{host.label}</strong>
				<span class="text-muted text-small">({host.hostname}:{host.port})</span>
				<CopyButton text={hostBlock(host)} />
			</div>
			<pre class="ssh-config">{hostBlock(host)}</pre>
		</div>
	{/each}
{:else}
	<p>
		Copy this into your <code>~/.ssh/config</code> to configure the Callis bastion connection. On
		Windows, this file is at <code>C:\Users\&lt;you&gt;\.ssh\config</code>.
	</p>
	<p class="text-small text-muted">
		Replace <code>~/.ssh/your_ed25519_key</code> with the path to the private key matching the
		public key you uploaded above.
	</p>

	<div class="ssh-config-actions">
		<CopyButton text={bastionBlock} />
	</div>

	<pre class="ssh-config">{bastionBlock}</pre>

	<p class="text-muted">
		No hosts are assigned to this account yet. Ask an administrator to assign you to jump targets
		&mdash; they will then appear here with ready-to-use SSH config.
	</p>
{/if}
