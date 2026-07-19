<script lang="ts">
	import AuditDetail from '$lib/components/AuditDetail.svelte';
	import { formatDateTimeSeconds, humanize } from '$lib/format';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	const audit = $derived(data.audit);
	const filters = $derived(data.filters);

	function pageUrl(target: number): string {
		const params = new URLSearchParams();
		params.set('page', String(target));
		if (filters.action) params.set('action', filters.action);
		if (filters.actor) params.set('actor', filters.actor);
		if (filters.date_from) params.set('date_from', filters.date_from);
		if (filters.date_to) params.set('date_to', filters.date_to);
		return `/audit?${params.toString()}`;
	}
</script>

<h2>Audit Log</h2>

<p class="text-muted">
	Security events and administrative actions — logins, key changes, host modifications, and user
	management. Use the filters below to narrow results.
</p>

<form method="get" action="/audit" class="filter-form" data-sveltekit-keepfocus>
	<div class="grid">
		<div>
			<label for="action">Event Type</label>
			<select id="action" name="action">
				<option value="">All Events</option>
				{#each audit.actions as a (a)}
					<option value={a} selected={filters.action === a}>{a}</option>
				{/each}
			</select>
		</div>
		<div>
			<label for="actor">User</label>
			<select id="actor" name="actor">
				<option value="">All Users</option>
				{#each audit.users as u (u.id)}
					<option value={u.id} selected={filters.actor === u.id}>{u.username}</option>
				{/each}
			</select>
		</div>
		<div>
			<label for="date_from">From</label>
			<input type="date" id="date_from" name="date_from" value={filters.date_from} />
		</div>
		<div>
			<label for="date_to">To</label>
			<input type="date" id="date_to" name="date_to" value={filters.date_to} />
		</div>
	</div>
	<button type="submit" class="outline">Filter</button>
</form>

<figure>
	<table>
		<thead>
			<tr>
				<th>Time</th>
				<th>Action</th>
				<th>Actor</th>
				<th>Target</th>
				<th>Source IP</th>
				<th>Detail</th>
			</tr>
		</thead>
		<tbody>
			{#each audit.entries as entry (entry.id)}
				<tr>
					<td class="text-small">{formatDateTimeSeconds(entry.timestamp)}</td>
					<td>
						<span class="badge badge-action badge-{entry.action}">{humanize(entry.action)}</span>
					</td>
					<td>{entry.actor_username ?? 'system'}</td>
					<td class="text-small">
						{#if entry.target_type}
							<span class="target-type">{humanize(entry.target_type)}</span>
						{/if}
						{#if entry.target_id}
							<span class="target-label">{entry.target_id.slice(0, 8)}</span>
						{/if}
					</td>
					<td class="text-small"><code>{entry.source_ip ?? ''}</code></td>
					<td class="text-small text-muted">
						<AuditDetail detail={entry.detail} />
					</td>
				</tr>
			{:else}
				<tr><td colspan="6" class="text-muted">No audit entries found.</td></tr>
			{/each}
		</tbody>
	</table>
</figure>

{#if audit.total_pages > 1}
	<nav aria-label="Pagination" class="pagination">
		{#if audit.page > 1}
			<a href={pageUrl(audit.page - 1)} role="button" class="outline">&laquo; Prev</a>
		{/if}
		<span class="pagination-info">
			Page {audit.page} of {audit.total_pages} ({audit.total} entries)
		</span>
		{#if audit.page < audit.total_pages}
			<a href={pageUrl(audit.page + 1)} role="button" class="outline">Next &raquo;</a>
		{/if}
	</nav>
{/if}
