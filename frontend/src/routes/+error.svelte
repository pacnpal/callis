<script lang="ts">
	import { page } from '$app/state';
</script>

<div class="error-page">
	<h1>{page.status === 404 ? 'Not Found' : 'Error'}</h1>
	<p>{page.error?.message ?? 'An unexpected error occurred. Please try again later.'}</p>
	<p><a href="/dashboard" role="button">Return to Dashboard</a></p>
</div>
