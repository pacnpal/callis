# Callis — Svelte Frontend Migration Plan

Status: **proposed** (not started). This document is the plan of record for a
future PR that migrates the web UI from server-rendered Jinja2 + htmx to
Svelte. Nothing in the current codebase depends on it.

---

## 1. Why (and why not)

**Today:** the UI is FastAPI + Jinja2 + htmx + Pico CSS. It is deliberately
build-free — `docs/REQUIREMENTS.md` NFR-MAINT-03 currently states there must be
no Node.js, npm, or frontend build step of any kind.

**Motivation to migrate:** richer interactivity (optimistic updates, client-side
filtering/sorting of audit and host tables, form validation UX), typed API
contracts, and component reuse instead of the current template partials.

**Cost:** a build toolchain, a JS dependency tree to keep patched (this is a
security product — the attack surface of the admin UI matters), and a rewrite
of every template. The migration must not regress the deployment story:
**one `docker compose up -d`, no Node at runtime.**

**Decision gate:** do the migration only when a concrete UI need exceeds what
htmx does well. The backend refactor below (Phase 0) is worth doing regardless.

## 2. Guiding constraints

1. **Build once, use many.** Node exists *only* in a Docker build stage. The
   published image ships compiled static assets; the runtime image stays
   Python-only. No CDN dependencies (removes the current unpkg/jsdelivr CSP
   allowlist — CSP tightens to `'self'`).
2. **Deterministic builds.** `package-lock.json` committed; `npm ci` in the
   build stage; Vite/Svelte versions pinned exactly like `uv.lock` pins Python.
3. **SSOT.** API becomes the single source of truth: the JSON API the SPA
   consumes is the same data layer the Jinja2 pages use during the transition
   (no duplicated view logic).
4. **Security posture is non-negotiable:** session cookie stays httpOnly +
   SameSite=Strict (no tokens in JS), CSP without `unsafe-inline`/`unsafe-eval`,
   TOTP/setup guards enforced server-side exactly as today.
5. **NFR-MAINT-03 must be rewritten in the same PR** that introduces the build
   step, to: "No Node.js at runtime. The frontend is compiled in a Docker build
   stage; the published image contains only static assets."

## 3. Architecture

- **Svelte 5 + Vite** (SPA, not SvelteKit — no Node server allowed at runtime,
  and the app is behind auth with no SEO needs; SvelteKit's `adapter-static`
  is the fallback if routing/layout ergonomics are wanted).
- FastAPI serves `dist/` at `/` and exposes `/api/v1/*` JSON endpoints.
- Auth/session/TOTP/setup guards stay server-side middleware; the SPA calls
  `/api/v1/me` on boot and routes accordingly. 401/419 responses redirect to
  the server-rendered login page (login/setup/TOTP enrollment stay Jinja2 —
  they are security-critical, tiny, and benefit from zero JS).

```
Dockerfile (multi-stage):
  Stage 1: node:22-alpine  → npm ci && vite build  → /frontend/dist
  Stage 2: python:3.12-slim → uv sync --frozen … + COPY --from=1 /frontend/dist ./static/app
```

## 4. Phases

**Phase 0 — API extraction (no UI change).** Add `/api/v1` JSON endpoints
(users, keys, hosts, assignments, audit, settings) with Pydantic response
models, backed by the same service functions the HTML routes use. Ship + test
independently. This is pure SSOT/modularity work and is valuable even if the
migration stops here.

**Phase 1 — Scaffold + one page.** Vite + Svelte scaffold in `frontend/`,
multi-stage Docker build, serve the SPA at `/app`. Migrate the **Audit Log**
page first (read-only, biggest UX win from client-side filtering/pagination).
Jinja2 pages remain the default; `/app` is opt-in.

**Phase 2 — Interactive pages.** Hosts (assignment UX), Users, User detail
(key upload/generate dialogs), Dashboard, Settings. Delete each Jinja2
template + htmx partial as its Svelte page lands.

**Phase 3 — Cutover.** SPA becomes `/`; remove htmx, remaining page templates,
and the CDN allowlist from the CSP. Login/setup/TOTP stay server-rendered.
Update REQUIREMENTS.md, ARCHITECTURE.md, DEVELOPMENT.md; add `npm ci && vite
build` + Playwright smoke tests to CI.

## 5. Component inventory (from current templates)

| Current template | Svelte component(s) |
|---|---|
| base.html nav/footer/flash | `AppShell`, `Nav`, `Flash`, `ThemeToggle` |
| dashboard.html | `StatCards`, `GettingStarted`, `SshConfigSnippet`, `RecentActivity` |
| users.html + user_row | `UserTable`, `UserRow`, `CreateUserDialog` |
| user_detail.html + key_list + generated_key | `UserProfile`, `KeyTable`, `KeyUploadForm`, `GenerateKeyDialog`, `RoleSelect` |
| hosts.html + host_row + ssh_config | `HostTable`, `HostRow`, `AssignUserSelect`, `AddHostDialog`, `SshConfigBlock`, `DeployKeyPanel` |
| audit.html + audit_rows | `AuditTable`, `AuditFilters`, `Pagination` |
| settings.html | `SettingsForm`, `SettingField`, `InstallerPanel` |
| login/setup/totp_setup | stay server-rendered (Jinja2) |

## 6. Risks

- **Dependency churn/supply chain:** mitigate with lockfile pinning, Renovate
  (already configured), and a minimal dependency policy (Svelte + Vite only;
  no component libraries — port the existing Pico CSS styling).
- **CSP regressions:** Vite must emit no inline scripts (`build.modulePreload`
  and hashed assets are fine); verify headers in CI.
- **Session handling in SPA:** all state changes still go through the cookie
  session + server-side role checks; the SPA is a view layer only.
