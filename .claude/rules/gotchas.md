# Gotchas consumers rely on

**`AUTH_BYPASS_ENABLED=true` never disables auth on auth endpoints.** It short-circuits
`requirePermission()` straight to `PERMIT` without calling user-service at all — but it explicitly
still `403`s on anything path-matching `/login|/signin|/signup|/register|/auth`. This is dev/
local-only, and every consuming service's own auth layer has the same carve-out — don't "simplify"
this check away as redundant when reviewing this package; it's the last line of defense inside this
package specifically, independent of whatever the caller already did.

**`validateGatewayRequest` is header-presence-only, not cryptographic** (see the file's own doc
comment). It checks `x-jwt-verified === "true"`, that `x-user-id`/`x-tenant-id` are present and
non-empty, and defensively resets `x-user-roles`/`x-user-permissions` to `"[]"` if they're not valid
JSON arrays. It does **not** do HMAC signature verification, IP allowlisting, or replay-window
checking, despite the README describing those as features — if you need those guarantees, they don't
currently exist in this file; don't assume they're silently running.

**One deliberate bypass exists**: `x-auth-source: azuread` + `x-service-caller: system.notifier`
skips identity-header validation entirely, for n8n/automation callers that authenticate via Azure AD
rather than the user-JWT gateway flow. Don't remove this without checking whether n8n workflows still
depend on it.

**Console logging is intentional here, not leftover debugging.** Nearly every method in
`policy.middleware.js` and `policyClient.js` logs verbosely to `console.log`/`console.error` with a
`[POLICY_MIDDLEWARE]`/`[POLICY_CLIENT]` prefix, including full request context and stack traces on
failure — deliberate given how hard cross-service authorization failures are to debug in Azure/
staging without it. Before stripping any of it out as noise, check whether it's relied on during
incident triage.

All writes go through `@projectShell/logging-lib`'s `createLogger`, into the `gateway/` log folder
(override via `GATEWAY_LOG_SERVICE_NAME`) — the same `LOG_ROOT` convention documented in
`logging-lib`'s own `CLAUDE.md`.

## Why this package matters for the platform's cross-service-auth rule

This package's `validateGatewayRequest`/`requirePermission` are the actual enforcement point for the
platform rule "cross-service calls forward the caller's identity headers, never a shared API key" —
a consuming service that skips this package's gateway-header validation, or invents its own
`x-api-key` check instead of calling `requirePermission()`, breaks that rule in a way nothing else in
this package catches. In the full `projectShell` checkout (not a standalone clone of this repo), the
header-forwarding half of that rule is additionally hook-enforced by
`.claude/hooks/enforce-hard-rules.mjs` (blocks the literal header key `x-api-key` and unregistered
`*_API_KEY` env vars anywhere under `backend/`) — that hook lives in the parent checkout, not here,
so it has no effect when this package is cloned standalone.
