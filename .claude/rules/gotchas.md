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

**Console logging is intentional here, but it is safe metadata only.** `policy.middleware.js` and
`policyClient.js` log every authorization step with a `[POLICY_MIDDLEWARE]`/`[POLICY_CLIENT]` prefix
for cross-service triage, using the explicit field sets in `src/safeLog.js`:

- request context: `{resource, action, userId, tenantId, authPath (gateway|token|bypass), roleCount,
  permissionCount, bodyFields, queryFields, correlationId}` — body/query **field names only**;
- decision: `{decision, reason, success, policyVersion, userId, tenantId, userType}`;
- DENY: reason/decision/code, `requiredPermissions` (resource codes) and the user's `permissionCount`;
- errors: `{name, code, status}`; user-service error bodies: `{reason, decision, code}`;
- structured (logging-lib) rows: `path` without the query string.

**Never log** request body or query *values*, `originalUrl`/query strings, the Authorization header,
tokens or anything decoded from them, the user's email, names or other personal data, the roles or
permissions lists, the raw policy result, raw error response bodies, whole error objects or stack
traces. Add a field only by adding it explicitly to a `safeLog.js` field set. Logging only: the
context sent to user-service, decisions, `req.user`/`req.policyContext`/`req.tenantId` and the
401/403/500 bodies (including the permissions the 403 returns) are unchanged by this rule.

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
