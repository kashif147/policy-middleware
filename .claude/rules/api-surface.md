# API surface

Three source files, each independently exported (see `package.json`'s `exports` map —
`.`/`./middleware`/`./client`/`./security`) so a consuming service can import just the piece it
needs. `src/index.js` wires them together: `createDefaultPolicyMiddleware(baseURL, options)` is the
factory every consuming service actually calls, pre-filled with Azure-friendly defaults
(`timeout: 15000, retries: 5, cacheTimeout: 300000, retryDelay: 2000`) that callers can override.
Consuming services generally wrap this factory in their own thin `middlewares/policy.middleware.js`
(`createDefaultPolicyMiddleware(POLICY_SERVICE_URL, {...})`) — see audit-service's,
communication-service's, events-service's, and notification-service's own `CLAUDE.md` files, which
each describe that wrapper from the consumer side.

## `src/policyClient.js` (`PolicyClient`)

The HTTP client to user-service's policy-evaluation endpoint. Two request modes:
`evaluateWithHeaders(headers, resource, action, context)` forwards the gateway's already-verified
identity headers (`x-jwt-verified`, `x-user-id`, `x-tenant-id`, `x-user-roles`,
`x-user-permissions`, etc.) as-is, with **no token in the body** — the preferred path when a request
came through the gateway. `evaluatePolicy(token, ...)` is the legacy fallback that sends a raw Bearer
token for user-service to verify itself.

Results are cached in-memory (`Map`, default 5-minute TTL) keyed off a hash of
token-or-user-context + resource + action + context — call `clearCache()`/`getCacheStats()` when a
caller needs to bust the cache (e.g. right after a role change), don't wait for the TTL. `makeRequest()`'s
retry logic is deliberately asymmetric: `401`/`403` fail immediately (a policy denial is not
transient — retrying won't change it), `5xx`/network errors retry with exponential backoff up to
`retries` (default 3, consuming services usually configure 5), and other `4xx` fail immediately too.

## `src/policy.middleware.js` (`PolicyMiddleware`)

The Express middleware factory (`requirePermission(resource, action)`). It builds an authorization
`context` from `req.body`/`req.query` merged with the resolved `userId`/`tenantId`/`roles`/
`permissions` (deliberately stripping `id` from body/query unless it's an actual route param, to
avoid ambiguity with the resource being acted on), decides whether gateway headers are present
(`x-jwt-verified === "true" && x-auth-source === "gateway"`) and calls `evaluateWithHeaders`/
`evaluatePolicy` accordingly, then on `PERMIT` sets `req.policyContext`/`req.user`/`req.userId`/
`req.tenantId`/`req.roles`/`req.permissions` for downstream controllers.

## `src/gatewaySecurity.js` (`validateGatewayRequest`)

Validates that a request actually came through the gateway rather than trusting
`x-jwt-verified: true` blindly from an untrusted source. See `gotchas.md` for the specific ways this
check is weaker than it sounds, and the one deliberate bypass path for automation callers.
