"use strict";
// Phase B / Z9.1: the policy client's decision-cache key. Every verified identity attribute the
// user-service PDP decides on (full user id, full tenant id, user type, roles, permissions), the
// request target and the whole canonical context are in the key, so: no user/user or tenant/tenant
// collision, a role or permission change naturally misses the decision cached for the old
// authorization state, nested context values are never dropped, and a token is identified by a
// hash of the WHOLE token. Decisions themselves (ASU, PlatformPrincipal, ordinary roles) are the
// PDP's and are returned unchanged. Every scenario runs against both builds: dist/ and dist/esm/.
// Run: node --test test/  (from the package root, after npm run build)

const os = require("os");
const path = require("path");
const fs = require("fs");
process.env.LOG_ROOT = process.env.LOG_ROOT || fs.mkdtempSync(path.join(os.tmpdir(), "pm-cachekey-"));

const test = require("node:test");
const assert = require("node:assert/strict");

// Same ObjectId creation second -> identical first 8 characters (the old key used only those).
const A = "68cbf7806080b4621d469d34";
const A2 = "68cbf7806080b4621d46ffff";
const U1 = "6a0000006080b4621d4600a1";
const U2 = "6a0000006080b4621d4600b2";
const ROLE = (code, id = "6a00000000000000000000r1") => ({ id, code, name: code });
const gw = (o = {}) => ({
  "x-jwt-verified": "true",
  "x-auth-source": "gateway",
  "x-user-id": o.userId || U1,
  "x-tenant-id": o.tenantId || A,
  "x-user-type": o.userType || "CRM",
  "x-user-email": o.email || "person@example.org",
  "x-user-roles": JSON.stringify(o.roles || [ROLE("ASU")]),
  "x-user-permissions": JSON.stringify(o.permissions || ["*"]),
  ...(o.correlationId ? { "x-correlation-id": o.correlationId } : {}),
});
// The context the middleware builds (policy.middleware.js requirePermission).
const ctxOf = (h, extra = {}) => ({
  userId: h["x-user-id"],
  tenantId: h["x-tenant-id"],
  userRoles: JSON.parse(h["x-user-roles"]),
  userPermissions: JSON.parse(h["x-user-permissions"]),
  ...extra,
});

const quietly = async (fn) => {
  const l = console.log, e = console.error;
  console.log = console.error = () => {};
  try { return await fn(); } finally { console.log = l; console.error = e; }
};

const builds = [
  ["cjs", async () => ({ PolicyClient: require("../dist/policyClient"), PolicyMiddleware: require("../dist/policy.middleware") })],
  ["esm", async () => ({ PolicyClient: (await import("../dist/esm/policyClient.js")).default, PolicyMiddleware: (await import("../dist/esm/policy.middleware.js")).default })],
];

for (const [name, load] of builds) {
  const key = async (h, extra) => {
    const { PolicyClient } = await load();
    const c = new PolicyClient("http://pdp");
    const ctx = ctxOf(h, extra);
    return c.getCacheKeyFromContext(h["x-user-id"], h["x-tenant-id"], "role", "read", ctx, h);
  };

  test(`[${name}] no user/user collision for users created in the same second (same 8-char prefix)`, async () => {
    assert.notEqual(await key(gw({ userId: U1 })), await key(gw({ userId: U2 })));
  });

  test(`[${name}] no tenant/tenant collision for tenants with the same 8-char prefix`, async () => {
    assert.notEqual(await key(gw({ tenantId: A })), await key(gw({ tenantId: A2 })));
  });

  test(`[${name}] a role change misses the old decision (SU -> ASU with the same permissions)`, async () => {
    assert.notEqual(await key(gw({ roles: [ROLE("SU")] })), await key(gw({ roles: [ROLE("ASU", "6a00000000000000000000r2")] })));
    assert.notEqual(await key(gw({ roles: [ROLE("REO")] })), await key(gw({ roles: [ROLE("REO"), ROLE("IRO", "6a00000000000000000000r3")] })));
  });

  test(`[${name}] a permission change or a user-type change misses the old decision`, async () => {
    assert.notEqual(await key(gw({ permissions: ["role:read"] })), await key(gw({ permissions: ["role:read", "role:write"] })));
    assert.notEqual(await key(gw({ userType: "CRM" })), await key(gw({ userType: "PORTAL" })));
  });

  test(`[${name}] nested context values are part of the key (never dropped)`, async () => {
    assert.notEqual(await key(gw(), { filter: { status: "open" } }), await key(gw(), { filter: { status: "closed" } }));
  });

  test(`[${name}] deterministic: same authorization state -> same key, whatever the property order`, async () => {
    const h = gw();
    assert.equal(await key(h, { a: 1, b: { y: 2, x: 1 } }), await key(h, { b: { x: 1, y: 2 }, a: 1 }));
    // not decision input: the email and the correlation id
    assert.equal(await key(gw({ email: "one@example.org", correlationId: "c1" })), await key(gw({ email: "two@example.org", correlationId: "c2" })));
  });

  test(`[${name}] token path: the whole token is the discriminator, not its first 20 / last 10 characters`, async () => {
    const { PolicyClient } = await load();
    const c = new PolicyClient("http://pdp");
    const head = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const t1 = `${head}.eyJpZCI6InVzZXItMSJ9.SAMEPREFIX__0123456789`;
    const t2 = `${head}.eyJpZCI6InVzZXItMiJ9.SAMEPREFIX__0123456789`;
    assert.notEqual(c.getCacheKey(t1, "role", "read", {}), c.getCacheKey(t2, "role", "read", {}));
    assert.equal(c.getCacheKey(t1, "role", "read", {}), c.getCacheKey(t1, "role", "read", {}));
  });

  test(`[${name}] keys / cache stats expose no ids, roles, permissions, email or token material`, async () => {
    const { PolicyClient } = await load();
    const c = new PolicyClient("http://pdp");
    const h = gw({ permissions: ["secretresource:secretaction"] });
    const k = c.getCacheKeyFromContext(U1, A, "role", "read", ctxOf(h), h);
    const t = c.getCacheKey("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SECRETSIGNATURE0123456789", "role", "read", {});
    for (const s of [k, t]) {
      assert.match(s, /^role:read:[0-9a-f]{64}$/);
      assert.ok(!/68cbf780|6a000000|ASU|secretresource|example\.org|eyJ|SECRET/.test(s), s);
    }
  });

  test(`[${name}] evaluateWithHeaders: cache hit for the same state; a role change re-asks the PDP and never returns the stale PERMIT`, async () => {
    const { PolicyClient } = await load();
    const c = new PolicyClient("http://pdp");
    const sent = [];
    let answer = { success: true, decision: "PERMIT", reason: "ASU_OWN_TENANT_ADMIN" };
    c.makeRequest = async (endpoint, opts) => (sent.push(opts.headers["x-user-roles"]), { ...answer });
    const asu = gw({ roles: [ROLE("ASU")] });
    const r1 = await quietly(() => c.evaluateWithHeaders(asu, "role", "write", ctxOf(asu)));
    const r2 = await quietly(() => c.evaluateWithHeaders(asu, "role", "write", ctxOf(asu)));
    assert.equal(r1.decision, "PERMIT");
    assert.equal(r2.decision, "PERMIT");
    assert.equal(sent.length, 1, "the second identical request is served from the cache");
    // the role is removed (the user signs in again: new roles / permissions headers)
    answer = { success: true, decision: "DENY", reason: "INSUFFICIENT_PERMISSIONS" };
    const ord = gw({ roles: [ROLE("REO", "6a00000000000000000000r9")], permissions: ["role:read"] });
    const r3 = await quietly(() => c.evaluateWithHeaders(ord, "role", "write", ctxOf(ord)));
    assert.equal(sent.length, 2, "the new authorization state is evaluated by the PDP");
    assert.equal(r3.decision, "DENY");
    // the same user in another tenant is never served the tenant-A decision
    const other = gw({ tenantId: A2 });
    await quietly(() => c.evaluateWithHeaders(other, "role", "write", ctxOf(other)));
    assert.equal(sent.length, 3);
  });

  test(`[${name}] tenant boundary stays first: no trusted tenant -> 401 before any PDP call or cache entry`, async () => {
    const { PolicyMiddleware } = await load();
    const mw = new PolicyMiddleware("http://pdp");
    let calls = 0;
    mw.policyClient.makeRequest = async () => (calls++, { success: true, decision: "PERMIT" });
    for (const tenant of ["not-a-tenant", "68CBF7806080B4621D469D34", ""]) {
      const req = { headers: gw({ tenantId: tenant || undefined }), body: {}, query: {}, params: {}, path: "/x" };
      if (!tenant) delete req.headers["x-tenant-id"];
      const res = { code: null, status(c) { this.code = c; return this; }, json() { return this; } };
      let nexted = false;
      await quietly(() => mw.requirePermission("role", "read")(req, res, () => (nexted = true)));
      assert.equal(res.code, 401, tenant);
      assert.equal(nexted, false);
    }
    assert.equal(calls, 0);
    assert.equal(mw.policyClient.getCacheStats().size, 0);
  });

  test(`[${name}] decisions are the PDP's, unchanged (ASU own-tenant PERMIT, platform DENY, ordinary DENY -> 403)`, async () => {
    const { PolicyMiddleware } = await load();
    const mw = new PolicyMiddleware("http://pdp");
    const byResource = {
      role: { success: true, decision: "PERMIT", reason: "ASU_OWN_TENANT_ADMIN", user: { id: U1, tenantId: A, roles: [], permissions: [] } },
      "platform:tenant": { success: false, decision: "DENY", reason: "PLATFORM_PERMISSION_NOT_TENANT_EVALUABLE" },
      lookup: { success: false, decision: "DENY", reason: "INSUFFICIENT_PERMISSIONS" },
    };
    mw.policyClient.makeRequest = async (endpoint, opts) => ({ ...byResource[opts.data.resource] });
    const run = async (resource) => {
      const req = { headers: gw(), body: {}, query: {}, params: {}, path: "/x" };
      const res = { code: null, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } };
      let nexted = false;
      await quietly(() => mw.requirePermission(resource, "read")(req, res, () => (nexted = true)));
      return { nexted, code: res.code, reason: res.body && res.body.reason, tenant: req.tenantId };
    };
    assert.deepEqual(await run("role"), { nexted: true, code: null, reason: null, tenant: A });
    assert.deepEqual(await run("platform:tenant"), { nexted: false, code: 403, reason: "PLATFORM_PERMISSION_NOT_TENANT_EVALUABLE", tenant: undefined });
    assert.deepEqual(await run("lookup"), { nexted: false, code: 403, reason: "INSUFFICIENT_PERMISSIONS", tenant: undefined });
  });
}
