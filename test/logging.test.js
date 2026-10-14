"use strict";
// Logging hardening: the policy middleware and client log safe metadata only - never request
// body/query values, the user's email, roles or permissions, token-derived values, raw policy
// results, raw error bodies, stacks or query strings in paths. Authorization behaviour (PERMIT/DENY,
// 401/403/500 bodies, req.user / req.policyContext / req.tenantId, the context sent to user-service,
// client return values) is unchanged. Every scenario runs against both builds: dist/ (CommonJS) and
// dist/esm/ (ESM).
// Run: node --test test/  (from the package root)

const os = require("os");
const path = require("path");
const fs = require("fs");
process.env.LOG_ROOT = process.env.LOG_ROOT || fs.mkdtempSync(path.join(os.tmpdir(), "pm-logging-log-"));

const test = require("node:test");
const assert = require("node:assert");
const util = require("util");

// --- sensitive inputs -------------------------------------------------------------------------
const B64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const JWT_CLAIMS = {
  sub: "user-token-1",
  tenantId: "tenant-token-1",
  email: "token.person@example.org",
  roles: ["TOKEN-SECRET-ROLE"],
  permissions: ["tokensecret:read"],
};
const JWT = `${B64({ alg: "HS256", typ: "JWT" })}.${B64(JWT_CLAIMS)}.SECRETSIGNATURE0123456789abcdef`;
const BODY = {
  email: "body.person@example.org",
  dateOfBirth: "1900-01-01",
  address: "1 Example Street, X00 TEST0",
  memberIds: ["MEMBER-SECRET-ID-777"],
  accessToken: JWT,
  nested: { mobile: "+000 0000 0000" },
};
const QUERY = { search: "query.person@example.org", token: "QUERY-SECRET-TOKEN-999" };
const ROLES = ["SECRET-ROLE-CODE"];
const PERMS = ["secretresource:secretaction"];
const RESULT_USER = {
  id: "user-1",
  tenantId: "tenant-1",
  userType: "CRM",
  email: "result.person@example.org",
  roles: ["RESULT-SECRET-ROLE"],
  permissions: ["resultsecret:write"],
};
const ERROR_TEXT = "SECRET-ERROR-TEXT for error.person@example.org";
const SENSITIVE = [
  JWT,
  ...JWT.split("."),
  JWT.slice(0, 20),
  "token.person@example.org",
  "TOKEN-SECRET-ROLE",
  "tokensecret:read",
  ...["body.person@example.org", "1900-01-01", "1 Example Street", "MEMBER-SECRET-ID-777", "+000 0000 0000"],
  "query.person@example.org",
  "QUERY-SECRET-TOKEN-999",
  "SECRET-ROLE-CODE",
  "secretresource:secretaction",
  "result.person@example.org",
  "RESULT-SECRET-ROLE",
  "resultsecret:write",
  "SECRET-ERROR-TEXT",
  "error.person@example.org",
  "SECRETSIGNATURE",
];

// --- log capture (console.* and the structured logger's stdout/stderr) ------------------------
async function capture(fn) {
  const lines = [];
  const render = (a) => (typeof a === "string" ? a : a instanceof Error ? util.inspect(a) : util.inspect(a, { depth: 8 }));
  const saved = {};
  for (const l of ["log", "error", "warn", "info", "debug"]) {
    saved[l] = console[l];
    console[l] = (...a) => lines.push(a.map(render).join(" "));
  }
  const out = process.stdout.write;
  const err = process.stderr.write;
  process.stdout.write = (s) => (lines.push(String(s)), true);
  process.stderr.write = (s) => (lines.push(String(s)), true);
  try {
    await fn();
  } finally {
    Object.assign(console, saved);
    process.stdout.write = out;
    process.stderr.write = err;
  }
  return lines.join("\n");
}
const assertClean = (text) => {
  for (const v of SENSITIVE) assert.ok(!text.includes(v), `log contains sensitive value ${String(v).slice(0, 8)}...`);
  assert.doesNotMatch(text, /\n\s+at \S+ \(/, "no stack traces");
  assert.doesNotMatch(text, /Bearer [A-Za-z0-9]/);
};

// --- request / response fakes -----------------------------------------------------------------
const gatewayHeaders = (extra = {}) => ({
  "x-jwt-verified": "true",
  "x-auth-source": "gateway",
  "x-user-id": "user-1",
  "x-tenant-id": "tenant-1",
  "x-user-roles": JSON.stringify(ROLES),
  "x-user-permissions": JSON.stringify(PERMS),
  "x-user-email": "header.person@example.org",
  "x-correlation-id": "corr-123",
  authorization: `Bearer ${JWT}`,
  cookie: "connect.sid=SECRET-COOKIE",
  ...extra,
});
const mkReq = (o = {}) => ({
  headers: {},
  body: structuredClone(BODY),
  query: { ...QUERY },
  params: {},
  path: "/api/things",
  originalUrl: "/api/things?search=query.person@example.org&token=QUERY-SECRET-TOKEN-999",
  ...o,
});
function mkRes() {
  const res = { statusCode: null, body: null };
  res.status = (s) => ((res.statusCode = s), res);
  res.json = (b) => ((res.body = JSON.parse(JSON.stringify(b))), res);
  return res;
}
async function run(pm, req, resource = "things", action = "write") {
  const res = mkRes();
  let nextCalled = false;
  const text = await capture(() => pm.requirePermission(resource, action)(req, res, () => (nextCalled = true)));
  return { req, res, nextCalled, text };
}
const permit = (user = RESULT_USER) => ({
  success: true,
  decision: "PERMIT",
  reason: "PERMISSION_GRANTED",
  policyVersion: "1.0.0",
  user: structuredClone(user),
  resource: "things",
  action: "write",
});
// What the middleware sends to user-service: identity, roles/permissions, then query and body
// (id removed unless a route param), with tenantId/userId re-asserted from the trusted context.
const expectedContext = (userId, tenantId, roles, perms) => ({
  ...{ userId, tenantId, userRoles: roles, userPermissions: perms },
  ...QUERY,
  ...BODY,
  tenantId,
  userId,
});

// --- scenarios, registered once per build -----------------------------------------------------
function scenarios(label, load) {
  let lib;
  test.before(async () => {
    lib = await load();
  });
  const newMiddleware = () => new lib.PolicyMiddleware("http://pdp.invalid", { retries: 1 });

  test(`${label}: 1 gateway path - PERMIT behaviour unchanged, safe metadata only`, async () => {
    const pm = newMiddleware();
    let sent;
    const result = permit();
    pm.policyClient.evaluateWithHeaders = async (headers, resource, action, context) => {
      sent = { headers, resource, action, context };
      return result;
    };
    const { req, nextCalled, text } = await run(pm, mkReq({ headers: gatewayHeaders() }));
    assert.equal(nextCalled, true);
    assert.equal(req.policyContext, result);
    assert.equal(req.user, result.user);
    assert.equal(req.userId, "user-1");
    assert.equal(req.tenantId, "tenant-1");
    assert.deepEqual(req.roles, RESULT_USER.roles);
    assert.deepEqual(req.permissions, RESULT_USER.permissions);
    assert.deepEqual(sent.context, expectedContext("user-1", "tenant-1", ROLES, PERMS));
    assert.equal(sent.resource, "things");
    assert.equal(sent.headers["x-user-id"], "user-1");
    assertClean(text);
    assert.doesNotMatch(text, /header\.person@example\.org|SECRET-COOKIE/);
    assert.match(text, /resource: 'things'/);
    assert.match(text, /action: 'write'/);
    assert.match(text, /userId: 'user-1'/);
    assert.match(text, /tenantId: 'tenant-1'/);
    assert.match(text, /authPath: 'gateway'/);
    assert.match(text, /roleCount: 1/);
    assert.match(text, /permissionCount: 1/);
    assert.match(text, /bodyFields: \[[^\]]*'email'[^\]]*'memberIds'/s);
    assert.match(text, /queryFields: \[ 'search', 'token' \]/);
    assert.match(text, /correlationId: 'corr-123'/);
    assert.match(text, /decision: 'PERMIT'/);
    assert.match(text, /userType: 'CRM'/);
  });

  test(`${label}: 2 token path - token, claims and context unchanged; nothing token-derived logged`, async () => {
    const pm = newMiddleware();
    let sent;
    pm.policyClient.evaluatePolicy = async (token, resource, action, context) => {
      sent = { token, resource, action, context };
      return permit();
    };
    const { req, nextCalled, text } = await run(pm, mkReq({ headers: { authorization: `Bearer ${JWT}` } }));
    assert.equal(nextCalled, true);
    assert.equal(sent.token, JWT);
    assert.deepEqual(
      sent.context,
      expectedContext(JWT_CLAIMS.sub, JWT_CLAIMS.tenantId, JWT_CLAIMS.roles, JWT_CLAIMS.permissions),
    );
    assert.equal(req.tenantId, "tenant-1");
    assertClean(text);
    assert.match(text, /authPath: 'token'/);
    assert.match(text, /userId: 'user-token-1'/);
  });

  test(`${label}: 3 auth-bypass path - same synthetic PERMIT; auth endpoint still 403`, async (t) => {
    process.env.AUTH_BYPASS_ENABLED = "true";
    t.after(() => delete process.env.AUTH_BYPASS_ENABLED);
    const pm = newMiddleware();
    pm.policyClient.evaluateWithHeaders = async () => assert.fail("bypass must not call user-service");
    const r = await run(pm, mkReq({ headers: gatewayHeaders() }));
    assert.equal(r.nextCalled, true);
    assert.deepEqual(r.req.user, { id: "user-1", userType: "PORTAL", tenantId: "tenant-1", roles: ROLES, permissions: PERMS });
    assert.equal(r.req.policyContext.reason, "AUTH_BYPASS_ENABLED");
    assertClean(r.text);
    assert.match(r.text, /authPath: 'bypass'/);
    const a = await run(pm, mkReq({ headers: gatewayHeaders(), path: "/auth/login" }));
    assert.equal(a.res.statusCode, 403);
    assert.deepEqual(a.res.body, {
      success: false,
      error: "Authentication bypass is not allowed for authentication endpoints",
      code: "SECURITY_VIOLATION",
      status: 403,
    });
    assertClean(a.text);
  });

  test(`${label}: 7 DENY - 403 body unchanged; requiredPermissions and counts logged, nothing else`, async () => {
    const pm = newMiddleware();
    const deny = {
      success: false,
      decision: "DENY",
      reason: "INSUFFICIENT_PERMISSIONS",
      error: ERROR_TEXT,
      code: "DENIED",
      userPermissions: [...PERMS, "anothersecret:perm"],
      requiredPermissions: ["things:write"],
      availablePermissions: ["things:read"],
      availableCanonical: ["things:read"],
      user: structuredClone(RESULT_USER),
    };
    pm.policyClient.evaluateWithHeaders = async () => deny;
    const { res, nextCalled, text } = await run(pm, mkReq({ headers: gatewayHeaders() }));
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 403);
    assert.deepEqual(res.body, {
      success: false,
      error: ERROR_TEXT,
      reason: "INSUFFICIENT_PERMISSIONS",
      code: "PERMISSION_DENIED",
      resource: "things",
      action: "write",
      userPermissions: [...PERMS, "anothersecret:perm"],
      requiredPermissions: ["things:write"],
      availablePermissions: ["things:read"],
      availableCanonical: ["things:read"],
    });
    assertClean(text);
    assert.doesNotMatch(text, /anothersecret/);
    assert.match(text, /Required permissions: \[ 'things:write' \]/);
    assert.match(text, /permissionCount: 2/);
    assert.match(text, /decision: 'DENY'/);
    assert.match(text, /reason: 'INSUFFICIENT_PERMISSIONS'/);
  });

  test(`${label}: 401 bodies unchanged`, async () => {
    const pm = newMiddleware();
    const noUser = await run(pm, mkReq({ headers: {} }));
    assert.equal(noUser.res.statusCode, 401);
    assert.deepEqual(noUser.res.body, { success: false, error: "Authentication required", code: "UNAUTHORIZED", status: 401 });
    const noToken = await run(pm, mkReq({ headers: {}, ctx: { userId: "user-1", tenantId: "tenant-1" } }));
    assert.equal(noToken.res.statusCode, 401);
    assert.deepEqual(noToken.res.body, { success: false, error: "Authorization token required", code: "UNAUTHORIZED", status: 401 });
    assertClean(noUser.text + noToken.text);
  });

  test(`${label}: 500 body unchanged; error logged as {name, code, status} without message or stack`, async () => {
    const pm = newMiddleware();
    pm.policyClient.evaluateWithHeaders = async () => {
      throw Object.assign(new Error(ERROR_TEXT), { code: "EBROKEN" });
    };
    const { res, text } = await run(pm, mkReq({ headers: gatewayHeaders() }));
    assert.equal(res.statusCode, 500);
    assert.deepEqual(res.body, { success: false, error: "Authorization service error", code: "POLICY_SERVICE_ERROR" });
    assertClean(text);
    assert.match(text, /name: 'Error', code: 'EBROKEN', status: null/);
  });

  test(`${label}: 8 user-service error responses - client return values unchanged, raw body not logged`, async () => {
    const client = new lib.PolicyClient("http://pdp.invalid", { retries: 1 });
    const data = {
      success: false,
      decision: "DENY",
      reason: "PERMISSION_DENIED",
      code: "DENIED",
      error: ERROR_TEXT,
      user: structuredClone(RESULT_USER),
    };
    const httpError = (status) =>
      Object.assign(new Error(`Request failed with status code ${status}`), {
        name: "AxiosError",
        code: "ERR_BAD_RESPONSE",
        config: { data: JSON.stringify({ token: JWT, context: BODY }), headers: { Authorization: `Bearer ${JWT}` } },
        response: { status, data: structuredClone(data) },
      });
    let n = 0;
    const call = async (fn, status) => {
      client.makeRequest = async () => {
        throw httpError(status);
      };
      let ret;
      const text = await capture(async () => (ret = await fn(++n)));
      return { ret, text };
    };
    // evaluate (token path) passes a 403 body through; evaluateWithHeaders never does.
    const a = await call((i) => client.evaluate(JWT, "things", "write", { i }), 403);
    assert.deepEqual(a.ret, { success: false, decision: "DENY", reason: "PERMISSION_DENIED", error: ERROR_TEXT, ...data });
    const a2 = await call((i) => client.evaluateWithHeaders(gatewayHeaders(), "things", "write", { i }), 403);
    assert.deepEqual(a2.ret, { success: false, decision: "DENY", reason: "POLICY_SERVICE_ERROR", error: "Request failed with status code 403" });
    const b = await call((i) => client.evaluate(JWT, "things", "write", { i }), 500);
    assert.deepEqual(b.ret, {
      success: false,
      decision: "DENY",
      reason: "POLICY_SERVICE_ERROR",
      error: "Request failed with status code 500",
      errorCode: "ERR_BAD_RESPONSE",
      errorResponse: data,
    });
    const c = await call((i) => client.evaluateWithHeaders(gatewayHeaders(), "things", "write", { i }), 500);
    assert.deepEqual(c.ret, { success: false, decision: "DENY", reason: "POLICY_SERVICE_ERROR", error: "Request failed with status code 500" });
    const d = await call(() => client.getPermissions(JWT, "things"), 500);
    assert.deepEqual(d.ret, { success: false, permissions: [], error: "Request failed with status code 500" });
    const e = await call(() => client.getPermissionsWithHeaders(gatewayHeaders(), "things"), 500);
    assert.deepEqual(e.ret, { success: false, permissions: [], error: "Request failed with status code 500" });
    const text = [a, a2, b, c, d, e].map((x) => x.text).join("\n");
    assertClean(text);
    assert.match(text, /name: 'AxiosError', code: 'ERR_BAD_RESPONSE', status: 403/);
    assert.match(text, /Server response data: \{ reason: 'PERMISSION_DENIED', decision: 'DENY', code: 'DENIED' \}/);
  });

  test(`${label}: 9 structured logs use the path without query-string values`, async () => {
    const req = mkReq({ headers: { "x-jwt-verified": "true", "x-auth-source": "gateway" } });
    let gatewayResult;
    const gw = await capture(() => (gatewayResult = lib.gatewaySecurity.validateGatewayRequest(req)));
    assert.equal(gatewayResult.valid, false);
    const tc = await capture(() =>
      lib.resolveTenantContext(
        mkReq({ headers: gatewayHeaders(), body: { tenantId: "other-tenant" } }),
        { mode: "warn" },
      ),
    );
    for (const text of [gw, tc]) {
      assert.match(text, /"path":"\/api\/things"/);
      assertClean(text);
    }
  });
}

scenarios("cjs", async () => require("../dist/index.js"));
scenarios("esm", async () => import("../dist/esm/index.js"));
