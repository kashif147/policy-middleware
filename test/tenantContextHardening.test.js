"use strict";
// Phase B tenant-context hardening: the ONLY trusted tenant is the gateway's verified boundary
// (x-auth-source "gateway" + x-jwt-verified "true" + 24-lowercase-hex x-tenant-id); no Bearer /
// tid / extension_tenantId / ctx fallback; strict warn|enforce configuration.
// Run: node --test  (from the package root). Numbers match the Phase B test list.

const os = require("os");
const path = require("path");
const fs = require("fs");
process.env.LOG_ROOT = process.env.LOG_ROOT || fs.mkdtempSync(path.join(os.tmpdir(), "pm-tenantctx-hard-"));

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  getTrustedTenant,
  resolveTenantContext,
  tenantContextMiddleware,
  resolveTenantContextMode,
  tenantContextModeFrom,
  isInternalTenantId,
} = require("../src/tenantContext");
const PolicyMiddleware = require("../src/policy.middleware");

const A = "68c6ad231ae58311ab99aaaa"; // internal ProjectShell tenant ids (24 lowercase hex)
const B = "6acd6119b28a863c61361bbb";
const GUID = "9188040d-6c67-4c5b-b112-36a304b66dad";

const gw = (tenantId, extra = {}) => ({ "x-auth-source": "gateway", "x-jwt-verified": "true", "x-tenant-id": tenantId, ...extra });
const mkReq = (o = {}) => ({ headers: {}, method: "GET", url: "/x", originalUrl: "/x", path: "/x", ...o });
function mkRes() {
  const r = { statusCode: null, payload: null };
  r.status = (c) => ((r.statusCode = c), r);
  r.json = (p) => ((r.payload = p), r);
  return r;
}
function runMw(mw, req) {
  const res = mkRes();
  let nexted = false;
  mw(req, res, () => (nexted = true));
  return { res, nexted };
}
function quiet(fn) {
  const w = process.stdout.write.bind(process.stdout);
  const out = [];
  process.stdout.write = (s) => (out.push(String(s)), true);
  try { return { value: fn(), out: out.join("") }; } finally { process.stdout.write = w; }
}
async function quietAsync(fn) {
  const w = process.stdout.write.bind(process.stdout), e = process.stderr.write.bind(process.stderr);
  const out = [];
  process.stdout.write = (s) => (out.push(String(s)), true);
  process.stderr.write = (s) => (out.push(String(s)), true);
  const log = console.log, err = console.error;
  console.log = (...a) => out.push(a.map(String).join(" "));
  console.error = (...a) => out.push(a.map(String).join(" "));
  try { return { value: await fn(), out: out.join("\n") }; } finally { process.stdout.write = w; process.stderr.write = e; console.log = log; console.error = err; }
}
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const unsignedJwt = (claims) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.${crypto.randomBytes(16).toString("base64url")}`;

function withEnv(value, fn) {
  const had = Object.prototype.hasOwnProperty.call(process.env, "TENANT_CONTEXT_MODE");
  const prev = process.env.TENANT_CONTEXT_MODE;
  if (value === undefined) delete process.env.TENANT_CONTEXT_MODE; else process.env.TENANT_CONTEXT_MODE = value;
  try { return fn(); } finally { if (had) process.env.TENANT_CONTEXT_MODE = prev; else delete process.env.TENANT_CONTEXT_MODE; }
}

// ------------------------------------------------------------------ TRUSTED
test("1 gateway + verified + valid 24-hex tenantId -> trusted (and pinned on req)", () => {
  const req = mkReq({ headers: gw(A) });
  assert.equal(getTrustedTenant(req), A);
  const r = quiet(() => resolveTenantContext(req, { mode: "warn" })).value;
  assert.equal(r.tenantId, A);
  assert.equal(r.trustedTenantPresent, true);
  assert.equal(req.tenantId, A);
});

test("2 matching body tenantId -> no mismatch", () => {
  const r = resolveTenantContext(mkReq({ headers: gw(A), body: { tenantId: A } }), { mode: "enforce" });
  assert.equal(r.mismatch, false);
  assert.equal(r.rejected, false);
});

test("3 matching query tenantId -> no mismatch", () => {
  const r = resolveTenantContext(mkReq({ headers: gw(A), query: { tenantId: A } }), { mode: "enforce" });
  assert.equal(r.mismatch, false);
  assert.equal(r.rejected, false);
});

// ------------------------------------------------------------------ UNTRUSTED
const untrusted = [
  ["4 missing x-auth-source", { "x-jwt-verified": "true", "x-tenant-id": A }],
  ["5 wrong x-auth-source (azuread)", gw(A, { "x-auth-source": "azuread" })],
  ["5 wrong x-auth-source (Gateway, case)", gw(A, { "x-auth-source": "Gateway" })],
  ["6 missing x-jwt-verified", { "x-auth-source": "gateway", "x-tenant-id": A }],
  ["7 x-jwt-verified != true (false)", gw(A, { "x-jwt-verified": "false" })],
  ["7 x-jwt-verified != true (TRUE)", gw(A, { "x-jwt-verified": "TRUE" })],
  ["8 missing x-tenant-id", { "x-auth-source": "gateway", "x-jwt-verified": "true" }],
  ["9 uppercase tenantId", gw(A.toUpperCase())],
  ["9 mixed-case tenantId", gw("68C6ad231ae58311ab99aaaa")],
  ["10 23 characters", gw(A.slice(1))],
  ["10 25 characters", gw(A + "a")],
  ["11 GUID / Microsoft tid", gw(GUID)],
  ["11 GUID without dashes (32 hex)", gw(GUID.replace(/-/g, ""))],
  ["12 non-hex 24 chars", gw("68c6ad231ae58311ab99aaag")],
  ["12 padded with spaces", gw(` ${A.slice(1)}`)],
  ["12 empty string", gw("")],
  ["12 duplicate header joined by Node", gw(`${A}, ${B}`)],
  ["12 array", gw([A])],
  ["12 object", gw({ toString: () => A })],
  ["12 number", gw(123456789012345678901234)],
  ["12 boolean", gw(true)],
  ["12 null", gw(null)],
];
for (const [label, headers] of untrusted) {
  test(`${label} -> ignored (no trusted tenant, nothing pinned, no mismatch decision)`, () => {
    const req = mkReq({ headers, body: { tenantId: B } });
    assert.equal(getTrustedTenant(req), undefined);
    const r = resolveTenantContext(req, { mode: "enforce" });
    assert.equal(r.trustedTenantPresent, false);
    assert.equal(r.tenantId, undefined);
    assert.equal(req.tenantId, undefined);
    assert.equal(r.rejected, false);
  });
}

test("isInternalTenantId accepts only 24 lowercase hex strings", () => {
  assert.equal(isInternalTenantId(A), true);
  for (const v of [A.toUpperCase(), A.slice(1), GUID, null, undefined, 1, true, [A], { a: 1 }, ""]) assert.equal(isInternalTenantId(v), false, String(v));
});

// ------------------------------------------------------------------ FALLBACK REMOVAL
test("13-16 tenantContext never derives a tenant from req.ctx / req.user / req.tenantId or a Bearer token", () => {
  const tok = unsignedJwt({ tenantId: A, tid: GUID, extension_tenantId: B, id: "u1" });
  for (const req of [
    mkReq({ headers: { authorization: `Bearer ${tok}` }, body: { tenantId: B } }),
    mkReq({ headers: { authorization: `Bearer ${tok}`, "x-jwt-verified": "true" } }),
    mkReq({ ctx: { tenantId: A }, user: { tenantId: A }, tenantId: A, body: { tenantId: B } }),
    mkReq({ ctx: { tenantId: GUID } }), // e.g. an azuread-populated ctx
    mkReq({ headers: { authorization: "Bearer not.a.jwt" } }),
  ]) {
    const before = req.tenantId;
    assert.equal(getTrustedTenant(req), undefined);
    const r = resolveTenantContext(req, { mode: "enforce" });
    assert.equal(r.trustedTenantPresent, false);
    assert.equal(req.tenantId, before, "an already-set req.tenantId is left alone, never replaced");
    assert.equal(r.rejected, false);
  }
});

function stubPm(decision = "PERMIT", user = { id: "u-verified", tenantId: B }) {
  const pm = new PolicyMiddleware("http://policy.invalid");
  const calls = [];
  const result = { success: decision === "PERMIT", decision, reason: decision === "PERMIT" ? "OK" : "DENY", user };
  pm.policyClient = {
    baseUrl: "http://policy.invalid",
    evaluateWithHeaders: async (headers, resource, action, context) => (calls.push({ mode: "headers", context }), result),
    evaluatePolicy: async (token, resource, action, context) => (calls.push({ mode: "token", context }), result),
  };
  return { pm, calls };
}
async function runPm(pm, req) {
  const res = mkRes();
  let nexted = false;
  const { out } = await quietAsync(() => pm.requirePermission("things", "read")(req, res, () => (nexted = true)));
  return { res, nexted, out };
}

test("13 Bearer with tenantId, no gateway headers: the tenant is NOT taken from the token (PDP verifies it)", async () => {
  const { pm, calls } = stubPm();
  const tok = unsignedJwt({ id: "u-claimed", tenantId: A });
  const req = mkReq({ headers: { authorization: `Bearer ${tok}` }, body: { tenantId: A } });
  const { nexted } = await runPm(pm, req);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].mode, "token");
  assert.equal(calls[0].context.tenantId, undefined, "no tenant derived from the unverified payload or body");
  assert.equal(calls[0].context.userId, undefined);
  assert.equal(nexted, true);
  assert.equal(req.tenantId, B, "identity comes only from the PDP's verified result");
});

test("13b req.ctx / req.user identity without gateway headers is not used; the Bearer goes to the PDP", async () => {
  const { pm, calls } = stubPm();
  const req = mkReq({ headers: { authorization: `Bearer ${unsignedJwt({ id: "u", tenantId: A })}` }, ctx: { userId: "ctx-user", tenantId: GUID }, user: { id: "ctx-user", tenantId: GUID } });
  const { nexted } = await runPm(pm, req);
  assert.equal(calls[0].mode, "token");
  assert.equal(calls[0].context.tenantId, undefined);
  assert.equal(calls[0].context.userId, undefined);
  assert.equal(nexted, true);
  assert.equal(req.tenantId, B, "from the PDP's verified result only");
  const noToken = stubPm();
  const r = await runPm(noToken.pm, mkReq({ ctx: { userId: "ctx-user", tenantId: A } }));
  assert.equal(r.res.statusCode, 401);
  assert.equal(noToken.calls.length, 0);
});

test("14/15 Bearer with tid / extension_tenantId -> never a tenant", async () => {
  for (const claims of [{ sub: "x", tid: GUID }, { sub: "x", extension_tenantId: A }]) {
    const { pm, calls } = stubPm("DENY", undefined);
    const req = mkReq({ headers: { authorization: `Bearer ${unsignedJwt(claims)}` } });
    const { res } = await runPm(pm, req);
    assert.equal(calls[0].context.tenantId, undefined);
    assert.equal(res.statusCode, 403);
    assert.equal(req.tenantId, undefined);
  }
});

test("16 malformed / unverified token -> no tenant context; no token at all -> 401 before the PDP", async () => {
  const { pm, calls } = stubPm("DENY", undefined);
  const r1 = await runPm(pm, mkReq({ headers: { authorization: "Bearer garbage" } }));
  assert.equal(calls[0].context.tenantId, undefined);
  assert.equal(r1.res.statusCode, 403);
  const { pm: pm2, calls: calls2 } = stubPm();
  const r2 = await runPm(pm2, mkReq({ headers: {} }));
  assert.equal(r2.res.statusCode, 401);
  assert.equal(calls2.length, 0);
});

test("requirePermission gateway path: tenant only from the verified 24-hex header; malformed -> 401, PDP not called", async () => {
  const ok = stubPm();
  const r = await runPm(ok.pm, mkReq({ headers: { ...gw(A), "x-user-id": "u1" }, body: { tenantId: B } }));
  assert.equal(ok.calls[0].mode, "headers");
  assert.equal(ok.calls[0].context.tenantId, A, "trusted tenant wins over the body");
  assert.equal(r.nexted, true);
  for (const t of [A.toUpperCase(), GUID, ""]) {
    const bad = stubPm();
    const rb = await runPm(bad.pm, mkReq({ headers: { ...gw(t), "x-user-id": "u1" } }));
    assert.equal(rb.res.statusCode, 401, JSON.stringify(t));
    assert.equal(bad.calls.length, 0);
  }
});

test("no jsonwebtoken / decode / tid fallback remains in the package source", () => {
  for (const f of fs.readdirSync(path.join(__dirname, "..", "src"))) {
    const code = fs.readFileSync(path.join(__dirname, "..", "src", f), "utf8").split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join("\n");
    assert.doesNotMatch(code, /require\(["']jsonwebtoken["']\)/, f);
    assert.doesNotMatch(code, /\bjwt\.decode\b|\.decode\(token/, f);
    assert.doesNotMatch(code, /\.tid\b|extension_tenantId/, f);
  }
});

// ------------------------------------------------------------------ WARN
test("17 WARN: trusted != body tenantId -> reported, request continues, trusted tenant kept", () => {
  const req = mkReq({ headers: gw(A), body: { tenantId: B } });
  const { value, out } = quiet(() => runMw(tenantContextMiddleware({ mode: "warn" }), req));
  assert.equal(value.nexted, true);
  assert.equal(value.res.statusCode, null);
  assert.equal(req.tenantId, A);
  assert.match(out, /TenantContextMismatch/);
  assert.match(out, /"outcome":"ignored"/);
});

test("18 WARN: trusted != query tenantId -> reported, request continues", () => {
  const req = mkReq({ headers: gw(A), query: { tenantId: B } });
  const { value, out } = quiet(() => runMw(tenantContextMiddleware({ mode: "warn" }), req));
  assert.equal(value.nexted, true);
  assert.match(out, /"suppliedSources":\["query"\]/);
});

test("WARN mismatch row carries no token / Authorization / body values", () => {
  const req = mkReq({ headers: gw(A, { authorization: "Bearer eyJsecret.x.y" }), body: { tenantId: B, password: "p@ss" } });
  const { out } = quiet(() => resolveTenantContext(req, { mode: "warn" }));
  for (const bad of ["Bearer", "eyJsecret", "p@ss", B]) assert.ok(!out.includes(bad), bad);
});

// ------------------------------------------------------------------ ENFORCE
test("19 ENFORCE: trusted != body tenantId -> 403", () => {
  const { value } = quiet(() => runMw(tenantContextMiddleware({ mode: "enforce" }), mkReq({ headers: gw(A), body: { tenantId: B } })));
  assert.equal(value.nexted, false);
  assert.equal(value.res.statusCode, 403);
  assert.equal(value.res.payload.code, "TENANT_CONTEXT_MISMATCH");
});

test("20 ENFORCE: trusted != query tenantId -> 403", () => {
  const { value } = quiet(() => runMw(tenantContextMiddleware({ mode: "enforce" }), mkReq({ headers: gw(A), query: { tenantId: B } })));
  assert.equal(value.res.statusCode, 403);
});

test("21 ENFORCE: matching tenant -> allowed", () => {
  const { nexted, res } = runMw(tenantContextMiddleware({ mode: "enforce" }), mkReq({ headers: gw(A), body: { tenantId: A }, query: { tenantId: A } }));
  assert.equal(nexted, true);
  assert.equal(res.statusCode, null);
});

test("ENFORCE with no trusted tenant: not rejected here, no tenant invented (existing behaviour)", () => {
  const req = mkReq({ headers: { "x-tenant-id": A }, body: { tenantId: B } });
  const { nexted } = runMw(tenantContextMiddleware({ mode: "enforce" }), req);
  assert.equal(nexted, true);
  assert.equal(req.tenantId, undefined);
});

// ------------------------------------------------------------------ SU
test("22 SU + mismatch in ENFORCE -> still 403 (no role exemption)", () => {
  for (const roles of ['["SU"]', '["SU","ASU"]']) {
    const req = mkReq({ headers: gw(A, { "x-user-roles": roles, "x-user-id": "su" }), body: { tenantId: B }, ctx: { roles: ["SU"] }, user: { roles: ["SU"] } });
    const { value } = quiet(() => runMw(tenantContextMiddleware({ mode: "enforce" }), req));
    assert.equal(value.res.statusCode, 403, roles);
    assert.equal(value.nexted, false);
  }
});

// ------------------------------------------------------------------ CONFIG
test("23 unset TENANT_CONTEXT_MODE -> warn (middleware does not block)", () => {
  withEnv(undefined, () => {
    assert.equal(tenantContextModeFrom(), "warn");
    const { value } = quiet(() => runMw(tenantContextMiddleware(), mkReq({ headers: gw(A), body: { tenantId: B } })));
    assert.equal(value.nexted, true);
  });
});

test("24 TENANT_CONTEXT_MODE=warn -> warn", () => {
  withEnv("warn", () => {
    assert.equal(tenantContextModeFrom(), "warn");
    const { value } = quiet(() => runMw(tenantContextMiddleware(), mkReq({ headers: gw(A), body: { tenantId: B } })));
    assert.equal(value.nexted, true);
  });
});

test("25 TENANT_CONTEXT_MODE=enforce -> enforce", () => {
  withEnv("enforce", () => {
    assert.equal(tenantContextModeFrom(), "enforce");
    const { value } = quiet(() => runMw(tenantContextMiddleware(), mkReq({ headers: gw(A), body: { tenantId: B } })));
    assert.equal(value.res.statusCode, 403);
  });
});

test("26 invalid values fail at configuration time (middleware creation), no silent fallback", () => {
  for (const v of ["", "WARN", "Enforce", "enforced", "true", "off", " warn", "warn "]) {
    withEnv(v, () => {
      assert.throws(() => tenantContextMiddleware(), /TENANT_CONTEXT_MODE/, JSON.stringify(v));
      assert.throws(() => tenantContextMiddleware({ mode: "warn" }), /TENANT_CONTEXT_MODE/, "a malformed env value fails even with an explicit mode");
    });
    assert.throws(() => resolveTenantContextMode(v), /must be "warn" or "enforce"/);
  }
  withEnv(undefined, () => {
    for (const m of ["ENFORCE", "block", null, 1, true]) assert.throws(() => tenantContextMiddleware({ mode: m }), /options\.mode/, String(m));
  });
  assert.equal(resolveTenantContextMode(undefined), "warn");
  assert.equal(resolveTenantContextMode("warn"), "warn");
  assert.equal(resolveTenantContextMode("enforce"), "enforce");
  withEnv("enforce", () => assert.equal(tenantContextModeFrom({ mode: "warn" }), "warn", "explicit option wins over a valid env value"));
});

test("26b the error message does not echo the configured value", () => {
  withEnv("enforce-SECRETISH", () => {
    assert.throws(() => tenantContextMiddleware(), (e) => !e.message.includes("SECRETISH"));
  });
});

// ------------------------------------------------------------------ PATH
test("27 path :tenantId: router-level mount never sees it; per-route detection is unchanged", () => {
  const express = require("express");
  const seen = [];
  const app = express();
  const router = express.Router();
  router.use(tenantContextMiddleware({ mode: "enforce" })); // router level (how services mount it)
  router.get("/tenants/:tenantId/things", (req, res) => (seen.push({ params: req.params, tenantId: req.tenantId }), res.json({ ok: true })));
  router.get("/per-route/:tenantId", tenantContextMiddleware({ mode: "enforce" }), (req, res) => res.json({ ok: true }));
  app.use(router);
  const server = app.listen(0, "127.0.0.1");
  return new Promise((resolve, reject) => {
    server.on("listening", async () => {
      try {
        const base = `http://127.0.0.1:${server.address().port}`;
        const headers = gw(A);
        const r1 = await fetch(`${base}/tenants/${B}/things`, { headers });
        assert.equal(r1.status, 200, "router-level: path tenant is left to requireTenantPathAccess");
        assert.equal(seen[0].params.tenantId, B);
        assert.equal(seen[0].tenantId, A);
        const r3 = await fetch(`${base}/per-route/${B}`, { headers });
        assert.equal(r3.status, 403, "per-route mount still flags params (existing behaviour)");
        resolve();
      } catch (e) { reject(e); } finally { server.close(); }
    });
  });
});
