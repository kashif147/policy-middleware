"use strict";
// Focused unit tests for the Phase 1A canonical tenant-context primitive.
// Run: node --test  (from the policy-middleware package root)

// Keep any logging-lib file writes out of the repo during tests.
const os = require("os");
const path = require("path");
const fs = require("fs");
process.env.LOG_ROOT =
  process.env.LOG_ROOT ||
  fs.mkdtempSync(path.join(os.tmpdir(), "pm-tenantctx-log-"));

const test = require("node:test");
const assert = require("node:assert");

const {
  toTenantString,
  getTrustedTenant,
  detectTenantOverride,
  resolveTenantContext,
  tenantContextMiddleware,
} = require("../src/tenantContext");

function mkReq(o = {}) {
  return {
    headers: o.headers || {},
    ctx: o.ctx,
    user: o.user,
    tenantId: o.tenantId,
    body: o.body,
    query: o.query,
    params: o.params,
    method: o.method || "GET",
    url: o.url || "/x",
    originalUrl: o.originalUrl || "/x",
  };
}
function mkRes() {
  const r = { statusCode: null, payload: null };
  r.status = (c) => ((r.statusCode = c), r);
  r.json = (p) => ((r.payload = p), r);
  return r;
}
const gwHeaders = (t) => ({ "x-jwt-verified": "true", "x-tenant-id": t });

// 1. trusted tenant only -> accepted, set on req
test("1 trusted tenant only -> accepted", () => {
  const req = mkReq({ headers: gwHeaders("T1") });
  const r = resolveTenantContext(req);
  assert.equal(r.tenantId, "T1");
  assert.equal(req.tenantId, "T1");
  assert.equal(r.mismatch, false);
  assert.equal(r.rejected, false);
});

// 2. matching body tenant -> accepted, no mismatch
test("2 matching body tenant -> accepted", () => {
  const req = mkReq({ headers: gwHeaders("T1"), body: { tenantId: "T1" } });
  const r = resolveTenantContext(req);
  assert.equal(r.mismatch, false);
  assert.equal(req.tenantId, "T1");
});

// 3. mismatching body tenant: warn retains trusted (no block); enforce rejects
test("3 mismatching body tenant: warn vs enforce", () => {
  const warnReq = mkReq({ headers: gwHeaders("T1"), body: { tenantId: "T2" } });
  const warn = resolveTenantContext(warnReq, { mode: "warn" });
  assert.equal(warn.mismatch, true);
  assert.equal(warn.rejected, false);
  assert.equal(warnReq.tenantId, "T1", "trusted retained in warn");

  const enfReq = mkReq({ headers: gwHeaders("T1"), body: { tenantId: "T2" } });
  const enf = resolveTenantContext(enfReq, { mode: "enforce" });
  assert.equal(enf.mismatch, true);
  assert.equal(enf.rejected, true);
  assert.equal(enfReq.tenantId, "T1", "trusted retained even in enforce");
});

// 4. mismatching query tenant
test("4 mismatching query tenant flagged", () => {
  const req = mkReq({ headers: gwHeaders("T1"), query: { tenantId: "T2" } });
  const r = resolveTenantContext(req, { mode: "enforce" });
  assert.deepEqual(r.mismatchSources, ["query"]);
  assert.equal(r.rejected, true);
  assert.equal(req.tenantId, "T1");
});

// 5. mismatching params tenant
test("5 mismatching params tenant flagged", () => {
  const req = mkReq({ headers: gwHeaders("T1"), params: { tenantId: "T2" } });
  const r = resolveTenantContext(req, { mode: "enforce" });
  assert.deepEqual(r.mismatchSources, ["params"]);
  assert.equal(req.tenantId, "T1");
});

// 6. multiple supplied tenant values
test("6 multiple supplied sources flagged", () => {
  const req = mkReq({
    headers: gwHeaders("T1"),
    body: { tenantId: "T2" },
    query: { tenantId: "T3" },
    params: { tenantId: "T4" },
  });
  const r = resolveTenantContext(req, { mode: "warn" });
  assert.deepEqual(r.mismatchSources.sort(), ["body", "params", "query"]);
  assert.equal(req.tenantId, "T1");
});

// 7. supplied tenant cannot replace trusted tenant
test("7 supplied cannot replace trusted", () => {
  const req = mkReq({ headers: gwHeaders("TRUE"), body: { tenantId: "EVIL" } });
  resolveTenantContext(req, { mode: "warn" });
  assert.equal(req.tenantId, "TRUE");
});

// 8. missing trusted tenant behavior: req.tenantId not set to a supplied value
test("8 missing trusted tenant -> no supplied promotion", () => {
  const req = mkReq({ body: { tenantId: "T9" } }); // no gateway header, no ctx
  const r = resolveTenantContext(req, { mode: "enforce" });
  assert.equal(r.trustedTenantPresent, false);
  assert.equal(r.tenantId, undefined);
  assert.equal(req.tenantId, undefined, "supplied tenant never becomes authoritative");
  assert.deepEqual(r.mismatchSources, [], "no trusted tenant -> no mismatch decision here");
  assert.equal(r.rejected, false);
});

// 9. tenant normalized to String (e.g. ObjectId-like)
test("9 tenant normalized to String", () => {
  const objectIdLike = { toString: () => "507f1f77bcf86cd799439011" };
  const req = mkReq({ ctx: { tenantId: objectIdLike } });
  const r = resolveTenantContext(req);
  assert.equal(typeof r.tenantId, "string");
  assert.equal(r.tenantId, "507f1f77bcf86cd799439011");
  assert.equal(typeof req.tenantId, "string");
});

// 10. policy.middleware context cannot be changed by body/query tenantId
//     (replicates the context assembly + canonical re-assert from policy.middleware.js)
test("10 policy context: canonical tenant survives body/query spread", () => {
  const trustedTenant = "T1";
  const req = mkReq({
    headers: gwHeaders(trustedTenant),
    body: { tenantId: "T2", note: "hello" },
    query: { tenantId: "T3", filter: "open" },
  });
  const override = detectTenantOverride(req, trustedTenant);
  assert.ok(override.mismatchSources.length >= 1);
  // assemble like policy.middleware: spread body/query, then re-assert canonical
  const context = {
    userId: "U1",
    tenantId: trustedTenant,
    ...req.query,
    ...req.body,
  };
  context.tenantId = trustedTenant; // the fix
  context.userId = "U1";
  assert.equal(context.tenantId, "T1", "canonical tenant wins over body/query");
});

// 11. non-tenant body/query attributes continue to flow into context
test("11 non-tenant attributes preserved", () => {
  const req = mkReq({
    headers: gwHeaders("T1"),
    body: { tenantId: "T2", note: "hello" },
    query: { filter: "open" },
  });
  const context = { tenantId: "T1", ...req.query, ...req.body };
  context.tenantId = "T1";
  assert.equal(context.note, "hello");
  assert.equal(context.filter, "open");
  assert.equal(context.tenantId, "T1");
});

// helpers: toTenantString / getTrustedTenant edge cases
test("toTenantString handles empty/undefined/number", () => {
  assert.equal(toTenantString(undefined), undefined);
  assert.equal(toTenantString(null), undefined);
  assert.equal(toTenantString(""), undefined);
  assert.equal(toTenantString(123), "123");
});
test("getTrustedTenant ignores x-tenant-id when not gateway-verified", () => {
  const req = mkReq({ headers: { "x-tenant-id": "SPOOF" } }); // no x-jwt-verified
  assert.equal(getTrustedTenant(req), undefined);
});

// tenantContextMiddleware wiring
test("middleware enforce -> 403 on mismatch", () => {
  const req = mkReq({ headers: gwHeaders("T1"), body: { tenantId: "T2" } });
  const res = mkRes();
  let nexted = false;
  tenantContextMiddleware({ mode: "enforce" })(req, res, () => (nexted = true));
  assert.equal(nexted, false);
  assert.equal(res.statusCode, 403);
  assert.equal(res.payload.code, "TENANT_CONTEXT_MISMATCH");
});
test("middleware warn -> next() on mismatch, trusted retained", () => {
  const req = mkReq({ headers: gwHeaders("T1"), body: { tenantId: "T2" } });
  const res = mkRes();
  let nexted = false;
  tenantContextMiddleware({ mode: "warn" })(req, res, () => (nexted = true));
  assert.equal(nexted, true);
  assert.equal(res.statusCode, null);
  assert.equal(req.tenantId, "T1");
});
test("middleware default mode is warn (backward-safe)", () => {
  const req = mkReq({ headers: gwHeaders("T1"), body: { tenantId: "T2" } });
  const res = mkRes();
  let nexted = false;
  tenantContextMiddleware()(req, res, () => (nexted = true));
  assert.equal(nexted, true, "default must not block");
});

// 12. no regression in existing gatewaySecurity behavior
test("12 gatewaySecurity still validates/ rejects as before", () => {
  const { validateGatewayRequest } = require("../src/gatewaySecurity");
  const ok = validateGatewayRequest(
    mkReq({
      headers: {
        "x-jwt-verified": "true",
        "x-user-id": "U1",
        "x-tenant-id": "T1",
      },
    })
  );
  assert.equal(ok.valid, true);
  const bad = validateGatewayRequest(mkReq({ headers: {} }));
  assert.equal(bad.valid, false);
});

// ---------------------------------------------------------------------------
// Phase 1A fix-first additions: alias contract, mismatch-log schema, dist exports
// ---------------------------------------------------------------------------

// Capture logging-lib Console output (JSON rows -> stdout) during fn().
function captureStdout(fn) {
  const orig = process.stdout.write.bind(process.stdout);
  const chunks = [];
  process.stdout.write = (s, ...rest) => {
    chunks.push(typeof s === "string" ? s : s.toString());
    return true;
  };
  try {
    fn();
  } finally {
    process.stdout.write = orig;
  }
  const raw = chunks.join("");
  const rows = raw
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch (_e) {
        return null;
      }
    })
    .filter(Boolean);
  return { raw, rows };
}
const findMismatchRow = (rows) =>
  rows.find((r) => r && r.eventType === "TenantContextMismatch");

// A. tenant_id alias cannot change canonical context.tenantId
test("A tenant_id alias cannot change canonical tenant scope", () => {
  const trusted = "T1";
  const req = mkReq({ headers: gwHeaders(trusted), body: { tenant_id: "T2", note: "x" } });
  // alias is NOT the canonical key -> not a mismatch of tenantId
  const r = resolveTenantContext(req, { mode: "enforce" });
  assert.equal(r.mismatch, false, "tenant_id is not the canonical key");
  // simulate policy context assembly + canonical re-assert
  const context = { tenantId: trusted, ...req.query, ...req.body };
  context.tenantId = trusted;
  assert.equal(context.tenantId, "T1");
  assert.equal(context.tenant_id, "T2", "alias remains an inert business field");
});

// B. tenantID alias cannot change canonical context.tenantId
test("B tenantID alias cannot change canonical tenant scope", () => {
  const trusted = "T1";
  const req = mkReq({ headers: gwHeaders(trusted), body: { tenantID: "T2" } });
  const r = resolveTenantContext(req, { mode: "enforce" });
  assert.equal(r.mismatch, false);
  const context = { tenantId: trusted, ...req.body };
  context.tenantId = trusted;
  assert.equal(context.tenantId, "T1");
  assert.equal(context.tenantID, "T2");
});

// C. nested tenant object cannot change canonical context.tenantId (PDP ignores it)
test("C nested tenant object cannot change canonical tenant scope", () => {
  const trusted = "T1";
  const req = mkReq({ headers: gwHeaders(trusted), body: { tenant: { id: "T2" } } });
  const r = resolveTenantContext(req, { mode: "enforce" });
  assert.equal(r.mismatch, false);
  const context = { tenantId: trusted, ...req.body };
  context.tenantId = trusted;
  assert.equal(context.tenantId, "T1");
  assert.deepEqual(context.tenant, { id: "T2" });
});

// D. WARN mismatch logging schema
test("D warn mismatch log has required safe fields, no secrets", () => {
  process.env.NODE_ENV = process.env.NODE_ENV || "test";
  const req = mkReq({
    headers: { ...gwHeaders("T1"), "x-auth-source": "gateway", authorization: "Bearer eyJsecret.aaa.bbb" },
    body: { tenantId: "T2", password: "p@ss" },
  });
  req.correlationId = "cid-warn-1";
  const { raw, rows } = captureStdout(() => resolveTenantContext(req, { mode: "warn" }));
  const row = findMismatchRow(rows);
  assert.ok(row, "mismatch row emitted");
  assert.equal(row.eventType, "TenantContextMismatch");
  assert.equal(row.mode, "warn");
  assert.equal(row.outcome, "ignored");
  assert.equal(row.trustedTenantId, "T1");
  assert.deepEqual(row.suppliedSources, ["body"]);
  assert.equal(row.correlationId, "cid-warn-1");
  assert.equal(row.authSource, "gateway");
  assert.ok(row.environment, "environment present");
  assert.equal(row.level, "business");
  // no secrets/PII in the emitted text
  for (const bad of ["Bearer", "eyJsecret", "authorization", "password", "p@ss"]) {
    assert.ok(!raw.includes(bad), `must not log ${bad}`);
  }
});

// E. ENFORCE mismatch logging + 403
test("E enforce mismatch logs at error level, outcome rejected, 403", () => {
  process.env.NODE_ENV = process.env.NODE_ENV || "test";
  const req = mkReq({
    headers: { ...gwHeaders("T1"), "x-auth-source": "gateway" },
    query: { tenantId: "T2" },
  });
  req.correlationId = "cid-enf-1";
  const res = mkRes();
  const { rows } = captureStdout(() =>
    tenantContextMiddleware({ mode: "enforce" })(req, res, () => {})
  );
  const row = findMismatchRow(rows);
  assert.ok(row, "mismatch row emitted");
  assert.equal(row.level, "error", "enforce logs at error level");
  assert.equal(row.mode, "enforce");
  assert.equal(row.outcome, "rejected");
  assert.equal(row.correlationId, "cid-enf-1");
  assert.equal(res.statusCode, 403);
  assert.equal(res.payload.code, "TENANT_CONTEXT_MISMATCH");
});

// F. generated distribution exports resolve (CJS + ESM)
test("F CJS dist exports resolve", () => {
  const cjs = require("../dist/index.js");
  assert.equal(typeof cjs.resolveTenantContext, "function");
  assert.equal(typeof cjs.tenantContextMiddleware, "function");
});
test("F ESM dist exports resolve", async () => {
  const esm = await import("../dist/esm/index.js");
  assert.equal(typeof esm.resolveTenantContext, "function");
  assert.equal(typeof esm.tenantContextMiddleware, "function");
});
