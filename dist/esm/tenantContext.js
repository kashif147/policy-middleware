/**
 * Canonical tenant-context primitive (Phase 1A).
 *
 * Rule: the ProjectShell Tenant._id (represented as a String) is the application
 * tenant id, and it must come only from trusted authenticated context
 * (gateway-injected `x-tenant-id` after JWT verification, or the auth
 * middleware's `req.ctx`/`req.user`). Caller-supplied tenantId from body/query/
 * params is NEVER allowed to become the authoritative tenant scope. Microsoft
 * Entra `tid` / B2C directory id are identity-provider ids, not app tenant ids.
 *
 * Modes:
 *   - "warn"    (default): trusted tenant stays authoritative; any mismatch with a
 *               caller-supplied tenantId is logged; the request is NOT blocked here.
 *   - "enforce": trusted tenant stays authoritative; a mismatch is rejected using
 *               the package's existing 403 response shape.
 *
 * The default is "warn" so the first consuming-service adoption is backward-safe.
 */
import { createLogger } from "@projectShell/logging-lib";

const tenantLogger = createLogger(
  process.env.POLICY_MW_LOG_SERVICE_NAME || "policy-middleware"
);

/** Normalize any tenant value to a String (or undefined). Never throws. */
function toTenantString(value) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "string") return value;
  try {
    return value.toString();
  } catch (_e) {
    return String(value);
  }
}

/**
 * The trusted application tenant id, from authenticated context only.
 * Order: gateway-verified `x-tenant-id` header, then auth-middleware context.
 * Header is trusted only when `x-jwt-verified: true` (the gateway sets both,
 * and strips spoofed copies before routing).
 */
function getTrustedTenant(req) {
  const headers = req.headers || {};
  const gatewayVerified = headers["x-jwt-verified"] === "true";
  const fromGateway = gatewayVerified ? headers["x-tenant-id"] : undefined;
  const fromCtx =
    (req.ctx && req.ctx.tenantId) ||
    (req.user && req.user.tenantId) ||
    req.tenantId;
  return toTenantString(fromGateway || fromCtx);
}

/** Caller-supplied (untrusted) tenantId values, by source. */
function getSuppliedTenants(req) {
  const out = [];
  const body = req.body && req.body.tenantId;
  const query = req.query && req.query.tenantId;
  const params = req.params && req.params.tenantId;
  if (body !== undefined) out.push({ source: "body", value: toTenantString(body) });
  if (query !== undefined) out.push({ source: "query", value: toTenantString(query) });
  if (params !== undefined) out.push({ source: "params", value: toTenantString(params) });
  return out;
}

/**
 * Compare trusted tenant against caller-supplied tenants.
 * Returns { trusted, supplied, mismatchSources } — mismatchSources lists the
 * sources whose value differs from the trusted tenant (only when a trusted
 * tenant is present; a supplied tenant with no trusted tenant is not a "match"
 * decision, it is handled by the missing-trusted-tenant path).
 */
function detectTenantOverride(req, trusted) {
  const trustedTenant = trusted !== undefined ? trusted : getTrustedTenant(req);
  const supplied = getSuppliedTenants(req);
  const mismatchSources =
    trustedTenant === undefined
      ? []
      : supplied
          .filter((s) => s.value !== undefined && s.value !== trustedTenant)
          .map((s) => s.source);
  return { trusted: trustedTenant, supplied, mismatchSources };
}

function logMismatch(req, trusted, mismatchSources, mode) {
  // Safe metadata only: never the JWT, Authorization header, cookies, body or PII.
  // correlationId/userId/tenantId are filled by logging-lib from `req`.
  const headers = req.headers || {};
  const meta = {
    eventType: "TenantContextMismatch",
    method: (req.method || "").toUpperCase(),
    path: req.originalUrl || req.url,
    authSource: headers["x-auth-source"] || null,
    environment: process.env.NODE_ENV || null,
    trustedTenantId: trusted,
    suppliedSources: mismatchSources,
    mode,
    outcome: mode === "enforce" ? "rejected" : "ignored",
  };
  const message = "Caller-supplied tenantId does not match trusted tenant";
  // enforce is a blocking security decision -> error level; warn -> business level.
  if (mode === "enforce") {
    tenantLogger.error(message, meta, req);
  } else {
    tenantLogger.business(message, meta, req);
  }
}

/**
 * Resolve and pin the canonical tenant on the request.
 *
 * - Sets `req.tenantId` (and `req.ctx.tenantId` when `req.ctx` exists) to the
 *   trusted tenant. Caller-supplied values never replace it.
 * - Logs a mismatch (safe metadata only).
 * - Returns a result object; does NOT send a response itself. In "enforce"
 *   mode with a mismatch it sets `result.rejected = true` so a middleware
 *   wrapper can reject; use `tenantContextMiddleware` for the wired version.
 *
 * @param {import('express').Request} req
 * @param {{ mode?: "warn"|"enforce" }} [options]
 */
function resolveTenantContext(req, options = {}) {
  const mode = options.mode === "enforce" ? "enforce" : "warn";
  const { trusted, supplied, mismatchSources } = detectTenantOverride(req);

  // Trusted tenant is always authoritative.
  if (trusted !== undefined) {
    req.tenantId = trusted;
    if (req.ctx) req.ctx.tenantId = trusted;
  }

  const result = {
    tenantId: trusted,
    trustedTenantPresent: trusted !== undefined,
    suppliedSources: supplied.map((s) => s.source),
    mismatch: mismatchSources.length > 0,
    mismatchSources,
    mode,
    rejected: false,
  };

  if (result.mismatch) {
    logMismatch(req, trusted, mismatchSources, mode);
    if (mode === "enforce") result.rejected = true;
  }
  return result;
}

/**
 * Express middleware wrapper around resolveTenantContext.
 * In "enforce" mode, a mismatch is rejected with the package's 403 shape.
 * In "warn" mode (default), it never blocks.
 */
function tenantContextMiddleware(options = {}) {
  return (req, res, next) => {
    const result = resolveTenantContext(req, options);
    if (result.rejected) {
      return res.status(403).json({
        success: false,
        error: "Tenant context mismatch",
        code: "TENANT_CONTEXT_MISMATCH",
        status: 403,
      });
    }
    return next();
  };
}

export {
  toTenantString,
  getTrustedTenant,
  getSuppliedTenants,
  detectTenantOverride,
  resolveTenantContext,
  tenantContextMiddleware,
};
