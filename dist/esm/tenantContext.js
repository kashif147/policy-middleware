/**
 * Canonical tenant-context primitive (Phase 1A).
 *
 * Rule: the ProjectShell Tenant._id (a 24-lowercase-hex ObjectId string) is the
 * application tenant id. The ONLY trusted source is the gateway's verified boundary:
 * `x-tenant-id` when `x-auth-source` is "gateway" AND `x-jwt-verified` is "true" AND the
 * value is exactly 24 lowercase hex characters (the gateway sets it from a verified
 * ProjectShell JWT and strips client copies). Anything else means NO trusted tenant -
 * never inferred from req.ctx/req.user, a Bearer token, Microsoft `tid` /
 * `extension_tenantId`, the body, the query or the params, and never normalised.
 * Caller-supplied tenantId values are only compared against the trusted tenant.
 *
 * Modes (per service: TENANT_CONTEXT_MODE, or an explicit `options.mode`):
 *   - "warn"    (default): trusted tenant stays authoritative; any mismatch with a
 *               caller-supplied tenantId is logged; the request is NOT blocked here.
 *   - "enforce": trusted tenant stays authoritative; a mismatch is rejected using
 *               the package's existing 403 response shape. No role is exempt.
 * Any other value (including an empty string) is a configuration error and throws.
 */
import { createLogger } from "@projectShell/logging-lib";

const tenantLogger = createLogger(
  process.env.POLICY_MW_LOG_SERVICE_NAME || "policy-middleware"
);

/** Canonical internal ProjectShell tenant id: exactly 24 lowercase hexadecimal characters. */
const INTERNAL_TENANT_ID = /^[0-9a-f]{24}$/;
const TENANT_CONTEXT_MODES = ["warn", "enforce"];

function isInternalTenantId(value) {
  return typeof value === "string" && INTERNAL_TENANT_ID.test(value);
}

/**
 * Validate a tenant-context mode. `undefined` -> "warn" (default); "warn" / "enforce"
 * pass through; anything else throws (no silent fallback). The offending value is not
 * echoed in the message.
 */
function resolveTenantContextMode(value) {
  if (value === undefined) return "warn";
  if (TENANT_CONTEXT_MODES.includes(value)) return value;
  throw new Error(
    'Invalid tenant context mode: TENANT_CONTEXT_MODE (or options.mode) must be "warn" or "enforce"'
  );
}

/**
 * The mode for a middleware/resolver: an explicit `options.mode` wins; otherwise the
 * service's TENANT_CONTEXT_MODE environment setting. Both are always validated, so a
 * malformed TENANT_CONTEXT_MODE fails even when a mode is passed explicitly.
 */
function tenantContextModeFrom(options = {}) {
  const fromEnv = resolveTenantContextMode(process.env.TENANT_CONTEXT_MODE);
  return options.mode !== undefined ? resolveTenantContextMode(options.mode) : fromEnv;
}

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
 * The trusted application tenant id, or undefined. Trusted ONLY when the request carries
 * the gateway's verified boundary: x-auth-source "gateway", x-jwt-verified "true" and an
 * x-tenant-id of exactly 24 lowercase hex characters. No other source is consulted.
 */
function getTrustedTenant(req) {
  const headers = req.headers || {};
  if (headers["x-auth-source"] !== "gateway") return undefined;
  if (headers["x-jwt-verified"] !== "true") return undefined;
  const tenantId = headers["x-tenant-id"];
  return isInternalTenantId(tenantId) ? tenantId : undefined;
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
  const mode = tenantContextModeFrom(options);
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
 * The mode is resolved and validated once, when the middleware is created (service
 * startup): an invalid TENANT_CONTEXT_MODE / options.mode throws there.
 */
function tenantContextMiddleware(options = {}) {
  const mode = tenantContextModeFrom(options);
  return (req, res, next) => {
    const result = resolveTenantContext(req, { mode });
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
  INTERNAL_TENANT_ID,
  TENANT_CONTEXT_MODES,
  isInternalTenantId,
  resolveTenantContextMode,
  tenantContextModeFrom,
  toTenantString,
  getTrustedTenant,
  getSuppliedTenants,
  detectTenantOverride,
  resolveTenantContext,
  tenantContextMiddleware,
};
