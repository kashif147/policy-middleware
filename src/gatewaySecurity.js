/**
 * Gateway Security Middleware (Simplified)
 *
 * Security model (Industry Best Practice):
 * - NGINX gateway is the SINGLE authority for JWT verification
 * - Services trust gateway-injected headers if x-jwt-verified === "true"
 * - No HMAC signing or timestamp checks (gateway is trusted boundary)
 *
 * This middleware:
 * - Validates presence and shape of gateway headers
 * - Trusts requests if x-jwt-verified === "true" && x-auth-source === "gateway"
 *
 * Structured logs: `${LOG_ROOT}/<gateway>/app-*.log` and `error-*.log`
 * (same layout as other services; default LOG_ROOT is cwd/logs). Override folder with GATEWAY_LOG_SERVICE_NAME.
 */
const { createLogger } = require("@projectShell/logging-lib");

const gatewayStructuredLogger = createLogger(
  process.env.GATEWAY_LOG_SERVICE_NAME || "gateway"
);

function writeLog(level, message, data = null, req = null) {
  const meta =
    data && typeof data === "object" && !Array.isArray(data)
      ? { eventType: "GatewaySecurity", ...data }
      : {
          eventType: "GatewaySecurity",
          ...(data != null ? { detail: data } : {}),
        };
  const upper = String(level).toUpperCase();
  if (upper === "ERROR") {
    gatewayStructuredLogger.error(message, meta, req);
  } else {
    gatewayStructuredLogger.business(message, meta, req);
  }
}

/**
 * Soft token expiry check (LOG ONLY)
 * Gateway already verified token.
 */
function isTokenExpired(req) {
  const expiresAtRaw = req.headers["x-token-expires-at"];
  if (!expiresAtRaw) return false;

  const expiresAt = Number(expiresAtRaw);
  if (!Number.isFinite(expiresAt)) return false;

  const now = Date.now();
  const graceMs = Number(process.env.TOKEN_EXPIRY_GRACE_PERIOD_MS || 60000);

  return now > expiresAt + graceMs;
}

/**
 * Validate gateway-injected headers
 */
function validateGatewayHeaders(req) {
  const headers = req.headers;

  // 1. Gateway verification flag (HARD REQUIREMENT)
  if (headers["x-jwt-verified"] !== "true") {
    writeLog(
      "ERROR",
      "Gateway did not verify token",
      {
        path: req.originalUrl || req.url,
        jwtVerified: headers["x-jwt-verified"],
      },
      req
    );
    return {
      valid: false,
      reason: "Gateway did not verify token",
    };
  }

  // 1.5 System caller bypass (n8n, automation)
  if (
    headers["x-auth-source"] === "azuread" &&
    headers["x-service-caller"] === "system.notifier"
  ) {
    return { valid: true };
  }

  // 2. Required identity headers
  const userId = headers["x-user-id"];
  const tenantId = headers["x-tenant-id"];

  if (
    !userId ||
    !tenantId ||
    (typeof userId === "string" && userId.trim() === "") ||
    (typeof tenantId === "string" && tenantId.trim() === "")
  ) {
    writeLog(
      "ERROR",
      "Missing required gateway identity headers",
      {
        path: req.originalUrl || req.url,
        hasUserId: Boolean(userId && String(userId).trim()),
        hasTenantId: Boolean(tenantId && String(tenantId).trim()),
      },
      req
    );
    return {
      valid: false,
      reason: "Missing required gateway identity headers",
    };
  }

  // 3. Defensive JSON validation for roles and permissions
  try {
    if (headers["x-user-roles"]) {
      const roles = JSON.parse(headers["x-user-roles"]);
      if (!Array.isArray(roles)) {
        console.warn("x-user-roles is not an array, resetting");
        writeLog(
          "WARN",
          "x-user-roles is not an array, reset to []",
          { path: req.originalUrl || req.url },
          req
        );
        req.headers["x-user-roles"] = "[]";
      }
    }

    if (headers["x-user-permissions"]) {
      const permissions = JSON.parse(headers["x-user-permissions"]);
      if (!Array.isArray(permissions)) {
        console.warn("x-user-permissions is not an array, resetting");
        writeLog(
          "WARN",
          "x-user-permissions is not an array, reset to []",
          { path: req.originalUrl || req.url },
          req
        );
        req.headers["x-user-permissions"] = "[]";
      }
    }
  } catch {
    console.warn("Invalid role/permission headers, resetting");
    writeLog(
      "WARN",
      "Invalid role/permission headers, reset to defaults",
      { path: req.originalUrl || req.url },
      req
    );
    req.headers["x-user-roles"] = "[]";
    req.headers["x-user-permissions"] = "[]";
  }

  if (isTokenExpired(req)) {
    writeLog(
      "WARN",
      "Access token past soft expiry (grace period)",
      {
        eventType: "GatewayTokenSoftExpired",
        path: req.originalUrl || req.url,
      },
      req
    );
  }

  return { valid: true };
}

/**
 * Main gateway validation entry point (Simplified)
 */
function validateGatewayRequest(req) {
  return validateGatewayHeaders(req);
}

module.exports = {
  validateGatewayRequest,
};
