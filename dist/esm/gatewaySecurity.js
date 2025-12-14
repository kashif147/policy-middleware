/**
 * Gateway Security Middleware
 *
 * Security model:
 * - NGINX gateway is the SINGLE authority for JWT verification
 * - JWT expiry is enforced ONLY at the gateway
 * - Services trust gateway-injected headers
 *
 * This middleware:
 * - Validates presence and shape of gateway headers
 * - Performs SOFT token expiry logging (never blocks)
 * - DOES NOT perform cryptographic verification
 */

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
    return {
      valid: false,
      reason: "Gateway did not verify token",
    };
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
        req.headers["x-user-roles"] = "[]";
      }
    }

    if (headers["x-user-permissions"]) {
      const permissions = JSON.parse(headers["x-user-permissions"]);
      if (!Array.isArray(permissions)) {
        console.warn("x-user-permissions is not an array, resetting");
        req.headers["x-user-permissions"] = "[]";
      }
    }
  } catch {
    console.warn("Invalid role/permission headers, resetting");
    req.headers["x-user-roles"] = "[]";
    req.headers["x-user-permissions"] = "[]";
  }

  return { valid: true };
}

/**
 * Main gateway validation entry point
 */
function validateGatewayRequest(req) {
  const startTime = Date.now();
  const clientIp = req.headers["x-forwarded-for"] || req.socket?.remoteAddress;

  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  // 1. Header validation (HARD BLOCK)
  const headerCheck = validateGatewayHeaders(req);
  if (!headerCheck.valid) {
    logSecurityEvent("GATEWAY_HEADER_VALIDATION_FAILED", {
      reason: headerCheck.reason,
      clientIp,
      userId,
      tenantId,
      severity: "HIGH",
      duration: Date.now() - startTime,
    });
    return headerCheck;
  }

  // 2. Soft expiry logging (NEVER BLOCK)
  if (isTokenExpired(req)) {
    logSecurityEvent("GATEWAY_TOKEN_EXPIRED_SOFT", {
      reason: "Token expired but accepted (gateway verified)",
      clientIp,
      userId,
      tenantId,
      severity: "LOW",
      duration: Date.now() - startTime,
    });
  }

  return { valid: true };
}

/**
 * Security event logger
 */
function logSecurityEvent(event, payload) {
  try {
    console.warn(`[Security Event] ${event}:`, payload);
  } catch {
    // Logging must never block execution
  }
}

export {
  validateGatewayRequest,
};
