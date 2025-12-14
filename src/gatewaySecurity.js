/**
 * Gateway Security Middleware
 * Node services MUST trust NGINX as the JWT authority.
 * JWT expiry is enforced ONLY at the gateway.
 */
console.log("DEBUG TOKEN HEADERS", {
  expHeader: req.headers["x-token-expires-at"],
  expAsNumber: Number(req.headers["x-token-expires-at"]),
  now: Date.now(),
  nowSeconds: Math.floor(Date.now() / 1000),
});

const crypto = require("crypto");

/**
 * Soft token expiry check (LOG ONLY – NEVER BLOCK)
 * x-token-expires-at is JWT exp (seconds)
 */
function isTokenExpired(req) {
  const raw = req.headers["x-token-expires-at"];
  if (!raw) return false;

  const expirySeconds = Number(raw);
  if (!Number.isFinite(expirySeconds)) return false;

  const expiryMs = expirySeconds * 1000;
  const now = Date.now();

  const graceMs = Number(process.env.TOKEN_EXPIRY_GRACE_PERIOD_MS || 60000);

  if (now > expiryMs + graceMs) {
    console.warn("Token appears expired but accepted (gateway verified)", {
      expiryMs,
      now,
      expiredByMs: now - expiryMs,
    });
    return true;
  }

  return false;
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
  if (!headers["x-user-id"] || !headers["x-tenant-id"]) {
    return {
      valid: false,
      reason: "Missing required gateway identity headers",
    };
  }

  // 3. Validate JSON headers safely
  try {
    if (headers["x-user-roles"]) {
      const roles = JSON.parse(headers["x-user-roles"]);
      if (!Array.isArray(roles)) {
        console.warn(
          "x-user-roles is not a JSON array, treating as empty array"
        );
        req.headers["x-user-roles"] = "[]";
      }
    }

    if (headers["x-user-permissions"]) {
      const permissions = JSON.parse(headers["x-user-permissions"]);
      if (!Array.isArray(permissions)) {
        console.warn(
          "x-user-permissions is not a JSON array, treating as empty array"
        );
        req.headers["x-user-permissions"] = "[]";
      }
    }
  } catch (err) {
    console.warn("Invalid JSON in role/permission headers, resetting", err);
    req.headers["x-user-roles"] = "[]";
    req.headers["x-user-permissions"] = "[]";
  }

  return { valid: true };
}

/**
 * Verify gateway HMAC signature
 */
function verifyGatewaySignature(req) {
  const signature = req.headers["x-gateway-signature"];
  const timestamp = req.headers["x-gateway-timestamp"];
  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  if (!signature || !timestamp || !userId || !tenantId) {
    return {
      valid: false,
      reason: "Missing gateway signature headers",
    };
  }

  const secret = process.env.GATEWAY_SECRET;
  if (!secret) {
    return {
      valid: false,
      reason: "Gateway secret not configured",
    };
  }

  const payload = `${userId}|${tenantId}|${timestamp}`;
  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");

  if (expectedSignature !== signature) {
    return {
      valid: false,
      reason: "Invalid gateway signature",
    };
  }

  return { valid: true };
}

/**
 * Main gateway validation entry point
 */
function validateGatewayRequest(req, options = {}) {
  const startTime = Date.now();
  const clientIp = req.headers["x-forwarded-for"] || req.socket?.remoteAddress;

  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  // 1. Header validation
  const headerCheck = validateGatewayHeaders(req);
  if (!headerCheck.valid) {
    return headerCheck;
  }

  // 2. Soft expiry check (LOG ONLY)
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

  // 3. Gateway signature verification
  const sigCheck = verifyGatewaySignature(req);
  if (!sigCheck.valid) {
    logSecurityEvent("GATEWAY_VALIDATION_FAILED", {
      reason: sigCheck.reason,
      clientIp,
      userId,
      tenantId,
      severity: "HIGH",
      duration: Date.now() - startTime,
    });

    return sigCheck;
  }

  return { valid: true };
}

/**
 * Security event logger (safe fallback)
 */
function logSecurityEvent(event, payload) {
  try {
    console.warn(`[Security Event] ${event}:`, payload);
  } catch {
    // never block execution due to logging
  }
}

module.exports = {
  validateGatewayRequest,
};
