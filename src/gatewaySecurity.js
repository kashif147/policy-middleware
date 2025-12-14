/**
 * Gateway Security Middleware
 * Node services MUST trust NGINX as the JWT authority.
 * JWT expiry is enforced ONLY at the gateway.
 */
const crypto = require("crypto");

/**
 * Soft token expiry check (LOG ONLY – NEVER BLOCK)
 * x-token-expires-at is JWT exp (seconds)
 */
// function isTokenExpired(req) {
//   const raw = req.headers["x-token-expires-at"];
//   if (!raw) return false;

//   const expirySeconds = Number(raw);
//   if (!Number.isFinite(expirySeconds)) return false;

//   const expiryMs = expirySeconds * 1000;
//   const now = Date.now();

//   const graceMs = Number(process.env.TOKEN_EXPIRY_GRACE_PERIOD_MS || 60000);

//   if (now > expiryMs + graceMs) {
//     console.warn("Token appears expired but accepted (gateway verified)", {
//       expiryMs,
//       now,
//       expiredByMs: now - expiryMs,
//     });
//     return true;
//   }

//   return false;
// }
function isTokenExpired(req) {
  const expiresAtRaw = req.headers["x-token-expires-at"];

  if (!expiresAtRaw) {
    return false;
  }

  const expiresAt = Number(expiresAtRaw);
  if (!Number.isFinite(expiresAt)) {
    return false;
  }

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

  // 2. Required identity headers (must be non-empty)
  // Gateway sets these from JWT payload:
  //   user_id = payload.sub or payload.id or ""
  //   tenant_id = payload.tenantId or payload.tid or ""
  // We require non-empty values for security
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
  // Get userId/tenantId from headers (already validated in validateGatewayHeaders)
  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  // Validate all required signature headers are present and non-empty
  if (!signature || !timestamp || !userId || !tenantId) {
    return {
      valid: false,
      reason: "Missing gateway signature headers",
    };
  }

  // Ensure values are not just whitespace (safe string check)
  const isEmpty = (val) => typeof val === "string" && val.trim() === "";
  if (
    isEmpty(signature) ||
    isEmpty(timestamp) ||
    isEmpty(userId) ||
    isEmpty(tenantId)
  ) {
    return {
      valid: false,
      reason: "Empty gateway signature headers",
    };
  }

  // Prevent replay attacks (5 minute window)
  // Gateway sends timestamp as: tostring(ngx.time() * 1000)
  // ngx.time() returns seconds, * 1000 converts to milliseconds
  // Result is a string representation of milliseconds since epoch
  const now = Date.now();
  const headerTime = parseInt(timestamp, 10);
  if (isNaN(headerTime) || headerTime <= 0) {
    return {
      valid: false,
      reason: "Invalid timestamp format",
    };
  }
  // Allow 5 minute window (300000ms = 5 minutes)
  // This matches typical replay attack prevention windows
  const timeDiff = Math.abs(now - headerTime);
  if (timeDiff > 300000) {
    return {
      valid: false,
      reason: "Timestamp outside acceptable window",
    };
  }

  // Get secret from environment (matches gateway: os.getenv("GATEWAY_SECRET"))
  const secret = process.env.GATEWAY_SECRET;
  if (!secret) {
    return {
      valid: false,
      reason: "Gateway secret not configured",
    };
  }

  // Build signature payload exactly as gateway does:
  // table.concat({user_id, tenant_id, timestamp}, "|")
  // Gateway uses pipe separator "|" to join: userId|tenantId|timestamp
  const payload = `${userId}|${tenantId}|${timestamp}`;

  // Generate HMAC-SHA256 signature (matches gateway: resty_hmac with SHA256)
  // Gateway: hmac:update(signature_payload) then str.to_hex(hmac:final())
  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex")
    .toLowerCase(); // Ensure lowercase hex (gateway uses str.to_hex which is lowercase)

  // Compare signatures (case-sensitive string comparison)
  // Normalize received signature to lowercase for comparison
  const receivedSignature = (signature || "").toLowerCase();

  if (expectedSignature !== receivedSignature) {
    // Debug logging for signature mismatch
    console.warn("[GATEWAY_SECURITY] Signature mismatch:", {
      received: signature,
      receivedNormalized: receivedSignature,
      expected: expectedSignature,
      payload: payload,
      userId,
      tenantId,
      timestamp,
      secretLength: secret ? secret.length : 0,
    });
    return {
      valid: false,
      reason: "Invalid signature",
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
    logSecurityEvent("SIGNATURE_VALIDATION_FAILED", {
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
