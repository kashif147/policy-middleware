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
 * - Verifies HMAC signature to ensure request came from gateway
 */
throw new Error("GATEWAY SECURITY LOADED");

import crypto from "crypto";

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
 * Verify gateway HMAC signature
 * IMPORTANT: NO timestamp parsing BEFORE signature verification
 */
function verifyGatewaySignature(req) {
  console.log("[GATEWAY_SECURITY] verifyGatewaySignature called");
  const signature = req.headers["x-gateway-signature"];
  const timestamp = req.headers["x-gateway-timestamp"];
  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  console.log("[GATEWAY_SECURITY] Signature inputs:", {
    hasSignature: !!signature,
    hasTimestamp: !!timestamp,
    hasUserId: !!userId,
    hasTenantId: !!tenantId,
    signatureLength: signature?.length,
    timestampValue: timestamp,
  });

  if (!signature || !timestamp || !userId || !tenantId) {
    return {
      valid: false,
      reason: "Missing gateway signature headers",
    };
  }

  let secret = process.env.GATEWAY_SECRET;
  if (!secret) {
    return {
      valid: false,
      reason: "Gateway secret not configured",
    };
  }

  // Match Lua behavior: only trim trailing whitespace (gsub("%s+$", ""))
  // Lua: gateway_secret:gsub("%s+$", "")
  secret = secret.replace(/\s+$/, "");
  if (!secret) {
    return {
      valid: false,
      reason: "Gateway secret is empty",
    };
  }

  // EXACT payload as built by Lua:
  // table.concat({ user_id, tenant_id, timestamp }, "|")
  const payload = `${userId}|${tenantId}|${timestamp}`;

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(payload, "utf8")
    .digest("hex")
    .toLowerCase();

  const receivedSignature = signature.trim().toLowerCase();

  if (expectedSignature !== receivedSignature) {
    // Debug logging for signature mismatch - use console.error to ensure visibility
    const debugInfo = {
      payload,
      userId,
      tenantId,
      timestamp,
      timestampType: typeof timestamp,
      secretLength: secret.length,
      secretFirstChar: secret[0],
      secretLastChar: secret[secret.length - 1],
      expectedSignature,
      receivedSignature,
      expectedLength: expectedSignature.length,
      receivedLength: receivedSignature.length,
    };
    // Force output to stderr to bypass any filtering
    process.stderr.write("========================================\n");
    process.stderr.write("[GATEWAY_SECURITY] SIGNATURE_MISMATCH:\n");
    process.stderr.write(JSON.stringify(debugInfo, null, 2) + "\n");
    process.stderr.write("========================================\n");
    console.error("========================================");
    console.error("[GATEWAY_SECURITY] SIGNATURE_MISMATCH:");
    console.error(JSON.stringify(debugInfo, null, 2));
    console.error("========================================");
    console.log("[GATEWAY_SECURITY] SIGNATURE_MISMATCH:", debugInfo);
    return {
      valid: false,
      reason: "Invalid signature",
      debug: debugInfo, // Include debug info in response for troubleshooting
    };
  }

  // Replay protection (ONLY AFTER SIGNATURE MATCH)
  const headerTime = Number(timestamp);
  if (!Number.isFinite(headerTime)) {
    return {
      valid: false,
      reason: "Invalid timestamp format",
    };
  }

  const now = Date.now();
  const timeDiff = Math.abs(now - headerTime);

  if (timeDiff > 300000) {
    return {
      valid: false,
      reason: "Timestamp outside acceptable window",
    };
  }

  return { valid: true };
}

/**
 * Main gateway validation entry point
 */
function validateGatewayRequest(req) {
  console.log("[GATEWAY_SECURITY] validateGatewayRequest called");
  const startTime = Date.now();
  const clientIp = req.headers["x-forwarded-for"] || req.socket?.remoteAddress;

  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  // 1. Header validation (HARD BLOCK)
  console.log("[GATEWAY_SECURITY] Step 1: Validating headers...");
  const headerCheck = validateGatewayHeaders(req);
  if (!headerCheck.valid) {
    console.log(
      "[GATEWAY_SECURITY] Header validation failed:",
      headerCheck.reason
    );
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

  // 3. Signature verification
  console.log("[GATEWAY_SECURITY] Step 3: Verifying signature...");
  const sigCheck = verifyGatewaySignature(req);
  if (!sigCheck.valid) {
    console.log(
      "[GATEWAY_SECURITY] Signature verification failed:",
      sigCheck.reason
    );
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
