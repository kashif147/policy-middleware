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
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// File logging for Azure (accessible via Kudu)
let logFileStream = null;
try {
  const logDir = path.join(process.cwd(), "logs");
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
  const logFile = path.join(logDir, "gateway-security.log");
  logFileStream = fs.createWriteStream(logFile, { flags: "a" });
} catch (error) {
  // If file logging fails, continue without it
  console.warn("[GATEWAY_SECURITY] File logging not available:", error.message);
}

// Helper to write to both stdout and file
function writeLog(level, message, data = null) {
  const timestamp = new Date().toISOString();
  const logEntry = data
    ? `[${timestamp}] [${level}] ${message}\n${JSON.stringify(data, null, 2)}\n`
    : `[${timestamp}] [${level}] ${message}\n`;

  // Always write to stdout (for Azure log stream)
  process.stdout.write(logEntry);

  // Also write to file (for Kudu access)
  if (logFileStream) {
    logFileStream.write(logEntry);
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
  writeLog("INFO", "[GATEWAY_SECURITY] verifyGatewaySignature called");
  console.warn("[GATEWAY_SECURITY] verifyGatewaySignature called");

  // Get raw header values - Express normalizes headers to lowercase
  const signature = req.headers["x-gateway-signature"];
  const timestamp = req.headers["x-gateway-timestamp"];
  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  // Log raw header values with detailed inspection
  // Use process.stdout.write to ensure logs appear in Azure log stream
  const rawHeaderLog = {
    signature: signature
      ? `${signature.substring(0, 20)}... (len=${signature.length})`
      : null,
    signatureRaw: signature ? JSON.stringify(signature) : null,
    timestamp: timestamp
      ? `${timestamp} (type=${typeof timestamp}, len=${timestamp?.length})`
      : null,
    timestampRaw: timestamp ? JSON.stringify(timestamp) : null,
    userId: userId ? `${userId} (len=${userId.length})` : null,
    userIdRaw: userId ? JSON.stringify(userId) : null,
    tenantId: tenantId ? `${tenantId} (len=${tenantId.length})` : null,
    tenantIdRaw: tenantId ? JSON.stringify(tenantId) : null,
    hasWhitespace: {
      signature: signature ? signature !== signature.trim() : false,
      timestamp: timestamp ? timestamp !== timestamp.trim() : false,
      userId: userId ? userId !== userId.trim() : false,
      tenantId: tenantId ? tenantId !== tenantId.trim() : false,
    },
  };
  writeLog("INFO", "[GATEWAY_SECURITY] RAW_HEADER_VALUES", rawHeaderLog);
  console.error("[GATEWAY_SECURITY] RAW_HEADER_VALUES:", rawHeaderLog);

  console.warn("[GATEWAY_SECURITY] Signature inputs:", {
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
  // CRITICAL: Use raw values as-is, don't trim (gateway doesn't trim these)
  const payload = `${userId}|${tenantId}|${timestamp}`;

  // Log BEFORE signature generation to see exact inputs
  const beforeSigLog = {
    payload,
    payloadRaw: JSON.stringify(payload),
    payloadLength: payload.length,
    payloadBytes: Buffer.from(payload, "utf8").length,
    payloadHex: Buffer.from(payload, "utf8").toString("hex"),
    userId,
    userIdRaw: JSON.stringify(userId),
    userIdLength: userId?.length,
    tenantId,
    tenantIdRaw: JSON.stringify(tenantId),
    tenantIdLength: tenantId?.length,
    timestamp,
    timestampRaw: JSON.stringify(timestamp),
    timestampLength: timestamp?.length,
    timestampType: typeof timestamp,
    secretLength: secret.length,
    secretFirstChar: secret[0],
    secretLastChar: secret[secret.length - 1],
    secretFirstBytes: Buffer.from(secret.substring(0, 10), "utf8").toString(
      "hex"
    ),
  };
  process.stdout.write(
    `[GATEWAY_SECURITY] BEFORE_SIGNATURE_GENERATION: ${JSON.stringify(
      beforeSigLog,
      null,
      2
    )}\n`
  );
  console.error(
    "[GATEWAY_SECURITY] BEFORE_SIGNATURE_GENERATION:",
    beforeSigLog
  );

  // Compare with expected payload from gateway logs
  const expectedPayload =
    "68c6c6368e834293355e49ba|68cbf7806080b4621d469d34|1765819948000";
  const payloadComparison = {
    servicePayload: payload,
    gatewayPayload: expectedPayload,
    match: payload === expectedPayload,
    servicePayloadHex: Buffer.from(payload, "utf8").toString("hex"),
    gatewayPayloadHex: Buffer.from(expectedPayload, "utf8").toString("hex"),
  };
  process.stdout.write(
    `[GATEWAY_SECURITY] PAYLOAD_COMPARISON: ${JSON.stringify(
      payloadComparison,
      null,
      2
    )}\n`
  );
  console.error("[GATEWAY_SECURITY] PAYLOAD_COMPARISON:", payloadComparison);

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(payload, "utf8")
    .digest("hex")
    .toLowerCase();

  const receivedSignature = signature.trim().toLowerCase();

  // Log signature comparison
  const sigComparison = {
    expectedSignature,
    receivedSignature,
    match: expectedSignature === receivedSignature,
    expectedLength: expectedSignature.length,
    receivedLength: receivedSignature.length,
    expectedFirst20: expectedSignature.substring(0, 20),
    receivedFirst20: receivedSignature.substring(0, 20),
  };
  process.stdout.write(
    `[GATEWAY_SECURITY] SIGNATURE_COMPARISON: ${JSON.stringify(
      sigComparison,
      null,
      2
    )}\n`
  );
  console.error("[GATEWAY_SECURITY] SIGNATURE_COMPARISON:", sigComparison);

  if (expectedSignature !== receivedSignature) {
    // Debug logging for signature mismatch - use console.error to ensure visibility
    const debugInfo = {
      payload,
      payloadBytes: Buffer.from(payload, "utf8").toString("hex"),
      userId,
      tenantId,
      timestamp,
      timestampType: typeof timestamp,
      secretLength: secret.length,
      secretFirstChar: secret[0],
      secretLastChar: secret[secret.length - 1],
      secretFirst10Hex: Buffer.from(secret.substring(0, 10), "utf8").toString(
        "hex"
      ),
      expectedSignature,
      receivedSignature,
      expectedLength: expectedSignature.length,
      receivedLength: receivedSignature.length,
      expectedFirst20: expectedSignature.substring(0, 20),
      receivedFirst20: receivedSignature.substring(0, 20),
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
    console.warn("[GATEWAY_SECURITY] SIGNATURE_MISMATCH:", debugInfo);
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
  writeLog("INFO", "[GATEWAY_SECURITY] validateGatewayRequest called");
  console.warn("[GATEWAY_SECURITY] validateGatewayRequest called");
  const startTime = Date.now();
  const clientIp = req.headers["x-forwarded-for"] || req.socket?.remoteAddress;

  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  // 1. Header validation (HARD BLOCK)
  writeLog("INFO", "[GATEWAY_SECURITY] Step 1: Validating headers...");
  console.warn("[GATEWAY_SECURITY] Step 1: Validating headers...");
  const headerCheck = validateGatewayHeaders(req);
  if (!headerCheck.valid) {
    console.warn(
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
  writeLog("INFO", "[GATEWAY_SECURITY] Step 3: Verifying signature...");
  console.warn("[GATEWAY_SECURITY] Step 3: Verifying signature...");
  const sigCheck = verifyGatewaySignature(req);
  if (!sigCheck.valid) {
    console.warn(
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

module.exports = {
  validateGatewayRequest,
};
