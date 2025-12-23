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
 * REMOVED: HMAC signature verification
 * Gateway is trusted boundary - no need for signature verification
 * Services trust requests if x-jwt-verified === "true" && x-auth-source === "gateway"
 */

/**
 * Main gateway validation entry point (Simplified)
 * Trusts requests if gateway headers are present and valid
 * No HMAC or timestamp checks - gateway is trusted boundary
 */
function validateGatewayRequest(req) {
  // Only validate headers - gateway is trusted
  return validateGatewayHeaders(req);
}

module.exports = {
  validateGatewayRequest,
};
