/**
 * Gateway Header Security Validation
 *
 * Shared security module for validating gateway headers
 * Prevents spoofing attacks and implements OWASP Top 10 security controls
 *
 * This module is part of @membership/policy-middleware package
 */

import crypto from "crypto";

/**
 * Security event logger
 * Logs all gateway validation attempts for monitoring and alerting
 */
function logSecurityEvent(eventType, details) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    eventType,
    ...details,
  };

  // Log to console (in production, this should go to a logging service)
  if (process.env.NODE_ENV === "production") {
    // In production, use structured logging
    console.log(JSON.stringify(logEntry));
  } else {
    // In development, use readable format
    console.log(`[Security Event] ${eventType}:`, details);
  }

  // Emit event for external monitoring (if event emitter is available)
  if (typeof process.emit === "function") {
    process.emit("security:event", logEntry);
  }
}

/**
 * Verify gateway header signature
 * @param {Object} req - Express request object
 * @returns {boolean} True if signature is valid
 */
function verifyGatewaySignature(req) {
  const startTime = Date.now();
  const signature = req.headers["x-gateway-signature"];
  const timestamp = req.headers["x-gateway-timestamp"];
  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.ip ||
    req.connection?.remoteAddress;

  if (!signature || !timestamp || !userId || !tenantId) {
    logSecurityEvent("SIGNATURE_VALIDATION_FAILED", {
      reason: "Missing required headers",
      clientIp,
      userId,
      tenantId,
      duration: Date.now() - startTime,
    });
    return false;
  }

  // Prevent replay attacks (5 minute window)
  const now = Date.now();
  const headerTime = parseInt(timestamp, 10);
  if (isNaN(headerTime) || Math.abs(now - headerTime) > 300000) {
    logSecurityEvent("SIGNATURE_VALIDATION_FAILED", {
      reason: "Timestamp outside acceptable window",
      clientIp,
      userId,
      tenantId,
      timestampAge: Math.abs(now - headerTime),
      duration: Date.now() - startTime,
    });
    return false;
  }

  // Verify HMAC signature
  const gatewaySecret = process.env.GATEWAY_SECRET || process.env.JWT_SECRET;
  if (!gatewaySecret) {
    logSecurityEvent("SIGNATURE_VALIDATION_ERROR", {
      reason: "GATEWAY_SECRET not configured",
      clientIp,
      severity: "HIGH",
    });
    return false;
  }

  const message = `${userId}:${tenantId}:${timestamp}`;
  const expectedSig = crypto
    .createHmac("sha256", gatewaySecret)
    .update(message)
    .digest("hex");

  try {
    const isValid = crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSig)
    );

    const duration = Date.now() - startTime;

    if (isValid) {
      logSecurityEvent("SIGNATURE_VALIDATION_SUCCESS", {
        clientIp,
        userId,
        tenantId,
        duration,
      });
    } else {
      logSecurityEvent("SIGNATURE_VALIDATION_FAILED", {
        reason: "Invalid signature",
        clientIp,
        userId,
        tenantId,
        duration,
        severity: "HIGH",
      });
    }

    return isValid;
  } catch (error) {
    logSecurityEvent("SIGNATURE_VALIDATION_ERROR", {
      reason: error.message,
      clientIp,
      userId,
      tenantId,
      duration: Date.now() - startTime,
      severity: "HIGH",
    });
    return false;
  }
}

/**
 * Verify request comes from gateway IP
 * @param {Object} req - Express request object
 * @returns {boolean} True if IP is whitelisted
 */
function verifyGatewayIP(req) {
  const startTime = Date.now();
  const gatewayIPs =
    process.env.GATEWAY_IPS?.split(",").map((ip) => ip.trim()) || [];

  // If no IPs configured, skip validation (not recommended for production)
  if (gatewayIPs.length === 0) {
    logSecurityEvent("IP_VALIDATION_SKIPPED", {
      reason: "GATEWAY_IPS not configured",
      warning: true,
    });
    return true; // Allow for development
  }

  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.ip ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress;

  if (!clientIp) {
    logSecurityEvent("IP_VALIDATION_FAILED", {
      reason: "Could not determine client IP",
      duration: Date.now() - startTime,
    });
    return false;
  }

  const isValid = gatewayIPs.some((allowedIp) => {
    // Support CIDR notation
    if (allowedIp.includes("/")) {
      // Simple CIDR check (for production, use ipaddr.js library)
      return clientIp.startsWith(allowedIp.split("/")[0]);
    }
    return clientIp === allowedIp;
  });

  const duration = Date.now() - startTime;

  if (isValid) {
    logSecurityEvent("IP_VALIDATION_SUCCESS", {
      clientIp,
      allowedIPs: gatewayIPs,
      duration,
    });
  } else {
    logSecurityEvent("IP_VALIDATION_FAILED", {
      reason: "IP not in whitelist",
      clientIp,
      allowedIPs: gatewayIPs,
      duration,
      severity: "HIGH",
    });
  }

  return isValid;
}

/**
 * Validate gateway headers format and content
 * @param {Object} req - Express request object
 * @returns {Object} { valid: boolean, errors: string[] }
 */
function validateGatewayHeaders(req) {
  const errors = [];
  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  // Validate required headers exist
  if (!userId) errors.push("Missing x-user-id header");
  if (!tenantId) errors.push("Missing x-tenant-id header");

  // Validate format (basic checks)
  if (userId && (userId.length > 100 || userId.length < 1)) {
    errors.push("Invalid x-user-id format");
  }
  if (tenantId && (tenantId.length > 100 || tenantId.length < 1)) {
    errors.push("Invalid x-tenant-id format");
  }

  // Validate JSON headers (lenient - treat invalid as empty arrays)
  const rolesStr = req.headers["x-user-roles"];
  if (rolesStr && rolesStr.trim() !== "") {
    try {
      const roles = JSON.parse(rolesStr);
      if (!Array.isArray(roles)) {
        // If it's not an array but is valid JSON, log warning but don't fail
        console.warn(
          "x-user-roles is not a JSON array, treating as empty array"
        );
      }
    } catch (e) {
      // If JSON parsing fails, log warning but don't fail validation
      // Gateway will send empty arrays, but if it sends invalid format, we'll handle it gracefully
      console.warn(
        "Invalid x-user-roles JSON format, treating as empty array:",
        e.message
      );
    }
  }

  const permsStr = req.headers["x-user-permissions"];
  if (permsStr && permsStr.trim() !== "") {
    try {
      const perms = JSON.parse(permsStr);
      if (!Array.isArray(perms)) {
        // If it's not an array but is valid JSON, log warning but don't fail
        console.warn(
          "x-user-permissions is not a JSON array, treating as empty array"
        );
      }
    } catch (e) {
      // If JSON parsing fails, log warning but don't fail validation
      // Gateway will send empty arrays, but if it sends invalid format, we'll handle it gracefully
      console.warn(
        "Invalid x-user-permissions JSON format, treating as empty array:",
        e.message
      );
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Check if token is expired (if expiration header is present)
 * @param {Object} req - Express request object
 * @returns {boolean} True if expired
 */
// function isTokenExpired(req) {
//   const expiresAt = req.headers["x-token-expires-at"];
//   if (!expiresAt) {
//     // If no expiration header, assume valid (gateway should set this)
//     return false;
//   }

//   const expiryTime = parseInt(expiresAt, 10);
//   if (isNaN(expiryTime)) {
//     console.warn("Invalid x-token-expires-at format");
//     return false; // Don't reject if format is wrong, just log
//   }

//   // Add grace period to handle clock skew and network latency (default 60 seconds)
//   const gracePeriodMs = parseInt(
//     process.env.TOKEN_EXPIRY_GRACE_PERIOD_MS || "60000",
//     10
//   );
//   const now = Date.now();
//   const expiryWithGrace = expiryTime + gracePeriodMs;

//   // Log if token is expired but within grace period
//   if (now > expiryTime && now <= expiryWithGrace) {
//     const expiredBy = now - expiryTime;
//     console.warn(
//       `Token expired ${expiredBy}ms ago but within grace period (${gracePeriodMs}ms)`
//     );
//   }

//   return now > expiryWithGrace;
// }
function isTokenExpired(req) {
  const expiresAt = req.headers["x-token-expires-at"];
  if (!expiresAt) {
    // No expiry header means gateway did not enforce expiry
    return false;
  }

  const expirySeconds = parseInt(expiresAt, 10);
  if (isNaN(expirySeconds)) {
    console.warn("Invalid x-token-expires-at format:", expiresAt);
    return false;
  }

  // JWT exp is in seconds → convert to milliseconds
  const expiryMs = expirySeconds * 1000;

  const gracePeriodMs = parseInt(
    process.env.TOKEN_EXPIRY_GRACE_PERIOD_MS || "60000",
    10
  );

  const now = Date.now();
  const expiryWithGrace = expiryMs + gracePeriodMs;

  // Optional diagnostic logging
  if (now > expiryMs && now <= expiryWithGrace) {
    console.warn(
      `Token expired ${now - expiryMs}ms ago but still within grace period`
    );
  }

  return now > expiryWithGrace;
}

/**
 * Comprehensive gateway header validation
 * @param {Object} req - Express request object
 * @returns {Object} { valid: boolean, reason?: string }
 */
function validateGatewayRequest(req) {
  const startTime = Date.now();
  const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.ip ||
    req.connection?.remoteAddress;
  const userId = req.headers["x-user-id"];
  const tenantId = req.headers["x-tenant-id"];

  // Check if gateway headers are present
  const jwtVerified = req.headers["x-jwt-verified"];
  const authSource = req.headers["x-auth-source"];

  if (jwtVerified !== "true" || authSource !== "gateway") {
    logSecurityEvent("GATEWAY_VALIDATION_FAILED", {
      reason: "Not a gateway request",
      clientIp,
      duration: Date.now() - startTime,
    });
    return { valid: false, reason: "Not a gateway request" };
  }

  // Validate header format
  const formatCheck = validateGatewayHeaders(req);
  if (!formatCheck.valid) {
    const reason = `Header validation failed: ${formatCheck.errors.join(", ")}`;
    logSecurityEvent("GATEWAY_VALIDATION_FAILED", {
      reason,
      clientIp,
      userId,
      tenantId,
      errors: formatCheck.errors,
      duration: Date.now() - startTime,
      severity: "MEDIUM",
    });
    return {
      valid: false,
      reason,
    };
  }

  // Check token expiration
  if (isTokenExpired(req)) {
    const expiresAt = req.headers["x-token-expires-at"];
    const expiryTime = expiresAt ? parseInt(expiresAt, 10) : null;
    const now = Date.now();
    const expiredBy =
      expiryTime && !isNaN(expiryTime) ? now - expiryTime : null;
    const gracePeriodMs = parseInt(
      process.env.TOKEN_EXPIRY_GRACE_PERIOD_MS || "60000",
      10
    );

    logSecurityEvent("GATEWAY_VALIDATION_FAILED", {
      reason: "Token expired",
      clientIp,
      userId,
      tenantId,
      duration: Date.now() - startTime,
      severity: "MEDIUM",
      ...(expiredBy !== null && {
        expiredByMs: expiredBy,
        expiredBySeconds: Math.round(expiredBy / 1000),
        gracePeriodMs,
        expiryTime,
        currentTime: now,
      }),
    });
    return {
      valid: false,
      reason:
        expiredBy !== null
          ? `Token expired ${Math.round(expiredBy / 1000)}s ago`
          : "Token expired",
    };
  }

  // Verify signature (if enabled)
  if (process.env.GATEWAY_SIGNATURE_ENABLED !== "false") {
    if (!verifyGatewaySignature(req)) {
      return { valid: false, reason: "Invalid gateway signature" };
    }
  }

  // Verify IP (if enabled)
  if (process.env.GATEWAY_IP_VALIDATION !== "false") {
    if (!verifyGatewayIP(req)) {
      return { valid: false, reason: "Request not from gateway IP" };
    }
  }

  const duration = Date.now() - startTime;
  logSecurityEvent("GATEWAY_VALIDATION_SUCCESS", {
    clientIp,
    userId,
    tenantId,
    duration,
  });

  return { valid: true };
}

export {
  verifyGatewaySignature,
  verifyGatewayIP,
  validateGatewayHeaders,
  isTokenExpired,
  validateGatewayRequest,
  logSecurityEvent,
};
