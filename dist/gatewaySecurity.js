/**
 * Gateway Header Security Validation
 * 
 * Shared security module for validating gateway headers
 * Prevents spoofing attacks and implements OWASP Top 10 security controls
 * 
 * This module is part of @membership/policy-middleware package
 */

const crypto = require("crypto");

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
  const clientIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || 
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

  // Validate JSON headers
  const rolesStr = req.headers["x-user-roles"];
  if (rolesStr) {
    try {
      const roles = JSON.parse(rolesStr);
      if (!Array.isArray(roles)) {
        errors.push("x-user-roles must be a JSON array");
      }
    } catch (e) {
      errors.push("Invalid x-user-roles JSON format");
    }
  }

  const permsStr = req.headers["x-user-permissions"];
  if (permsStr) {
    try {
      const perms = JSON.parse(permsStr);
      if (!Array.isArray(perms)) {
        errors.push("x-user-permissions must be a JSON array");
      }
    } catch (e) {
      errors.push("Invalid x-user-permissions JSON format");
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
function isTokenExpired(req) {
  const expiresAt = req.headers["x-token-expires-at"];
  if (!expiresAt) {
    // If no expiration header, assume valid (gateway should set this)
    return false;
  }

  const expiryTime = parseInt(expiresAt, 10);
  if (isNaN(expiryTime)) {
    console.warn("Invalid x-token-expires-at format");
    return false; // Don't reject if format is wrong, just log
  }

  return Date.now() > expiryTime;
}

/**
 * Comprehensive gateway header validation
 * @param {Object} req - Express request object
 * @returns {Object} { valid: boolean, reason?: string }
 */
function validateGatewayRequest(req) {
  const startTime = Date.now();
  const clientIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || 
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
    logSecurityEvent("GATEWAY_VALIDATION_FAILED", {
      reason: "Token expired",
      clientIp,
      userId,
      tenantId,
      duration: Date.now() - startTime,
      severity: "MEDIUM",
    });
    return { valid: false, reason: "Token expired" };
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

module.exports = {
  verifyGatewaySignature,
  verifyGatewayIP,
  validateGatewayHeaders,
  isTokenExpired,
  validateGatewayRequest,
  logSecurityEvent, // Export for external use
};
