/**
 * Standardized Error Handling for Gateway Security
 * 
 * Provides consistent error responses across all services
 */

/**
 * Create standardized authentication error response
 * @param {string} message - Error message
 * @param {string} code - Error code
 * @param {Object} details - Additional error details
 * @returns {Object} Error response object
 */
function createAuthError(message, code = "AUTH_ERROR", details = {}) {
  return {
    success: false,
    error: {
      message,
      code,
      status: 401,
      ...details,
    },
    timestamp: new Date().toISOString(),
  };
}

/**
 * Create standardized authorization error response
 * @param {string} message - Error message
 * @param {string} code - Error code
 * @param {Object} details - Additional error details
 * @returns {Object} Error response object
 */
function createForbiddenError(message, code = "FORBIDDEN", details = {}) {
  return {
    success: false,
    error: {
      message,
      code,
      status: 403,
      ...details,
    },
    timestamp: new Date().toISOString(),
  };
}

/**
 * Create standardized validation error response
 * @param {string} message - Error message
 * @param {string} code - Error code
 * @param {Array} errors - Validation errors
 * @returns {Object} Error response object
 */
function createValidationError(message, code = "VALIDATION_ERROR", errors = []) {
  return {
    success: false,
    error: {
      message,
      code,
      status: 400,
      errors,
    },
    timestamp: new Date().toISOString(),
  };
}

/**
 * Gateway validation error codes
 */
const GATEWAY_ERROR_CODES = {
  NOT_GATEWAY_REQUEST: "NOT_GATEWAY_REQUEST",
  MISSING_HEADERS: "MISSING_HEADERS",
  INVALID_SIGNATURE: "INVALID_SIGNATURE",
  INVALID_IP: "INVALID_IP",
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  HEADER_VALIDATION_FAILED: "HEADER_VALIDATION_FAILED",
  REPLAY_ATTACK: "REPLAY_ATTACK",
};

/**
 * Map validation reason to error code
 * @param {string} reason - Validation failure reason
 * @returns {string} Error code
 */
function mapReasonToErrorCode(reason) {
  if (reason.includes("Not a gateway request")) {
    return GATEWAY_ERROR_CODES.NOT_GATEWAY_REQUEST;
  }
  if (reason.includes("Missing")) {
    return GATEWAY_ERROR_CODES.MISSING_HEADERS;
  }
  if (reason.includes("signature")) {
    return GATEWAY_ERROR_CODES.INVALID_SIGNATURE;
  }
  if (reason.includes("IP")) {
    return GATEWAY_ERROR_CODES.INVALID_IP;
  }
  if (reason.includes("expired")) {
    return GATEWAY_ERROR_CODES.TOKEN_EXPIRED;
  }
  if (reason.includes("Header validation")) {
    return GATEWAY_ERROR_CODES.HEADER_VALIDATION_FAILED;
  }
  if (reason.includes("timestamp") || reason.includes("replay")) {
    return GATEWAY_ERROR_CODES.REPLAY_ATTACK;
  }
  return "GATEWAY_VALIDATION_FAILED";
}

export {
  createAuthError,
  createForbiddenError,
  createValidationError,
  GATEWAY_ERROR_CODES,
  mapReasonToErrorCode,
};

