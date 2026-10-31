/**
 * Core Policy Client for Centralized RBAC Policy Evaluation
 * Framework-agnostic implementation that can be used across platforms
 *
 * Usage in Node.js/Express microservices:
 * const PolicyClient = require('./policyClient');
 * const policy = new PolicyClient('http://user-service:3000');
 */

const axios = require("axios");
const crypto = require("crypto");
const { errorFields, responseFields } = require("./safeLog");

// Phase B / Z9.1 decision-cache key epoch: bump to make every previously cached decision miss when
// the key inputs or the PDP's decision semantics change.
const CACHE_KEY_EPOCH = "z9.1";

// Key-sorted deep copy (arrays keep their order); toJSON values (Date, ObjectId) are honoured.
function canonicalize(value, seen = new WeakSet()) {
  if (value && typeof value.toJSON === "function") value = value.toJSON();
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) throw new TypeError("circular context");
  seen.add(value);
  const out = Array.isArray(value)
    ? value.map((v) => (v === undefined ? null : canonicalize(v, seen)))
    : Object.keys(value)
        .sort()
        .reduce((o, k) => {
          if (value[k] !== undefined && typeof value[k] !== "function") o[k] = canonicalize(value[k], seen);
          return o;
        }, {});
  seen.delete(value);
  return out;
}

class PolicyClient {
  constructor(baseUrl, options = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, ""); // Remove trailing slash
    this.timeout = options.timeout || 5000;
    this.retries = options.retries || 3;
    this.cache = new Map();
    this.cacheTimeout = options.cacheTimeout || 300000; // 5 minutes
    this.retryDelay = options.retryDelay || 1000;
  }

  /**
   * Evaluate a single authorization request
   * @param {string} token - JWT token
   * @param {string} resource - Resource being accessed
   * @param {string} action - Action being performed
   * @param {Object} context - Additional context
   * @returns {Promise<Object>} Policy decision
   */
  async evaluate(token, resource, action, context = {}) {
    const cacheKey = this.getCacheKey(token, resource, action, context);

    // Check cache first
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.result;
      }
      this.cache.delete(cacheKey);
    }

    try {
      const response = await this.makeRequest("/policy/evaluate", {
        method: "POST",
        data: { token, resource, action, context },
        headers: { "Content-Type": "application/json" },
      });

      // Cache successful results
      if (response.success) {
        this.cache.set(cacheKey, {
          result: response,
          timestamp: Date.now(),
        });
      }

      return response;
    } catch (error) {
      // Explicit fields only: never the stack, request config or raw response body.
      console.log(
        "[POLICY_CLIENT] ERROR: Policy evaluation failed:",
        errorFields(error)
      );

      // If we got a response from the server, include it
      if (error.response) {
        console.log("[POLICY_CLIENT] Server response status:", error.response.status);
        console.log("[POLICY_CLIENT] Server response data:", responseFields(error.response.data));
        
        // If it's a 403, the server already evaluated and denied - return that response
        if (error.response.status === 403 && error.response.data) {
          return {
            success: false,
            decision: "DENY",
            reason: error.response.data.reason || "PERMISSION_DENIED",
            error: error.response.data.error || error.message,
            ...error.response.data, // Include all fields from server response
          };
        }
      }
      
      return {
        success: false,
        decision: "DENY",
        reason: "POLICY_SERVICE_ERROR",
        error: error.message,
        errorCode: error.code,
        errorResponse: error.response?.data,
      };
    }
  }

  /**
   * Alias for evaluate method (backward compatibility)
   */
  async evaluatePolicy(token, resource, action, context = {}) {
    return this.evaluate(token, resource, action, context);
  }

  /**
   * Evaluate policy using gateway headers instead of token
   * @param {Object} headers - Request headers (including gateway headers)
   * @param {string} resource - Resource being accessed
   * @param {string} action - Action being performed
   * @param {Object} context - Additional context
   * @returns {Promise<Object>} Policy decision
   */
  async evaluateWithHeaders(headers, resource, action, context = {}) {
    // Create cache key from user context instead of token
    const userId = headers["x-user-id"] || context.userId;
    const tenantId = headers["x-tenant-id"] || context.tenantId;
    const cacheKey = this.getCacheKeyFromContext(
      userId,
      tenantId,
      resource,
      action,
      context,
      headers
    );

    // Check cache first
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.result;
      }
      this.cache.delete(cacheKey);
    }

    try {
      // Forward gateway headers to user-service
      // CRITICAL: Forward identity headers only - no HMAC or timestamp needed
      const forwardHeaders = {
        "Content-Type": "application/json",
      };

      // Forward identity headers (authoritative source)
      if (headers["x-jwt-verified"])
        forwardHeaders["x-jwt-verified"] = headers["x-jwt-verified"];
      if (headers["x-auth-source"])
        forwardHeaders["x-auth-source"] = headers["x-auth-source"];
      if (headers["x-user-id"])
        forwardHeaders["x-user-id"] = headers["x-user-id"];
      if (headers["x-tenant-id"])
        forwardHeaders["x-tenant-id"] = headers["x-tenant-id"];
      if (headers["x-user-email"])
        forwardHeaders["x-user-email"] = headers["x-user-email"];
      if (headers["x-user-type"])
        forwardHeaders["x-user-type"] = headers["x-user-type"];
      if (headers["x-user-roles"])
        forwardHeaders["x-user-roles"] = headers["x-user-roles"];
      if (headers["x-user-permissions"])
        forwardHeaders["x-user-permissions"] = headers["x-user-permissions"];
      if (headers["x-correlation-id"])
        forwardHeaders["x-correlation-id"] = headers["x-correlation-id"];

      const response = await this.makeRequest("/policy/evaluate", {
        method: "POST",
        data: { resource, action, context }, // No token in body
        headers: forwardHeaders,
      });

      // Cache successful results
      if (response.success) {
        this.cache.set(cacheKey, {
          result: response,
          timestamp: Date.now(),
        });
      }

      return response;
    } catch (error) {
      console.log(
        "[POLICY_CLIENT] ERROR: Policy evaluation failed:",
        errorFields(error)
      );
      return {
        success: false,
        decision: "DENY",
        reason: "POLICY_SERVICE_ERROR",
        error: error.message,
      };
    }
  }

  /**
   * Get user permissions for a specific resource using headers
   * @param {Object} headers - Request headers (including gateway headers)
   * @param {string} resource - Resource name
   * @returns {Promise<Object>} User permissions
   */
  async getPermissionsWithHeaders(headers, resource) {
    try {
      const forwardHeaders = {
        "Content-Type": "application/json",
      };

      // Forward gateway headers
      if (headers["x-jwt-verified"])
        forwardHeaders["x-jwt-verified"] = headers["x-jwt-verified"];
      if (headers["x-auth-source"])
        forwardHeaders["x-auth-source"] = headers["x-auth-source"];
      if (headers["x-user-id"])
        forwardHeaders["x-user-id"] = headers["x-user-id"];
      if (headers["x-tenant-id"])
        forwardHeaders["x-tenant-id"] = headers["x-tenant-id"];
      if (headers["x-user-roles"])
        forwardHeaders["x-user-roles"] = headers["x-user-roles"];
      if (headers["x-user-permissions"])
        forwardHeaders["x-user-permissions"] = headers["x-user-permissions"];
      if (headers["x-correlation-id"])
        forwardHeaders["x-correlation-id"] = headers["x-correlation-id"];

      return await this.makeRequest(`/policy/permissions/${resource}`, {
        method: "GET",
        headers: forwardHeaders,
      });
    } catch (error) {
      console.log(
        "[POLICY_CLIENT] ERROR: Get permissions failed:",
        errorFields(error)
      );
      return {
        success: false,
        permissions: [],
        error: error.message,
      };
    }
  }

  /**
   * Get user permissions for a specific resource (legacy token-based)
   * @param {string} token - JWT token
   * @param {string} resource - Resource name
   * @returns {Promise<Object>} User permissions
   */
  async getPermissions(token, resource) {
    try {
      return await this.makeRequest(`/policy/permissions/${resource}`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
    } catch (error) {
      console.log(
        "[POLICY_CLIENT] ERROR: Get permissions failed:",
        errorFields(error)
      );
      return {
        success: false,
        permissions: [],
        error: error.message,
      };
    }
  }

  /**
   * Make HTTP request with retries
   * @param {string} endpoint - API endpoint
   * @param {Object} options - Request options
   * @returns {Promise<Object>} Response data
   */
  async makeRequest(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    let lastError;

    for (let attempt = 1; attempt <= this.retries; attempt++) {
      try {
        const config = {
          url,
          timeout: this.timeout,
          ...options,
        };

        const response = await axios(config);
        return response.data;
      } catch (error) {
        lastError = error;

        // Get HTTP status code from error response
        const statusCode = error.response?.status;

        // Fail immediately on 401 (Unauthorized) or 403 (Forbidden)
        // Policy denial is not transient - no retries
        if (statusCode === 401 || statusCode === 403) {
          console.log(
            `[POLICY_CLIENT] ERROR: Policy request failed with ${statusCode} (${
              statusCode === 401 ? "Unauthorized" : "Forbidden"
            }) - failing immediately, no retries`
          );
          throw error;
        }

        // Retry only on 5xx server errors
        // Network errors and other 4xx errors fail immediately
        const isServerError = statusCode >= 500 && statusCode < 600;
        const isNetworkError =
          !statusCode &&
          (error.code === "ECONNREFUSED" ||
            error.code === "ETIMEDOUT" ||
            error.code === "ENOTFOUND");

        if (attempt < this.retries && (isServerError || isNetworkError)) {
          const delay = this.retryDelay * Math.pow(2, attempt - 1); // Exponential backoff
          console.log(
            `[POLICY_CLIENT] WARN: Policy request failed (attempt ${attempt}/${
              this.retries
            }) - ${
              isServerError ? `Server error ${statusCode}` : "Network error"
            } - retrying in ${delay}ms...`
          );
          await this.sleep(delay);
        } else {
          // Fail immediately for non-retryable errors (4xx except 401/403 already handled)
          if (statusCode && statusCode < 500) {
            console.log(
              `[POLICY_CLIENT] ERROR: Policy request failed with ${statusCode} - failing immediately, no retries`
            );
          }
          throw error;
        }
      }
    }

    throw lastError;
  }

  /**
   * Generate cache key for a token-based request.
   *
   * Phase B / Z9.1: the token is identified by a sha256 of the WHOLE token (never a substring - the
   * first 20 characters are the HS256 header, identical for every token), so two tokens can only
   * share a cached decision if they are byte-identical.
   * @param {string} token - JWT token
   * @param {string} resource - Resource name
   * @param {string} action - Action name
   * @param {Object} context - Context object
   * @returns {string} Cache key (`resource:action:<sha256>`, no identifiers)
   */
  getCacheKey(token, resource, action, context) {
    return this.decisionKey(resource, action, {
      path: "token",
      token: this.hashToken(token),
      context,
    });
  }

  /**
   * sha256 of the whole token (cache discriminator only; never logged)
   * @param {string} token - JWT token
   * @returns {string|null} Hex digest
   */
  hashToken(token) {
    if (!token) return null;
    return crypto.createHash("sha256").update(String(token)).digest("hex");
  }

  /**
   * Generate cache key from context (for header-based requests).
   *
   * Phase B / Z9.1: the key is a fingerprint of EVERY verified identity attribute user-service's
   * PDP decides on for a header-based request (policyEvaluationService.evaluatePolicyWithHeaders:
   * x-user-id, x-tenant-id, x-user-type, x-user-roles, x-user-permissions) plus the request target
   * and the whole canonical context - the same inputs as the PDP's own identity digest. There is no
   * stored role/permission revision to reuse: a role or permission change reaches a request as a
   * new token (new x-user-roles / x-user-permissions), so it naturally misses every decision cached
   * for the old authorization state. Full user and tenant ids, never prefixes. The user's email is
   * not decision input and is not part of the key.
   * @param {string} userId - User ID (full)
   * @param {string} tenantId - Tenant ID (full, the trusted tenant)
   * @param {string} resource - Resource name
   * @param {string} action - Action name
   * @param {Object} context - Context object
   * @param {Object} [headers] - The identity headers forwarded to the PDP
   * @returns {string} Cache key (`resource:action:<sha256>`, no identifiers)
   */
  getCacheKeyFromContext(userId, tenantId, resource, action, context, headers = {}) {
    return this.decisionKey(resource, action, {
      path: "headers",
      userId: userId == null ? null : String(userId),
      tenantId: tenantId == null ? null : String(tenantId),
      identity: {
        userId: headers["x-user-id"] ?? null,
        tenantId: headers["x-tenant-id"] ?? null,
        userType: headers["x-user-type"] ?? null,
        roles: headers["x-user-roles"] ?? null,
        permissions: headers["x-user-permissions"] ?? null,
      },
      context,
    });
  }

  /**
   * `resource:action:<sha256(epoch + inputs)>` - deterministic, collision-resistant, and safe to
   * expose through getCacheStats() (no user/tenant ids, roles, permissions or token material).
   */
  decisionKey(resource, action, inputs) {
    const digest = crypto
      .createHash("sha256")
      .update(this.hashObject({ epoch: CACHE_KEY_EPOCH, resource, action, ...inputs }))
      .digest("hex");
    return `${resource}:${action}:${digest}`;
  }

  /**
   * Canonical JSON for caching: object keys sorted at EVERY depth, array order preserved, so equal
   * content always gives the same string and nested values (e.g. role objects, nested body fields)
   * are never dropped.
   * @param {Object} obj - Object to serialise
   * @returns {string} Canonical JSON
   */
  hashObject(obj) {
    try {
      return JSON.stringify(canonicalize(obj));
    } catch (error) {
      return "invalid-context";
    }
  }

  /**
   * Sleep utility for retries
   * @param {number} ms - Milliseconds to sleep
   * @returns {Promise} Sleep promise
   */
  sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Clear the cache
   */
  clearCache() {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache statistics
   */
  getCacheStats() {
    return {
      size: this.cache.size,
      maxSize: this.cacheTimeout,
      entries: Array.from(this.cache.keys()),
    };
  }
}

module.exports = PolicyClient;
