/**
 * Core Policy Client for Centralized RBAC Policy Evaluation
 * Framework-agnostic implementation that can be used across platforms
 *
 * Usage in Node.js/Express microservices:
 * const PolicyClient = require('./policyClient');
 * const policy = new PolicyClient('http://user-service:3000');
 */

const axios = require("axios");

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
      console.error("Policy evaluation failed:", error.message);
      return {
        success: false,
        decision: "DENY",
        reason: "POLICY_SERVICE_ERROR",
        error: error.message,
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
   * Get user permissions for a specific resource
   * @param {string} token - JWT token
   * @param {string} resource - Resource name
   * @returns {Promise<Object>} User permissions
   */
  async getPermissions(token, resource) {
    try {
      return await this.makeRequest(`/policy/permissions/${resource}`, {
        method: "GET",
        headers: { 
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json" 
        },
      });
    } catch (error) {
      console.error("Get permissions failed:", error.message);
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

        if (attempt < this.retries) {
          const delay = this.retryDelay * Math.pow(2, attempt - 1); // Exponential backoff
          console.warn(
            `Policy request failed (attempt ${attempt}/${this.retries}), retrying in ${delay}ms...`
          );
          await this.sleep(delay);
        }
      }
    }

    throw lastError;
  }

  /**
   * Generate cache key for request
   * @param {string} token - JWT token
   * @param {string} resource - Resource name
   * @param {string} action - Action name
   * @param {Object} context - Context object
   * @returns {string} Cache key
   */
  getCacheKey(token, resource, action, context) {
    const tokenHash = this.hashToken(token);
    const contextHash = this.hashObject(context);
    return `${tokenHash}:${resource}:${action}:${contextHash}`;
  }

  /**
   * Hash JWT token for caching (first 20 chars + last 10 chars)
   * @param {string} token - JWT token
   * @returns {string} Hashed token
   */
  hashToken(token) {
    if (!token || token.length < 30) return token;
    return token.substring(0, 20) + "..." + token.substring(token.length - 10);
  }

  /**
   * Hash object for caching
   * @param {Object} obj - Object to hash
   * @returns {string} Hashed object
   */
  hashObject(obj) {
    try {
      return JSON.stringify(obj, Object.keys(obj).sort());
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
