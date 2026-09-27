/**
 * Shared Policy Middleware Package
 *
 * Exports the policy middleware and client for use across microservices
 */

const PolicyMiddleware = require("./policy.middleware");
const PolicyClient = require("./policyClient");
const gatewaySecurity = require("./gatewaySecurity");
// Destructured (not whole-module) require so the ESM build emits a NAMED import
// matching tenantContext.js's named exports (a default import would be undefined).
const { resolveTenantContext, tenantContextMiddleware } = require("./tenantContext");

// Create default policy middleware instance
const createDefaultPolicyMiddleware = (baseURL, options = {}) => {
  return new PolicyMiddleware(baseURL, {
    timeout: 15000, // Increased timeout for Azure
    retries: 5, // More retries for Azure
    cacheTimeout: 300000, // 5 minutes
    retryDelay: 2000, // Base delay between retries
    ...options,
  });
};

// Default instance (requires baseURL to be set)
const defaultPolicyMiddleware = null;

module.exports = {
  PolicyMiddleware,
  PolicyClient,
  gatewaySecurity,
  resolveTenantContext,
  tenantContextMiddleware,
  createDefaultPolicyMiddleware,
  defaultPolicyMiddleware,
};
