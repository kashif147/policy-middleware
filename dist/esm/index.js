/**
 * Shared Policy Middleware Package
 *
 * Exports the policy middleware and client for use across microservices
 */

import PolicyMiddleware from "./policy.middleware.js";
import PolicyClient from "./policyClient.js";

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

export {
  PolicyMiddleware,
  PolicyClient,
  createDefaultPolicyMiddleware,
  defaultPolicyMiddleware,
};

export default {
  PolicyMiddleware,
  PolicyClient,
  createDefaultPolicyMiddleware,
  defaultPolicyMiddleware,
};
