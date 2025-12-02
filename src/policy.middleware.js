/**
 * Centralized RBAC Policy Middleware
 *
 * This middleware integrates with the centralized policy evaluation service
 * using the policy client for consistent authorization across all microservices.
 */

const PolicyClient = require("./policyClient");

class PolicyMiddleware {
  constructor(baseURL, options = {}) {
    this.policyClient = new PolicyClient(baseURL, options);
  }

  /**
   * Express middleware factory for route protection
   * @param {string} resource - Resource being protected (e.g., 'tenant', 'user', 'role', 'permission')
   * @param {string} action - Action being performed (e.g., 'read', 'write', 'delete', 'create')
   * @returns {Function} Express middleware function
   */
  requirePermission(resource, action) {
    return async (req, res, next) => {
      try {
        console.log(`=== POLICY MIDDLEWARE START: ${resource}:${action} ===`);
        console.log("Policy service URL:", this.policyClient.baseUrl);

        const token = req.headers.authorization?.replace("Bearer ", "");

        if (!token) {
          console.log("No authorization token found");
          return res.status(401).json({
            success: false,
            error: "Authorization token required",
            code: "UNAUTHORIZED",
            status: 401,
          });
        }

        // Extract context from request
        // Filter out 'id' from body/query if it's not a route parameter to avoid validation issues
        // The 'id' field should only come from route parameters (req.params.id)
        const bodyContext = { ...req.body };
        const queryContext = { ...req.query };
        
        // Remove 'id' from body and query unless it's a route parameter
        if (!req.params?.id) {
          delete bodyContext.id;
          delete queryContext.id;
        }
        
        const context = {
          userId: req.ctx?.userId || req.user?.id || req.userId,
          tenantId: req.ctx?.tenantId || req.user?.tenantId || req.tenantId,
          userRoles: req.ctx?.roles || req.user?.roles || req.roles || [],
          userPermissions:
            req.ctx?.permissions ||
            req.user?.permissions ||
            req.permissions ||
            [],
          ...queryContext, // Include query params (id filtered if not route param)
          ...bodyContext, // Include request body (id filtered if not route param)
        };
        
        // Final safety check: remove 'id' from context if it's not from route params
        if (!req.params?.id && context.id) {
          delete context.id;
        }

        // ALWAYS delegate authorization to user service - maintain single source of truth
        console.log(
          `[POLICY_MIDDLEWARE] Delegating authorization to user service for ${resource}:${action}`
        );
        console.log(`[POLICY_MIDDLEWARE] Token: ${token.substring(0, 20)}...`);
        console.log(`[POLICY_MIDDLEWARE] Context:`, context);

        let result;

        // Check if auth bypass is enabled
        // SECURITY: Never allow bypass on authentication endpoints
        const authEndpoints = ['/login', '/signin', '/signup', '/register', '/auth'];
        const isAuthEndpoint = authEndpoints.some(endpoint => 
          req.path.toLowerCase().includes(endpoint.toLowerCase())
        );
        
        if (process.env.AUTH_BYPASS_ENABLED === "true") {
          if (isAuthEndpoint) {
            console.error(
              `[POLICY_MIDDLEWARE] SECURITY ERROR: Bypass attempted on authentication endpoint: ${req.path}`
            );
            return res.status(403).json({
              success: false,
              error: "Authentication bypass is not allowed for authentication endpoints",
              code: "SECURITY_VIOLATION",
              status: 403,
            });
          }
          
          console.log(
            `[POLICY_MIDDLEWARE] Auth bypass enabled, granting access for ${resource}:${action}`
          );

          // Still validate token to extract user info, but skip authorization
          let userFromToken = null;
          try {
            const response = await this.policyClient.makeRequest(
              "/token/validate",
              {
                method: "GET",
                headers: { Authorization: `Bearer ${token}` },
              }
            );
            if (response.success && response.user) {
              userFromToken = response.user;
              console.log(
                "[POLICY_MIDDLEWARE] Token validated, user extracted:",
                userFromToken
              );
            }
          } catch (error) {
            console.log(
              "[POLICY_MIDDLEWARE] Token validation failed, using fallback:",
              error.message
            );
          }

          result = {
            success: true,
            decision: "PERMIT",
            reason: "AUTH_BYPASS_ENABLED",
            user: userFromToken ||
              req.user || {
                id: context.userId || "bypass-user-id",
                userType: "PORTAL",
                tenantId: context.tenantId || "default-tenant",
                roles: [],
                permissions: [],
              },
            resource,
            action,
            timestamp: new Date().toISOString(),
          };
        } else {
          result = await this.policyClient.evaluatePolicy(
            token,
            resource,
            action,
            context
          );
        }

        console.log(
          `[POLICY_MIDDLEWARE] User service response:`,
          JSON.stringify(result, null, 2)
        );

        if (result.success && result.decision === "PERMIT") {
          // Attach policy context to request for use in controllers
          req.policyContext = result;

          // Set req.user for backward compatibility with existing controllers
          if (result.user) {
            req.user = result.user;
            req.userId = result.user.id;
            req.tenantId = result.user.tenantId;
            req.roles = result.user.roles || [];
            req.permissions = result.user.permissions || [];
          }

          console.log(
            `[POLICY_MIDDLEWARE] ✅ Authorization granted for ${resource}:${action}`
          );
          console.log("=== POLICY MIDDLEWARE SUCCESS ===");
          next();
        } else {
          console.log(
            `[POLICY_MIDDLEWARE] ❌ Authorization denied for ${resource}:${action}`
          );
          console.log(
            `[POLICY_MIDDLEWARE] Reason: ${result.reason || "Unknown"}`
          );
          return res.status(403).json({
            success: false,
            error: "Insufficient permissions",
            reason: result.reason || "PERMISSION_DENIED",
            code: "PERMISSION_DENIED",
            resource,
            action,
          });
        }
      } catch (error) {
        console.error("Policy middleware error:", error);
        return res.status(500).json({
          success: false,
          error: "Authorization service error",
          code: "POLICY_SERVICE_ERROR",
        });
      }
    };
  }

  /**
   * Check if user has permission (returns boolean)
   * @param {string} token - JWT token
   * @param {string} resource - Resource being accessed
   * @param {string} action - Action being performed
   * @param {Object} context - Additional context (optional)
   * @returns {boolean} True if permitted, false otherwise
   */
  async hasPermission(token, resource, action, context = {}) {
    try {
      const result = await this.policyClient.evaluatePolicy(
        token,
        resource,
        action,
        context
      );
      return result.success && result.decision === "PERMIT";
    } catch (error) {
      console.error("Permission check failed:", error);
      return false;
    }
  }

  /**
   * Get user permissions for a specific resource
   * @param {string} token - JWT token
   * @param {string} resource - Resource name
   * @returns {Object} User permissions
   */
  async getPermissions(token, resource) {
    return await this.policyClient.getPermissions(token, resource);
  }

  /**
   * Clear the policy client cache
   */
  clearCache() {
    this.policyClient.clearCache();
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache statistics
   */
  getCacheStats() {
    return this.policyClient.getCacheStats();
  }
}

module.exports = PolicyMiddleware;
