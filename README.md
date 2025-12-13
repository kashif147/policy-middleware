# @membership/policy-middleware

Shared policy middleware for membership microservices with centralized RBAC.

## Installation

```bash
npm install @membership/policy-middleware
```

## Usage

### Basic Setup

```javascript
const {
  createDefaultPolicyMiddleware,
} = require("@membership/policy-middleware");

// Create policy middleware instance
const policyMiddleware = createDefaultPolicyMiddleware(
  process.env.POLICY_SERVICE_URL || "http://user-service:3000"
);

// Use in routes
router.get(
  "/protected",
  policyMiddleware.requirePermission("resource", "action"),
  controller.method
);
```

### Gateway Security Module

The package includes a shared gateway security module for validating gateway headers:

```javascript
const { gatewaySecurity } = require("@membership/policy-middleware/security");

// Validate gateway request
const validation = gatewaySecurity.validateGatewayRequest(req);
if (!validation.valid) {
  return res.status(401).json({ error: validation.reason });
}
```

**Security Features:**
- HMAC signature verification
- IP whitelist validation
- Header format validation
- Token expiration checking
- Replay attack prevention (5-minute window)
- OWASP Top 10 compliance

### Environment Variables

- `POLICY_SERVICE_URL`: URL of the centralized policy service (user-service)
- `AUTH_BYPASS_ENABLED`: Set to 'true' to bypass authentication (development only)
- `GATEWAY_SECRET`: Shared secret for HMAC signature verification
- `GATEWAY_IPS`: Comma-separated list of gateway IP addresses
- `GATEWAY_SIGNATURE_ENABLED`: Enable/disable signature verification (default: true)
- `GATEWAY_IP_VALIDATION`: Enable/disable IP validation (default: true)

### Features

- **Centralized Authorization**: All authorization decisions made by user-service
- **Gateway Security**: OWASP-compliant gateway header validation
- **Caching**: Built-in request caching for performance
- **Retry Logic**: Automatic retries with exponential backoff
- **Error Handling**: Comprehensive error handling and logging
- **Backward Compatibility**: Works with existing controller patterns

### API

#### `requirePermission(resource, action)`

Express middleware factory for route protection.

```javascript
// Protect a route
router.get(
  "/users",
  policyMiddleware.requirePermission("user", "read"),
  userController.getAll
);
```

#### `hasPermission(token, resource, action, context)`

Check if user has permission (returns boolean).

```javascript
const hasAccess = await policyMiddleware.hasPermission(token, "user", "read", {
  userId: "123",
});
```

#### `getPermissions(token, resource)`

Get user permissions for a specific resource.

```javascript
const permissions = await policyMiddleware.getPermissions(token, "user");
```

## Migration from Individual Middleware

Replace individual policy middleware files with this shared package:

1. Install the package
2. Update imports
3. Remove duplicate middleware files
4. Update environment variables

## License

MIT
