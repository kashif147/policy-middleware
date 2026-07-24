# CLAUDE.md

`@membership/policy-middleware` is the shared authorization package consumed by every backend
microservice in this platform. It provides two things: centralized RBAC (`requirePermission()`,
delegating the actual decision to user-service's `/policy/evaluate`) and gateway-header validation
(`validateGatewayRequest()`, trusting nginx as the single JWT-verification authority). Its two most
consequential behaviors — the `AUTH_BYPASS_ENABLED` auth-endpoint carve-out and
`validateGatewayRequest`'s header-presence-only model — are covered in `gotchas.md` below; read that
before changing either function.

### Build and deploy model
@.claude/rules/build-and-deploy.md

### API surface
@.claude/rules/api-surface.md

### Gotchas consumers rely on
@.claude/rules/gotchas.md
