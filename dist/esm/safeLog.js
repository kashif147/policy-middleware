/**
 * Safe logging fields for the policy middleware and client.
 *
 * Request bodies and query strings (personal data, ids, tokens), the user's email, roles and
 * permissions, raw policy results, raw error response bodies and whole error objects are never
 * logged. These helpers reduce each of them to explicit, non-personal fields.
 */

const SAFE_ID = /^[A-Za-z0-9_.:-]{1,128}$/;

/** Field names of a plain object (never its values); [] for anything else. */
function fieldNames(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value)
    : [];
}

/** Length of an array, 0 for anything else. */
function count(value) {
  return Array.isArray(value) ? value.length : 0;
}

/** Request path without its query string. */
function pathOnly(req) {
  return String((req && (req.originalUrl || req.url)) || "").split("?")[0];
}

/** Correlation id of the request, when one is present and looks like an identifier. */
function correlationIdOf(req) {
  const value =
    (req && req.correlationId) ||
    (req && req.headers && req.headers["x-correlation-id"]);
  return typeof value === "string" && SAFE_ID.test(value) ? value : null;
}

/** A policy decision without the user's email, roles, permissions or any other payload. */
function decisionFields(result) {
  const r = result && typeof result === "object" ? result : {};
  const user = r.user && typeof r.user === "object" ? r.user : {};
  return {
    decision: r.decision ?? null,
    reason: r.reason ?? null,
    success: r.success ?? null,
    policyVersion: r.policyVersion ?? null,
    userId: user.id ?? null,
    tenantId: user.tenantId ?? null,
    userType: user.userType ?? null,
  };
}

/** An error without its message, stack, request config or response body. */
function errorFields(error) {
  return {
    name: (error && error.name) || null,
    code: (error && error.code) ?? null,
    status: (error && error.response && error.response.status) ?? (error && error.status) ?? null,
  };
}

/** A policy / user-service error response body, reduced to reason, decision and code. */
function responseFields(data) {
  const d = data && typeof data === "object" ? data : {};
  return {
    reason: d.reason ?? null,
    decision: d.decision ?? null,
    code: d.code ?? null,
  };
}

export {
  fieldNames,
  count,
  pathOnly,
  correlationIdOf,
  decisionFields,
  errorFields,
  responseFields,
};
