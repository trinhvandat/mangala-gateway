# ADR 0003: Security Status Contract and Regression Suite

## Status
Accepted

## Context
Gateway authorization has multiple decision points:
- Spring Security authentication entry
- JWT validation in `JwtAuthenticationFilter`
- ABAC authorization in `AbacAuthorizationFilter`

Without a locked regression matrix, behavior drift between `401`, `403`, and no-policy handling can break clients and weaken security guarantees.

## Decision
- Standardize 401 responses as JSON payload with `code=GATEWAY_UNAUTHORIZED`.
- Keep ABAC authorization denials as `403` with `X-Forbidden-Reason`.
- Keep no-policy handling configurable by `gateway.policy.no-match-behavior`:
  - `DENY` => `403`
  - `ALLOW` => pass-through with `X-Authorization-Rule=no-policy-allow`
- Add automated regression suite covering 401/403/no-policy contract.
- Run regression suite in GitHub Actions for pull requests.

## Consequences
- Pros:
  - Stable client-facing security contract.
  - Faster detection of authn/authz regressions.
  - Clear distinction between authentication failure and authorization denial.
- Cons:
  - Additional test maintenance when security flow changes.
  - Mixed response contract remains (`401` JSON vs `403` reason header) by design choice.
