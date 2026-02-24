# ADR 0004: Enforce Policy API mTLS in Non-Dev Profiles

## Status
Accepted

## Context
Gateway loads authorization policy snapshots from auth internal APIs (`/v1/internal/policies*`).
Without explicit profile-based safeguards, non-dev environments can run with plain HTTP or missing client-certificate configuration.

## Decision
- Add gateway policy API mTLS client configuration under `gateway.policy.mtls.*`.
- Use mTLS-capable WebClient builder for `AuthPolicyApiClient` when `gateway.policy.mtls.enabled=true`.
- Add startup guard:
  - if active profile is non-dev and `gateway.policy.profile-guard.enforce-mtls-in-non-dev=true`
  - then require `gateway.policy.mtls.enabled=true` and non-empty key/trust store settings.

## Consequences
- Pros:
  - Prevents insecure non-dev deployments by fail-fast startup validation.
  - Creates explicit transport-security contract for policy loading path.
- Cons:
  - Requires certificate material provisioning in non-dev environments.
  - Misconfiguration causes startup failure until mTLS settings are corrected.
