# ADR 0001: Policy Loading From Auth Internal API

## Status
Accepted

## Context
Gateway enforces authorization but policy ownership belongs to `mangala-authentication`.
Direct gateway reads against auth database create tight coupling and break service boundaries.

## Decision
Gateway policy loader must use auth internal APIs:
- `GET /v1/internal/policies`
- `GET /v1/internal/policies/version`

Gateway compares remote version and only reloads full policy snapshot when version increases.
Policy cache is atomically swapped to avoid inconsistent reads.

## Consequences
- Pros:
  - Preserves ownership boundary of auth service.
  - Keeps gateway policy behavior consistent and auditable.
- Cons:
  - Gateway bootstrap depends on availability and correctness of auth internal API.
  - Requires secure service-to-service protection for internal endpoints.
