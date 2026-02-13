# AGENTS.md

## Purpose
Fast bootstrap context for contributors and coding agents.
Read this first before scanning the entire repository.

## Service Scope
- Service: `mangala-gateway`
- Base package: `org.mangala.gateway`
- Main class: `src/main/java/org/mangala/gateway/GatewayApplication.java`

## Architecture Conventions
- Package-by-capability with clear responsibility boundaries:
  - `config`: framework and infra configuration
  - `filter`: request pipeline filters (JWT, logging)
  - `authorization`: ABAC authorization decision flow
  - `policy`: policy cache, loader, version checker, update listener
  - `abac`: SpEL evaluator and security sandbox for condition expressions
  - `audit`: authorization audit events/publisher
  - `health`: policy/cache/circuit breaker health contributors
- Shared security contracts and DTOs are in `mangala-common-security`.

## Naming Conventions
- Java fields/methods/variables: `camelCase`.
- Config classes: `*Config`, `*Properties` with `@ConfigurationProperties`.
- Policy workflow classes:
  - Loader: `PolicyLoader`
  - Cache: `PolicyCache`
  - Update listener: `PolicyUpdateListener`
  - Poll fallback: `PolicyVersionChecker`

## Security and Authorization Rules
- JWT authentication happens in `JwtAuthenticationFilter`.
- ABAC authorization happens in `AbacAuthorizationFilter`.
- Policy source of truth is loaded from auth internal APIs:
  - `GET /v1/internal/policies`
  - `GET /v1/internal/policies/version`
- No direct auth DB access from gateway.

## Documentation Update Rule
Update these docs when policy loading contract, authorization behavior, or cache/version flow changes:
- `docs/context-map.yaml`
- `docs/adr/*`

Run `scripts/check-context-sync.sh` before PR.
