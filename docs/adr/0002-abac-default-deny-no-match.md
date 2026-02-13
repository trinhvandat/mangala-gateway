# ADR 0002: ABAC No-Match Uses Default Deny

## Status
Accepted

## Context
In policy-based authorization, missing policy rules can accidentally expose endpoints when behavior is permissive.

## Decision
Default no-match behavior is `DENY` and configurable via `gateway.policy.no-match-behavior`.
Permissive mode `ALLOW` is only for controlled development scenarios.

## Consequences
- Pros:
  - Secure-by-default posture for authorization.
  - Reduces accidental exposure when new routes are introduced without policy.
- Cons:
  - Can block traffic if policy data is incomplete or stale.
  - Requires strong operational discipline for policy rollout.
