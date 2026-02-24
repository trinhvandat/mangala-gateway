# ADR Guide

Keep Architecture Decision Records concise and immutable.

## File naming
- `0001-short-title.md`, `0002-short-title.md`, ...

## Template
```
# ADR {N}: {Title}

## Status
Accepted | Proposed | Superseded

## Context
What problem are we solving? What constraints exist?

## Decision
What was chosen?

## Consequences
Tradeoffs, risks, and follow-up actions.
```

## Rules
- Do not rewrite history in old ADRs.
- If a decision changes, add a new ADR that supersedes old one.
- Link related ADRs explicitly.
