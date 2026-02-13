#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CONTEXT_FILE="docs/context-map.yaml"
ADR_DIR="docs/adr"

if [[ ! -f "$CONTEXT_FILE" ]]; then
  echo "[FAIL] Missing $CONTEXT_FILE"
  exit 1
fi

if [[ ! -d "$ADR_DIR" ]]; then
  echo "[FAIL] Missing $ADR_DIR"
  exit 1
fi

CHANGED_FILES="$(git status --porcelain -uall | awk '{print $2}')"

if [[ -z "$CHANGED_FILES" ]]; then
  echo "[OK] No file changes detected."
  exit 0
fi

needs_doc_update=0

if echo "$CHANGED_FILES" | grep -qE '^src/main/java/org/mangala/gateway/(policy|authorization|abac)/'; then
  needs_doc_update=1
fi

if echo "$CHANGED_FILES" | grep -qE '^mangala-common-security/src/main/java/org/mangala/security/'; then
  needs_doc_update=1
fi

if echo "$CHANGED_FILES" | grep -q '^src/main/java/org/mangala/gateway/policy/PolicyLoader.java'; then
  needs_doc_update=1
fi

if [[ "$needs_doc_update" -eq 1 ]]; then
  if ! echo "$CHANGED_FILES" | grep -q '^docs/context-map.yaml'; then
    echo "[WARN] Policy/authorization-related code changed but docs/context-map.yaml was not updated."
    exit 2
  fi
fi

echo "[OK] Context sync check passed."
