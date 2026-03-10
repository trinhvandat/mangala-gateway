#!/bin/bash
# Build Docker image for mangala-gateway
# This script handles the multi-module dependency on common-security

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT_DIR"

# Temporarily move gateway's .dockerignore to use root's
if [ -f mangala-gateway/.dockerignore ]; then
    mv mangala-gateway/.dockerignore mangala-gateway/.dockerignore.bak
    trap "mv mangala-gateway/.dockerignore.bak mangala-gateway/.dockerignore 2>/dev/null || true" EXIT
fi

docker build -f mangala-gateway/Dockerfile -t mangala-gateway "${@}" .

echo "✓ Successfully built mangala-gateway"
