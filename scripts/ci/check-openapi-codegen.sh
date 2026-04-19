#!/usr/bin/env bash
# check-openapi-codegen.sh — VALIDATION 5-10-01
# Runs the OpenAPI codegen script and asserts the output matches the committed
# generated types. Fails if the generated file has drifted from the OpenAPI spec.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "Running OpenAPI codegen..."
pnpm --filter secureprompt-web codegen >/dev/null 2>&1

# Check for drift in the generated types file.
# The codegen script outputs to src/types/api.gen.ts (per package.json codegen script).
if ! git diff --exit-code secureprompt-web/src/types/api.gen.ts 2>/dev/null; then
    echo ""
    echo "ERROR: OpenAPI codegen drift detected." >&2
    echo "The generated types in secureprompt-web/src/types/api.gen.ts are out of sync" >&2
    echo "with secureprompt-schemas/openapi/v1/openapi.yaml." >&2
    echo ""
    echo "Fix: Run 'pnpm --filter secureprompt-web codegen' and commit the result." >&2
    exit 1
fi

echo "openapi-codegen OK"
