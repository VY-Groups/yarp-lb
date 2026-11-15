#!/usr/bin/env bash
# Relay only lifecycle commands through the exact GitHub Actions run artifacts.
set -euo pipefail
name="${1:?artifact name}"
destination="${2:?destination directory}"
: "${GITHUB_RUN_ID:?}"
: "${GITHUB_REPOSITORY:?}"
: "${GH_TOKEN:?}"
mkdir -p "$destination"
for attempt in $(seq 1 120); do
  if gh run download "$GITHUB_RUN_ID" --repo "$GITHUB_REPOSITORY" \
      --name "$name" --dir "$destination" >/dev/null 2>&1; then
    echo "RECEIVED: $name (same-run artifact)"
    exit 0
  fi
  sleep 3
done
echo "NO-GO: missing same-run artifact $name after 360 seconds" >&2
exit 1
