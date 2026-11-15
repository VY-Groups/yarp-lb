#!/usr/bin/env bash
# Preflight admission gate for optional live EC2 integration.
# Never substitutes test results, target addresses, or success evidence.
set -euo pipefail
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY required}"
: "${GITHUB_EVENT_NAME:?GITHUB_EVENT_NAME required}"
if [[ -n "${BACKEND_A_HOST:-}" && -n "${BACKEND_B_HOST:-}" ]]; then
  echo 'enabled=true' >> "$GITHUB_OUTPUT"
  exit 0
fi
mkdir -p artifacts/ec2
printf 'NOT_TESTED: live EC2 targets not configured; no EC2 requests attempted.\n' > artifacts/ec2/not-tested.txt
{
  echo '### Live EC2 integration: NOT TESTED'
  echo 'One or both BACKEND_A_HOST / BACKEND_B_HOST repository variables are missing.'
  echo 'No external backend requests were sent. Offline safety tests passed independently.'
} >> "$GITHUB_STEP_SUMMARY"
if [[ "$GITHUB_EVENT_NAME" == "workflow_dispatch" ]]; then
  echo '::error::Manual live request requires both repository variables'
  exit 1
fi
echo 'enabled=false' >> "$GITHUB_OUTPUT"
echo '::warning::Scheduled EC2 live checks NOT TESTED: targets not configured'
