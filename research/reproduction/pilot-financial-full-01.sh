#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

git rev-parse HEAD > runs/setup/pilot-financial-full-01-commit.txt
git diff --binary > runs/setup/pilot-financial-full-01-code.patch

exec timeout --signal=INT --kill-after=60s 20m \
  .venv/bin/python -m host_lab direct-user \
  --client codex \
  --model gpt-6-sol \
  --codex-auth subscription \
  --permissions full \
  --task-profile financial \
  --max-requests 30 \
  --output runs/pilot-financial-full
