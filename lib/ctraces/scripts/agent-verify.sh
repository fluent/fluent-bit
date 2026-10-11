#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

bash -n \
    "${repo_root}/scripts/agent-build.sh" \
    "${repo_root}/scripts/agent-test.sh" \
    "${repo_root}/scripts/agent-verify.sh"

"${repo_root}/scripts/agent-build.sh"
"${repo_root}/scripts/agent-test.sh"
