#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${CTR_BUILD_DIR:-"${repo_root}/build/agent"}

if [[ ! -f "${build_dir}/CTestTestfile.cmake" ]]; then
    echo "test build not found: run scripts/agent-build.sh first" >&2
    exit 1
fi

ctest --test-dir "${build_dir}" --output-on-failure "$@"
