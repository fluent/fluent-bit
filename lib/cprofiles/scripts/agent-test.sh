#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_directory="${CPROF_BUILD_DIR:-${repository_root}/build/agent}"

if [[ ! -f "${build_directory}/CTestTestfile.cmake" ]]; then
    "${repository_root}/scripts/agent-build.sh"
fi

ctest --test-dir "${build_directory}" --output-on-failure "$@"
