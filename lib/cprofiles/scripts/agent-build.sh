#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_directory="${CPROF_BUILD_DIR:-${repository_root}/build/agent}"

cmake -S "${repository_root}" \
      -B "${build_directory}" \
      -DCPROF_TESTS=On \
      "$@"
cmake --build "${build_directory}"
