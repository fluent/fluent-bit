#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${CTR_BUILD_DIR:-"${repo_root}/build/agent"}

cmake -S "${repo_root}" -B "${build_dir}" -DCTR_DEV=On -DCTR_TESTS=On
cmake --build "${build_dir}" --parallel
