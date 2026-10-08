#!/bin/sh

set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${BUILD_DIR:-"$root_dir/build/agent"}
build_jobs=${BUILD_JOBS:-8}

cmake -S "$root_dir" -B "$build_dir" -DCFL_TESTS=On
cmake --build "$build_dir" -j"$build_jobs"
