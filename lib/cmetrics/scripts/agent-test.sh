#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${BUILD_DIR:-"$repository_root/build/agent"}

if [ ! -f "$build_dir/CTestTestfile.cmake" ]; then
    echo "error: $build_dir is not configured for tests; run scripts/agent-build.sh first" >&2
    exit 1
fi

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [ctest-regular-expression]" >&2
    exit 2
fi

if [ "$#" -eq 1 ]; then
    ctest --test-dir "$build_dir" --output-on-failure -R "$1"
else
    ctest --test-dir "$build_dir" --output-on-failure
fi
