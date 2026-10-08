#!/bin/sh

set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${BUILD_DIR:-"$root_dir/build/agent"}

if [ ! -f "$build_dir/CTestTestfile.cmake" ]; then
    echo "test build not found; run scripts/agent-build.sh first" >&2
    exit 1
fi

if [ "$#" -gt 1 ]; then
    echo "usage: scripts/agent-test.sh [ctest-regular-expression]" >&2
    exit 2
fi

if [ "$#" -eq 1 ]; then
    ctest --test-dir "$build_dir" -R "$1" --output-on-failure
else
    ctest --test-dir "$build_dir" --output-on-failure
fi
