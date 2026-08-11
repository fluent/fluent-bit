#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${BUILD_DIR:-"$repository_root/build/agent"}

git -C "$repository_root" submodule update --init --recursive

cmake -S "$repository_root" -B "$build_dir" \
    -DCMT_TESTS=On \
    -DCMT_INSTALL_TARGETS=Off \
    "$@"

cmake --build "$build_dir"
