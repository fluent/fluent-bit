#!/usr/bin/env bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

rm -fr spec
# check spec test cases for GC
git clone -b main --single-branch https://github.com/WebAssembly/gc.git spec
pushd spec

git restore . && git clean -ffd .
# Reset to commit: "[test] Unify the error message."
git reset --hard 0caaadc65b5e1910512d8ae228502edcf9d60390
git apply ../../../wamr-test-suites/spec-test-script/gc_ignore_cases.patch

# Set OCaml compiler environment
eval $(opam config env)

echo "compile the reference interpreter"
pushd interpreter
make
popd
