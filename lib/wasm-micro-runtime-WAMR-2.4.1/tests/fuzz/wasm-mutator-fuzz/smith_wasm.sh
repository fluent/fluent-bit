#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#


# 1.check parameter
if [ ! $1 ]; then
	echo "Parameter is empty, please enter parameter !"
    exit
fi
EXPECTED_NUM=$1

# 2.check dir
buildPath="./build"
corpusPath="$buildPath/CORPUS_DIR"
rm -rf "${corpusPath}"
mkdir -p "${corpusPath}"

# 3.change dir
cd "${corpusPath}"

# 4.generate *.wasm file
echo "Generating $EXPECTED_NUM Wasm files for each kind as required"

# Generate wasm files with different features
# Try on and on until the generated wasm file exists
function try_generate_wasm()
{
    SMITH_OPTIONS=$1
    GENERATED_WASM_NAME=$2

    local try_i=0
    until [[ -f $GENERATED_WASM_NAME ]]; do
        # Larger input seeds tend to generate larger WebAssembly modules. (256KB)
        head -c 262144 /dev/urandom | wasm-tools smith $SMITH_OPTIONS -o $GENERATED_WASM_NAME  >/dev/null 2>&1
        try_i=$((try_i+1))
    done

    printf -- "-- output ${GENERATED_WASM_NAME} in %d retries\n" $try_i
}

WASM_SHAPE=" --ensure-termination \
--export-everything true \
--fuel 7 \
--generate-custom-sections true \
--min-funcs 5 \
--max-instructions 1024 \
--min-globals 10"

WASM_MVP_FEATURES=" --bulk-memory-enabled true \
--multi-value-enabled true \
--reference-types-enabled true \
--simd-enabled true \
--tail-call-enabled true"

for i in $(seq 1 $EXPECTED_NUM)
do
    # mvp
    try_generate_wasm "${WASM_SHAPE} ${WASM_MVP_FEATURES}" test_mvp_$i.wasm

    # other proposals
    try_generate_wasm "${WASM_SHAPE} --exceptions-enabled true" test_exception_$i.wasm
    try_generate_wasm "${WASM_SHAPE} --gc-enabled true" test_gc_$i.wasm
    try_generate_wasm "${WASM_SHAPE} --memory64-enabled true" test_memory64_$i.wasm
    try_generate_wasm "${WASM_SHAPE} --threads-enabled true" test_threads_$i.wasm
done

printf "Done\n"
