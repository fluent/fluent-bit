#!/bin/bash

#
# Copyright (C) 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

readonly MODE=$1
readonly TARGET=$2

readonly WORK_DIR=$PWD
readonly PLATFORM=$(uname -s | tr A-Z a-z)
readonly WAMR_DIR="${WORK_DIR}/../../../.."
readonly IWASM_CMD="${WORK_DIR}/../../../../product-mini/platforms/${PLATFORM}/build/iwasm"
readonly WAMRC_CMD="${WORK_DIR}/../../../../wamr-compiler/build/wamrc"
readonly C_TESTS="tests/c/testsuite/"
readonly ASSEMBLYSCRIPT_TESTS="tests/assemblyscript/testsuite/"
readonly THREAD_PROPOSAL_TESTS="tests/proposals/wasi-threads/"
readonly THREAD_INTERNAL_TESTS="${WAMR_DIR}/core/iwasm/libraries/lib-wasi-threads/test/"
readonly LIB_SOCKET_TESTS="${WAMR_DIR}/core/iwasm/libraries/lib-socket/test/"

run_aot_tests () {
    local tests=("$@")
    for test_wasm in ${tests[@]}; do
        test_aot="${test_wasm%.wasm}.aot"
        test_json="${test_wasm%.wasm}.json"

        if [ -f ${test_wasm} ]; then
            expected=$(jq .exit_code ${test_json})
        fi

        echo "Compiling $test_wasm to $test_aot"
        ${WAMRC_CMD} --enable-multi-thread ${target_option} \
            -o ${test_aot} ${test_wasm}

        echo "Running $test_aot"
        expected=0
        if [ -f ${test_json} ]; then 
            expected=$(jq .exit_code ${test_json})
        fi
        
        ${IWASM_CMD} $test_aot
        
        ret=${PIPESTATUS[0]}

        echo "expected=$expected, actual=$ret"
        if [[ $expected != "" ]] && [[ $expected != $ret ]];then
            exit_code=1
        fi
    done
} 

if [[ $MODE != "aot" ]];then
    python3 -m venv wasi-env && source wasi-env/bin/activate
    python3 -m pip install -r test-runner/requirements.txt
    TEST_RUNTIME_EXE="${IWASM_CMD}" python3 test-runner/wasi_test_runner.py \
                -r adapters/wasm-micro-runtime.py \
                -t \
                    ${C_TESTS} \
                    ${ASSEMBLYSCRIPT_TESTS} \
                    ${THREAD_PROPOSAL_TESTS} \
                    ${THREAD_INTERNAL_TESTS} \
                    ${LIB_SOCKET_TESTS} \
    exit_code=${PIPESTATUS[0]}
    deactivate
else
    target_option=""
    if [[ $TARGET == "X86_32" ]];then
        target_option="--target=i386"
    fi

    exit_code=0
    for testsuite in ${THREAD_PROPOSAL_TESTS} ${THREAD_INTERNAL_TESTS}; do
        tests=$(ls ${testsuite}*.wasm)
        tests_array=($tests)
        run_aot_tests "${tests_array[@]}"
    done
fi

exit ${exit_code}