#!/bin/bash

#
# Copyright (C) 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

THIS_DIR=$(cd $(dirname $0) && pwd -P)

readonly MODE=$1
readonly TARGET=$2
readonly TEST_FILTER=$3

readonly WORK_DIR=$PWD

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    readonly PLATFORM=windows
    readonly PYTHON_EXE=python
    # see https://github.com/pypa/virtualenv/commit/993ba1316a83b760370f5a3872b3f5ef4dd904c1
    readonly VENV_BIN_DIR=Scripts
    readonly IWASM_EXE=$(cygpath -m "${WORK_DIR}/../../../../product-mini/platforms/${PLATFORM}/build/RelWithDebInfo/iwasm.exe")
else
    readonly PLATFORM=$(uname -s | tr A-Z a-z)
    readonly VENV_BIN_DIR=bin
    readonly PYTHON_EXE=python3
    readonly IWASM_EXE="${WORK_DIR}/../../../../product-mini/platforms/${PLATFORM}/build/iwasm"
fi

readonly WAMR_DIR="${WORK_DIR}/../../../.."
readonly IWASM_CMD="${IWASM_EXE} \
    --allow-resolve=google-public-dns-a.google.com \
    --addr-pool=::1/128,127.0.0.1/32"

readonly IWASM_CMD_STRESS="${IWASM_CMD} --max-threads=12"
readonly WAMRC_CMD="${WORK_DIR}/../../../../wamr-compiler/build/wamrc"
readonly C_TESTS="tests/c/testsuite/"
readonly RUST_TESTS="tests/rust/testsuite/"
readonly ASSEMBLYSCRIPT_TESTS="tests/assemblyscript/testsuite/"
readonly THREAD_PROPOSAL_TESTS="tests/proposals/wasi-threads/"
readonly THREAD_INTERNAL_TESTS="${WAMR_DIR}/core/iwasm/libraries/lib-wasi-threads/test/"
readonly THREAD_STRESS_TESTS="${WAMR_DIR}/core/iwasm/libraries/lib-wasi-threads/stress-test/"
readonly LIB_SOCKET_TESTS="${WAMR_DIR}/core/iwasm/libraries/lib-socket/test/"

run_aot_tests () {
    local -n tests=$1
    local -n excluded_tests=$2

    for test_wasm in ${tests[@]}; do
        # get the base file name from the filepath
        local test_name=${test_wasm##*/}
        test_name=${test_name%.wasm}

        for excluded_test in "${excluded_tests[@]}"; do
            if [[ $excluded_test == "\"$test_name\"" ]]; then
                echo "Skipping test $test_name"
                continue 2
            fi
        done

        local iwasm="${IWASM_CMD}"
        if [[ $test_wasm =~ "stress" ]]; then
            iwasm="${IWASM_CMD_STRESS}"
        fi

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

        $PYTHON_EXE ${THIS_DIR}/pipe.py | ${iwasm} $test_aot
        ret=${PIPESTATUS[1]}

        echo "expected=$expected, actual=$ret"
        if [[ $expected != "" ]] && [[ $expected != $ret ]];then
            exit_code=1
        fi
    done
}

if [[ $MODE != "aot" ]];then
    $PYTHON_EXE -m venv wasi-env && source wasi-env/${VENV_BIN_DIR}/activate
    $PYTHON_EXE -m pip install -r test-runner/requirements.txt

    export TEST_RUNTIME_EXE="${IWASM_CMD}"

    TEST_OPTIONS="-r adapters/wasm-micro-runtime.py \
        -t \
            ${C_TESTS} \
            ${RUST_TESTS} \
            ${ASSEMBLYSCRIPT_TESTS} \
            ${THREAD_PROPOSAL_TESTS} \
            ${THREAD_INTERNAL_TESTS} \
            ${LIB_SOCKET_TESTS}"

    if [ -n "$TEST_FILTER" ]; then
        TEST_OPTIONS="${TEST_OPTIONS} --exclude-filter ${TEST_FILTER}"
    fi

    $PYTHON_EXE ${THIS_DIR}/pipe.py | TSAN_OPTIONS=${TSAN_OPTIONS} $PYTHON_EXE test-runner/wasi_test_runner.py $TEST_OPTIONS

    ret=${PIPESTATUS[1]}

    TEST_RUNTIME_EXE="${IWASM_CMD_STRESS}" TSAN_OPTIONS=${TSAN_OPTIONS} $PYTHON_EXE test-runner/wasi_test_runner.py \
            -r adapters/wasm-micro-runtime.py \
            -t \
                ${THREAD_STRESS_TESTS}

    if [ "${ret}" -eq 0 ]; then
        ret=${PIPESTATUS[0]}
    fi

    exit_code=${ret}

    deactivate
else
    target_option=""
    if [[ $TARGET == "X86_32" ]];then
        target_option="--target=i386"
    fi

    exit_code=0
    for testsuite in ${THREAD_STRESS_TESTS} ${THREAD_PROPOSAL_TESTS} ${THREAD_INTERNAL_TESTS}; do
        tests=$(ls ${testsuite}*.wasm)
        tests_array=($tests)

        if [ -n "$TEST_FILTER" ]; then
            readarray -t excluded_tests_array < <(jq -c \
                --slurpfile testsuite_manifest $testsuite/manifest.json \
                '.[$testsuite_manifest[0].name] // {} | keys[]' \
                $TEST_FILTER)
        else
            excluded_tests_array=()
        fi

        run_aot_tests tests_array excluded_tests_array
    done
fi

exit ${exit_code}
