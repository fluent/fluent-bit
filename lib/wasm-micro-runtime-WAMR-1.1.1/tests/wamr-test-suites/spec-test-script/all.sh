#!/bin/bash

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

# exit if meet an exception
function DEBUG() {
    [[ -n $(env | grep "\<DEBUG\>") ]] && $@
}
DEBUG set -xevu

# Run the following command to test a single wast file:
#   ./spec-test-script/runtest.py --wast2wasm ./workspace/wabt/out/gcc/Release/wat2wasm \
#   --interpreter iwasm <wast file>

readonly SPEC_TEST_DIR="spec/test/core"
readonly WAST2WASM_CMD="./wabt/out/gcc/Release/wat2wasm"
readonly WAMRC_CMD="../../../wamr-compiler/build/wamrc"
PLATFORM=$(uname -s | tr A-Z a-z)
IWASM_CMD="../../../product-mini/platforms/${PLATFORM}/build/iwasm"

# "imports" and "linking" are only avilable when enabling multi modules
# "comments" is for runtest.py

IGNORE_LIST=(
    "comments" "inline-module" "imports" "linking" "names"
)

readonly -a MULTI_MODULE_LIST=(
    "imports" "linking"
)

SGX_IGNORE_LIST=("conversions" "f32_bitwise" "f64_bitwise")

# these cases run failed due to native stack overflow check failed
SGX_AOT_IGNORE_LIST=("call_indirect" "call" "fac" "skip-stack-guard-page")

function usage() {
    echo "Usage: all.sh [-t] [-m <x86_64|x86_32|ARMV7_VFP|THUMBV7_VFP>] [-M] [-x] [-S] [-r]"
    exit 1
}

function run_case_w_aot() {
    local test_case=$1
    echo "============> run ${test_case} with AOT"
    python2.7 runtest.py \
        --wast2wasm ${WAST2WASM_CMD} \
        --interpreter ${IWASM_CMD} \
        ${SPEC_TEST_DIR}/${test_case} \
        --aot-compiler ${WAMRC_CMD} \
        --aot --aot-target ${TARGET} \
        ${SGX_OPT} \
        ${SIMD_OPT} \
        ${REF_TYPES_OPT}
    #--no_cleanup
    if [[ $? != 0 ]]; then
        echo "============> run ${test_case} failed"
        exit 1
    fi
}

function run_case_wo_aot() {
    local test_case=$1
    echo "============> run ${test_case}"
    python2.7 runtest.py \
        --wast2wasm ${WAST2WASM_CMD} \
        --interpreter ${IWASM_CMD} \
        ${SPEC_TEST_DIR}/${test_case} \
        --aot-compiler ${WAMRC_CMD} \
        ${SGX_OPT} \
        ${SIMD_OPT} \
        ${REF_TYPES_OPT}
    #--no_cleanup
    if [[ $? != 0 ]]; then
        echo "============> run ${test_case} failed"
        exit 1
    fi
}

ENABLE_MULTI_MODULE=0
TARGET="X86_64"
SGX_OPT=""
AOT=false
SIMD_OPT=""
REF_TYPES_OPT=""
while getopts ":Mm:txSr" opt; do
    case $opt in
    t) AOT=true ;;
    m)
        TARGET=$OPTARG
        if [[ ${TARGET} == 'X86_32' ]]; then
            TARGET='i386'
        elif [[ ${TARGET} == 'X86_64' ]]; then
            TARGET='x86_64'
        elif [[ ${TARGET} == 'ARMV7_VFP' ]]; then
            TARGET='armv7'
        elif [[ ${TARGET} == 'THUMBV7_VFP' ]]; then
            TARGET='thumbv7'
        elif [[ ${TARGET} == 'RISCV64' || ${TARGET} == 'RISCV64_LP64D' ]]; then
            TARGET='riscv64_lp64d'
        elif [[ ${TARGET} == 'RISCV64_LP64' ]]; then
            TARGET='riscv64_lp64'
        else
            usage
        fi ;;
    M) ENABLE_MULTI_MODULE=1 ;;
    x) SGX_OPT="--sgx" ;;
    S) SIMD_OPT="--simd" ;;
    r) REF_TYPES_OPT="--ref_types" ;;
    *) usage ;;
    esac
done

function contain() {
    # [$1, $-1)
    local list=${@:0:${#}}
    # [$-1]
    local item=${@:${#}}
    [[ ${list} =~ (^| )${item}($| ) ]] && return 0 || return 1
}

if [[ ${SGX_OPT} ]]; then
    IWASM_CMD="../../../product-mini/platforms/linux-sgx/enclave-sample/iwasm"
    IGNORE_LIST+=("${SGX_IGNORE_LIST[@]}")
    if [[ "true" == ${AOT} ]]; then
        IGNORE_LIST+=("${SGX_AOT_IGNORE_LIST[@]}")
    fi
fi

if [[ ${TARGET} == "i386" ]]; then
    IGNORE_LIST+=("float_exprs")
fi

declare -i COUNTER=0
for wast in $(find ${SPEC_TEST_DIR} -name "*.wast" -type f | sort -n); do
    # remove a prefix spec/test/core/
    wast=${wast#${SPEC_TEST_DIR}/}
    # ${wast%.wast} will remove a surfix .wast
    if contain "${IGNORE_LIST[@]}" ${wast%.wast}; then
        echo "============> ignore ${wast}"
        continue
    else
        [[ "true" == ${AOT} ]] && run_case_w_aot ${wast} ||
            run_case_wo_aot ${wast}
        ((COUNTER += 1))
    fi
done

# for now, Multi_Module is always disabled while AOT is true
if [[ "false" == ${AOT} && 1 == ${ENABLE_MULTI_MODULE} ]]; then
    echo "============> run cases about multi module"
    for wast in ${MULTI_MODULE_LIST[@]}; do
        run_case_wo_aot ${wast}.wast
        ((COUNTER += 1))
    done
fi

echo "PASS ALL ${COUNTER} SPEC CASES"
DEBUG set -xevu
exit 0
