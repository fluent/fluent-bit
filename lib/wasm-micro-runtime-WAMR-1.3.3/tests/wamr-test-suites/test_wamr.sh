#!/usr/bin/env bash

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

function DEBUG() {
  [[ -n $(env | grep "\<DEBUG\>") ]] && $@
}
DEBUG set -xv pipefail

function help()
{
    echo "test_wamr.sh [options]"
    echo "-c clean previous test results, not start test"
    echo "-s {suite_name} test only one suite (spec|wasi_certification|wamr_compiler)"
    echo "-m set compile target of iwasm(x86_64|x86_32|armv7|armv7_vfp|thumbv7|thumbv7_vfp|"
    echo "                               riscv32|riscv32_ilp32f|riscv32_ilp32d|riscv64|"
    echo "                               riscv64_lp64f|riscv64_lp64d|aarch64|aarch64_vfp)"
    echo "-t set compile type of iwasm(classic-interp|fast-interp|jit|aot|fast-jit|multi-tier-jit)"
    echo "-M enable multi module feature"
    echo "-p enable multi thread feature"
    echo "-S enable SIMD feature"
    echo "-G enable GC feature"
    echo "-X enable XIP feature"
    echo "-e enable exception handling"
    echo "-x test SGX"
    echo "-w enable WASI threads"
    echo "-b use the wabt binary release package instead of compiling from the source code"
    echo "-g build iwasm with debug version"
    echo "-v enable GC heap verification"
    echo "-P run the spec test parallelly"
    echo "-Q enable qemu"
    echo "-F set the firmware path used by qemu"
    echo "-C enable code coverage collect"
    echo "-j set the platform to test"
    echo "-T set sanitizer to use in tests(ubsan|tsan|asan)"
}

OPT_PARSED=""
WABT_BINARY_RELEASE="NO"
#default type
TYPE=("classic-interp" "fast-interp" "jit" "aot" "fast-jit" "multi-tier-jit")
#default target
TARGET="X86_64"
ENABLE_WASI_THREADS=0
ENABLE_MULTI_MODULE=0
ENABLE_MULTI_THREAD=0
COLLECT_CODE_COVERAGE=0
ENABLE_SIMD=0
ENABLE_GC=0
ENABLE_XIP=0
ENABLE_EH=0
ENABLE_DEBUG_VERSION=0
ENABLE_GC_HEAP_VERIFY=0
#unit test case arrary
TEST_CASE_ARR=()
SGX_OPT=""
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    PLATFORM=windows
    PYTHON_EXE=python
else
    PLATFORM=$(uname -s | tr A-Z a-z)
    PYTHON_EXE=python3
fi
PARALLELISM=0
ENABLE_QEMU=0
QEMU_FIRMWARE=""
# prod/testsuite-all branch
WASI_TESTSUITE_COMMIT="ee807fc551978490bf1c277059aabfa1e589a6c2"
TARGET_LIST=("AARCH64" "AARCH64_VFP" "ARMV7" "ARMV7_VFP" "THUMBV7" "THUMBV7_VFP" \
             "RISCV32" "RISCV32_ILP32F" "RISCV32_ILP32D" "RISCV64" "RISCV64_LP64F" "RISCV64_LP64D")

while getopts ":s:cabgvt:m:MCpSXexwPGQF:j:T:" opt
do
    OPT_PARSED="TRUE"
    case $opt in
        s)
        TEST_CASE_ARR+=($OPTARG)
        # get next suite if there are multiple vaule in -s
        eval "nxarg=\${$((OPTIND))}"
        # just get test cases, loop until the next symbol '-'
        # IN  ====>  -s spec wasi unit -t fast-classic
        # GET ====>  spec wasi unit
        while [[ "${nxarg}" != -* && ${nxarg} ]];
        do
            TEST_CASE_ARR+=(${nxarg})
            OPTIND=$((OPTIND+1))
            eval "nxarg=\${$((OPTIND))}"
        done
        echo "test following cases: ${TEST_CASE_ARR[@]}"
        ;;
        c)
        read -t 5 -p "Are you sure to delete all reports. y/n    " cmd
        if [[ $cmd == "y" && $(ls -A workspace/report) ]];then
            rm -fr workspace/report/*
            rm -fr /tmp/*.wasm /tmp/*.wast /tmp/*.aot
            echo "cleaned all reports and temp files"
        fi
        exit 0;;
        a)
        TEST_ALL_AOT_RUNTIME="all"
        echo "test all runtimes in sightglass_aot"
        ;;
        b)
        WABT_BINARY_RELEASE="YES"
        echo "use a WABT binary release instead of compiling from source code"
        ;;
        t)
        echo "set compile type of wamr " ${OPTARG}
        if [[ ${OPTARG} != "classic-interp" && ${OPTARG} != "fast-interp" \
            && ${OPTARG} != "jit" && ${OPTARG} != "aot"
            && ${OPTARG} != "fast-jit" && ${OPTARG} != "multi-tier-jit" ]]; then
            echo "*----- please varify a type of compile when using -t! -----*"
            help
            exit 1
        fi

        TYPE=(${OPTARG})
        ;;
        m)
        echo "set compile target of wamr" ${OPTARG}
        TARGET=$(echo "$OPTARG" | tr '[a-z]' '[A-Z]') # set target to uppercase if input x86_32 or x86_64 --> X86_32 and X86_64
        ;;
        w)
        echo "enable WASI threads"
        ENABLE_WASI_THREADS=1
        ;;
        M)
        echo "enable multi module feature"
        ENABLE_MULTI_MODULE=1
        ;;
        C)
        echo "enable code coverage"
        COLLECT_CODE_COVERAGE=1
        ;;
        p)
        echo "enable multi thread feature"
        ENABLE_MULTI_THREAD=1
        ;;
        S)
        echo "enable SIMD feature"
        ENABLE_SIMD=1
        ;;
        X)
        echo "enable XIP feature"
        ENABLE_XIP=1
        ;;
        e)
        echo "enable exception handling feature"
        ENABLE_EH=1
        ;;
        x)
        echo "test SGX"
        SGX_OPT="--sgx"
        ;;
        g)
        echo "enable build iwasm with debug version"
        ENABLE_DEBUG_VERSION=1
        ;;
        v)
        echo "enable GC heap verification"
        ENABLE_GC_HEAP_VERIFY=1
        ;;
        G)
        echo "enable GC feature"
        ENABLE_GC=1
        ;;
        P)
        PARALLELISM=1
        ;;
        Q)
        echo "enable QEMU"
        ENABLE_QEMU=1
        ;;
        F)
        echo "QEMU firmware" ${OPTARG}
        QEMU_FIRMWARE=${OPTARG}
        ;;
        j)
        echo "test platform " ${OPTARG}
        PLATFORM=${OPTARG}
        ;;
        T)
        echo "sanitizer is " ${OPTARG}
        WAMR_BUILD_SANITIZER=${OPTARG}
        ;;
        ?)
        help
        exit 1
        ;;
    esac
done

# Parameters are not allowed, use options instead
if [ -z "$OPT_PARSED" ];
then
    if [ ! -z "$1" ];
    then
        help
        exit 1
    fi
fi

mkdir -p workspace
cd workspace

readonly WORK_DIR=$PWD

readonly DATE=$(date +%Y-%m-%d_%H:%M:%S)
readonly REPORT_DIR=${WORK_DIR}/report/${DATE}
mkdir -p ${REPORT_DIR}

readonly WAMR_DIR=${WORK_DIR}/../../..

if [[ ${SGX_OPT} == "--sgx" ]];then
    readonly IWASM_LINUX_ROOT_DIR="${WAMR_DIR}/product-mini/platforms/linux-sgx"
    readonly IWASM_CMD="${WAMR_DIR}/product-mini/platforms/linux-sgx/enclave-sample/iwasm"
else
    readonly IWASM_LINUX_ROOT_DIR="${WAMR_DIR}/product-mini/platforms/${PLATFORM}"
    readonly IWASM_CMD="${WAMR_DIR}/product-mini/platforms/${PLATFORM}/build/iwasm"
fi

readonly WAMRC_CMD="${WAMR_DIR}/wamr-compiler/build/wamrc"

readonly CLASSIC_INTERP_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_AOT=0 \
    -DWAMR_BUILD_SPEC_TEST=1 \
    -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE}"

readonly FAST_INTERP_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=1 \
    -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_AOT=0 \
    -DWAMR_BUILD_SPEC_TEST=1 \
    -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE}"

# jit: report linking error if set COLLECT_CODE_COVERAGE,
#      now we don't collect code coverage of jit type
readonly ORC_EAGER_JIT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_AOT=1 \
    -DWAMR_BUILD_LAZY_JIT=0 \
    -DWAMR_BUILD_SPEC_TEST=1 \
    -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE}"

readonly ORC_LAZY_JIT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_AOT=1 \
    -DWAMR_BUILD_LAZY_JIT=1 \
    -DWAMR_BUILD_SPEC_TEST=1 \
    -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE}"

readonly AOT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_AOT=1 \
    -DWAMR_BUILD_SPEC_TEST=1 \
    -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE}"

readonly FAST_JIT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_AOT=0 \
    -DWAMR_BUILD_FAST_JIT=1 \
    -DWAMR_BUILD_SPEC_TEST=1 \
    -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE}"

readonly MULTI_TIER_JIT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1 \
    -DWAMR_BUILD_SPEC_TEST=1 \
    -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE}"

readonly COMPILE_FLAGS=(
        "${CLASSIC_INTERP_COMPILE_FLAGS}"
        "${FAST_INTERP_COMPILE_FLAGS}"
        "${ORC_EAGER_JIT_COMPILE_FLAGS}"
        "${ORC_LAZY_JIT_COMPILE_FLAGS}"
        "${AOT_COMPILE_FLAGS}"
        "${FAST_JIT_COMPILE_FLAGS}"
        "${MULTI_TIER_JIT_COMPILE_FLAGS}"
    )

function unit_test()
{
    echo "Now start unit tests"

    cd ${WORK_DIR}
    rm -fr unittest-build && mkdir unittest-build
    cd unittest-build

    echo "Build unit test"
    touch ${REPORT_DIR}/unit_test_report.txt
    cmake ${WORK_DIR}/../../unit -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE}
    make -j
    make test | tee -a ${REPORT_DIR}/unit_test_report.txt

    echo "Finish unit tests"
}

function sightglass_test()
{
    echo "Now start sightglass benchmark tests"

    cd ${WORK_DIR}/../sightglass/benchmarks

    # build iwasm first
    if [[ $1 == "classic-interp" || $1 == "fast-interp" ]];then
        ./test_interp.sh ${SGX_OPT}
        cp report.txt ${REPORT_DIR}/sightglass_$1_test_report.txt
    fi

    if [[ $1 == "aot" ]];then
        ./test_aot.sh ${SGX_OPT}
        cp report.txt ${REPORT_DIR}/sightglass_aot_test_report.txt
    fi

    if [[ $1 == "jit" ]];then
        [[ $TEST_ALL_AOT_RUNTIME ]] && ./test_aot.sh ${TEST_ALL_AOT_RUNTIME} ${SGX_OPT} \
                                    || ./test_aot.sh jit ${SGX_OPT}
        cp report.txt ${REPORT_DIR}/sightglass_jit_test_report.txt
    fi

    echo "Finish sightglass benchmark tests"
}

function setup_wabt()
{
    if [ ${WABT_BINARY_RELEASE} == "YES" ]; then
        echo "download a binary release and install"
        local WAT2WASM=${WORK_DIR}/wabt/out/gcc/Release/wat2wasm
        if [ ! -f ${WAT2WASM} ]; then
            case ${PLATFORM} in
                cosmopolitan)
                    ;;
                linux)
                    WABT_PLATFORM=ubuntu
                    ;;
                darwin)
                    WABT_PLATFORM=macos-12
                    ;;
                windows)
                    WABT_PLATFORM=windows
                    ;;
                *)
                    echo "wabt platform for ${PLATFORM} in unknown"
                    exit 1
                    ;;
            esac
            if [ ! -f /tmp/wabt-1.0.31-${WABT_PLATFORM}.tar.gz ]; then
                curl -L \
                    https://github.com/WebAssembly/wabt/releases/download/1.0.31/wabt-1.0.31-${WABT_PLATFORM}.tar.gz \
                    -o /tmp/wabt-1.0.31-${WABT_PLATFORM}.tar.gz
            fi

            cd /tmp \
            && tar zxf wabt-1.0.31-${WABT_PLATFORM}.tar.gz \
            && mkdir -p ${WORK_DIR}/wabt/out/gcc/Release/ \
            && install wabt-1.0.31/bin/wa* ${WORK_DIR}/wabt/out/gcc/Release/ \
            && cd -
        fi
    else
        echo "download source code and compile and install"
        if [ ! -d "wabt" ];then
            echo "wabt not exist, clone it from github"
            git clone --recursive https://github.com/WebAssembly/wabt
        fi
        echo "upate wabt"
        cd wabt
        git pull
        git reset --hard origin/main
        cd ..
        make -C wabt gcc-release -j 4
    fi
}

# TODO: with iwasm only
function spec_test()
{
    echo "Now start spec tests"
    touch ${REPORT_DIR}/spec_test_report.txt

    cd ${WORK_DIR}
    if [ ! -d "spec" ];then
        echo "spec not exist, clone it from github"
        git clone -b master --single-branch https://github.com/WebAssembly/spec
    fi

    pushd spec

    # restore and clean everything
    git reset --hard HEAD

    # update basic test cases
    echo "update spec test cases"
    git fetch origin main
    # restore from XX_ignore_cases.patch
    # resotre branch
    git checkout -B main
    # [spec] Update note on module initialization trapping (#1493)
    git reset --hard 044d0d2e77bdcbe891f7e0b9dd2ac01d56435f0b
    git apply ../../spec-test-script/ignore_cases.patch
    if [[ ${ENABLE_SIMD} == 1 ]]; then
        git apply ../../spec-test-script/simd_ignore_cases.patch
    fi
    if [[ ${ENABLE_MULTI_MODULE} == 1 && $1 == 'aot'  ]]; then
        git apply ../../spec-test-script/multi_module_aot_ignore_cases.patch
    fi

    # udpate thread cases
    if [ ${ENABLE_MULTI_THREAD} == 1 ]; then
        echo "checkout spec for threads proposal"
        if [[ -z $(git remote -v | grep "\<threads\>") ]]; then
            git remote add threads https://github.com/WebAssembly/threads
        fi

        # fetch spec for threads proposal
        git fetch threads
        # Fix error in Web embedding desc for atomic.notify (#185)
        git reset --hard 85b562cd6805947876ec5e8b975ab0127c55a0a2
        git checkout threads/main

        git apply ../../spec-test-script/thread_proposal_ignore_cases.patch
        git apply ../../spec-test-script/thread_proposal_fix_atomic_case.patch
    fi

    if [ ${ENABLE_EH} == 1 ]; then
        echo "checkout exception-handling test cases"
        popd
        if [ ! -d "exception-handling" ];then
            echo "exception-handling not exist, clone it from github"
            git clone -b master --single-branch https://github.com/WebAssembly/exception-handling 
        fi
        pushd exception-handling

        # restore and clean everything
        git reset --hard 51c721661b671bb7dc4b3a3acb9e079b49778d36
        
        if [[ ${ENABLE_MULTI_MODULE} == 0 ]]; then
            git apply ../../spec-test-script/exception_handling.patch
        fi
        
        popd
        echo $(pwd)
    fi

    # update GC cases
    if [[ ${ENABLE_GC} == 1 ]]; then
        echo "checkout spec for GC proposal"

        popd
        rm -fr spec
        # check spec test cases for GC
        git clone -b main --single-branch https://github.com/WebAssembly/gc.git spec
        pushd spec

        git restore . && git clean -ffd .
        # Sync constant expression descriptions
        git reset --hard 62beb94ddd41987517781732f17f213d8b866dcc
        git apply ../../spec-test-script/gc_ignore_cases.patch

        echo "compile the reference intepreter"
        pushd interpreter
        make opt
        popd
    fi

    popd
    echo $(pwd)

    setup_wabt

    ln -sf ${WORK_DIR}/../spec-test-script/all.py .
    ln -sf ${WORK_DIR}/../spec-test-script/runtest.py .

    local ARGS_FOR_SPEC_TEST=""

    # multi-module only enable in interp mode
    if [[ 1 == ${ENABLE_MULTI_MODULE} ]]; then
        if [[ $1 == 'classic-interp' || $1 == 'fast-interp' || $1 == 'aot' ]]; then
            ARGS_FOR_SPEC_TEST+="-M "
        fi
    fi

    if [[ 1 == ${ENABLE_EH} ]]; then
        ARGS_FOR_SPEC_TEST+="-e "
    fi

    # sgx only enable in interp mode and aot mode
    if [[ ${SGX_OPT} == "--sgx" ]];then
        if [[ $1 == 'classic-interp' || $1 == 'fast-interp' || $1 == 'aot' || $1 == 'fast-jit' ]]; then
          ARGS_FOR_SPEC_TEST+="-x "
        fi
    fi

    # simd only enable in jit mode and aot mode
    if [[ ${ENABLE_SIMD} == 1 ]]; then
        if [[ $1 == 'jit' || $1 == 'aot' ]]; then
          ARGS_FOR_SPEC_TEST+="-S "
        fi
    fi

    if [[ ${ENABLE_MULTI_THREAD} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="-p "
    fi

    if [[ ${ENABLE_XIP} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="-X "
    fi

    # set the current running target
    ARGS_FOR_SPEC_TEST+="-m ${TARGET} "

    # require warmc only in aot mode
    if [[ $1 == 'aot' ]]; then
        ARGS_FOR_SPEC_TEST+="-t "
    fi

    if [[ ${PARALLELISM} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="--parl "
    fi

    if [[ ${ENABLE_GC} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="--gc "
    fi

    if [[ ${ENABLE_QEMU} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="--qemu "
        ARGS_FOR_SPEC_TEST+="--qemu-firmware ${QEMU_FIRMWARE} "
    fi

    if [[ ${PLATFORM} == "windows" ]]; then
        ARGS_FOR_SPEC_TEST+="--no-pty "
    fi

    # set log directory
    ARGS_FOR_SPEC_TEST+="--log ${REPORT_DIR}"

    cd ${WORK_DIR}
    echo "${PYTHON_EXE} ./all.py ${ARGS_FOR_SPEC_TEST} | tee -a ${REPORT_DIR}/spec_test_report.txt"
    ${PYTHON_EXE} ./all.py ${ARGS_FOR_SPEC_TEST} | tee -a ${REPORT_DIR}/spec_test_report.txt
    if [[ ${PIPESTATUS[0]} -ne 0 ]];then
        echo -e "\nspec tests FAILED" | tee -a ${REPORT_DIR}/spec_test_report.txt
        exit 1
    fi
    cd -

    echo -e "\nFinish spec tests" | tee -a ${REPORT_DIR}/spec_test_report.txt
}

function wasi_test()
{
    echo "Now start wasi tests"
    touch ${REPORT_DIR}/wasi_test_report.txt

    cd ${WORK_DIR}/../../wasi
    [[ $1 != "aot" ]] && \
        python wasi_test.py --interpreter ${IWASM_CMD} ${SGX_OPT}\
                            | tee ${REPORT_DIR}/wasi_test_report.txt \
    || \
        python wasi_test.py --aot --aot-compiler ${WAMRC_CMD} ${SGX_OPT}\
                            --interpreter ${IWASM_CMD} \
                            | tee ${REPORT_DIR}/wasi_test_report.txt
    echo "Finish wasi tests"
}

function wamr_compiler_test()
{
    if [[ $1 != "aot" ]]; then
        echo "WAMR compiler tests only support AOT mode"
        exit 1
    fi

    echo  "Now start WAMR compiler tests"
    setup_wabt
    cd ${WORK_DIR}/../wamr-compiler-test-script
    ./run_wamr_compiler_tests.sh ${WORK_DIR}/wabt/out/gcc/Release/wat2wasm $WAMRC_CMD $IWASM_CMD \
        | tee -a ${REPORT_DIR}/wamr_compiler_test_report.txt

    ret=${PIPESTATUS[0]}

    if [[ ${ret} -ne 0 ]];then
        echo -e "\nWAMR compiler tests FAILED" | tee -a ${REPORT_DIR}/wamr_compiler_test_report.txt
        exit 1
    fi
    echo -e "\nFinish WAMR compiler tests" | tee -a ${REPORT_DIR}/wamr_compiler_test_report.txt
}

function wasi_certification_test()
{
    echo  "Now start wasi certification tests"

    cd ${WORK_DIR}
    if [ ! -d "wasi-testsuite" ]; then
        echo "wasi-testsuite not exist, clone it from github"
        git clone -b prod/testsuite-all \
            --single-branch https://github.com/WebAssembly/wasi-testsuite.git
    fi
    cd wasi-testsuite
    git reset --hard ${WASI_TESTSUITE_COMMIT}

    TSAN_OPTIONS=${TSAN_OPTIONS} bash ../../wasi-test-script/run_wasi_tests.sh $1 $TARGET $WASI_TEST_FILTER \
        | tee -a ${REPORT_DIR}/wasi_test_report.txt
    ret=${PIPESTATUS[0]}

    if [[ ${ret} -ne 0 ]];then
        echo -e "\nwasi tests FAILED" | tee -a ${REPORT_DIR}/wasi_test_report.txt
        exit 1
    fi
    echo -e "\nFinish wasi tests" | tee -a ${REPORT_DIR}/wasi_test_report.txt
}

function polybench_test()
{
    echo "Now start polybench tests"

    cd ${WORK_DIR}/../polybench
    if [[ $1 == "aot" || $1 == "jit" ]];then
        ./build.sh AOT ${SGX_OPT}
        ./test_aot.sh $1 ${SGX_OPT}
    else
        ./build.sh
        ./test_interp.sh ${SGX_OPT}
    fi
    cp report.txt ${REPORT_DIR}/polybench_$1_test_report.txt

    echo "Finish polybench tests"
}

function libsodium_test()
{
    echo "Now start libsodium tests"

    cd ${WORK_DIR}/../libsodium
    if [[ $1 == "aot" || $1 == "jit" ]];then
        ./build.sh ${SGX_OPT}
        ./test_aot.sh $1 ${SGX_OPT}
    else
        ./test_interp.sh ${SGX_OPT}
    fi
    cp report.txt ${REPORT_DIR}/libsodium_$1_test_report.txt

    echo "Finish libsodium tests"
}

function malformed_test()
{
    # build iwasm firstly
    cd ${WORK_DIR}/../../malformed
    ./malformed_test.py --run ${IWASM_CMD} | tee ${REPORT_DIR}/malfomed_$1_test_report.txt
}

function collect_standalone()
{
    if [[ ${COLLECT_CODE_COVERAGE} == 1 ]]; then
        pushd ${WORK_DIR} > /dev/null 2>&1

        CODE_COV_FILE=""
        if [[ -z "${CODE_COV_FILE}" ]]; then
            CODE_COV_FILE="${WORK_DIR}/wamr.lcov"
        else
            CODE_COV_FILE="${CODE_COV_FILE}"
        fi

        STANDALONE_DIR=${WORK_DIR}/../../standalone

        echo "Collect code coverage of standalone dump-call-stack"
        ./collect_coverage.sh "${CODE_COV_FILE}" "${STANDALONE_DIR}/dump-call-stack/build"
        echo "Collect code coverage of standalone dump-mem-profiling"
        ./collect_coverage.sh "${CODE_COV_FILE}" "${STANDALONE_DIR}/dump-mem-profiling/build"
        echo "Collect code coverage of standalone dump-perf-profiling"
        ./collect_coverage.sh "${CODE_COV_FILE}" "${STANDALONE_DIR}/dump-perf-profiling/build"
        if [[ $1 == "aot" ]]; then
            echo "Collect code coverage of standalone pad-test"
            ./collect_coverage.sh "${CODE_COV_FILE}" "${STANDALONE_DIR}/pad-test/build"
        fi
        echo "Collect code coverage of standalone test-invoke-native"
        ./collect_coverage.sh "${CODE_COV_FILE}" "${STANDALONE_DIR}/test-invoke-native/build"
        echo "Collect code coverage of standalone test-running-modes"
        ./collect_coverage.sh "${CODE_COV_FILE}" "${STANDALONE_DIR}/test-running-modes/build"
        echo "Collect code coverage of standalone test-running-modes/c-embed"
        ./collect_coverage.sh "${CODE_COV_FILE}" "${STANDALONE_DIR}/test-running-modes/c-embed/build"
        echo "Collect code coverage of standalone test-ts2"
        ./collect_coverage.sh "${CODE_COV_FILE}" "${STANDALONE_DIR}/test-ts2/build"

        popd > /dev/null 2>&1
    fi
}

function standalone_test()
{
    if [[ ${COLLECT_CODE_COVERAGE} == 1 ]]; then
        export COLLECT_CODE_COVERAGE=1
    fi

    cd ${WORK_DIR}/../../standalone

    args="--$1"

    [[ ${SGX_OPT} == "--sgx" ]] && args="$args --sgx" || args="$args --no-sgx"

    [[ ${ENABLE_MULTI_THREAD} == 1 ]] && args="$args --thread" || args="$args --no-thread"

    [[ ${ENABLE_SIMD} == 1 ]] && args="$args --simd" || args="$args --no-simd"

    args="$args ${TARGET}"

    ./standalone.sh $args | tee ${REPORT_DIR}/standalone_$1_test_report.txt

    collect_standalone "$1"
}

function build_iwasm_with_cfg()
{
    echo "Build iwasm with compile flags " $* " for spec test" \
        | tee -a ${REPORT_DIR}/spec_test_report.txt

    if [[ ${SGX_OPT} == "--sgx" ]];then
        cd ${WAMR_DIR}/product-mini/platforms/linux-sgx \
        && if [ -d build ]; then rm -rf build/*; else mkdir build; fi \
        && cd build \
        && cmake $* .. \
        && make -j 4
        cd ${WAMR_DIR}/product-mini/platforms/linux-sgx/enclave-sample \
        && make clean \
        && make SPEC_TEST=1
    else
        cd ${WAMR_DIR}/product-mini/platforms/${PLATFORM} \
        && if [ -d build ]; then rm -rf build/*; else mkdir build; fi \
        && cd build \
        && cmake $* .. \
        && cmake --build . -j 4 --config RelWithDebInfo --target iwasm
    fi

    if [ "$?" != 0 ];then
        echo -e "build iwasm failed"
        exit 1
    fi

    if [[ ${PLATFORM} == "cosmopolitan" ]]; then
        # convert from APE to ELF so it can be ran easier
        # HACK: link to linux so tests work when platform is detected by uname
        cp iwasm.com iwasm \
        && ./iwasm --assimilate \
        && rm -rf ../../linux/build \
        && mkdir ../../linux/build \
        && ln -s ../../cosmopolitan/build/iwasm ../../linux/build/iwasm
        if [ "$?" != 0 ];then
            echo -e "build iwasm failed (cosmopolitan)"
            exit 1
        fi
    fi
}

function build_wamrc()
{
    if [[ "${TARGET_LIST[*]}" =~ "${TARGET}" ]]; then
        echo "suppose wamrc is already built"
        return
    fi

    echo "Build wamrc for spec test under aot compile type"
    cd ${WAMR_DIR}/wamr-compiler \
        && ./build_llvm.sh \
        && if [ -d build ]; then rm -r build/*; else mkdir build; fi \
        && cd build \
        && cmake .. -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE} \
        && make -j 4
}

### Need to add a test suite?
### The function name should be ${suite_name}_test
# function xxx_test()
# {
#
# }

function collect_coverage()
{
    if [[ ${COLLECT_CODE_COVERAGE} == 1 ]]; then
        ln -sf ${WORK_DIR}/../spec-test-script/collect_coverage.sh ${WORK_DIR}

        CODE_COV_FILE=""
        if [[ -z "${CODE_COV_FILE}" ]]; then
            CODE_COV_FILE="${WORK_DIR}/wamr.lcov"
        else
            CODE_COV_FILE="${CODE_COV_FILE}"
        fi

        pushd ${WORK_DIR} > /dev/null 2>&1
        echo "Collect code coverage of iwasm"
        ./collect_coverage.sh ${CODE_COV_FILE} ${IWASM_LINUX_ROOT_DIR}/build
        if [[ $1 == "llvm-aot" ]]; then
            echo "Collect code coverage of wamrc"
            ./collect_coverage.sh ${CODE_COV_FILE} ${WAMR_DIR}/wamr-compiler/build
        fi
        for suite in "${TEST_CASE_ARR[@]}"; do
            if [[ ${suite} = "unit" ]]; then
                echo "Collect code coverage of unit test"
                ./collect_coverage.sh ${CODE_COV_FILE} ${WORK_DIR}/unittest-build
                break
            fi
        done
        popd > /dev/null 2>&1
    else
        echo "code coverage isn't collected"
    fi
}

function trigger()
{
    local EXTRA_COMPILE_FLAGS=""
    # default enabled features
    EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_BULK_MEMORY=1"

    if [[ ${ENABLE_MULTI_MODULE} == 1 ]];then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_MULTI_MODULE=1"
    else
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_MULTI_MODULE=0"
    fi

    if [[ ${ENABLE_MULTI_THREAD} == 1 ]];then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_LIB_PTHREAD=1"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_REF_TYPES=0"
    else
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_REF_TYPES=1"
    fi

    if [[ ${ENABLE_SIMD} == 1 ]]; then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SIMD=1"
    else
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SIMD=0"
    fi

    if [[ ${ENABLE_GC} == 1 ]]; then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_GC=1"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_REF_TYPES=1"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_BULK_MEMORY=1"
    fi

    if [[ ${ENABLE_DEBUG_VERSION} == 1 ]]; then
        EXTRA_COMPILE_FLAGS+=" -DCMAKE_BUILD_TYPE=Debug"
    fi

    if [[ ${ENABLE_GC_HEAP_VERIFY} == 1 ]]; then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_GC_HEAP_VERIFY=1"
    fi

    if [[ ${ENABLE_WASI_THREADS} == 1 ]]; then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_LIB_WASI_THREADS=1"
    fi

    if [[ ${ENABLE_EH} == 1 ]]; then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_EXCE_HANDLING=1"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_TAIL_CALL=1"
    fi
    echo "SANITIZER IS" $WAMR_BUILD_SANITIZER

    if [[ "$WAMR_BUILD_SANITIZER" == "ubsan" ]]; then
        echo "Setting run with ubsan"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SANITIZER=ubsan"
    fi

    if [[ "$WAMR_BUILD_SANITIZER" == "asan" ]]; then
        echo "Setting run with asan"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SANITIZER=asan"
    fi

    if [[ "$WAMR_BUILD_SANITIZER" == "tsan" ]]; then
        echo "Setting run with tsan"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SANITIZER=tsan"
    fi

    # Make sure we're using the builtin WASI libc implementation
    # if we're running the wasi certification tests.
    if [[ $TEST_CASE_ARR ]]; then
        for test in "${TEST_CASE_ARR[@]}"; do
            if [[ "$test" == "wasi_certification" ]]; then
                EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_LIBC_UVWASI=0 -DWAMR_BUILD_LIBC_WASI=1"
                break
            fi
        done
    fi

    for t in "${TYPE[@]}"; do
        case $t in
            "classic-interp")
                if [[ ${ENABLE_SIMD} == 1 ]]; then
                    echo "does not support SIMD in interp mode, bypass"
                    continue
                fi

                echo "work in classic-interp mode"
                # classic-interp
                BUILD_FLAGS="$CLASSIC_INTERP_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                if [[ ${ENABLE_QEMU} == 0 ]]; then
                    build_iwasm_with_cfg $BUILD_FLAGS
                fi
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" classic-interp
                done
                collect_coverage classic-interp
            ;;

            "fast-interp")
                if [[ ${ENABLE_SIMD} == 1 ]]; then
                    echo "does not support SIMD in interp mode, bypass"
                    continue
                fi

                echo "work in fast-interp mode"
                # fast-interp
                BUILD_FLAGS="$FAST_INTERP_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                if [[ ${ENABLE_QEMU} == 0 ]]; then
                    build_iwasm_with_cfg $BUILD_FLAGS
                fi
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" fast-interp
                done
                collect_coverage fast-interp
            ;;

            "jit")
                if [[ ${TARGET} == "X86_32" ]]; then
                    echo "does not support an X86_32 target in JIT mode, bypass"
                    continue
                fi

                echo "work in orc jit eager compilation mode"
                BUILD_FLAGS="$ORC_EAGER_JIT_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                build_iwasm_with_cfg $BUILD_FLAGS
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" jit
                done
                collect_coverage llvm-jit

                echo "work in orc jit lazy compilation mode"
                BUILD_FLAGS="$ORC_LAZY_JIT_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                build_iwasm_with_cfg $BUILD_FLAGS
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" jit
                done
                collect_coverage llvm-jit
            ;;

            "aot")
                echo "work in aot mode"
                # aot
                BUILD_FLAGS="$AOT_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                if [[ ${ENABLE_QEMU} == 0 ]]; then
                    build_iwasm_with_cfg $BUILD_FLAGS
                fi
                build_wamrc
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" aot
                done
                collect_coverage llvm-aot
            ;;

            "fast-jit")
                echo "work in fast-jit mode"
                # fast-jit
                BUILD_FLAGS="$FAST_JIT_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                build_iwasm_with_cfg $BUILD_FLAGS
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" fast-jit
                done
                collect_coverage fast-jit
            ;;

            "multi-tier-jit")
                echo "work in multi-tier-jit mode"
                # multi-tier-jit
                BUILD_FLAGS="$MULTI_TIER_JIT_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                build_iwasm_with_cfg $BUILD_FLAGS
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" multi-tier-jit
                done
                collect_coverage multi-tier-jit
            ;;

            *)
            echo "unexpected mode, do nothing"
            ;;
        esac
    done
}

# if collect code coverage, ignore -s, test all test cases.
if [[ $TEST_CASE_ARR ]];then
    trigger || (echo "TEST FAILED"; exit 1)
else
    # test all suite, ignore polybench and libsodium because of long time cost
    TEST_CASE_ARR=("spec")
    : '
    if [[ $COLLECT_CODE_COVERAGE == 1 ]];then
        # add polybench if collecting code coverage data
        TEST_CASE_ARR+=("polybench")
        # add libsodium if needed, which takes long time to run
        TEST_CASE_ARR+=("libsodium")
    fi
    '
    trigger || (echo "TEST FAILED"; exit 1)
    # Add more suites here
fi

echo -e "Test finish. Reports are under ${REPORT_DIR}"
DEBUG set +xv pipefail
echo "TEST SUCCESSFUL"
exit 0
