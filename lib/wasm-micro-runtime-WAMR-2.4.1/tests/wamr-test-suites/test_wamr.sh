#!/usr/bin/env bash

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

function DEBUG() {
  [[ -n $(env | grep "\<DEBUG\>") ]] && $@
}
DEBUG set -exv pipefail

function help()
{
    echo "test_wamr.sh [options]"
    echo "-c clean previous test results, not start test"
    echo "-s {suite_name} test only one suite (spec|standalone|malformed|wasi_certification|"
    echo "                                     unit|wamr_compiler)"
    echo "-m set compile target of iwasm(x86_64|x86_32|armv7|armv7_vfp|thumbv7|thumbv7_vfp|"
    echo "                               riscv32|riscv32_ilp32f|riscv32_ilp32d|riscv64|"
    echo "                               riscv64_lp64f|riscv64_lp64d|aarch64|aarch64_vfp)"
    echo "-t set compile type of iwasm(classic-interp|fast-interp|jit|aot|fast-jit|multi-tier-jit)"
    echo "-M enable multi module feature"
    echo "-p enable multi thread feature"
    echo "-S enable SIMD feature"
    echo "-G enable GC feature"
    echo "-W enable memory64 feature"
    echo "-E enable multi memory feature"
    echo "-X enable XIP feature"
    echo "-e enable exception handling"
    echo "-x test SGX"
    echo "-w enable WASI threads"
    echo "-a test all runtimes in sightglass suite"
    echo "-b use the wabt binary release package instead of compiling from the source code"
    echo "-g build iwasm with debug version"
    echo "-v enable GC heap verification"
    echo "-P run the spec test parallelly"
    echo "-Q enable qemu"
    echo "-F set the firmware path used by qemu"
    echo "-C enable code coverage collect"
    echo "-j set the platform to test"
    echo "-T set sanitizer to use in tests(ubsan|tsan|asan|posan)"
    echo "-A use the specified wamrc command instead of building it"
    echo "-N enable extended const expression feature"
    echo "-r [requirement name] [N [N ...]] specify a requirement name followed by one or more"
    echo "                                  subrequirement IDs, if no subrequirement is specificed,"
    echo "                                  it will run all subrequirements. When this optin is used,"
    echo "                                  only run requirement tests"
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
ENABLE_EXTENDED_CONST_EXPR=0
ENABLE_MEMORY64=0
ENABLE_MULTI_MEMORY=0
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
WAMRC_CMD=""
# prod/testsuite-all branch
WASI_TESTSUITE_COMMIT="ee807fc551978490bf1c277059aabfa1e589a6c2"
TARGET_LIST=("AARCH64" "AARCH64_VFP" "ARMV7" "ARMV7_VFP" "THUMBV7" "THUMBV7_VFP" \
             "RISCV32" "RISCV32_ILP32F" "RISCV32_ILP32D" "RISCV64" "RISCV64_LP64F" "RISCV64_LP64D" "XTENSA")
REQUIREMENT_NAME=""
# Initialize an empty array for subrequirement IDs
SUBREQUIREMENT_IDS=()

while getopts ":s:cabgvt:m:MCpSXexwWEPGQF:j:T:r:A:N" opt
do
    OPT_PARSED="TRUE"
    case $opt in
        s)
        TEST_CASE_ARR+=($OPTARG)
        # get next suite if there are multiple vaule in -s
        eval "nxarg=\${$((OPTIND))}"
        # just get test cases, loop until the next symbol '-'
        # IN  ====>  -s spec unit -t fast-classic
        # GET ====>  spec unit
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
        W)
        echo "enable wasm64(memory64) feature"
        ENABLE_MEMORY64=1
        ;;
        E)
        echo "enable multi memory feature(auto enable multi module)"
        ENABLE_MULTI_MEMORY=1
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
        N)
        echo "enable extended const expression feature"
        ENABLE_EXTENDED_CONST_EXPR=1
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
        r)
        REQUIREMENT_NAME=$OPTARG
        # get next arg if there are multiple values after -r
        eval "nxarg=\${$((OPTIND))}"
        # loop until the next symbol '-' or the end of arguments
        while [[ "${nxarg}" =~ ^[0-9]+$ ]]; do
            SUBREQUIREMENT_IDS+=("$nxarg")
            OPTIND=$((OPTIND+1))
            eval "nxarg=\${$((OPTIND))}"
        done
        echo "Only Test requirement name: ${REQUIREMENT_NAME}"
        [[ ${#SUBREQUIREMENT_IDS[@]} -ne 0 ]] && echo "Choose subrequirement IDs: ${SUBREQUIREMENT_IDS[@]}"
        ;;
        A)
        echo "Using wamrc ${OPTARG}"
        WAMRC_CMD=${OPTARG}
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
readonly REQUIREMENT_SCRIPT_DIR=${WORK_DIR}/../requirement-engineering-test-script

if [[ ${SGX_OPT} == "--sgx" ]];then
    readonly IWASM_LINUX_ROOT_DIR="${WAMR_DIR}/product-mini/platforms/linux-sgx"
    readonly IWASM_CMD="${WAMR_DIR}/product-mini/platforms/linux-sgx/enclave-sample/iwasm"
else
    readonly IWASM_LINUX_ROOT_DIR="${WAMR_DIR}/product-mini/platforms/${PLATFORM}"
    readonly IWASM_CMD="${WAMR_DIR}/product-mini/platforms/${PLATFORM}/build/iwasm"
fi

readonly WAMRC_CMD_DEFAULT="${WAMR_DIR}/wamr-compiler/build/wamrc"

readonly CLASSIC_INTERP_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_AOT=0"

readonly FAST_INTERP_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=1 \
    -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_AOT=0"

# jit: report linking error if set COLLECT_CODE_COVERAGE,
#      now we don't collect code coverage of jit type
readonly ORC_EAGER_JIT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_AOT=1 \
    -DWAMR_BUILD_LAZY_JIT=0"

readonly ORC_LAZY_JIT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_AOT=1 \
    -DWAMR_BUILD_LAZY_JIT=1"

readonly AOT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_AOT=1"

readonly FAST_JIT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_AOT=0 \
    -DWAMR_BUILD_FAST_JIT=1"

readonly MULTI_TIER_JIT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1"

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
    # please sync with .github/actions/install-wasi-sdk-wabt/action.yml
    case ${PLATFORM} in
        cosmopolitan)
            ;;
        linux)
            WABT_URL=https://github.com/WebAssembly/wabt/releases/download/1.0.37/wabt-1.0.37-ubuntu-20.04.tar.gz
            WABT_VERSION=1.0.37
            ;;
        darwin)
            WABT_URL=https://github.com/WebAssembly/wabt/releases/download/1.0.36/wabt-1.0.36-macos-12.tar.gz
            WABT_VERSION=1.0.36
            ;;
        windows)
            WABT_URL=https://github.com/WebAssembly/wabt/releases/download/1.0.37/wabt-1.0.37-windows.tar.gz
            WABT_VERSION=1.0.37
            ;;
        *)
            echo "wabt platform for ${PLATFORM} in unknown"
            exit 1
            ;;
    esac

    if [ ${WABT_BINARY_RELEASE} == "YES" ]; then
        echo "download a binary release and install"
        local WAT2WASM=${WORK_DIR}/wabt/out/gcc/Release/wat2wasm
        if [ ! -f ${WAT2WASM} ]; then
            pushd /tmp
            wget -O wabt-tar.gz --progress=dot:giga ${WABT_URL}
            tar xf wabt-tar.gz
            popd

            mkdir -p ${WORK_DIR}/wabt/out/gcc/Release/
            cp /tmp/wabt-${WABT_VERSION}/bin/* ${WORK_DIR}/wabt/out/gcc/Release/
        fi
    else
        echo "download source code and compile and install"
        if [ ! -d "wabt" ];then
            echo "wabt not exist, clone it from github"
            git clone --recursive https://github.com/WebAssembly/wabt
        fi
        echo "upate wabt"
        cd wabt \
        && git fetch origin \
        && git reset --hard origin/main \
        && git checkout tags/${WABT_VERSION} -B ${WABT_VERSION} \
        && git submodule update --init \
        && cd .. \
        && make -C wabt gcc-release -j 4 || exit 1
    fi
}

function compile_reference_interpreter()
{
    echo "compile the reference interpreter"
    pushd interpreter
    make
    if [ $? -ne 0 ]
    then
        echo "Failed to compile the reference interpreter"
        exit 1
    fi
    popd
}

# TODO: with iwasm only
function spec_test()
{
    local RUNNING_MODE="$1"

    echo "Now start spec tests"
    touch ${REPORT_DIR}/spec_test_report.txt

    cd ${WORK_DIR}

    # update basic test cases
    echo "downloading spec test cases..."

    rm -rf spec
    if [ ${ENABLE_MULTI_THREAD} == 1 ]; then
        echo "checkout spec from threads proposal"

        # check spec test cases for threads
        git clone -b main --single-branch https://github.com/WebAssembly/threads.git spec
        pushd spec

        # May 31, 2012 [interpreter] implement atomic.wait and atomic.notify (#194)
        git reset --hard 09f2831349bf409187abb6f7868482a8079f2264
        git apply --ignore-whitespace ../../spec-test-script/thread_proposal_ignore_cases.patch || exit 1
        git apply --ignore-whitespace ../../spec-test-script/thread_proposal_fix_atomic_case.patch || exit 1
        git apply --ignore-whitespace ../../spec-test-script/thread_proposal_remove_memory64_flag_case.patch
    elif [ ${ENABLE_EH} == 1 ]; then
        echo "checkout exception-handling test cases"

        git clone -b main --single-branch https://github.com/WebAssembly/exception-handling spec
        pushd spec

        # Jun 6, 2023 Merge branch 'upstream' into merge-upstream
        git reset --hard 51c721661b671bb7dc4b3a3acb9e079b49778d36
        git apply --ignore-whitespace ../../spec-test-script/exception_handling.patch || exit 1
    elif [[ ${ENABLE_GC} == 1 ]]; then
        echo "checkout spec for GC proposal"

        # check spec test cases for GC
        git clone -b main --single-branch https://github.com/WebAssembly/gc.git spec
        pushd spec

        #  Dec 9, 2024. Merge branch 'funcref'
        git reset --hard 756060f5816c7e2159f4817fbdee76cf52f9c923
        git apply --ignore-whitespace ../../spec-test-script/gc_ignore_cases.patch || exit 1

        if [[ ${ENABLE_QEMU} == 1 ]]; then
            # Decrease the recursive count for tail call cases as nuttx qemu's
            # native stack size is much smaller
            git apply --ignore-whitespace ../../spec-test-script/gc_nuttx_tail_call.patch || exit 1
        fi

        # As of version 1.0.36, wabt is still unable to correctly handle the GC proposal.
        #
        # $ $ /opt/wabt-1.0.36/bin/wast2json --enable-all ../spec/test/core/br_if.wast
        #
        # ../spec/test/core/br_if.wast:670:26: error: unexpected token "null", expected a numeric index or a name (e.g. 12 or $foo).
        #     (func $f (param (ref null $t)) (result funcref) (local.get 0))
        #
        compile_reference_interpreter
    elif [[ ${ENABLE_EXTENDED_CONST_EXPR} == 1 ]]; then
        echo "checkout spec for extended const expression proposal"

        git clone -b main --single-branch https://github.com/WebAssembly/extended-const.git spec
        pushd spec

        # Jan 14, 2025. README.md: Add note that this proposal is done (#20)
        git reset --hard 8d4f6aa2b00a8e7c0174410028625c6a176db8a1
        # ignore import table cases
        git apply --ignore-whitespace ../../spec-test-script/extended_const.patch || exit 1
        
    elif [[ ${ENABLE_MEMORY64} == 1 ]]; then
        echo "checkout spec for memory64 proposal"

        # check spec test cases for memory64
        git clone -b main --single-branch https://github.com/WebAssembly/memory64.git spec
        pushd spec

        # Reset to commit: "Merge remote-tracking branch 'upstream/main' into merge2"
        git reset --hard 48e69f394869c55b7bbe14ac963c09f4605490b6
        git checkout 044d0d2e77bdcbe891f7e0b9dd2ac01d56435f0b -- test/core/elem.wast test/core/data.wast
        # Patch table64 extension
        git checkout 940398cd4823522a9b36bec4984be4b153dedb81 -- test/core/call_indirect.wast test/core/table.wast test/core/table_copy.wast test/core/table_copy_mixed.wast test/core/table_fill.wast test/core/table_get.wast test/core/table_grow.wast test/core/table_init.wast test/core/table_set.wast test/core/table_size.wast
        git apply --ignore-whitespace ../../spec-test-script/memory64_ignore_cases.patch || exit 1
    elif [[ ${ENABLE_MULTI_MEMORY} == 1 ]]; then
        echo "checkout spec for multi memory proposal"

        # check spec test cases for multi memory
        git clone -b main --single-branch https://github.com/WebAssembly/multi-memory.git spec
        pushd spec

        # Reset to commit: "Merge pull request #48 from backes/specify-memcpy-immediate-order"
        git reset --hard fbc99efd7a788db300aec3dd62a14577ec404f1b
        git checkout 044d0d2e77bdcbe891f7e0b9dd2ac01d56435f0b -- test/core/elem.wast
        git apply --ignore-whitespace ../../spec-test-script/multi_memory_ignore_cases.patch || exit 1
        if [[ ${RUNNING_MODE} == "aot" ]]; then
            git apply --ignore-whitespace ../../spec-test-script/multi_module_aot_ignore_cases.patch || exit 1
        fi
    else
        echo "checkout spec for default proposal"

        git clone -b main --single-branch https://github.com/WebAssembly/spec
        pushd spec

        # Dec 20, 2024. Use WPT version of test harness for HTML core test conversion (#1859)
        git reset --hard f3a0e06235d2d84bb0f3b5014da4370613886965
        git apply --ignore-whitespace ../../spec-test-script/ignore_cases.patch || exit 1
        if [[ ${ENABLE_SIMD} == 1 ]]; then
            git apply --ignore-whitespace ../../spec-test-script/simd_ignore_cases.patch || exit 1
        fi
        if [[ ${ENABLE_MULTI_MODULE} == 1 ]]; then
            git apply --ignore-whitespace ../../spec-test-script/multi_module_ignore_cases.patch || exit 1

            if [[ ${RUNNING_MODE} == "aot" ]]; then
                git apply --ignore-whitespace ../../spec-test-script/multi_module_aot_ignore_cases.patch || exit 1
            fi
        fi
    fi

    popd
    echo $(pwd)

    #TODO: remove it when we can assume wabt is installed
    # especially for CI Or there is installation script in the project
    # that we can rely on
    setup_wabt

    ln -sf ${WORK_DIR}/../spec-test-script/all.py .
    ln -sf ${WORK_DIR}/../spec-test-script/runtest.py .

    local ARGS_FOR_SPEC_TEST=""

    if [[ 1 == ${ENABLE_MULTI_MODULE} ]]; then
        ARGS_FOR_SPEC_TEST+="-M "
    fi

    if [[ 1 == ${ENABLE_EH} ]]; then
        ARGS_FOR_SPEC_TEST+="-e "
    fi

    if [[ ${SGX_OPT} == "--sgx" ]];then
        ARGS_FOR_SPEC_TEST+="-x "
    fi

    if [[ ${ENABLE_SIMD} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="-S "
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
        ARGS_FOR_SPEC_TEST+="--aot-compiler ${WAMRC_CMD} "
    fi

    if [[ ${PARALLELISM} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="--parl "
    fi

    if [[ ${ENABLE_GC} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="--gc "
    fi

    if [[ ${ENABLE_EXTENDED_CONST_EXPR} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="--enable-extended-const "
    fi

    if [[ 1 == ${ENABLE_MEMORY64} ]]; then
        ARGS_FOR_SPEC_TEST+="--memory64 "
    fi

    # multi memory is only enabled in interp and aot mode
    if [[ 1 == ${ENABLE_MULTI_MEMORY} ]]; then
        if [[ $1 == 'classic-interp' || $1 == 'aot' ]]; then
            ARGS_FOR_SPEC_TEST+="--multi-memory "
        fi
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

function wamr_compiler_test()
{
    if [[ $1 != "aot" ]]; then
        echo "WAMR compiler tests only support AOT mode, skip $1"
        return 0
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
        echo "Collect code coverage of standalone test-module-malloc"
        ./collect_coverage.sh "${CODE_COV_FILE}" "${STANDALONE_DIR}/test-module-malloc/build"

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

    BUILD_LLVM_SH=build_llvm.sh
    if [ ${TARGET} = "XTENSA" ]; then
        BUILD_LLVM_SH=build_llvm_xtensa.sh
    fi

    echo "Build wamrc for spec test under aot compile type"
    cd ${WAMR_DIR}/wamr-compiler \
        && ./${BUILD_LLVM_SH} \
        && if [ -d build ]; then rm -r build/*; else mkdir build; fi \
        && cd build \
        && cmake .. \
             -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE} \
             -DWAMR_BUILD_SHRUNK_MEMORY=0 \
             -DWAMR_BUILD_EXTENDED_CONST_EXPR=${ENABLE_EXTENDED_CONST_EXPR} \
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

# decide whether execute test cases in current running mode based on the current configuration or not
# return 1 if the test case should be executed, otherwise return 0
function do_execute_in_running_mode()
{
    local RUNNING_MODE="$1"

    # filter out uncompatible running mode based on targeting proposal features
    # keep alpha order

    if [[ ${ENABLE_EH} -eq 1 ]]; then
        if [[ "${RUNNING_MODE}" != "classic-interp" ]]; then
            echo "support exception handling in classic-interp"
            return 0;
        fi
    fi

    if [[ ${ENABLE_GC} -eq 1 ]]; then
        if [[ "${RUNNING_MODE}" != "classic-interp" \
                && "${RUNNING_MODE}" != "fast-interp" \
                && "${RUNNING_MODE}" != "jit" \
                && "${RUNNING_MODE}" != "aot" ]]; then
            echo "support gc in both interp modes, llvm-jit mode and aot mode"
            return 0;
        fi
    fi

    if [[ ${ENABLE_MEMORY64} -eq 1 ]]; then
        if [[ "${RUNNING_MODE}" != "classic-interp" \
                && "${RUNNING_MODE}" != "aot" ]]; then
            echo "support memory64(wasm64) in classic-interp mode and aot mode"
            return 0
        fi
    fi

    if [[ ${ENABLE_MULTI_MEMORY} -eq 1 ]]; then
        if [[ "${RUNNING_MODE}" != "classic-interp" ]]; then
            echo "support multi-memory in classic-interp mode mode"
            return 0
        fi
    fi

    if [[ ${ENABLE_MULTI_MODULE} -eq 1 ]]; then
        if [[ "${RUNNING_MODE}" != "classic-interp" \
                && "${RUNNING_MODE}" != "fast-interp" \
                && "${RUNNING_MODE}" != "aot" ]]; then
            echo "support multi-module in both interp modes"
            return 0
        fi
    fi

    if [[ ${ENABLE_SIMD} -eq 1 ]]; then
        if [[ "${RUNNING_MODE}" != "jit" && "${RUNNING_MODE}" != "aot" && "${RUNNING_MODE}" != "fast-interp" ]]; then
            echo "support simd in llvm-jit, aot and fast-interp mode"
            return 0;
        fi
    fi

    # filter out uncompatible running mode based on SGX support
    if [[ ${SGX_OPT} == "--sgx" ]]; then
        if [[ "${RUNNING_MODE}" != "classic-interp" \
                && "${RUNNING_MODE}" != "fast-interp" \
                && "${RUNNING_MODE}" != "aot" \
                && "${RUNNING_MODE}" != "fast-jit" ]]; then
            echo "support sgx in both interp modes, fast-jit mode and aot mode"
            return 0
        fi
    fi

    # filter out uncompatible running mode based on architecture
    if [[ ${TARGET} == "X86_32" ]]; then
        if [[ "${RUNNING_MODE}" == "jit" || "${RUNNING_MODE}" == "fast-jit" || "${RUNNING_MODE}" == "multi-tier-jit" ]]; then
            echo "both llvm-jit, fast-jit and multi-tier-jit mode do not support X86_32 target"
            return 0;
        fi

        if [[ ${ENABLE_MEMORY64} -eq 1 ]]; then
            echo "memory64 does not support X86_32 target"
            return 0;
        fi

        if [[ ${ENABLE_MULTI_MEMORY} -eq 1 ]]; then
            echo "multi-memory does not support X86_32 target"
            return 0;
        fi

        if [[ ${ENABLE_SIMD} -eq 1 ]]; then
            echo "simd does not support X86_32 target"
            return 0;
        fi
    fi

    # by default, always execute the test case
    return 1
}

function trigger()
{
    # Check if REQUIREMENT_NAME is set, if set, only calling requirement test and early return
    if [[ -n $REQUIREMENT_NAME ]]; then
        python ${REQUIREMENT_SCRIPT_DIR}/run_requirement.py -o ${REPORT_DIR}/ -r "$REQUIREMENT_NAME" "${SUBREQUIREMENT_IDS[@]}"
        # early return with the python script exit status
        return $?
    fi

    local EXTRA_COMPILE_FLAGS=""
    # for spec test
    EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SPEC_TEST=1"
    EXTRA_COMPILE_FLAGS+=" -DCOLLECT_CODE_COVERAGE=${COLLECT_CODE_COVERAGE}"
    EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SHRUNK_MEMORY=0"

    # default enabled features
    EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_BULK_MEMORY=1"
    EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_REF_TYPES=1"
    EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_LIBC_WASI=0"

    if [[ ${ENABLE_MULTI_MODULE} == 1 ]];then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_MULTI_MODULE=1"
    else
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_MULTI_MODULE=0"
    fi

    if [[ ${ENABLE_MEMORY64} == 1 ]];then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_MEMORY64=1"
    else
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_MEMORY64=0"
    fi

    if [[ ${ENABLE_MULTI_MEMORY} == 1 ]];then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_MULTI_MEMORY=1"
    else
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_MULTI_MEMORY=0"
    fi

    if [[ ${ENABLE_MULTI_THREAD} == 1 ]];then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_LIB_PTHREAD=1"
    fi

    if [[ ${ENABLE_SIMD} == 1 ]]; then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SIMD=1"
    else
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SIMD=0"
    fi

    if [[ ${ENABLE_GC} == 1 ]]; then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_GC=1"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_BULK_MEMORY=1"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_TAIL_CALL=1"
    fi

    if [[ ${ENABLE_EXTENDED_CONST_EXPR} == 1 ]]; then
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_EXTENDED_CONST_EXPR=1"
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

    if [[ "$WAMR_BUILD_SANITIZER" == "posan" ]]; then
        echo "Setting run with posan"
        EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_SANITIZER=posan"
    fi

    # Make sure we're using the builtin WASI libc implementation
    # if we're running the wasi certification tests.
    if [[ $TEST_CASE_ARR ]]; then
        for test in "${TEST_CASE_ARR[@]}"; do
            if [[ "$test" == "wasi_certification" ]]; then
                EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_WASI_TEST=1"
            fi
            if [[ "$test" == "wasi_certification"
                  || "$test" == "standalone" ]]; then
                EXTRA_COMPILE_FLAGS+=" -DWAMR_BUILD_LIBC_UVWASI=0 -DWAMR_BUILD_LIBC_WASI=1"
                break
            fi
        done
    fi

    for t in "${TYPE[@]}"; do
        do_execute_in_running_mode $t
        if [[ $? -eq 1 ]]; then
            echo "execute in running mode" $t
        else
            echo "skip in running mode" $t
            continue
        fi

        case $t in
            "classic-interp")
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
                if [ -z "${WAMRC_CMD}" ]; then
                   build_wamrc
                   WAMRC_CMD=${WAMRC_CMD_DEFAULT}
                fi
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
    TEST_CASE_ARR=("spec" "malformed" "standalone")
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
DEBUG set +exv pipefail
echo "TEST SUCCESSFUL"
exit 0
