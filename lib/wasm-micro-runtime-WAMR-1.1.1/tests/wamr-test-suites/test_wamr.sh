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
    echo "-s {suite_name} test only one suite (spec)"
    echo "-m set compile target of iwasm(x86_64\x86_32\armv7_vfp\thumbv7_vfp\riscv64_lp64d\riscv64_lp64)"
    echo "-t set compile type of iwasm(classic-interp\fast-interp\jit\aot\fast-jit)"
    echo "-M enable multi module feature"
    echo "-p enable multi thread feature"
    echo "-S enable SIMD feature"
    echo "-X enable XIP feature"
    echo "-x test SGX"
    echo "-b use the wabt binary release package instead of compiling from the source code"
    echo "-P run the spec test parallelly"
}

OPT_PARSED=""
WABT_BINARY_RELEASE="NO"
#default type
TYPE=("classic-interp" "fast-interp" "jit" "aot" "fast-jit")
#default target
TARGET="X86_64"
ENABLE_MULTI_MODULE=0
ENABLE_MULTI_THREAD=0
COLLECT_CODE_COVERAGE=0
ENABLE_SIMD=0
ENABLE_XIP=0
#unit test case arrary
TEST_CASE_ARR=()
SGX_OPT=""
PLATFORM=$(uname -s | tr A-Z a-z)
PARALLELISM=0

while getopts ":s:cabt:m:MCpSXxP" opt
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
            rm -r workspace/report/*
            echo "cleaned all reports"
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
            && ${OPTARG} != "jit" && ${OPTARG} != "aot" && ${OPTARG} != "fast-jit" ]]; then
            echo "*----- please varify a type of compile when using -t! -----*"
            help
            exit 1
        fi

        TYPE=(${OPTARG})
        ;;
        m)
        echo "set compile target of wamr" ${OPTARG}
        TARGET=${OPTARG^^} # set target to uppercase if input x86_32 or x86_64 --> X86_32 and X86_64
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
        x)
        echo "test SGX"
        SGX_OPT="--sgx"
        ;;
        P)
        PARALLELISM=1
        ;;
        ?)
        help
        exit 1;;
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

# TODO: a strong assumation about a link to the WAMR project
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
readonly JIT_COMPILE_FLAGS="\
    -DWAMR_BUILD_TARGET=${TARGET} \
    -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_AOT=1 \
    -DWAMR_BUILD_SPEC_TEST=1"

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
    -DWAMR_BUILD_SPEC_TEST=1"

readonly COMPILE_FLAGS=(
        "${CLASSIC_INTERP_COMPILE_FLAGS}"
        "${FAST_INTERP_COMPILE_FLAGS}"
        "${JIT_COMPILE_FLAGS}"
        "${AOT_COMPILE_FLAGS}"
        "${FAST_JIT_COMPILE_FLAGS}"
    )

# TODO: with libiwasm.so only
function unit_test()
{
    echo "Now start unit tests"

    cd ${WORK_DIR}
    readonly UNIT_CASES="wasm-vm host-tool utils"

    echo "Build unit test"
    touch ${REPORT_DIR}/unit_test_report.txt

    for compile_flag in "${COMPILE_FLAGS[@]}"; do
        echo "Build unit test with compile flags with " ${compile_flag}

        # keep going and do not care if it is success or not
        make -ki clean | true
        cmake ${compile_flag} ${WORK_DIR}/../../unit && make -j 4
        if [ "$?" != 0 ];then
            echo -e "build unit test failed, you may need to change wamr into dev/aot branch and ensure llvm is built"
            exit 1
        fi

        echo ${compile_flag} >> ${REPORT_DIR}/unit_test_report.txt

        for case in ${UNIT_CASES}
        do
            echo "run ${case} ..."
            cd ./${case}/
            ./${case/-/_}"_test" | tee -a ${REPORT_DIR}/unit_test_report.txt
            cd -
            echo "finish ${case}"
        done
    done

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

    popd
    echo $(pwd)

    if [ ${WABT_BINARY_RELEASE} == "YES" ]; then
        echo "download a binary release and install"
        local WAT2WASM=${WORK_DIR}/wabt/out/gcc/Release/wat2wasm
        if [ ! -f ${WAT2WASM} ]; then
            case ${PLATFORM} in
                linux)
                    WABT_PLATFORM=ubuntu
                    ;;
                darwin)
                    WABT_PLATFORM=macos
                    ;;
                *)
                    echo "wabt platform for ${PLATFORM} in unknown"
                    exit 1
                    ;;
            esac
            if [ ! -f /tmp/wabt-1.0.29-${WABT_PLATFORM}.tar.gz ]; then
                wget \
                    https://github.com/WebAssembly/wabt/releases/download/1.0.29/wabt-1.0.29-${WABT_PLATFORM}.tar.gz \
                    -P /tmp
            fi

            cd /tmp \
            && tar zxf wabt-1.0.29-${WABT_PLATFORM}.tar.gz \
            && mkdir -p ${WORK_DIR}/wabt/out/gcc/Release/ \
            && install wabt-1.0.29/bin/wa* ${WORK_DIR}/wabt/out/gcc/Release/ \
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

    ln -sf ${WORK_DIR}/../spec-test-script/all.py .
    ln -sf ${WORK_DIR}/../spec-test-script/runtest.py .

    local ARGS_FOR_SPEC_TEST=""

    # multi-module only enable in interp mode
    if [[ 1 == ${ENABLE_MULTI_MODULE} ]]; then
        if [[ $1 == 'classic-interp' || $1 == 'fast-interp' ]]; then
            ARGS_FOR_SPEC_TEST+="-M "
        fi
    fi

    # sgx only enable in interp mode and aot mode
    if [[ ${SGX_OPT} == "--sgx" ]];then
        if [[ $1 == 'classic-interp' || $1 == 'fast-interp' || $1 == 'aot' ]]; then
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
        if [[ $1 == 'fast-jit' ]]; then
          echo "fast-jit doesn't support multi-thread feature yet, skip it"
          return
        fi
    fi

    if [[ ${ENABLE_XIP} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="-X "
    fi

    # require warmc only in aot mode
    if [[ $1 == 'aot' ]]; then
        ARGS_FOR_SPEC_TEST+="-t -m ${TARGET} "
    fi

    if [[ ${PARALLELISM} == 1 ]]; then
        ARGS_FOR_SPEC_TEST+="--parl "
    fi

    cd ${WORK_DIR}
    python3 ./all.py ${ARGS_FOR_SPEC_TEST} | tee -a ${REPORT_DIR}/spec_test_report.txt
    [[ ${PIPESTATUS[0]} -ne 0 ]] && exit 1
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

function malformed_test()
{
    # build iwasm firstly
    cd ${WORK_DIR}/../../malformed
    ./malformed_test.py --run ${IWASM_CMD} | tee ${REPORT_DIR}/malfomed_$1_test_report.txt
}

function standalone_test()
{
    cd ${WORK_DIR}/../../standalone

    args=""

    [[ $1 == "aot" ]] && args="$args --aot" || args="$args --no-aot"
    [[ ${SGX_OPT} == "--sgx" ]] && args="$args --sgx" || args="$args --no-sgx"

    if [[ ${ENABLE_MULTI_THREAD} == 1 ]];then
        args="$args --thread"
    fi

    ./standalone.sh $args | tee ${REPORT_DIR}/standalone_$1_test_report.txt
}

function build_iwasm_with_cfg()
{
    echo "Build iwasm with compile flags with " $* " for spec test" \
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
        && make -j 4
    fi

    if [ "$?" != 0 ];then
        echo -e "build iwasm failed"
        exit 1
    fi
}

function build_wamrc()
{
    if [[ $TARGET == "ARMV7_VFP" || $TARGET == "THUMBV7_VFP"
          || $TARGET == "RISCV64" || $TARGET == "RISCV64_LP64D"
          || $TARGET == "RISCV64_LP64" ]];then
        echo "suppose wamrc is already built"
        return
    fi

    echo "Build wamrc for spec test under aot compile type"
    cd ${WAMR_DIR}/wamr-compiler \
        && ./build_llvm.sh \
        && if [ -d build ]; then rm -r build/*; else mkdir build; fi \
        && cd build \
        && cmake .. \
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
    if [[ ${COLLECT_CODE_COVERAGE} == 1 ]];then
        cd ${IWASM_LINUX_ROOT_DIR}/build
        lcov -t "iwasm code coverage" -o iwasm.info -c -d .
        genhtml -o iwasm-gcov iwasm.info
        [[ -d iwasm-gcov ]] && \
                cp -r iwasm-gcov ${REPORT_DIR}/$1_iwasm_gcov || \
                echo "generate code coverage html failed"
    else
        echo "will not collect code coverage"
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
                build_iwasm_with_cfg $BUILD_FLAGS
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
                build_iwasm_with_cfg $BUILD_FLAGS
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

                echo "work in jit mode"
                # jit
                BUILD_FLAGS="$JIT_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                build_iwasm_with_cfg $BUILD_FLAGS
                build_wamrc
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" jit
                done
            ;;

            "aot")
                echo "work in aot mode"
                # aot
                BUILD_FLAGS="$AOT_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                build_iwasm_with_cfg $BUILD_FLAGS
                build_wamrc
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" aot
                done
                collect_coverage aot
            ;;

            "fast-jit")
                echo "work in fast-jit mode"
                # jit
                BUILD_FLAGS="$FAST_JIT_COMPILE_FLAGS $EXTRA_COMPILE_FLAGS"
                build_iwasm_with_cfg $BUILD_FLAGS
                for suite in "${TEST_CASE_ARR[@]}"; do
                    $suite"_test" fast-jit
                done
            ;;

            *)
            echo "unexpected mode, do nothing"
            ;;
        esac
    done
}

# if collect code coverage, ignore -s, test all test cases.
if [[ $TEST_CASE_ARR && $COLLECT_CODE_COVERAGE != 1 ]];then
    trigger || (echo "TEST FAILED"; exit 1)
else
    # test all suite, ignore polybench because of long time cost
    TEST_CASE_ARR=("sightglass" "spec" "wasi" "malformed" "standalone")
    trigger || (echo "TEST FAILED"; exit 1)
    # Add more suites here
fi

echo -e "Test finish. Reports are under ${REPORT_DIR}"
DEBUG set +xv pipefail
echo "TEST SUCCESSFUL"
exit 0
