#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

CURR_DIR=$PWD
WAMR_DIR=${PWD}/../..
OUT_DIR=${PWD}/out
BUILD_DIR=${PWD}/build

IWASM_ROOT=${PWD}/../../core/iwasm
APP_FRAMEWORK_DIR=${PWD}/../../core/app-framework
NATIVE_LIBS=${APP_FRAMEWORK_DIR}/app-native-shared
APP_LIB_SRC="${APP_FRAMEWORK_DIR}/base/app/*.c ${APP_FRAMEWORK_DIR}/sensor/app/*.c \
             ${APP_FRAMEWORK_DIR}/connection/app/*.c ${NATIVE_LIBS}/*.c"
WASM_APPS=${PWD}/wasm-apps
CLEAN=
CM_BUILD_TYPE="-DCMAKE_BUILD_TYPE=Debug"
CM_TOOLCHAIN=""

usage ()
{
    echo "build.sh [options]"
    echo " -p [profile]"
    echo " -d [target]"
    echo " -c, rebuild SDK"
    exit 1
}


while getopts "p:dch" opt
do
    case $opt in
        p)
        PROFILE=$OPTARG
        ;;
        d)
        CM_BUILD_TYPE="-DCMAKE_BUILD_TYPE=Debug"
        ;;
        c)
        CLEAN="TRUE"
        ;;
        h)
        usage
        exit 1;
        ;;
        ?)
        echo "Unknown arg: $arg"
        usage
        exit 1
        ;;
    esac
done


if [ "$CLEAN" = "TRUE" ]; then
    rm -rf $CURR_DIR/cmake-build
fi


while  [ ! -n "$PROFILE" ]
do
    support_profiles=`ls -l "profiles/" |grep '^d' | awk '{print $9}'`
    read -p "Enter build target profile (default=host-interp) -->
$support_profiles
\>:" read_platform
    if [ ! -n "$read_platform" ]; then
        PROFILE="host-interp"
    else
        PROFILE=$read_platform
    fi
done

ARG_TOOLCHAIN=""
TOOL_CHAIN_FILE=$CURR_DIR/profiles/$PROFILE/toolchain.cmake
if [  -f $TOOL_CHAIN_FILE ]; then
    CM_TOOLCHAIN="-DCMAKE_TOOLCHAIN_FILE=$TOOL_CHAIN_FILE"
    ARG_TOOLCHAIN="-t $TOOL_CHAIN_FILE"
    echo "toolchain file: $TOOL_CHAIN_FILE"
fi


SDK_CONFIG_FILE=$CURR_DIR/profiles/$PROFILE/wamr_config_simple.cmake
if [ ! -f $SDK_CONFIG_FILE ]; then
    echo "SDK config file [$SDK_CONFIG_FILE] doesn't exit. quit.."
    exit 1
fi



rm -rf ${OUT_DIR}
mkdir ${OUT_DIR}
mkdir ${OUT_DIR}/wasm-apps

cd ${WAMR_DIR}/core/shared/mem-alloc

PROFILE="simple-$PROFILE"


echo "#####################build wamr sdk"
cd ${WAMR_DIR}/wamr-sdk
./build_sdk.sh -n $PROFILE -x $SDK_CONFIG_FILE $ARG_TOOLCHAIN
[ $? -eq 0 ] || exit $?


echo "#####################build simple project"
cd ${CURR_DIR}
mkdir -p cmake-build/$PROFILE
cd cmake-build/$PROFILE
cmake ../.. -DWAMR_BUILD_SDK_PROFILE=$PROFILE $CM_TOOLCHAIN $CM_BUILD_TYPE
make
if [ $? != 0 ];then
    echo "BUILD_FAIL simple exit as $?\n"
    exit 2
fi
cp -a simple ${OUT_DIR}
echo "#####################build simple project success"

echo -e "\n\n"
echo "#####################build host-tool"
cd ${WAMR_DIR}/test-tools/host-tool
mkdir -p bin
cd bin
cmake .. $CM_TOOLCHAIN $CM_BUILD_TYPE
make
if [ $? != 0 ];then
        echo "BUILD_FAIL host tool exit as $?\n"
        exit 2
fi
cp host_tool ${OUT_DIR}
echo "#####################build host-tool success"

echo -e "\n\n"
echo "#####################build wasm apps"

cd ${WASM_APPS}

for i in `ls *.c`
do
APP_SRC="$i"
OUT_FILE=${i%.*}.wasm

/opt/wasi-sdk/bin/clang                                              \
        -I${WAMR_DIR}/wamr-sdk/out/$PROFILE/app-sdk/wamr-app-framework/include  \
        -L${WAMR_DIR}/wamr-sdk/out/$PROFILE/app-sdk/wamr-app-framework/lib      \
        -lapp_framework                                              \
        --target=wasm32 -O3 -z stack-size=4096 -Wl,--initial-memory=65536 \
        --sysroot=${WAMR_DIR}/wamr-sdk/out/$PROFILE/app-sdk/libc-builtin-sysroot  \
        -Wl,--allow-undefined-file=${WAMR_DIR}/wamr-sdk/out/$PROFILE/app-sdk/libc-builtin-sysroot/share/defined-symbols.txt \
        -Wl,--strip-all,--no-entry -nostdlib \
        -Wl,--export=on_init -Wl,--export=on_destroy \
        -Wl,--export=on_request -Wl,--export=on_response \
        -Wl,--export=on_sensor_event -Wl,--export=on_timer_callback \
        -Wl,--export=on_connection_data \
        -Wl,--export=__heap_base -Wl,--export=__data_end \
        -o ${OUT_DIR}/wasm-apps/${OUT_FILE} ${APP_SRC}
if [ -f ${OUT_DIR}/wasm-apps/${OUT_FILE} ]; then
        echo "build ${OUT_FILE} success"
else
        echo "build ${OUT_FILE} fail"
fi
done

echo "#####################build wasm apps done"
