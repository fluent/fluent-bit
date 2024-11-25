#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

PROJECT_DIR=$PWD
WAMR_DIR=${PWD}/../..
OUT_DIR=${PWD}/out
BUILD_DIR=${PWD}/build
WAMR_RUNTIME_CFG=${PROJECT_DIR}/wamr_config_gui.cmake
LV_CFG_PATH=${PROJECT_DIR}/lv_config

if [ -z $KW_BUILD ] || [ -z $KW_OUT_FILE ];then
    echo "Local Build Env"
    cmakewrap="cmake"
    makewrap="make"
else
    echo "Klocwork Build Env"
    cmakewrap="cmake -DCMAKE_BUILD_TYPE=Debug"
    makewrap="kwinject -o $KW_OUT_FILE make"
fi

if [ ! -d $BUILD_DIR ]; then
    mkdir ${BUILD_DIR}
fi

rm -rf ${OUT_DIR}
mkdir ${OUT_DIR}


echo -e "\n\n"
echo "##################### 1. build wamr-sdk gui start#####################"
cd ${WAMR_DIR}/wamr-sdk
./build_sdk.sh -n gui -x ${WAMR_RUNTIME_CFG} -e ${LV_CFG_PATH}
[ $? -eq 0 ] || exit $?

echo "#####################build wamr-sdk success"



echo "##################### 2. build wasm runtime start#####################"
cd $BUILD_DIR
mkdir -p wasm-runtime-wgl
cd wasm-runtime-wgl
$cmakewrap ${PROJECT_DIR}/wasm-runtime-wgl/linux-build -DWAMR_BUILD_SDK_PROFILE=gui
[ $? -eq 0 ] || exit $?
$makewrap
[ $? -eq 0 ] || exit $?
cp wasm_runtime_wgl ${OUT_DIR}/

echo "##################### build littlevgl wasm runtime end#####################"
echo -e "\n\n"


echo "#####################build host-tool"
cd $BUILD_DIR
mkdir -p host-tool
cd host-tool
$cmakewrap ${WAMR_DIR}/test-tools/host-tool
$makewrap
if [ $? != 0 ];then
        echo "BUILD_FAIL host tool exit as $?\n"
        exit 2
fi
cp host_tool ${OUT_DIR}
echo "#####################build host-tool success"
echo -e "\n\n"

echo "##################### 3. build wasm ui app start#####################"
cd ${PROJECT_DIR}/wasm-apps
export OUT_DIR=${OUT_DIR}
./build_apps.sh

