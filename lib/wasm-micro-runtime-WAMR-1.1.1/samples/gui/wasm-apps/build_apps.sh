#!/bin/bash

APPS_ROOT=$(cd "$(dirname "$0")/" && pwd)
cd ${APPS_ROOT}

echo "OUT_DIR: ${OUT_DIR}"

if [ -z ${OUT_DIR} ]; then
    OUT_DIR=${APPS_ROOT}/out
    echo "set the wasm app folder: ${OUT_DIR}"

    if [ -d ${OUT_DIR} ]; then
        rm -rf ${OUT_DIR}
        echo "removed the present output folder: ${OUT_DIR}"
    fi
    mkdir ${OUT_DIR}

fi

if [ -z ${WAMR_DIR} ]; then
    WAMR_DIR=${APPS_ROOT}/../../..
fi


cd ${APPS_ROOT}/increase

rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=${WAMR_DIR}/wamr-sdk/out/gui/app-sdk/wamr_toolchain.cmake \
         -DWASI_SDK_DIR=/opt/wasi-sdk
make
[ $? -eq 0 ] || exit $?
mv ui_increase.wasm ${OUT_DIR}/

# $makewrap
# mv ui_app.wasm ${OUT_DIR}/

cd ${APPS_ROOT}/decrease
make
[ $? -eq 0 ] || exit $?
mv ui_decrease.wasm ${OUT_DIR}/

echo "WASM files generated in folder  ${OUT_DIR}"

echo "#####################  build WASM APPs finished #####################"
