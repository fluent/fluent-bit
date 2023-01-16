#!/bin/bash

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

####################################
#   build tensorflow-lite sample   #
####################################
if [ ! -d "${EMSDK}" ]; then
    echo "can not find emsdk. "
    echo "please refer to https://emscripten.org/docs/getting_started/downloads.html "
    echo "to install it, or active it by 'source <emsdk_dir>emsdk_env.sh'"
    exit
fi

set -xe

EMSDK_WASM_DIR="${EMSDK}/upstream/emscripten/cache/sysroot/lib/wasm32-emscripten"
BUILD_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${BUILD_SCRIPT_DIR}/out"
TENSORFLOW_DIR="${BUILD_SCRIPT_DIR}/tensorflow"
TF_LITE_BUILD_DIR="${TENSORFLOW_DIR}/tensorflow/lite/tools/make"
WAMR_PLATFORM_DIR="${BUILD_SCRIPT_DIR}/../../../product-mini/platforms"
WAMRC_DIR="${BUILD_SCRIPT_DIR}/../../../wamr-compiler"

function Clear_Before_Exit
{
    [[ -f ${TENSORFLOW_DIR}/tf_lite.patch ]] &&
       rm -f ${TENSORFLOW_DIR}/tf_lite.patch
    # resume the libc.a under EMSDK_WASM_DIR
    cd ${EMSDK_WASM_DIR}
    mv libc.a.bak libc.a
}

# 1.hack emcc
cd ${EMSDK_WASM_DIR}
# back up libc.a
cp libc.a libc.a.bak
# delete some objects in libc.a
emar d libc.a open.o
emar d libc.a mmap.o
emar d libc.a munmap.o
emranlib libc.a

# 2. build tf-lite
cd ${BUILD_SCRIPT_DIR}
# 2.1 clone tf repo from Github and checkout to 2303ed commit
if [ ! -d "tensorflow" ]; then
    git clone https://github.com/tensorflow/tensorflow.git
fi

cd ${TENSORFLOW_DIR}
git checkout 2303ed4bdb344a1fc4545658d1df6d9ce20331dd

# 2.2 copy the tf-lite.patch to tensorflow_root_dir and apply
cd ${TENSORFLOW_DIR}
cp ${BUILD_SCRIPT_DIR}/tf_lite.patch .
git checkout tensorflow/lite/tools/make/Makefile
git checkout tensorflow/lite/tools/make/targets/linux_makefile.inc

if [[ $(git apply tf_lite.patch 2>&1) =~ "error" ]]; then
    echo "git apply patch failed, please check tf-lite related changes..."
    Clear_Before_Exit
    exit 0
fi

cd ${TF_LITE_BUILD_DIR}
# 2.3 download dependencies
if [ ! -d "${TF_LITE_BUILD_DIR}/downloads" ]; then
    source download_dependencies.sh
fi

# 2.4 build tf-lite target
if [ -d "${TF_LITE_BUILD_DIR}/gen" ]; then
    rm -fr ${TF_LITE_BUILD_DIR}/gen
fi

make -j 4 -C "${TENSORFLOW_DIR}" -f ${TF_LITE_BUILD_DIR}/Makefile

# remove patch file and recover emcc libc.a after building
Clear_Before_Exit

# 2.5 copy /make/gen target files to out/
rm -rf ${OUT_DIR}
mkdir ${OUT_DIR}
cp -r ${TF_LITE_BUILD_DIR}/gen/linux_x86_64/bin/. ${OUT_DIR}/

# 3. compile tf-model.wasm to tf-model.aot with wamrc
# 3.1 build wamr-compiler
cd ${WAMRC_DIR}
./build_llvm.sh
rm -fr build && mkdir build
cd build && cmake ..
make
# 3.2 compile tf-mode.wasm to tf-model.aot
WAMRC_CMD="$(pwd)/wamrc"
cd ${OUT_DIR}
if [[ $1 == '--sgx' ]]; then
    ${WAMRC_CMD} --enable-simd -sgx -o benchmark_model.aot benchmark_model.wasm
elif [[  $1 == '--threads' ]]; then
    ${WAMRC_CMD} --enable-simd --enable-multi-thread -o benchmark_model.aot benchmark_model.wasm
else
    ${WAMRC_CMD} --enable-simd -o benchmark_model.aot benchmark_model.wasm
fi

# 4. build iwasm with pthread and libc_emcc enable
#    platform:
#     linux by default
#     linux-sgx if $1 equals '--sgx'
if [[ $1 == '--sgx' ]]; then
    cd ${WAMR_PLATFORM_DIR}/linux-sgx
    rm -fr build && mkdir build
    cd build && cmake .. -DWAMR_BUILD_SIMD=1 -DWAMR_BUILD_LIB_PTHREAD=1 -DWAMR_BUILD_LIBC_EMCC=1
    make
    cd ../enclave-sample
    make
else
    cd ${WAMR_PLATFORM_DIR}/linux
    rm -fr build && mkdir build
    cd build && cmake .. -DWAMR_BUILD_SIMD=1 -DWAMR_BUILD_LIB_PTHREAD=1 -DWAMR_BUILD_LIBC_EMCC=1
    make
fi

# 5. run tensorflow with iwasm
cd ${BUILD_SCRIPT_DIR}
# 5.1 download tf-lite model
if [ ! -f mobilenet_quant_v1_224.tflite ]; then
    wget "https://storage.googleapis.com/download.tensorflow.org/models/tflite/mobilenet_v1_224_android_quant_2017_11_08.zip"
    unzip mobilenet_v1_224_android_quant_2017_11_08.zip
fi

# 5.2 run tf-lite model with iwasm
echo "---> run tensorflow benchmark model with iwasm"
if [[ $1 == '--sgx' ]]; then
    IWASM_CMD="${WAMR_PLATFORM_DIR}/linux-sgx/enclave-sample/iwasm"
else
    IWASM_CMD="${WAMR_PLATFORM_DIR}/linux/build/iwasm"
fi

if [[  $1 == '--threads' ]]; then
    ${IWASM_CMD} --heap-size=10475860 \
             ${OUT_DIR}/benchmark_model.aot --num_threads=4 \
             --graph=mobilenet_quant_v1_224.tflite --max_secs=300
else
    ${IWASM_CMD} --heap-size=10475860 \
             ${OUT_DIR}/benchmark_model.aot \
             --graph=mobilenet_quant_v1_224.tflite --max_secs=300
fi

