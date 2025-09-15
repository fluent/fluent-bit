#!/usr/bin/env bash

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

sudo apt update

sudo apt install -y build-essential cmake g++-multilib libgcc-12-dev lib32gcc-12-dev ccache ninja-build

WAMR_DIR=${PWD}

# TODO: use pre-built llvm binary to build wamrc to
#       avoid static code analysing for llvm
: '
# build wamrc
cd ${WAMR_DIR}/wamr-compiler
./build_llvm.sh
rm -fr build && mkdir build && cd build
cmake ..
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build wamrc!"
    exit 1;
fi
'

# build iwasm with default features enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -fr build && mkdir build && cd build
cmake ..
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with default features enabled!"
    exit 1;
fi

# build iwasm with default features enabled on x86_32
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -fr build && mkdir build && cd build
cmake .. -DWAMR_BUILD_TARGET=X86_32
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with default features enabled on x86_32!"
    exit 1;
fi

# build iwasm with classic interpreter enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_FAST_INTERP=0
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with classic interpreter enabled!"
    exit 1;
fi

# build iwasm with extra features enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -fr build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug \
    -DWAMR_BUILD_LIB_PTHREAD=1 -DWAMR_BUILD_LIB_PTHREAD_SEMAPHORE=1 \
    -DWAMR_BUILD_MULTI_MODULE=1 -DWAMR_BUILD_SIMD=1 \
    -DWAMR_BUILD_TAIL_CALL=1 -DWAMR_BUILD_REF_TYPES=1 \
    -DWAMR_BUILD_CUSTOM_NAME_SECTION=1 -DWAMR_BUILD_MEMORY_PROFILING=1 \
    -DWAMR_BUILD_PERF_PROFILING=1 -DWAMR_BUILD_DUMP_CALL_STACK=1 \
    -DWAMR_BUILD_LOAD_CUSTOM_SECTION=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build wamrc iwasm with extra features enabled!"
    exit 1;
fi

# build iwasm with global heap pool enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -fr build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug \
    -DWAMR_BUILD_ALLOC_WITH_USER_DATA=1 \
    -DWAMR_DISABLE_STACK_HW_BOUND_CHECK=1 \
    -DWAMR_BUILD_GLOBAL_HEAP_POOL=1 \
    -DWAMR_BUILD_GLOBAL_HEAP_SIZE=131072
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with global heap pool enabled!"
    exit 1;
fi

# build iwasm with wasi-threads enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -fr build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_LIB_WASI_THREADS=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with wasi-threads enabled!"
    exit 1;
fi

# build iwasm with GC enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_GC=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with GC enabled!"
    exit 1;
fi

# build iwasm with exception handling enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_EXCE_HANDLING=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with exception handling enabled!"
    exit 1;
fi

# build iwasm with memory64 enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_MEMORY64=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with memory64 enabled!"
    exit 1;
fi

# build iwasm with multi-memory enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_MULTI_MEMORY=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with multi-memory enabled!"
    exit 1;
fi

# build iwasm with hardware boundary check disabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_DISABLE_HW_BOUND_CHECK=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with hardware boundary check disabled!"
    exit 1;
fi

# build iwasm with quick AOT entry disabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_QUICK_AOT_ENTRY=0
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with quick AOT entry disabled!"
    exit 1;
fi

# build iwasm with wakeup of blocking operations disabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_DISABLE_WAKEUP_BLOCKING_OP=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with wakeup of blocking operations disabled!"
    exit 1;
fi

# build iwasm with module instance context disabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_MODULE_INST_CONTEXT=0 \
         -DWAMR_BUILD_LIBC_BUILTIN=0 -DWAMR_BUILD_LIBC_WASI=0
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with module instance context disabled!"
    exit 1;
fi

# build iwasm with libc-uvwasi enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -fr build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_LIBC_UVWASI=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with libc-uvwasi enabled!"
    exit 1;
fi

# build iwasm with fast jit lazy mode enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_FAST_JIT_DUMP=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with fast jit lazy mode enabled!"
    exit 1;
fi

# build iwasm with fast jit eager mode enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_FAST_JIT_DUMP=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with fast jit eager mode enabled!"
    exit 1;
fi

# TODO: use pre-built llvm binary to build llvm-jit and multi-tier-jit
: '
# build iwasm with llvm jit lazy mode enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_JIT=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build llvm jit lazy mode enabled!"
    exit 1;
fi

# build iwasm with llvm jit eager mode enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=0
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build llvm jit eager mode enabled!"
    exit 1;
fi

# build iwasm with multi-tier jit enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1 \
                                    -DWAMR_BUILD_FAST_JIT_DUMP=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with multi-tier jit enabled!"
    exit 1;
fi
'

# build iwasm with wasm mini-loader enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_MINI_LOADER=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build with wasm mini-loader enabled!"
    exit 1;
fi

# build iwasm with source debugging enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_DEBUG_INTERP=1 -DWAMR_BUILD_DEBUG_AOT=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with source debugging enabled!"
    exit 1;
fi

# build iwasm with AOT static PGO enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_STATIC_PGO=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with AOT static PGO enabled!"
    exit 1;
fi

# build iwasm with configurable bounds checks enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_CONFIGURABLE_BOUNDS_CHECKS=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with configurable bounds checks enabled!"
    exit 1;
fi

# build iwasm with linux perf support enabled
cd ${WAMR_DIR}/product-mini/platforms/linux/
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_LINUX_PERF=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with linux perf support enabled!"
    exit 1;
fi

# build iwasm with shared heap enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_SHARED_HEAP=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm with shared heap enabled!"
    exit 1;
fi

# build iwasm with dynamic aot debug enabled
cd ${WAMR_DIR}/product-mini/platforms/linux
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_DYNAMIC_AOT_DEBUG=1
make -j
if [[ $? != 0 ]]; then
    echo "Failed to build iwasm dynamic aot debug enabled!"
    exit 1;
fi
