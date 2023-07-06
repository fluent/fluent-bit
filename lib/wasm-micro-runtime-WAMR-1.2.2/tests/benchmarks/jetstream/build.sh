#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

OUT_DIR=$PWD/out
WAMRC_CMD=$PWD/../../../wamr-compiler/build/wamrc

mkdir -p jetstream
mkdir -p ${OUT_DIR}

cd jetstream

echo "Download source files .."
wget https://browserbench.org/JetStream/wasm/gcc-loops.cpp
wget https://browserbench.org/JetStream/wasm/quicksort.c
wget https://browserbench.org/JetStream/wasm/HashSet.cpp
wget https://browserbench.org/JetStream/simple/float-mm.c

patch -p1 < ../jetstream.patch

echo "Build gcc-loops with g++ .."
g++ -O3 -msse2 -msse3 -msse4 -o ${OUT_DIR}/gcc-loops_native gcc-loops.cpp

echo "Build gcc-loops with em++ .."
em++ -O3 -s STANDALONE_WASM=1 -msimd128 \
         -s INITIAL_MEMORY=1048576 \
         -s TOTAL_STACK=32768 \
         -s "EXPORTED_FUNCTIONS=['_main']" \
         -s ERROR_ON_UNDEFINED_SYMBOLS=0 \
         -o ${OUT_DIR}/gcc-loops.wasm gcc-loops.cpp

echo "Compile gcc-loops.wasm to gcc-loops.aot"
${WAMRC_CMD} -o ${OUT_DIR}/gcc-loops.aot ${OUT_DIR}/gcc-loops.wasm

echo "Build quicksort with gcc .."
gcc -O3 -msse2 -msse3 -msse4 -o ${OUT_DIR}/quicksort_native quicksort.c

echo "Build quicksort with emcc .."
emcc -O3 -s STANDALONE_WASM=1 -msimd128 \
         -s INITIAL_MEMORY=1048576 \
         -s TOTAL_STACK=32768 \
         -s "EXPORTED_FUNCTIONS=['_main']" \
         -o ${OUT_DIR}/quicksort.wasm quicksort.c

echo "Compile quicksort.wasm to quicksort.aot"
${WAMRC_CMD} -o ${OUT_DIR}/quicksort.aot ${OUT_DIR}/quicksort.wasm

echo "Build HashSet with g++ .."
g++ -O3 -msse2 -msse3 -msse4 -o ${OUT_DIR}/HashSet_native HashSet.cpp \
        -lstdc++

echo "Build HashSet with em++ .."
em++ -O3 -s STANDALONE_WASM=1 -msimd128 \
         -s INITIAL_MEMORY=1048576 \
         -s TOTAL_STACK=32768 \
         -s "EXPORTED_FUNCTIONS=['_main']" \
         -o ${OUT_DIR}/HashSet.wasm HashSet.cpp

echo "Compile HashSet.wasm to HashSet.aot"
${WAMRC_CMD} -o ${OUT_DIR}/HashSet.aot ${OUT_DIR}/HashSet.wasm

echo "Build float-mm with gcc .."
gcc -O3 -msse2 -msse3 -msse4 -o ${OUT_DIR}/float-mm_native float-mm.c

echo "Build float-mm with emcc .."
emcc -O3 -s STANDALONE_WASM=1 -msimd128 \
         -s INITIAL_MEMORY=1048576 \
         -s TOTAL_STACK=32768 \
         -s "EXPORTED_FUNCTIONS=['_main']" \
         -o ${OUT_DIR}/float-mm.wasm float-mm.c

echo "Compile float-mm.wasm to float-mm.aot"
${WAMRC_CMD} -o ${OUT_DIR}/float-mm.aot ${OUT_DIR}/float-mm.wasm
