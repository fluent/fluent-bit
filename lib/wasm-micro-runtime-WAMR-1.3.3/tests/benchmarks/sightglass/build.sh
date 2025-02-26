#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

PLATFORM=$(uname -s | tr A-Z a-z)

OUT_DIR=$PWD/out
WAMRC_CMD=$PWD/../../../wamr-compiler/build/wamrc
SHOOTOUT_CASES="base64 fib2 gimli heapsort matrix memmove nestedloop \
                nestedloop2 nestedloop3 random seqhash sieve strchr \
                switch2"

if [ ! -d sightglass ]; then
    git clone https://github.com/wasm-micro-runtime/sightglass.git
fi

mkdir -p ${OUT_DIR}

cd sightglass/benchmarks/shootout

for bench in $SHOOTOUT_CASES
do
    echo "Build ${bench}_native"
    gcc -O3 -o ${OUT_DIR}/${bench}_native -Dblack_box=set_res -Dbench=${bench} \
        -I../../include ${bench}.c main/main_${bench}.c main/my_libc.c

    echo "Build ${bench}.wasm"
    /opt/wasi-sdk/bin/clang -O3 -nostdlib \
        -Wno-unknown-attributes \
        -Dblack_box=set_res \
        -I../../include -DNOSTDLIB_MODE \
        -Wl,--initial-memory=1310720,--allow-undefined \
        -Wl,--strip-all,--no-entry \
        -o ${OUT_DIR}/${bench}.wasm \
        -Wl,--export=app_main -Wl,--export=_start \
        ${bench}.c main/main_${bench}.c main/my_libc.c

    echo "Compile ${bench}.wasm into ${bench}.aot"
    ${WAMRC_CMD} -o ${OUT_DIR}/${bench}.aot ${OUT_DIR}/${bench}.wasm
    if [[ ${PLATFORM} == "linux" ]]; then
        echo "Compile ${bench}.wasm into ${bench}_segue.aot"
        ${WAMRC_CMD} --enable-segue -o ${OUT_DIR}/${bench}_segue.aot ${OUT_DIR}/${bench}.wasm
    fi
done

cd ..

echo "Done"
