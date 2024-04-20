# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

WAMR_DIR=${PWD}/../../..

echo "Build wasm app .."
/opt/wasi-sdk/bin/clang -O3 \
        -z stack-size=4096 -Wl,--initial-memory=65536 \
        -o test.wasm main.c \
        -Wl,--export=main -Wl,--export=__main_argc_argv \
        -Wl,--export=fib2 \
        -Wl,--export=test1 \
        -Wl,--export=test2 \
        -Wl,--export=test3 \
        -Wl,--export=test4 \
        -Wl,--export=__data_end -Wl,--export=__heap_base \
        -Wl,--strip-all,--no-entry \
        -Wl,--allow-undefined \
        -nostdlib \

echo "Build binarydump tool .."
rm -fr build && mkdir build && cd build
cmake ../../../../../test-tools/binarydump-tool
make
cd ..

echo "Generate test_wasm.h .."
./build/binarydump -o test_wasm.h -n wasm_test_file test.wasm

rm -fr build

echo "Done"
