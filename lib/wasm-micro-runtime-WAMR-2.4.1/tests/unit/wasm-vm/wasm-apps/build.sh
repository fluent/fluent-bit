# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

readonly CURR_DIR=$PWD
readonly BINARYDUMP_DIR=$PWD/../../../../test-tools/binarydump-tool

# build binarydump
cd $BINARYDUMP_DIR
mkdir -p build && cd build
cmake .. && make -j
cp -a binarydump $CURR_DIR

cd $CURR_DIR

## build app1
/opt/wasi-sdk/bin/clang -O3 \
    -z stack-size=4096 -Wl,--initial-memory=65536 \
    -o app1/app1.wasm app1/main.c -Wl,--export-all \
    -Wl,--export=__heap_base,--export=__data_end \
    -Wl,--no-entry -nostdlib -Wl,--allow-undefined
./binarydump -o app1_wasm.h -n app1_wasm app1/app1.wasm
wavm disassemble app1/app1.wasm app1.wast
rm -f app1/app1.wasm

## build app2
/opt/wasi-sdk/bin/clang -O3 \
    -z stack-size=4096 -Wl,--initial-memory=65536 \
    -o app2/app2.wasm app2/main.c -Wl,--export-all \
    -Wl,--export=__heap_base,--export=__data_end \
    -Wl,--no-entry -nostdlib -Wl,--allow-undefined
./binarydump -o app2_wasm.h -n app2_wasm app2/app2.wasm
wavm disassemble app2/app2.wasm app2.wast
rm -f app2/app2.wasm

## build app3
/opt/wasi-sdk/bin/clang -O3 \
    -z stack-size=4096 -Wl,--initial-memory=65536 \
    -o app3/app3.wasm app3/main.c -Wl,--export-all \
    -Wl,--export=__heap_base,--export=__data_end \
    -Wl,--no-entry -nostdlib -Wl,--allow-undefined
./binarydump -o app3_wasm.h -n app3_wasm app3/app3.wasm
wavm disassemble app3/app3.wasm app3.wast
rm -f app3/app3.wasm
