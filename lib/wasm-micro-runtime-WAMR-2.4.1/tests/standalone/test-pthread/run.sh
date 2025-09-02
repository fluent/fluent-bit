#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

if [[ $2 == "--sgx" ]]; then
    readonly IWASM_CMD="../../../product-mini/platforms/linux-sgx/enclave-sample/iwasm"
else
    readonly IWASM_CMD="../../../product-mini/platforms/linux/build/iwasm"
fi
readonly WAMRC_CMD="../../../wamr-compiler/build/wamrc"

if [[ $1 != "--aot" ]]; then
    echo "============> run create_join.wasm"
    ${IWASM_CMD} --heap-size=16384 create_join.wasm
    echo "============> run main_thread_return.wasm"
    ${IWASM_CMD} --heap-size=16384 main_thread_return.wasm
    echo "============> run thread_cancel.wasm"
    ${IWASM_CMD} --heap-size=16384 thread_cancel.wasm
    echo "============> run thread_exit.wasm"
    ${IWASM_CMD} --heap-size=16384 thread_exit.wasm
    echo "============> run wasi.wasm"
    ${IWASM_CMD} --heap-size=16384 wasi.wasm
    echo "============> run pthread_mutex.wasm"
    ${IWASM_CMD} --heap-size=16384 pthread_mutex.wasm
    echo "============> run pthread_cond.wasm"
    ${IWASM_CMD} --heap-size=16384 pthread_cond.wasm
    echo "============> run pthread_key.wasm"
    ${IWASM_CMD} --heap-size=16384 pthread_key.wasm
else
    echo "============> compile create_join.wasm to aot"
    if [[ $2 == "--sgx" ]]; then
        ${WAMRC_CMD} -sgx --enable-multi-thread -o create_join.aot create_join.wasm
    else
        ${WAMRC_CMD} --enable-multi-thread -o create_join.aot create_join.wasm
    fi
    echo "============> run create_join.aot"
    ${IWASM_CMD} --heap-size=16384 create_join.aot

    echo "============> compile main_thread_return.wasm to aot"
    if [[ $2 == "--sgx" ]]; then
        ${WAMRC_CMD} -sgx --enable-multi-thread -o main_thread_return.aot main_thread_return.wasm
    else
        ${WAMRC_CMD} --enable-multi-thread -o main_thread_return.aot main_thread_return.wasm
    fi
    echo "============> run main_thread_return.aot"
    ${IWASM_CMD} --heap-size=16384 main_thread_return.aot

    echo "============> compile thread_cancel.wasm to aot"
    if [[ $2 == "--sgx" ]]; then
        ${WAMRC_CMD} -sgx --enable-multi-thread -o thread_cancel.aot thread_cancel.wasm
    else
        ${WAMRC_CMD} --enable-multi-thread -o thread_cancel.aot thread_cancel.wasm
    fi
    echo "============> run thread_cancel.aot"
    ${IWASM_CMD} --heap-size=16384 thread_cancel.aot

    echo "============> compile thread_exit.wasm to aot"
    if [[ $2 == "--sgx" ]]; then
        ${WAMRC_CMD} -sgx --enable-multi-thread -o thread_exit.aot thread_exit.wasm
    else
        ${WAMRC_CMD} --enable-multi-thread -o thread_exit.aot thread_exit.wasm
    fi
    echo "============> run thread_exit.aot"
    ${IWASM_CMD} --heap-size=16384 thread_exit.aot

    echo "============> compile wasi.wasm to aot"
    if [[ $2 == "--sgx" ]]; then
        ${WAMRC_CMD} -sgx --enable-multi-thread -o wasi.aot wasi.wasm
    else
        ${WAMRC_CMD} --enable-multi-thread -o wasi.aot wasi.wasm
    fi
    echo "============> run wasi.aot"
    ${IWASM_CMD} --heap-size=16384 wasi.aot

    echo "============> compile pthread_mutex.wasm to aot"
    if [[ $2 == "--sgx" ]]; then
        ${WAMRC_CMD} -sgx --enable-multi-thread -o pthread_mutex.aot pthread_mutex.wasm
    else
        ${WAMRC_CMD} --enable-multi-thread -o pthread_mutex.aot pthread_mutex.wasm
    fi
    echo "============> run pthread_mutex.aot"
    ${IWASM_CMD} --heap-size=16384 pthread_mutex.aot

    echo "============> compile pthread_cond.wasm to aot"
    if [[ $2 == "--sgx" ]]; then
        ${WAMRC_CMD} -sgx --enable-multi-thread -o pthread_cond.aot pthread_cond.wasm
    else
        ${WAMRC_CMD} --enable-multi-thread -o pthread_cond.aot pthread_cond.wasm
    fi
    echo "============> run pthread_cond.aot"
    ${IWASM_CMD} --heap-size=16384 pthread_cond.aot

    echo "============> compile pthread_key.wasm to aot"
    if [[ $2 == "--sgx" ]]; then
        ${WAMRC_CMD} -sgx --enable-multi-thread -o pthread_key.aot pthread_key.wasm
    else
        ${WAMRC_CMD} --enable-multi-thread -o pthread_key.aot pthread_key.wasm
    fi
    echo "============> run pthread_key.aot"
    ${IWASM_CMD} --heap-size=16384 pthread_key.aot
fi

cd threads-opcode-wasm-apps
rm -rf build && mkdir build && cd build
cmake .. && make
cd ../..

wasm_files=$(ls threads-opcode-wasm-apps/build/*.wasm)

for wasm_file in $wasm_files; do
    wasm_file_name="${wasm_file%.wasm}"
    # avoid keep printing warning: warning: SGX pthread_cond_timedwait isn't supported, calling pthread_cond_wait instead!
    if [[ $2 == "--sgx" ]] && [[ ${wasm_file_name} == *"atomic_wait_notify"* ]]; then
        echo "============> didn't run ${wasm_file_name} on sgx aot mode, it will output too much warning info"
        continue
    fi

    if [[ $1 != "--aot" ]]; then
        echo "============> run ${wasm_file_name}.wasm"
        ${IWASM_CMD} --heap-size=16384 ${wasm_file_name}.wasm
    else
        echo "============> compile ${wasm_file_name}.wasm to aot"
        if [[ $2 == "--sgx" ]]; then
            ${WAMRC_CMD} -sgx --enable-multi-thread --opt-level=0 -o ${wasm_file_name}.aot ${wasm_file_name}.wasm
        else
            ${WAMRC_CMD} --enable-multi-thread --opt-level=0 -o ${wasm_file_name}.aot ${wasm_file_name}.wasm
        fi
        echo "============> run ${wasm_file_name}.aot"
        ${IWASM_CMD} --heap-size=16384 ${wasm_file_name}.aot
    fi
done
