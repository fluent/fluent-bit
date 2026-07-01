#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

if [[ $2 == "--sgx" ]];then
    readonly IWASM_CMD="../../../product-mini/platforms/linux-sgx/enclave-sample/iwasm"
else
    readonly IWASM_CMD="../../../product-mini/platforms/linux/build/iwasm"
fi
readonly WAMRC_CMD="../../../wamr-compiler/build/wamrc"

if [[ $1 != "--aot" ]]; then
    echo "============> run c_ray.wasm"
    cat scene | ${IWASM_CMD} c_ray.wasm -s 1024x768 > foo.ppm
else
    echo "============> compile c_ray.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o c_ray.aot c_ray.wasm \
                        || ${WAMRC_CMD} -o c_ray.aot c_ray.wasm
    echo "============> run c_ray.aot"
    cat scene | ${IWASM_CMD} c_ray.aot -s 1024x768 > foo.ppm
fi
