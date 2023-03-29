# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# WASM application that uses WASI-NN

/opt/wasi-sdk/bin/clang \
    -Wl,--allow-undefined \
    -Wl,--strip-all,--no-entry \
    --sysroot=/opt/wasi-sdk/share/wasi-sysroot \
    -I/home/wamr/core/iwasm/libraries/wasi-nn \
    -o test_tensorflow.wasm test_tensorflow.c

# TFLite models to use in the tests

cd models
python3 average.py
python3 max.py
python3 mult_dimension.py
python3 mult_outputs.py
python3 sum.py
