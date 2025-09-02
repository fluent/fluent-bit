#!/bin/sh

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# on intel mac, this ends up with a lot of the following error.
#
#  AttributeError: 'Sequential' object has no attribute '_get_save_spec'.
#
# * "pip install tensorflow" installs tensorflow 2.16.2 on intel mac.
#   (because it's the last version before tf deprecated the target.)
# * keras 3 support in the version seems incomplete (thus the error)
# * a workaround: use keras 2 as mentioned in:
#   https://github.com/tensorflow/tensorflow/releases/tag/v2.16.1
#   https://blog.tensorflow.org/2024/03/whats-new-in-tensorflow-216.html

CURR_PATH=$(cd $(dirname $0) && pwd -P)

# WASM application that uses WASI-NN

/opt/wasi-sdk/bin/clang \
    --target=wasm32-wasi \
    -DNN_LOG_LEVEL=1 \
    -Wl,--allow-undefined \
    -I../include -I../src/utils \
    -o test_tensorflow.wasm \
    test_tensorflow.c utils.c

# TFLite models to use in the tests

cd ${CURR_PATH}/models
python3 average.py
python3 max.py
python3 mult_dimension.py
python3 mult_outputs.py
python3 sum.py

# Specific tests for TPU

cd ${CURR_PATH}
/opt/wasi-sdk/bin/clang \
    --target=wasm32-wasi \
    -DNN_LOG_LEVEL=1 \
    -Wl,--allow-undefined \
    -I../include -I../src/utils \
    -o test_tensorflow_quantized.wasm \
    test_tensorflow_quantized.c utils.c

cd ${CURR_PATH}/models
python3 quantized.py

cd ${CURR_PATH}
