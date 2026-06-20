# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import tensorflow as tf

from utils import save_model

model = tf.keras.Sequential([
    tf.keras.layers.InputLayer(input_shape=[5, 5, 1]),
    tf.keras.layers.Conv2D(1, (5, 5), kernel_initializer=tf.keras.initializers.Constant(
        value=1), bias_initializer='zeros'
    )
])

# Export model to tflite

save_model(model, "sum.tflite")
