# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import tensorflow as tf
from utils import save_model

model = tf.keras.Sequential([
    tf.keras.layers.InputLayer(input_shape=[5, 5, 1]),
    tf.keras.layers.AveragePooling2D(
        pool_size=(5, 5), strides=None, padding="valid", data_format=None)

])

# Export model to tflite

save_model(model, "average.tflite")
