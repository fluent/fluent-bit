# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import tensorflow as tf
import numpy as np
from keras.layers import AveragePooling2D, Conv2D

from tensorflow.keras import Input, Model

from utils import save_model


inputs = Input(shape=(4, 4, 1))

output1 = Conv2D(1, (4, 1), kernel_initializer=tf.keras.initializers.Constant(
    value=1), bias_initializer='zeros'
)(inputs)
output2 = AveragePooling2D(pool_size=(
    4, 1), strides=None, padding="valid", data_format=None)(inputs)

model = Model(inputs=inputs, outputs=[output1, output2])

inp = np.arange(16).reshape((1, 4, 4, 1))

print(inp)

res = model.predict(inp)

print(res)
print(res[0].shape)
print(res[1].shape)

save_model(model, "mult_out.tflite")
