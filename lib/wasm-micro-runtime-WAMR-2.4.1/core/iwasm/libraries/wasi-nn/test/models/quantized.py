# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import tensorflow as tf
import numpy as np
import pathlib

model = tf.keras.Sequential([
    tf.keras.layers.InputLayer(input_shape=[5, 5, 1]),
    tf.keras.layers.AveragePooling2D(
        pool_size=(5, 5), strides=None, padding="valid", data_format=None)

])

def representative_dataset():
    for _ in range(1000):
      data = np.random.randint(0, 25, (1, 5, 5, 1))
      yield [data.astype(np.float32)]

converter = tf.lite.TFLiteConverter.from_keras_model(model)
converter.optimizations = [tf.lite.Optimize.DEFAULT]
converter.representative_dataset = representative_dataset
converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
converter.inference_input_type = tf.uint8  # or tf.int8
converter.inference_output_type = tf.uint8  # or tf.int8
tflite_model = converter.convert()

tflite_models_dir = pathlib.Path("./")
tflite_model_file = tflite_models_dir / "quantized_model.tflite"
tflite_model_file.write_bytes(tflite_model)
