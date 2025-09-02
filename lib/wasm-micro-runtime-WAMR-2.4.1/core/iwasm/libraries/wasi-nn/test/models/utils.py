# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

import tensorflow as tf
import pathlib


def save_model(model, filename):
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    tflite_model = converter.convert()
    tflite_models_dir = pathlib.Path("./")
    tflite_model_file = tflite_models_dir/filename
    tflite_model_file.write_bytes(tflite_model)
