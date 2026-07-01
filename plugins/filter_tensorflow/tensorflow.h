/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_FILTER_TENSORFLOW_H
#define FLB_FILTER_TENSORFLOW_H

struct flb_tensorflow {
    TfLiteModel* model;
    TfLiteInterpreterOptions* interpreter_options;
    TfLiteInterpreter* interpreter;
    flb_sds_t input_field;
    TfLiteType input_tensor_type;
    TfLiteType output_tensor_type;

    /* IO buffer */
    void* input;
    void* output;
    int input_size;
    int input_byte_size;
    int output_size;
    int output_byte_size;

    /* feature scaling/normalization */
    int include_input_fields;
    float* normalization_value;

    struct flb_filter_instance *ins;
};

#endif
