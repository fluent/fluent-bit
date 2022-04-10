/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <stdio.h>
#include <unistd.h>

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_config_map.h>

#include "tensorflow/lite/c/c_api.h"
#include "tensorflow/lite/c/common.h"

#include <msgpack.h>
#include <time.h>
#include "tensorflow.h"

#define MSGPACK_INTEGER(x) (x == MSGPACK_OBJECT_POSITIVE_INTEGER || \
                            x == MSGPACK_OBJECT_NEGATIVE_INTEGER)
#define MSGPACK_FLOAT(x) (x == MSGPACK_OBJECT_FLOAT ||            \
                          x == MSGPACK_OBJECT_FLOAT32)
#define MSGPACK_NUMBER(x) (MSGPACK_INTEGER(x) || MSGPACK_FLOAT(x))

void print_tensor_info(struct flb_tensorflow *ctx, const TfLiteTensor* tensor)
{
    int i;
    TfLiteType type;
    char tensor_info[128] = "";
    char tensor_dim[8];

    type = TfLiteTensorType(tensor);
    sprintf(tensor_info, "type: %s dimensions: {", TfLiteTypeGetName(type));
    for (i = 0; i < TfLiteTensorNumDims(tensor) - 1; i++) {
        sprintf(tensor_dim, "%d, ", TfLiteTensorDim(tensor, i));
        strcat(tensor_info, tensor_dim);
    }
    sprintf(tensor_dim, "%d}", TfLiteTensorDim(tensor, i));
    strcat(tensor_info, tensor_dim);

    flb_plg_info(ctx->ins, "%s", tensor_info);
}

void print_model_io(struct flb_tensorflow *ctx)
{
    int i;
    int num;
    const TfLiteTensor* tensor;

    /* Input information */
    num = TfLiteInterpreterGetInputTensorCount(ctx->interpreter);
    for (i = 0; i < num; i++) {
        tensor = TfLiteInterpreterGetInputTensor(ctx->interpreter, i);
        flb_plg_info(ctx->ins, "===== input #%d =====", i + 1);
        print_tensor_info(ctx, tensor);
    }

    /* Output information */
    num = TfLiteInterpreterGetOutputTensorCount(ctx->interpreter);
    for (i = 0; i < num; i++) {
        tensor = TfLiteInterpreterGetOutputTensor(ctx->interpreter, i);
        flb_plg_info(ctx->ins, "===== output #%d ====", i + 1);
        print_tensor_info(ctx, tensor);
    }
}

void build_interpreter(struct flb_tensorflow *ctx, char* model_path)
{
    /* from c_api.h */
    ctx->model = TfLiteModelCreateFromFile(model_path);
    ctx->interpreter_options = TfLiteInterpreterOptionsCreate();
    ctx->interpreter = TfLiteInterpreterCreate(ctx->model, ctx->interpreter_options);
    TfLiteInterpreterAllocateTensors(ctx->interpreter);

    flb_info("TensorFlow Lite interpreter created!");
    print_model_io(ctx);
}

void inference(TfLiteInterpreter* interpreter, void* input_data, void* output_data, int input_buf_size, int output_buf_size) {
    /* from c_api.h */
    TfLiteTensor* input_tensor = TfLiteInterpreterGetInputTensor(interpreter, 0);
    TfLiteTensorCopyFromBuffer(input_tensor, input_data, input_buf_size);

    TfLiteInterpreterInvoke(interpreter);

    const TfLiteTensor* output_tensor = TfLiteInterpreterGetOutputTensor(interpreter, 0);
    TfLiteTensorCopyToBuffer(output_tensor, output_data, output_buf_size);
}

int allocateIOBuffer(struct flb_tensorflow *ctx, void** buf, TfLiteType type, int size)
{
    if (type == kTfLiteFloat32) {
        *buf = (void*) flb_malloc(size * sizeof(float));
    }
    else {
        flb_plg_error(ctx->ins, "Tensor type (%d) is not currently supported!", type);
        return -1;
    }

    return 0;
}

void flb_tensorflow_conf_destroy(struct flb_tensorflow *ctx)
{
    flb_sds_destroy(ctx->input_field);

    if (ctx->input) {
        flb_free(ctx->input);
    }

    if (ctx->output) {
        flb_free(ctx->output);
    }

    if (ctx->normalization_value) {
        flb_free(ctx->normalization_value);
    }

    /* delete TensorFlow model and interpreter */
    if (ctx->model) {
        TfLiteModelDelete(ctx->model);
    }

    TfLiteInterpreterOptionsDelete(ctx->interpreter_options);
    TfLiteInterpreterDelete(ctx->interpreter);

    flb_free(ctx);
}

static int cb_tensorflow_init(struct flb_filter_instance *f_ins,
                              struct flb_config *config,
                              void *data)
{
    int i;
    int ret;
    struct flb_tensorflow *ctx = NULL;
    const char *tmp;
    const TfLiteTensor* tensor;

    ctx = flb_calloc(1, sizeof(struct flb_tensorflow));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ret = flb_filter_config_map_set(f_ins, (void *) ctx);
    if (ret == -1) {
        flb_tensorflow_conf_destroy(ctx);
        return -1;
    }

    ctx->ins = f_ins;

    tmp = flb_filter_get_property("input_field", f_ins);
    if (!tmp) {
        flb_plg_error(ctx->ins, "input field is not defined!");
        flb_tensorflow_conf_destroy(ctx);
        return -1;
    }

    ctx->input_field = flb_sds_create(tmp);

    tmp = flb_filter_get_property("model_file", f_ins);
    if (!tmp) {
        flb_plg_error(ctx->ins, "TensorFlow Lite model file is not provided!");
        flb_tensorflow_conf_destroy(ctx);
        return -1;
    }

    if(access(tmp, F_OK) == -1) {
        flb_plg_error(ctx->ins, "TensorFlow Lite model file %s not found!", tmp);
        flb_tensorflow_conf_destroy(ctx);
        return -1;
    }

    build_interpreter(ctx, (char *) tmp);

    if (!ctx->interpreter) {
        flb_plg_error(ctx->ins, "Error creating the interpreter");
        flb_tensorflow_conf_destroy(ctx);
        return -1;
    }

    /* calculate input information */
    ctx->input_size = 1;
    tensor = TfLiteInterpreterGetInputTensor(ctx->interpreter, 0);
    for (i = 0; i < TfLiteTensorNumDims(tensor); i++) {
        ctx->input_size *= TfLiteTensorDim(tensor, i);
    }
    ctx->input_tensor_type = TfLiteTensorType(tensor);
    if (allocateIOBuffer(ctx, &ctx->input, ctx->input_tensor_type, ctx->input_size) == -1) {
        flb_tensorflow_conf_destroy(ctx);
        return -1;
    }
    ctx->input_byte_size = TfLiteTensorByteSize(tensor);

    /* calculate output information */
    ctx->output_size = 1;
    tensor = TfLiteInterpreterGetOutputTensor(ctx->interpreter, 0);
    for (i = 0; i < TfLiteTensorNumDims(tensor); i++) {
        ctx->output_size *= TfLiteTensorDim(tensor, i);
    }
    ctx->output_tensor_type = TfLiteTensorType(tensor);
    if (allocateIOBuffer(ctx, &ctx->output, ctx->output_tensor_type, ctx->output_size) == -1) {
        flb_tensorflow_conf_destroy(ctx);
        return -1;
    }
    ctx->output_byte_size = TfLiteTensorByteSize(tensor);

    tmp = flb_filter_get_property("include_input_fields", f_ins);
    if (!tmp) {
        ctx->include_input_fields = FLB_TRUE;
    }
    else {
        ctx->include_input_fields = flb_utils_bool(tmp);
    }

    tmp = flb_filter_get_property("normalization_value", f_ins);
    if (tmp) {
        ctx->normalization_value = flb_malloc(sizeof(float));
        *ctx->normalization_value = atof(tmp);
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_tensorflow_filter(const void *data, size_t bytes,
                                const char *tag, int tag_len,
                                void **out_buf, size_t *out_bytes,
                                struct flb_filter_instance *f_ins,
                                struct flb_input_instance *i_ins,
                                void *filter_context,
                                struct flb_config *config)
{
    size_t off = 0;
    int i;
    int j;
    int input_data_type;
    (void) out_buf;
    (void) out_bytes;
    (void) f_ins;
    (void) i_ins;
    int map_size;

    msgpack_object root;
    msgpack_object map;
    msgpack_object key;
    msgpack_object value;

    struct flb_time tm;
    msgpack_unpacked result;
    msgpack_object *obj;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    struct flb_tensorflow* ctx;

    /* data pointers */
    float* dfloat;

    /* calculate inference time */
    clock_t start, end;
    double inference_time;

    /* initializations */
    ctx = filter_context;
    inference_time = 0;
    start = clock();

    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;

        /* TODO check if msgpack type is map */
        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        /* get timestamp from msgpack record */
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        for (i = 0; i < map_size; i++) {
            key = map.via.map.ptr[i].key;

            if (flb_sds_cmp(ctx->input_field, (char *) key.via.str.ptr, key.via.str.size) != 0) {
                continue;
            }

            value = map.via.map.ptr[i].val;
            if (value.type == MSGPACK_OBJECT_ARRAY)
            {
                int size = value.via.array.size;
                if (size == 0) {
                    flb_plg_error(ctx->ins, "input data size has to be non-zero!");
                    break;
                }

                if (size != ctx->input_size) {
                    flb_plg_error(ctx->ins, "input data size doesn't match model's input size!");
                    break;
                }

                /* we only accept numbers inside input array */
                input_data_type = value.via.array.ptr[0].type;
                if (!MSGPACK_NUMBER(input_data_type)) {
                    flb_plg_error(ctx->ins, "input data has to be of numerical type!");
                    break;
                }

                /* copy data from messagepack into the input buffer */
                /* tensor type: kTfLiteFloat32 */
                if (ctx->input_tensor_type == kTfLiteFloat32) {
                    if (sizeof(float) != sizeof(kTfLiteFloat32)) {
                        flb_plg_error(ctx->ins, "input tensor type (kTfLiteFloat32) doesn't match float size!");
                        break;
                    }

                    dfloat = (float *) ctx->input;

                    if (MSGPACK_FLOAT(input_data_type)) {
                        for (i = 0; i < value.via.array.size; i++) {
                            dfloat[i] = value.via.array.ptr[i].via.f64;
                        }
                    }
                    else if (MSGPACK_INTEGER(input_data_type)) {
                        for (i = 0; i < value.via.array.size; i++) {
                            dfloat[i] = ((float) value.via.array.ptr[i].via.i64);
                        }
                    }
                    else {
                        flb_plg_error(ctx->ins, "input record type is not supported for a float32 input tensor!");
                        break;
                    }

                    if (ctx->normalization_value) {
                        for (i = 0; i < value.via.array.size; i++) {
                            dfloat[i] /= *ctx->normalization_value;
                        }
                    }
                }
                else {
                    flb_plg_error(ctx->ins, "input tensor type is not currently not supported!");
                    break;
                }
            }
            else if (value.type == MSGPACK_OBJECT_BIN) {
                 if (ctx->input_tensor_type == kTfLiteFloat32) {
                     dfloat = (float *) ctx->input;

                     /*
                      * re:IEEE754 float size is 32 bits
                      * TODO: currently, the following assumes that the binrary
                      * string is the serialization of a string of characters (uint8_t).
                      * It is required to add other primitive data type encodings such as
                      * floating point numbers.
                      */
                     if (ctx->input_byte_size != (value.via.bin.size << 2)) {
                       flb_plg_error(ctx->ins, "input data size (%d bytes * 4) doesn't"
                                 "match model's input size (%d bytes)!",
                                 value.via.bin.size, ctx->input_byte_size);
                       break;
                     }

                     for (i = 0; i < value.via.bin.size; i++) {
                         dfloat[i] = ((float) value.via.bin.ptr[i]);
                     }

                     if (ctx->normalization_value) {
                         for (i = 0; i < value.via.bin.size; i++) {
                             dfloat[i] /= *ctx->normalization_value;
                         }
                     }
                }
            }
            else {
                flb_plg_error(ctx->ins, "input data format is not currently supported!");
                break;
            }

            /* run the inference */
            inference(ctx->interpreter, ctx->input, ctx->output, ctx->input_byte_size, ctx->output_byte_size);

            /* create output messagepack */
            end = clock();
            inference_time = ((double) (end - start)) / CLOCKS_PER_SEC;

            msgpack_pack_array(&tmp_pck, 2);
            flb_time_append_to_msgpack(&tm, &tmp_pck, 0);
            /* one more field for the result */
            if (ctx->include_input_fields) {
                msgpack_pack_map(&tmp_pck, map_size + 2);
            }
            else {
                msgpack_pack_map(&tmp_pck, 2);
            }

            if (ctx->include_input_fields) {
                for (j = 0; j < map_size; j++) {
                    msgpack_pack_object(&tmp_pck, map.via.map.ptr[j].key);
                    msgpack_pack_object(&tmp_pck, map.via.map.ptr[j].val);
                }
            }

            msgpack_pack_str(&tmp_pck, strlen("inference_time"));
            msgpack_pack_str_body(&tmp_pck, "inference_time", strlen("inference_time"));
            msgpack_pack_float(&tmp_pck, inference_time);

            msgpack_pack_str(&tmp_pck, strlen("output"));
            msgpack_pack_str_body(&tmp_pck, "output", 6);

            msgpack_pack_array(&tmp_pck, ctx->output_size);
            for (i=0; i < ctx->output_size; i++) {
                if (ctx->output_tensor_type == kTfLiteFloat32) {
                    msgpack_pack_float(&tmp_pck, ((float*) ctx->output)[i]);
                }
                /* TODO: work out other types */
            }
            break;
        }
    }
    msgpack_unpacked_destroy(&result);

    *out_buf  = tmp_sbuf.data;
    *out_bytes = tmp_sbuf.size;
    return FLB_FILTER_MODIFIED;
}

static int cb_tensorflow_exit(void *data, struct flb_config *config)
{
    struct flb_tensorflow *ctx = data;

    flb_tensorflow_conf_destroy(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "model_file", NULL,
        0, FLB_FALSE, 0,
        "Address of the TensorFlow Lite model file (.tflite)"
    },
    {
        FLB_CONFIG_MAP_STR, "input_field", NULL,
        0, FLB_FALSE, 0,
        "Input field name to use for inference."
    },
    {
        FLB_CONFIG_MAP_BOOL, "include_input_fields", "true",
        0, FLB_TRUE, offsetof(struct flb_tensorflow, include_input_fields),
        "Include input field in the output of the filter."
    },
    {
        FLB_CONFIG_MAP_DOUBLE, "normalization_value", NULL,
        0, FLB_FALSE, 0,
        "Divide input feature values to this value (e.g. divide image pixles by 255)."
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_tensorflow_plugin = {
    .name         = "tensorflow",
    .description  = "TensorFlow Lite inference engine",
    .cb_init      = cb_tensorflow_init,
    .cb_filter    = cb_tensorflow_filter,
    .cb_exit      = cb_tensorflow_exit,
    .config_map   = config_map,
    .flags        = 0
};
