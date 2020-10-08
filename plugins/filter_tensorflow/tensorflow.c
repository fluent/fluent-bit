/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_config_map.h>

#include <mbedtls/base64.h>

#include "tensorflow/lite/c/c_api.h"

#include <msgpack.h>
#include <time.h>
#include "tensorflow.h"

#define MSGPACK_INTEGER(x) (x == MSGPACK_OBJECT_POSITIVE_INTEGER || \
                            x == MSGPACK_OBJECT_NEGATIVE_INTEGER)
#define MSGPACK_FLOAT(x) (x == MSGPACK_OBJECT_FLOAT ||            \
                          x == MSGPACK_OBJECT_FLOAT32)
#define MSGPACK_NUMBER(x) (MSGPACK_INTEGER(x) || MSGPACK_FLOAT(x))

#define TFLITE_INTEGER(x) (x == kTfLiteInt16 || x == kTfLiteInt32 || x == kTfLiteInt64)
#define TFLITE_FLOAT(x) (x == kTfLiteFloat16 || x == kTfLiteFloat32)

void print_tensor_info(struct flb_tensorflow *ctx, const TfLiteTensor* tensor)
{
    int i;
    TfLiteType type;
    char dims[100] = "";

    type = TfLiteTensorType(tensor);
    sprintf(dims, "[tensorflow] type: %s  dimensions: {", TfLiteTypeGetName(type));
    for (i = 0; i < TfLiteTensorNumDims(tensor) - 1; i++) {
        sprintf(dims, "%s%d, ", dims, TfLiteTensorDim(tensor, i));
    }
    sprintf(dims, "%s%d}", dims, TfLiteTensorDim(tensor, i));

    flb_plg_debug(ctx->ins, "%s", dims);
}

void print_model_io(struct flb_tensorflow *ctx)
{
    int i;
    int num;
    const TfLiteTensor* tensor;
    char dims[100] = "";

    /* Input information */
    num = TfLiteInterpreterGetInputTensorCount(ctx->interpreter);
    for (i = 0; i < num; i++) {
        tensor = TfLiteInterpreterGetInputTensor(ctx->interpreter, i);
        flb_plg_debug(ctx->ins, "[tensorflow] ===== input #%d =====", i + 1);
        print_tensor_info(ctx, tensor);
    }

    /* Output information */
    num = TfLiteInterpreterGetOutputTensorCount(ctx->interpreter);
    for (i = 0; i < num; i++) {
        tensor = TfLiteInterpreterGetOutputTensor(ctx->interpreter, i);
        flb_plg_debug(ctx->ins, "[tensorflow] ===== output #%d ====", i + 1);
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

    flb_info("Tensorflow Lite interpreter created!");
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

int allocateIOBuffer(void** buf, TfLiteType type, int size)
{
    if (TFLITE_FLOAT(type)) {
        *buf = (void*) flb_malloc(size * sizeof(float));
    }
    else if (TFLITE_INTEGER(type)) {
        *buf = (void*) flb_malloc(size * sizeof(int));
    }
    else {
        flb_error("[tensorflow] tensor type (%d) is not currently supported!", type);
        return -1;
    }

    return 0;
}

static int cb_tf_init(struct flb_filter_instance *f_ins,
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

    tmp = flb_filter_get_property("input_field", f_ins);
    if (!tmp) {
        flb_error("[tensorflow] inuput field is not defined!");
        flb_free(ctx);
        return -1;
    }

    ctx->input_field = flb_sds_create(tmp);

    tmp = flb_filter_get_property("model_file", f_ins);
    if (!tmp) {
        flb_error("[tensorflow] Tensorflow Lite model file is not provided!");
        flb_free(ctx);
        return -1;
    }

    if(access(tmp, F_OK) == -1) {
        flb_error("[tensorflow] Tensorflow Lite model file %s not found!", tmp);
        flb_free(ctx);
        return -1;
    }

    build_interpreter(ctx, (char *) tmp);

    if (!ctx->interpreter) {
        flb_error("[tensorflow] error creating interpreter");
        flb_free(ctx);
        return -1;
    }

    /* calculate input information */
    ctx->input_size = 1;
    tensor = TfLiteInterpreterGetInputTensor(ctx->interpreter, 0);
    for (i = 0; i < TfLiteTensorNumDims(tensor); i++) {
        ctx->input_size *= TfLiteTensorDim(tensor, i);
    }
    ctx->input_tensor_type = TfLiteTensorType(tensor);
    if (allocateIOBuffer(&ctx->input, ctx->input_tensor_type, ctx->input_size) == -1) {
      flb_free(ctx);
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
    if (allocateIOBuffer(&ctx->output, ctx->output_tensor_type, ctx->output_size) == -1) {
      flb_free(ctx);
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

    ctx->ins = f_ins;

    ret = flb_filter_config_map_set(f_ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_tf_filter(const void *data, size_t bytes,
                        const char *tag, int tag_len,
                        void **out_buf, size_t *out_bytes,
                        struct flb_filter_instance *f_ins,
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

    struct flb_tensorflow* ctx = filter_context;

    /* data pointers */
    int* dint;
    float* dfloat;

    size_t b64_out_len;

    /* calculate inference time */
    clock_t start, end;
    double elapsed_time;

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

            /* convention: value has to be of primitive types, or array of
               primitive types i.e. unrolled data (like unrolled image) */
            value = map.via.map.ptr[i].val;
            if (value.type == MSGPACK_OBJECT_ARRAY)
            {
                int size = value.via.array.size;
                if (size == 0) {
                    flb_error("[tensorflow] input data size has to be non-zero!");
                    break;
                }

                if (size != ctx->input_size) {
                    flb_error("[tensorflow] input data size doesn't match model's input size!");
                    break;
                }

                /* we only accept numbers as in */
                input_data_type = value.via.array.ptr[0].type;
                if (!MSGPACK_NUMBER(input_data_type)) {
                    flb_error("[tensorflow] input data has to be of numerical type!");
                    break;
                }

                /* copy data from messagepack into input buffer */
                if (TFLITE_FLOAT(ctx->input_tensor_type)) {
                    dfloat = (float*) ctx->input;
                    if (MSGPACK_FLOAT(input_data_type)) {
                        for (i = 0; i < value.via.array.size; i++) {
                            if (ctx->normalization_value) {
                                dfloat[i] = value.via.array.ptr[i].via.f64 / *ctx->normalization_value;
                            }
                            else {
                                dfloat[i] = value.via.array.ptr[i].via.f64;
                            }
                        }
                    }
                    else { /* MSGPACK_INTEGER */
                        for (i = 0; i < value.via.array.size; i++) {
                            if (ctx->normalization_value) {
                                dfloat[i] = ((float) value.via.array.ptr[i].via.i64) / *ctx->normalization_value;
                            }
                            else {
                                dfloat[i] = ((float) value.via.array.ptr[i].via.i64);
                            }
                        }
                    }
                }
                else if (TFLITE_INTEGER(ctx->input_tensor_type)) {
                    dint = (int*) ctx->input;
                    if (MSGPACK_INTEGER(input_data_type)) {
                        for (i = 0; i < value.via.array.size; i++) {
                            dint[i] = value.via.array.ptr[i].via.i64;
                        }
                    }
                    else { /* MSGPACK_FLOAT */
                        for (i = 0; i < value.via.array.size; i++) {
                            dint[i] = (int) value.via.array.ptr[i].via.f64;
                        }
                    }
                }
                else {
                    flb_error("[tensorflow] input tensor type is not currently not supported!");
                    break;
                }
            }
            else if (value.type == MSGPACK_OBJECT_STR) {
                if(mbedtls_base64_decode(ctx->input, ctx->input_byte_size, &b64_out_len, (const unsigned char *) value.via.str.ptr, value.via.str.size) != 0) {
                  flb_error("[tensorflow] can't base64 decode the field!");
                  break;
                }

                if (b64_out_len != ctx->input_byte_size) {
                    flb_error("[tensorflow] input data size (%d bytes) doesn't"
                              "match model's input size (%d bytes)!",
                              b64_out_len, ctx->input_byte_size);
                    break;
                }
            }
            else {
                flb_error("[tensorflow] input data format is not currently supported!");
                break;
            }

            /* run the inference */
            inference(ctx->interpreter, ctx->input, ctx->output, ctx->input_byte_size, ctx->output_byte_size);

            /* create output messagepack */
            end = clock();
            elapsed_time = ((double) (end - start)) / CLOCKS_PER_SEC;

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
            msgpack_pack_float(&tmp_pck, elapsed_time);

            msgpack_pack_str(&tmp_pck, strlen("tf_out"));
            msgpack_pack_str_body(&tmp_pck, "tf_out", strlen("tf_out"));

            msgpack_pack_array(&tmp_pck, ctx->output_size);
            for (i=0; i < ctx->output_size; i++) {
                if (TFLITE_FLOAT(ctx->output_tensor_type)) {
                    msgpack_pack_float(&tmp_pck, ((float*) ctx->output)[i]);
                }
                else if (TFLITE_INTEGER(ctx->output_tensor_type)) {
                    msgpack_pack_int64(&tmp_pck, ((int*)ctx->output)[i]);
                }
            }
            break;
        }
    }
    msgpack_unpacked_destroy(&result);

    *out_buf  = tmp_sbuf.data;
    *out_bytes = tmp_sbuf.size;
    return FLB_FILTER_MODIFIED;
}

void flb_tf_conf_destroy(struct flb_tensorflow *ctx)
{
    flb_sds_destroy(ctx->input_field);
    flb_free(ctx->input);
    flb_free(ctx->output);
    if (ctx->normalization_value) {
        flb_free(ctx->normalization_value);
    }

    /* delete Tensorflow model and interpreter */
    TfLiteInterpreterDelete(ctx->interpreter);
    TfLiteInterpreterOptionsDelete(ctx->interpreter_options);
    TfLiteModelDelete(ctx->model);

    flb_free(ctx);
}

static int cb_tf_exit(void *data, struct flb_config *config)
{
    struct flb_tensorflow *ctx = data;

    flb_tf_conf_destroy(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "model_file", NULL,
        0, FLB_FALSE, 0,
        "Address of the Tensorflow Lite model file (.tflite)"
    },
    {
        FLB_CONFIG_MAP_STR, "input_field", NULL,
        0, FLB_FALSE, 0,
        "Input field name to use for inference."
    },
    {
        FLB_CONFIG_MAP_BOOL, "include_input_fields", "true",
        0, FLB_TRUE, offsetof(struct flb_tensorflow, include_input_fields),
        NULL
    },
    {
        FLB_CONFIG_MAP_DOUBLE, "normalization_value", NULL,
        0, FLB_FALSE, 0,
        NULL
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_tensorflow_plugin = {
    .name         = "tensorflow",
    .description  = "Tensorflow Lite inference engine",
    .cb_init      = cb_tf_init,
    .cb_filter    = cb_tf_filter,
    .cb_exit      = cb_tf_exit,
    .config_map   = config_map,
    .flags        = 0
};
