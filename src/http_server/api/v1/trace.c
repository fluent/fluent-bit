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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_chunk_trace.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

#define STR_INPUTS "inputs"
#define STR_INPUTS_LEN (sizeof(STR_INPUTS)-1)

#define HTTP_FIELD_MESSAGE        "message"
#define HTTP_FIELD_MESSAGE_LEN    (sizeof(HTTP_FIELD_MESSAGE)-1)
#define HTTP_FIELD_STATUS         "status"
#define HTTP_FIELD_STATUS_LEN     (sizeof(HTTP_FIELD_STATUS)-1)
#define HTTP_FIELD_RETURNCODE     "returncode"
#define HTTP_FIELD_RETURNCODE_LEN (sizeof(HTTP_FIELD_RETURNCODE)-1)

#define HTTP_RESULT_OK                   "ok"
#define HTTP_RESULT_OK_LEN               (sizeof(HTTP_RESULT_OK)-1)
#define HTTP_RESULT_ERROR                "error"
#define HTTP_RESULT_ERROR_LEN            (sizeof(HTTP_RESULT_ERROR)-1)
#define HTTP_RESULT_NOTFOUND             "not found"
#define HTTP_RESULT_NOTFOUND_LEN         (sizeof(HTTP_RESULT_NOTFOUND)-1)
#define HTTP_RESULT_METHODNOTALLOWED     "method not allowed"
#define HTTP_RESULT_METHODNOTALLOWED_LEN (sizeof(HTTP_RESULT_METHODNOTALLOWED)-1)
#define HTTP_RESULT_UNKNOWNERROR         "unknown error"
#define HTTP_RESULT_UNKNOWNERROR_LEN     (sizeof(HTTP_RESULT_UNKNOWNERROR)-1)

static struct flb_input_instance *find_input(struct flb_hs *hs, const char *name, size_t nlen)
{
    struct mk_list *head;
    struct flb_input_instance *in;


    mk_list_foreach(head, &hs->config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        if ((strlen(in->name) == nlen) && (strncmp(name, in->name, nlen) == 0)) {
            return in;
        }
        if (in->alias) {
            if ((strlen(in->alias) == nlen) && (strncmp(name, in->alias, nlen) == 0)) {
                return in;
            }
        }
    }
    return NULL;
}

static int enable_trace_input(struct flb_hs *hs, const char *name, ssize_t nlen, const char *prefix,
                              const char *output_name, struct mk_list *props)
{
    struct flb_input_instance *in;

    in = find_input(hs, name, nlen);
    if (in == NULL) {
        flb_error("unable to find input: [%d]%.*s", (int)nlen, (int)nlen, name);
        return 404;
    }

    flb_chunk_trace_context_new(in, output_name, prefix, NULL, props);

    if (in->chunk_trace_ctxt == NULL) {
        flb_error("unable to start tracing");
        return 503;
    }

    return 0;
}

static int disable_trace_input(struct flb_hs *hs, const char *name, size_t nlen)
{
    struct flb_input_instance *in;


    in = find_input(hs, name, nlen);
    if (in == NULL) {
        return 404;
    }

    if (in->chunk_trace_ctxt != NULL) {
        flb_chunk_trace_context_destroy(in);
    }
    return 201;
}

static flb_sds_t get_input_name(mk_request_t *request)
{
    const char base[] = "/api/v1/trace/";


    if (request->real_path.data == NULL) {
        return NULL;
    }
    if (request->real_path.len < sizeof(base)-1) {
        return NULL;
    }

    return flb_sds_create_len(&request->real_path.data[sizeof(base)-1],
                              request->real_path.len - (sizeof(base)-1));
}

static int http_disable_trace(mk_request_t *request, void *data,
                              const char *input_name, size_t input_nlen,
                              msgpack_packer *mp_pck)
{
    struct flb_hs *hs = data;
    int toggled_on = 503;


    toggled_on = disable_trace_input(hs, input_name, input_nlen);
    if (toggled_on < 300) {
        msgpack_pack_map(mp_pck, 1);
        msgpack_pack_str_with_body(mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
        return 201;
    }

    return toggled_on;
}

static int msgpack_params_enable_trace(struct flb_hs *hs, msgpack_unpacked *result,
                                       const char *input_name, ssize_t input_nlen)
{
    int ret = -1;
    int i;
    int x;
    flb_sds_t prefix = NULL;
    flb_sds_t output_name = NULL;
    int toggled_on = -1;
    msgpack_object *key;
    msgpack_object *val;
    struct mk_list *props = NULL;
    msgpack_object_kv *param;
    msgpack_object_str *param_key;
    msgpack_object_str *param_val;


    if (result->data.type == MSGPACK_OBJECT_MAP) {
        for (i = 0; i < result->data.via.map.size; i++) {
            key = &result->data.via.map.ptr[i].key;
            val = &result->data.via.map.ptr[i].val;

            if (key->type != MSGPACK_OBJECT_STR) {
                ret = -1;
                goto parse_error;
            }

            if (strncmp(key->via.str.ptr, "prefix", key->via.str.size) == 0) {
                if (val->type != MSGPACK_OBJECT_STR) {
                    ret = -1;
                    goto parse_error;
                }
                if (prefix != NULL) {
                    flb_sds_destroy(prefix);
                }
                prefix = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
            }
            else if (strncmp(key->via.str.ptr, "output", key->via.str.size) == 0) {
                if (val->type != MSGPACK_OBJECT_STR) {
                    ret = -1;
                    goto parse_error;
                }
                if (output_name != NULL) {
                    flb_sds_destroy(output_name);
                }
                output_name = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
            }
            else if (strncmp(key->via.str.ptr, "params", key->via.str.size) == 0) {
                if (val->type != MSGPACK_OBJECT_MAP) {
                    ret = -1;
                    goto parse_error;
                }
                if (props != NULL) {
                    flb_free(props);
                }
                props = flb_calloc(1, sizeof(struct mk_list));
                flb_kv_init(props);
                for (x = 0; x < val->via.map.size; x++) {
                    param = &val->via.map.ptr[x];
                    if (param->val.type != MSGPACK_OBJECT_STR) {
                        ret = -1;
                        goto parse_error;
                    }
                    if (param->key.type != MSGPACK_OBJECT_STR) {
                        ret = -1;
                        goto parse_error;
                    }
                    param_key = &param->key.via.str;
                    param_val = &param->val.via.str;
                    flb_kv_item_create_len(props,
                                          (char *)param_key->ptr, param_key->size,
                                          (char *)param_val->ptr, param_val->size);
                }
            }
        }

        if (output_name == NULL) {
            output_name = flb_sds_create("stdout");
        }

        toggled_on = enable_trace_input(hs, input_name, input_nlen, prefix, output_name, props);
        if (!toggled_on) {
            ret = -1;
            goto parse_error;
        }
    }

parse_error:
    if (prefix) flb_sds_destroy(prefix);
    if (output_name) flb_sds_destroy(output_name);
    if (props != NULL) {
        flb_kv_release(props);
        flb_free(props);
    }
    return ret;
}

static int http_enable_trace(mk_request_t *request, void *data,
                             const char *input_name, ssize_t input_nlen,
                             msgpack_packer *mp_pck)
{
    char *buf = NULL;
    size_t buf_size;
    msgpack_unpacked result;
    int ret = -1;
    int rc = -1;
    int i;
    int x;
    size_t off = 0;
    int root_type = MSGPACK_OBJECT_ARRAY;
    struct flb_hs *hs = data;
    flb_sds_t prefix = NULL;
    flb_sds_t output_name = NULL;
    msgpack_object *key;
    msgpack_object *val;
    struct mk_list *props = NULL;
    struct flb_chunk_trace_limit limit = { 0 };
    struct flb_input_instance *input_instance;


    if (request->method == MK_METHOD_GET) {
        ret = enable_trace_input(hs, input_name, input_nlen, "trace.", "stdout", NULL);
        if (ret == 0) {
                msgpack_pack_map(mp_pck, 1);
                msgpack_pack_str_with_body(mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
                msgpack_pack_str_with_body(mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
                return 200;
        }
        else {
            flb_error("unable to enable tracing for %.*s", (int)input_nlen, input_name);
            goto input_error;
        }
    }

    msgpack_unpacked_init(&result);
    rc = flb_pack_json(request->data.data, request->data.len, &buf, &buf_size,
                       &root_type, NULL);
    if (rc == -1) {
        ret = 503;
        flb_error("unable to parse json parameters");
        goto unpack_error;
    }

    rc = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (rc != MSGPACK_UNPACK_SUCCESS) {
        ret = 503;
        flb_error("unable to unpack msgpack parameters for %.*s", (int)input_nlen, input_name);
        goto unpack_error;
    }

    if (result.data.type == MSGPACK_OBJECT_MAP) {
        for (i = 0; i < result.data.via.map.size; i++) {
            key = &result.data.via.map.ptr[i].key;
            val = &result.data.via.map.ptr[i].val;

            if (key->type != MSGPACK_OBJECT_STR) {
                ret = 503;
                flb_error("non string key in parameters");
                goto parse_error;
            }

            if (strncmp(key->via.str.ptr, "prefix", key->via.str.size) == 0) {
                if (val->type != MSGPACK_OBJECT_STR) {
                    ret = 503;
                    flb_error("prefix is not a string");
                    goto parse_error;
                }
                if (prefix != NULL) {
                    flb_sds_destroy(prefix);
                }
                prefix = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
            }
            else if (strncmp(key->via.str.ptr, "output", key->via.str.size) == 0) {
                if (val->type != MSGPACK_OBJECT_STR) {
                    ret = 503;
                    flb_error("output is not a string");
                    goto parse_error;
                }
                if (output_name != NULL) {
                    flb_sds_destroy(output_name);
                }
                output_name = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
            }
            else if (strncmp(key->via.str.ptr, "params", key->via.str.size) == 0) {
                if (val->type != MSGPACK_OBJECT_MAP) {
                    ret = 503;
                    flb_error("output params is not a maps");
                    goto parse_error;
                }
                props = flb_calloc(1, sizeof(struct mk_list));
                flb_kv_init(props);
                for (x = 0; x < val->via.map.size; x++) {
                    if (val->via.map.ptr[x].val.type != MSGPACK_OBJECT_STR) {
                        ret = 503;
                        flb_error("output parameter key is not a string");
                        goto parse_error;
                    }
                    if (val->via.map.ptr[x].key.type != MSGPACK_OBJECT_STR) {
                        ret = 503;
                        flb_error("output parameter value is not a string");
                        goto parse_error;
                    }
                    flb_kv_item_create_len(props,
                                            (char *)val->via.map.ptr[x].key.via.str.ptr, val->via.map.ptr[x].key.via.str.size,
                                            (char *)val->via.map.ptr[x].val.via.str.ptr, val->via.map.ptr[x].val.via.str.size);
                }
            }
            else if (strncmp(key->via.str.ptr, "limit", key->via.str.size) == 0) {
                if (val->type != MSGPACK_OBJECT_MAP) {
                    ret = 503;
                    flb_error("limit must be a map of limit types");
                    goto parse_error;
                }
                if (val->via.map.size != 1) {
                    ret = 503;
                    flb_error("limit must have a single limit type");
                    goto parse_error;
                }
                if (val->via.map.ptr[0].key.type != MSGPACK_OBJECT_STR) {
                    ret = 503;
                    flb_error("limit type (key) must be a string");
                    goto parse_error;
                }
                if (val->via.map.ptr[0].val.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    ret = 503;
                    flb_error("limit type must be an integer");
                    goto parse_error;
                }
                if (strncmp(val->via.map.ptr[0].key.via.str.ptr, "seconds", val->via.map.ptr[0].key.via.str.size) == 0) {
                    limit.type = FLB_CHUNK_TRACE_LIMIT_TIME;
                    limit.seconds = val->via.map.ptr[0].val.via.u64;
                }
                else if (strncmp(val->via.map.ptr[0].key.via.str.ptr, "count", val->via.map.ptr[0].key.via.str.size) == 0) {
                    limit.type = FLB_CHUNK_TRACE_LIMIT_COUNT;
                    limit.count = val->via.map.ptr[0].val.via.u64;
                }
                else {
                    ret = 503;
                    flb_error("unknown limit type");
                    goto parse_error;
                }
            }
        }

        if (output_name == NULL) {
            output_name = flb_sds_create("stdout");
        }

        ret = enable_trace_input(hs, input_name, input_nlen, prefix, output_name, props);
        if (ret != 0) {
            flb_error("error when enabling tracing");
            goto parse_error;
        }

        if (limit.type != 0) {
            input_instance = find_input(hs, input_name, input_nlen);
            if (limit.type == FLB_CHUNK_TRACE_LIMIT_TIME) {
                flb_chunk_trace_context_set_limit(input_instance->chunk_trace_ctxt, limit.type, limit.seconds);
            }
            else if (limit.type == FLB_CHUNK_TRACE_LIMIT_COUNT) {
                flb_chunk_trace_context_set_limit(input_instance->chunk_trace_ctxt, limit.type, limit.count);
            }
        }
    }

    msgpack_pack_map(mp_pck, 1);
    msgpack_pack_str_with_body(mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
    msgpack_pack_str_with_body(mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);

    ret = 200;
parse_error:
    if (prefix) flb_sds_destroy(prefix);
    if (output_name) flb_sds_destroy(output_name);
    if (props != NULL) {
        flb_kv_release(props);
        flb_free(props);
    }
unpack_error:
    msgpack_unpacked_destroy(&result);
    if (buf != NULL) {
        flb_free(buf);
    }
input_error:
    return ret;
}

static void cb_trace(mk_request_t *request, void *data)
{
    flb_sds_t out_buf;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    int response = 404;
    flb_sds_t input_name = NULL;


    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    input_name = get_input_name(request);
    if (input_name == NULL) {
        response = 404;
        goto error;
    }

    if (request->method == MK_METHOD_POST || request->method == MK_METHOD_GET) {
        response = http_enable_trace(request, data, input_name, flb_sds_len(input_name), &mp_pck);
    }
    else if (request->method == MK_METHOD_DELETE) {
        response = http_disable_trace(request, data, input_name, flb_sds_len(input_name), &mp_pck);
    }
error:
    if (response == 404) {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_NOTFOUND, HTTP_RESULT_NOTFOUND_LEN);
    }
    else if (response == 503) {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_ERROR, HTTP_RESULT_ERROR_LEN);
    }

    if (input_name != NULL) {
        flb_sds_destroy(input_name);
    }

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    if (out_buf == NULL) {
        mk_http_status(request, 503);
        mk_http_done(request);
        return;
    }

    mk_http_status(request, response);
    mk_http_send(request, out_buf, flb_sds_len(out_buf), NULL);
    mk_http_done(request);

    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_sds_destroy(out_buf);
}

static void cb_traces(mk_request_t *request, void *data)
{
    flb_sds_t out_buf;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    int ret;
    char *buf = NULL;
    size_t buf_size;
    int root_type = MSGPACK_OBJECT_ARRAY;
    msgpack_unpacked result;
    flb_sds_t error_msg = NULL;
    int response = 200;
    const char *input_name;
    ssize_t input_nlen;
    msgpack_object_array *inputs = NULL;
    size_t off = 0;
    int i;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    ret = flb_pack_json(request->data.data, request->data.len, &buf, &buf_size,
                        &root_type, NULL);
    if (ret == -1) {
        goto unpack_error;
    }

    ret = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        ret = -1;
        error_msg = flb_sds_create("unfinished input");
        goto unpack_error;
    }

    if (result.data.type != MSGPACK_OBJECT_MAP) {
        response = 503;
        error_msg = flb_sds_create("input is not an object");
        goto unpack_error;
    }

    for (i = 0; i < result.data.via.map.size; i++) {
        if (result.data.via.map.ptr[i].val.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }
        if (result.data.via.map.ptr[i].key.type != MSGPACK_OBJECT_STR) {
            continue;
        }
        if (result.data.via.map.ptr[i].key.via.str.size < STR_INPUTS_LEN) {
            continue;
        }
        if (strncmp(result.data.via.map.ptr[i].key.via.str.ptr, STR_INPUTS, STR_INPUTS_LEN)) {
            continue;
        }
        inputs = &result.data.via.map.ptr[i].val.via.array;
    }

    if (inputs == NULL) {
        response = 503;
        error_msg = flb_sds_create("inputs not found");
        goto unpack_error;
    }

    msgpack_pack_map(&mp_pck, 2);

    msgpack_pack_str_with_body(&mp_pck, STR_INPUTS, STR_INPUTS_LEN);
    msgpack_pack_map(&mp_pck, inputs->size);

    for (i = 0; i < inputs->size; i++) {

        if (inputs->ptr[i].type != MSGPACK_OBJECT_STR || inputs->ptr[i].via.str.ptr == NULL) {
            response = 503;
            error_msg = flb_sds_create("invalid input");
            msgpack_sbuffer_clear(&mp_sbuf);
            goto unpack_error;
        }
    }

    for (i = 0; i < inputs->size; i++) {

        input_name = inputs->ptr[i].via.str.ptr;
        input_nlen = inputs->ptr[i].via.str.size;

        msgpack_pack_str_with_body(&mp_pck, input_name, input_nlen);

        if (request->method == MK_METHOD_POST) {

            ret = msgpack_params_enable_trace((struct flb_hs *)data, &result,
                                              input_name, input_nlen);

            if (ret != 0) {
                msgpack_pack_map(&mp_pck, 2);
                msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
                msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_ERROR, HTTP_RESULT_ERROR_LEN);
                msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_RETURNCODE,
                                           HTTP_FIELD_RETURNCODE_LEN);
                msgpack_pack_int64(&mp_pck, ret);
            }
            else {
                msgpack_pack_map(&mp_pck, 1);
                msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
                msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
            }
        }
        else if (request->method == MK_METHOD_DELETE) {
            disable_trace_input((struct flb_hs *)data, input_name, input_nlen);
            msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
            msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
        }
        else {
            msgpack_pack_map(&mp_pck, 2);
            msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
            msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_ERROR, HTTP_RESULT_ERROR_LEN);
            msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_MESSAGE, HTTP_FIELD_MESSAGE_LEN);
            msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_METHODNOTALLOWED,
                                       HTTP_RESULT_METHODNOTALLOWED_LEN);
        }
    }

    msgpack_pack_str_with_body(&mp_pck, "result", strlen("result"));
unpack_error:
    if (buf != NULL) {
        flb_free(buf);
    }
    msgpack_unpacked_destroy(&result);
    if (response == 404) {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_NOTFOUND, HTTP_RESULT_NOTFOUND_LEN);
    }
    else if (response == 503) {
        msgpack_pack_map(&mp_pck, 2);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_MESSAGE, HTTP_FIELD_MESSAGE_LEN);
        if (error_msg) {
            msgpack_pack_str_with_body(&mp_pck, error_msg, flb_sds_len(error_msg));
            flb_sds_destroy(error_msg);
        }
        else {
            msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_UNKNOWNERROR,
                                       HTTP_RESULT_UNKNOWNERROR_LEN);
        }
    }
    else {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, HTTP_FIELD_STATUS, HTTP_FIELD_STATUS_LEN);
        msgpack_pack_str_with_body(&mp_pck, HTTP_RESULT_OK, HTTP_RESULT_OK_LEN);
    }

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    if (out_buf == NULL) {
        out_buf = flb_sds_create("serialization error");
    }
    msgpack_sbuffer_destroy(&mp_sbuf);

    mk_http_status(request, response);
    mk_http_send(request,
                 out_buf, flb_sds_len(out_buf), NULL);
    mk_http_done(request);

    flb_sds_destroy(out_buf);
}

/* Perform registration */
int api_v1_trace(struct flb_hs *hs)
{
    if (hs->config->enable_chunk_trace == FLB_TRUE) {
        mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/traces/", cb_traces, hs);
        mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/trace/*", cb_trace, hs);
    }
    return 0;
}
