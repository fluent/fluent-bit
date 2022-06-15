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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_trace_chunk.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>


struct flb_input_instance *find_input(struct flb_hs *hs, const char *name)
{
    struct mk_list *head;
    struct flb_input_instance *in;


    mk_list_foreach(head, &hs->config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        if (strcmp(name, in->name) == 0) {
            return in;
        }
    }
    return NULL;
}

static int enable_trace_input(struct flb_hs *hs, const char *name, const char *prefix, const char *output_name, struct mk_list *props)
{
    struct flb_input_instance *in;
    

    in = find_input(hs, name);
    if (in == NULL) {
        return -1;
    }

    if (in->trace_ctxt != NULL) {
        flb_free(in->trace_ctxt);
    }
    in->trace_ctxt = flb_trace_chunk_context_new(hs->config, output_name, prefix, props);
    return (in->trace_ctxt == NULL ? -1 : 1);
}

static int disable_trace_input(struct flb_hs *hs, const char *name)
{
    struct flb_input_instance *in;
    

    in = find_input(hs, name);
    if (in == NULL) {
        return -1;
    }

    if (in->trace_ctxt != NULL) {
        flb_free(in->trace_ctxt);
    }
    in->trace_ctxt = NULL;
    return 0;
}

static int toggle_trace_input(struct flb_hs *hs, const char *name, const char *prefix, const char *output_name, struct mk_list *props)
{
    struct flb_input_instance *in;
    

    in = find_input(hs, name);
    if (in == NULL) {
        return -1;
    }

    if (in->trace_ctxt == NULL) {
        in->trace_ctxt = flb_trace_chunk_context_new(hs->config, output_name, prefix, props);
        return 1;
    } else {
        // check to see if we have one to destroy it...
        flb_free(in->trace_ctxt);
        in->trace_ctxt = NULL;
        return 0;
    }
}

/* API: List all built-in plugins */
static void cb_enable_trace(mk_request_t *request, void *data)
{
    flb_sds_t out_buf;
    char *buf = NULL;
    size_t buf_size;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    int ret;
    int i;
    int x;
    size_t off = 0;
    int root_type = MSGPACK_OBJECT_ARRAY;
    struct flb_hs *hs = data;
    flb_sds_t input_name = NULL;
    flb_sds_t prefix = NULL;
    flb_sds_t output_name = NULL;
    flb_sds_t enable_disable_str = NULL;
    int toggled_on = -1;
    int enable_disable = -1;
    msgpack_object *key;
    msgpack_object *val;
    struct mk_list *props = NULL;
    int response = 404;


    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);

    ret = flb_pack_json(request->data.data, request->data.len, &buf, &buf_size, &root_type);
    if (ret == -1) {
        response = 503;
        goto done;
    }

    ret = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (ret == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_STR) {
            input_name = flb_sds_create_len(result.data.via.str.ptr, result.data.via.str.size);
            toggled_on = toggle_trace_input(hs, input_name, "trace.", "stdout", (struct mk_list *)NULL);
            flb_sds_destroy(input_name);
        } else if (result.data.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < result.data.via.map.size; i++) {
                key = &result.data.via.map.ptr[i].key;
                val = &result.data.via.map.ptr[i].val;
                if (key->type != MSGPACK_OBJECT_STR) {
                    goto error;
                }
                if (strncmp(key->via.str.ptr, "input", key->via.str.size) == 0) {
                    if (val->type != MSGPACK_OBJECT_STR) {
                        goto error;
                    }
                    if (input_name != NULL) {
                        flb_sds_destroy(input_name);
                    }
                    input_name = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
                }
                if (strncmp(key->via.str.ptr, "prefix", key->via.str.size) == 0) {
                    if (val->type != MSGPACK_OBJECT_STR) {
                        goto error;
                    }
                    if (prefix != NULL) {
                        flb_sds_destroy(prefix);
                    }
                    prefix = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
                }
                if (strncmp(key->via.str.ptr, "output", key->via.str.size) == 0) {
                    if (val->type != MSGPACK_OBJECT_STR) {
                        goto error;
                    }
                    if (output_name != NULL) {
                        flb_sds_destroy(output_name);
                    }
                    output_name = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
                }
                if (strncmp(key->via.str.ptr, "params", key->via.str.size) == 0) {
                    if (val->type != MSGPACK_OBJECT_MAP) {
                        goto error;
                    }
                    props = flb_calloc(1, sizeof(struct mk_list));
                    flb_kv_init(props);
                    for (x = 0; x < val->via.map.size; x++) {
                        if (val->via.map.ptr[x].val.type != MSGPACK_OBJECT_STR) {
                            goto error;
                        }
                        if (val->via.map.ptr[x].key.type != MSGPACK_OBJECT_STR) {
                            goto error;
                        }
                        flb_kv_item_create_len(props,
                                               (char *)val->via.map.ptr[x].key.via.str.ptr, val->via.map.ptr[x].key.via.str.size,
                                               (char *)val->via.map.ptr[x].val.via.str.ptr, val->via.map.ptr[x].val.via.str.size);
                    }
                }
                if (strncmp(key->via.str.ptr, "enable", key->via.str.size) == 0) {
                    if (val->type == MSGPACK_OBJECT_BOOLEAN) {
                        enable_disable = val->via.boolean;
                    } else if (val->type == MSGPACK_OBJECT_STR) {
                        enable_disable_str = flb_sds_create_len(val->via.str.ptr, val->via.str.size);
                        enable_disable = flb_utils_bool(enable_disable_str);
                        flb_sds_destroy(enable_disable_str);
                    }
                }
            }

            if (output_name == NULL) {
                output_name = flb_sds_create("stdout");
            }

            switch (enable_disable) {
            case -1:
                toggled_on = toggle_trace_input(hs, input_name, prefix, output_name, props);
                break;
            case 1:
                toggled_on = enable_trace_input(hs, input_name, prefix, output_name, props);
                break;
            case 0:
                toggled_on = 0;
                disable_trace_input(hs, input_name);
                break;
            }
            if (prefix) flb_sds_destroy(prefix);
            if (input_name) flb_sds_destroy(input_name);
            if (output_name) flb_sds_destroy(output_name);
            if (props != NULL) {
                flb_kv_release(props);
                flb_free(props);
            }
        }

        msgpack_pack_map(&mp_pck, 2);
        msgpack_pack_str_with_body(&mp_pck, "status", strlen("status"));
        msgpack_pack_str_with_body(&mp_pck, "ok", strlen("ok"));
        msgpack_pack_str_with_body(&mp_pck, "enabled", strlen("enabled"));
        if (toggled_on) msgpack_pack_true(&mp_pck);
        else msgpack_pack_false(&mp_pck);

        response = 200;
    }

error:
done:
    if (buf != NULL) {
        flb_free(buf);
    }
    
    if (response == 404) {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, "status", strlen("status"));
        msgpack_pack_str_with_body(&mp_pck, "not found", strlen("not found"));
    } else if (response == 503) {
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, "status", strlen("status"));
        msgpack_pack_str_with_body(&mp_pck, "error", strlen("error"));
    }

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);

    mk_http_status(request, response);
    mk_http_send(request,
                 out_buf, flb_sds_len(out_buf), NULL);
    mk_http_done(request);

    flb_sds_destroy(out_buf);
}

/* Perform registration */
int api_v1_trace(struct flb_hs *hs)
{
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/trace", cb_enable_trace, hs);
    return 0;
}
