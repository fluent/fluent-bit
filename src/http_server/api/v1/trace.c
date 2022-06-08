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
#include <msgpack.h>

/* API: List all built-in plugins */
static void cb_enable_trace(mk_request_t *request, void *data)
{
    flb_sds_t out_buf;
    struct mk_list *head;
    char *buf;
    size_t buf_size;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    int ret;
    size_t off = 0;
    int root_type = MSGPACK_OBJECT_ARRAY;
    struct flb_input_instance *in;
    struct flb_hs *hs = data;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);

    ret = flb_pack_json(request->data.data, request->data.len, &buf, &buf_size, &root_type);
    if (ret == -1) {
        goto error;
    }
    ret = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (ret == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_STR) {
            mk_list_foreach(head, &hs->config->inputs) {
                in = mk_list_entry(head, struct flb_input_instance, _head);
                if (strncmp(result.data.via.str.ptr, in->name, result.data.via.str.size) == 0 &&
                    strlen(in->name) == result.data.via.str.size) {
                        in->trace_enabled = !in->trace_enabled;
                        msgpack_pack_map(&mp_pck, 2);
                        msgpack_pack_str_with_body(&mp_pck, "status", strlen("status"));
                        msgpack_pack_str_with_body(&mp_pck, "ok", strlen("ok"));
                        msgpack_pack_str_with_body(&mp_pck, "enabled", strlen("enabled"));
                        if (in->trace_enabled) msgpack_pack_true(&mp_pck);
                        else msgpack_pack_false(&mp_pck);

                        out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
                        mk_http_status(request, 200);
                        mk_http_send(request,
                                     out_buf, flb_sds_len(out_buf), NULL);
                        mk_http_done(request);
                        flb_sds_destroy(out_buf);
                        msgpack_sbuffer_destroy(&mp_sbuf);
                        msgpack_unpacked_destroy(&result);
                        return;
                }
            }
        }
    }

error:
    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str_with_body(&mp_pck, "status", strlen("status"));
    msgpack_pack_str_with_body(&mp_pck, "not found", strlen("not found"));
    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);

    mk_http_status(request, 404);
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
