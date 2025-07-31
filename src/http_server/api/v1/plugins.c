/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
static void cb_plugins(mk_request_t *request, void *data)
{
    int len;
    flb_sds_t out_buf;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct mk_list *head;
    struct flb_input_plugin *in;
    struct flb_filter_plugin *filter;
    struct flb_output_plugin *out;
    struct flb_hs *hs = data;
    struct flb_config *config = hs->config;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "plugins", 7);

    /*
     * plugins are: inputs, filters, outputs
     */
    msgpack_pack_map(&mp_pck, 3);

    /* Inputs */
    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "inputs", 6);
    len = mk_list_size(&config->in_plugins);
    msgpack_pack_array(&mp_pck, len);
    mk_list_foreach(head, &hs->config->in_plugins) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);
        len = strlen(in->name);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, in->name, len);
    }

    /* Filters */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "filters", 7);
    len = mk_list_size(&config->filter_plugins);
    msgpack_pack_array(&mp_pck, len);
    mk_list_foreach(head, &config->filter_plugins) {
        filter = mk_list_entry(head, struct flb_filter_plugin, _head);
        len = strlen(filter->name);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, filter->name, len);
    }

    /* Outputs */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "outputs", 7);
    len = mk_list_size(&config->out_plugins);
    msgpack_pack_array(&mp_pck, len);
    mk_list_foreach(head, &config->out_plugins) {
        out = mk_list_entry(head, struct flb_output_plugin, _head);
        len = strlen(out->name);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, out->name, len);
    }

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    msgpack_sbuffer_destroy(&mp_sbuf);

    mk_http_status(request, 200);
    mk_http_send(request,
                 out_buf, flb_sds_len(out_buf), NULL);
    mk_http_done(request);

    flb_sds_destroy(out_buf);
}

/* Perform registration */
int api_v1_plugins(struct flb_hs *hs)
{
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/plugins", cb_plugins, hs);
    return 0;
}
