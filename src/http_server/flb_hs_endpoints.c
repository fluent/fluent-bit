/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_http_server.h>
#include <msgpack.h>

/* Create a JSON buffer with informational data about the running service */
static int endpoint_root(struct flb_hs *hs)
{
    int c;
    flb_sds_t out_buf;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct mk_list *head;
    struct mk_list *list;
    struct flb_split_entry *entry;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Return minimal information without sensitive details */
    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "status", 6);
    msgpack_pack_str(&mp_pck, 2);
    msgpack_pack_str_body(&mp_pck, "ok", 2);

    /* export as JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (out_buf) {
        hs->ep_root_buf  = out_buf;
        hs->ep_root_size = flb_sds_len(out_buf);
    }

    return -1;
}

int flb_hs_endpoints(struct flb_hs *hs)
{
    endpoint_root(hs);
    return 0;
}

/* Release cached data from endpoints */
int flb_hs_endpoints_free(struct flb_hs *hs)
{
    if (hs->ep_root_buf) {
        flb_sds_destroy(hs->ep_root_buf);
    }

    return 0;
}
