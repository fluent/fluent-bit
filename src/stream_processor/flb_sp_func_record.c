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
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>

static inline void pack_key(msgpack_packer *mp_pck,
                            struct flb_sp_cmd_key *cmd_key,
                            const char *name, int len)
{
    if (cmd_key->alias) {
        msgpack_pack_str(mp_pck, flb_sds_len(cmd_key->alias));
        msgpack_pack_str_body(mp_pck, cmd_key->alias,
                              flb_sds_len(cmd_key->alias));
    }
    else {
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, name, len);
    }
}

static int func_tag(const char *tag, int tag_len,
                    msgpack_packer *mp_pck, struct flb_sp_cmd_key *cmd_key)
{
    pack_key(mp_pck, cmd_key, "RECORD_TAG()", 12);
    msgpack_pack_str(mp_pck, tag_len);
    msgpack_pack_str_body(mp_pck, tag, tag_len);

    return 1;
}

static int func_time(struct flb_time *tms, msgpack_packer *mp_pck,
                     struct flb_sp_cmd_key *cmd_key)
{
    double t;

    t = flb_time_to_double(tms);
    pack_key(mp_pck, cmd_key, "RECORD_TIME()", 13);
    msgpack_pack_double(mp_pck, t);

    return 1;
}

/*
 * Wrapper to handle record functions, returns the number of entries added
 * to the map.
 */
int flb_sp_func_record(const char *tag, int tag_len, struct flb_time *tms,
                       msgpack_packer *mp_pck, struct flb_sp_cmd_key *cmd_key)
{
    switch (cmd_key->record_func) {
    case FLB_SP_RECORD_TAG:
        return func_tag(tag, tag_len, mp_pck, cmd_key);
    case FLB_SP_RECORD_TIME:
        return func_time(tms, mp_pck, cmd_key);
    };

    return 0;
}
