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

static int func_now(msgpack_packer *mp_pck, struct flb_sp_cmd_key *cmd_key)
{
    size_t len;
    time_t now;
    char buf[32];
    struct tm *local;

    local = flb_malloc(sizeof(struct tm));
    if (!local) {
        flb_errno();
        return 0;
    }

    /* Get current system time */
    now = time(NULL);
    localtime_r(&now, local);

    /* Format string value */
    len = strftime(buf, sizeof(buf) - 1, "%Y-%m-%d %H:%M:%S", local);
    flb_free(local);

    pack_key(mp_pck, cmd_key, "NOW()", 5);
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, buf, len);

    return 1;
}

static int func_unix_timestamp(msgpack_packer *mp_pck,
                               struct flb_sp_cmd_key *cmd_key)
{
    time_t now;

    /* Get unix timestamp */
    now = time(NULL);

    pack_key(mp_pck, cmd_key, "UNIX_TIMESTAMP()", 16);
    msgpack_pack_uint64(mp_pck, now);
    return 1;
}

/*
 * Wrapper to handle time functions, returns the number of entries added
 * to the map.
 */
int flb_sp_func_time(msgpack_packer *mp_pck, struct flb_sp_cmd_key *cmd_key)
{
    switch (cmd_key->time_func) {
    case FLB_SP_NOW:
        return func_now(mp_pck, cmd_key);
    case FLB_SP_UNIX_TIMESTAMP:
        return func_unix_timestamp(mp_pck, cmd_key);
    };

    return 0;
}
