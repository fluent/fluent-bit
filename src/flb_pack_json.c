/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#include <fluent-bit.h>
#include <fluent-bit/flb_pack_json.h>

static int flb_pack_json_ext_internal(const char *json, size_t len,
                                      char **out_buf, size_t *out_size,
                                      int *out_root_type, int *out_records,
                                      size_t *consumed,
                                      struct flb_pack_opts *opts,
                                      int require_records)
{
    int ret;
    int backend;
    int state_out_size = 0;
    struct flb_pack_state *state = NULL;

    if (!opts) {
        backend = FLB_PACK_JSON_BACKEND_YYJSON;
    }
    else {
        backend = opts->backend;
        state = opts->state;
    }

    if (backend != FLB_PACK_JSON_BACKEND_JSMN &&
        backend != FLB_PACK_JSON_BACKEND_YYJSON) {
        return -1;
    }

    if (backend == FLB_PACK_JSON_BACKEND_JSMN) {
        if (state) {
            state_out_size = 0;

            /* state for incremental reads */
            if (require_records) {
                return -1;
            }

            ret = flb_pack_json_state(json, len, out_buf,
                                      &state_out_size, state);
            if (ret == 0 && out_size) {
                *out_size = (size_t) state_out_size;
            }

            return ret;
        }

        if (require_records) {
            return flb_pack_json_recs(json, len, out_buf, out_size,
                                      out_root_type, out_records, consumed);
        }

        return flb_pack_json(json, len, out_buf, out_size,
                             out_root_type, NULL);
    }
    else if (backend == FLB_PACK_JSON_BACKEND_YYJSON) {
        if (require_records) {
            return flb_pack_json_recs_yyjson(json, len, out_buf, out_size,
                                             out_root_type, out_records,
                                             consumed);
        }

        return flb_pack_json_yyjson(json, len, out_buf, out_size,
                                    out_root_type, NULL);
    }

    /* unknown backend */
    return -1;
}

int flb_pack_json_ext(const char *json, size_t len,
                      char **out_buf, size_t *out_size,
                      int *out_root_type,
                      struct flb_pack_opts *opts)
{
    return flb_pack_json_ext_internal(json, len, out_buf, out_size,
                                      out_root_type, NULL, NULL,
                                      opts, FLB_FALSE);
}

int flb_pack_json_recs_ext(const char *json, size_t len,
                           char **out_buf, size_t *out_size,
                           int *out_root_type, int *out_records,
                           size_t *consumed, struct flb_pack_opts *opts)
{
    return flb_pack_json_ext_internal(json, len, out_buf, out_size,
                                      out_root_type, out_records,
                                      consumed, opts, FLB_TRUE);
}
