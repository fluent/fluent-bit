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

#ifndef FLB_PACK_JSON_H
#define FLB_PACK_JSON_H

#include <fluent-bit/flb_pack.h>

#define FLB_PACK_JSON_BACKEND_JSMN    1
#define FLB_PACK_JSON_BACKEND_YYJSON  2


struct flb_pack_opts {
    /* which backend to use (default, jsmn, yyjson) */
    int backend;

    /* optional: required only for JSMN in streaming mode */
    struct flb_pack_state *state;
};

int flb_pack_json_ext(const char *json, size_t len,
                      char **out_buf, size_t *out_size,
                      int *out_root_type,
                      struct flb_pack_opts *opts);

#endif

