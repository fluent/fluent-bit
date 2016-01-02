/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include <fluent-bit/flb_config.h>
#include "es.h"

#define ES_HTTP_HEADER_SIZE  512

char *es_http_request(char *data, size_t len,
                      size_t *out_len,
                      struct flb_out_es_config *ctx, struct flb_config *config)
{
    int bytes;
    char *req;
    char *fmt =
        "POST /_bulk HTTP/1.1\r\n"
        "User-Agent: Fluent-Bit\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %lu\r\n\r\n";

    req = malloc(ES_HTTP_HEADER_SIZE + len);
    if (!req) {
        return NULL;
    }

    bytes = snprintf(req, ES_HTTP_HEADER_SIZE, fmt, len);
    memcpy(req + bytes, data, len);

    *out_len = (bytes + len);
    return req;
}
