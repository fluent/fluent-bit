/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <stdlib.h>

#include <jsmn/jsmn.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

static jsmntok_t *json_tokenise(char *js, size_t len)
{
    int ret;
    unsigned int n;
    jsmntok_t *tokens;
    jsmn_parser parser;

    jsmn_init(&parser);
    tokens = malloc(sizeof(jsmntok_t) * n);
    ret = jsmn_parse(&parser, js, len, tokens, n);

    while (ret == JSMN_ERROR_NOMEM) {
        n = n * 2 + 1;
        tokens = realloc(tokens, sizeof(jsmntok_t) * n);
        ret = jsmn_parse(&parser, js, len, tokens, n);
    }

    if (ret == JSMN_ERROR_INVAL) {
        flb_utils_error(FLB_ERR_JSON_INVAL);
        goto error;
    }

    if (ret == JSMN_ERROR_PART) {
        flb_utils_error(FLB_ERR_JSON_PART);
        goto error;
    }
    return tokens;

 error:
    free(tokens);
    return NULL;
}

/* It parse a JSON string and convert it to MessagePack format */
char *flb_pack_json(char *js, size_t len, int *size)
{
    jsmntok_t *tokens;

    tokens = json_tokenise(js, len);
    if (!tokens) {
        return NULL;
    }


    return NULL;
}
