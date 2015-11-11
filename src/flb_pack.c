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
#include <string.h>

#include <msgpack.h>
#include <jsmn/jsmn.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

static int json_tokenise(char *js, size_t len, int *arr_size,
                         jsmn_parser *parser, jsmntok_t **tokens)
{
    int ret;
    unsigned int n = 256;
    jsmntok_t *t;

    t = *tokens;
    t = calloc(1, sizeof(jsmntok_t) * n);
    if (!tokens) {
        return -1;
    }

    ret = jsmn_parse(parser, js, len, t, n);
    while (ret == JSMN_ERROR_NOMEM) {
        n = n * 2 + 1;
        t = realloc(t, sizeof(jsmntok_t) * n);
        if (!t) {
            goto error;
        }
        *tokens = t;
        ret = jsmn_parse(parser, js, len, t, n);
    }

    if (ret == JSMN_ERROR_INVAL) {
        flb_utils_error(FLB_ERR_JSON_INVAL);
        goto error;
    }

    if (ret == JSMN_ERROR_PART) {
        /* This is a partial JSON message, just stop */
        goto error;
    }

    /* Store the array length */
    *arr_size = n;
    *tokens = t;
    return 0;

 error:
    free(t);
    return -1;
}

static char *tokens_to_msgpack(char *js,
                               jsmntok_t *tokens, int arr_size, int *out_size)
{
    int i;
    int flen;
    char *p;
    char *buf;
    jsmntok_t *t;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;

    /* initialize buffers */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    for (i = 0; i < arr_size ; i++) {
        t = &tokens[i];
        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }
        flen = (t->end - t->start);

        switch (t->type) {
        case JSMN_OBJECT:
            msgpack_pack_map(&pck, t->size);
            break;
        case JSMN_ARRAY:
            msgpack_pack_array(&pck, t->size);
            break;
        case JSMN_STRING:
            msgpack_pack_bin(&pck, flen);
            msgpack_pack_bin_body(&pck, js + t->start, flen);
            break;
        case JSMN_PRIMITIVE:
            p = js + t->start;
            if (strncmp(p, "false", 5) == 0) {
                msgpack_pack_false(&pck);
            }
            else if (strncmp(p, "true", 4) == 0) {
                msgpack_pack_true(&pck);
            }
            else if (strncmp(p, "null", 4) == 0) {
                msgpack_pack_nil(&pck);
            }
            else {
                msgpack_pack_int64(&pck, atol(p));
            }
            break;
        }
    }

    /* dump data back to a new buffer */
    *out_size = sbuf.size;
    buf = malloc(sbuf.size);
    memcpy(buf, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);

    return buf;
}

/* It parse a JSON string and convert it to MessagePack format */
char *flb_pack_json(char *js, size_t len, int *size)
{
    int ret;
    int arr_size;
    int out;
    char *buf;
    jsmntok_t *tokens;
    jsmn_parser parser;

    if (!js) {
        return NULL;
    }

    jsmn_init(&parser);
    ret = json_tokenise(js, len, &arr_size, &parser, &tokens);
    if (ret != 0) {
        return NULL;
    }

    buf = tokens_to_msgpack(js, tokens, arr_size, &out);
    free(tokens);

    if (!buf) {
        return NULL;
    }

    *size = out;
    return buf;
}

void flb_pack_print(char *data, size_t bytes)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        /* FIXME: lazy output */
        printf("[%zd] ", cnt++);
        msgpack_object_print(stdout, result.data);
        printf("\n");
    }
    msgpack_unpacked_destroy(&result);
}
