/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser_decoder.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

static int unescape_string(char *buf, int buf_len, char **unesc_buf)
{
    int i = 0;
    int j = 0;
    char *p;
    char n;

    p = *unesc_buf;
    while (i < buf_len) {
        if (buf[i] == '\\') {
            if (i + 1 < buf_len) {
                n = buf[i + 1];
                if (n == 'n') {
                    p[j++] = '\n';
                    i++;
                }
                else if (n == 'a') {
                    p[j++] = '\a';
                    i++;
                }
                else if (n == 'b') {
                    p[j++] = '\b';
                    i++;
                }
                else if (n == 't') {
                    p[j++] = '\t';
                    i++;
                }
                else if (n == 'v') {
                    p[j++] = '\v';
                    i++;
                }
                else if (n == 'f') {
                    p[j++] = '\f';
                    i++;
                }
                else if (n == 'r') {
                    p[j++] = '\r';
                    i++;
                }
                i++;
                continue;
            }
            else {
                i++;
            }
        }
        p[j++] = buf[i++];
    }
    p[j] = '\0';
    return j;
}

/* Decode a stringified JSON message */
static int decode_json(struct flb_parser_dec *dec,
                       char *in_buf, size_t in_size,
                       char **out_buf, size_t *out_size)
{
    int len;
    int ret;
    char *buf;
    size_t size;

    /* JSON Decoder: content may be escaped */
    len = unescape_string(in_buf, in_size, &dec->buf_data);

    /* Is it JSON valid ? (pre validation to avoid mem allocation on tokens */
    ret = flb_pack_json_valid(dec->buf_data, len);
    if (ret == -1) {
        /* Invalid or no JSON Message */
        return -1;
    }

    /* It must be a map */
    if (dec->buf_data[0] != '{') {
        return -1;
    }

    /* Convert from unescaped JSON to MessagePack */
    ret = flb_pack_json(dec->buf_data, len, &buf, &size);
    if (ret != 0) {
        return -1;
    }

    *out_buf = buf;
    *out_size = size;

    return 0;
}

static int decode_escaped(struct flb_parser_dec *dec,
                          char *in_buf, size_t in_size,
                          char **out_buf, size_t *out_size)
{
    int len;

    /* Unescape string */
    len = unescape_string(in_buf, in_size, &dec->buf_data);
    *out_buf = dec->buf_data;
    *out_size = len;

    return 0;
}

/*
 * Given a msgpack map, apply the parser-decoder rules defined and generate
 * a new msgpack buffer.
 */
int flb_parser_decoder_do(struct mk_list *decoders,
                          char *in_buf, size_t in_size,
                          char **out_buf, size_t *out_size)
{
    int i;
    int ret;
    int matched;
    int decoded;
    size_t off = 0;
    char *dec_buf;
    size_t dec_size;
    char *tmp;
    struct mk_list *head;
    struct flb_parser_dec *dec;
    msgpack_object k;
    msgpack_object v;
    msgpack_object map;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;

    /* Initialize unpacker */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, in_buf, in_size, &off);
    map = result.data;

    if (map.type != MSGPACK_OBJECT_MAP) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /*
     * First check if any field in the record matches a decoder rule. It's
     * better to check this before hand otherwise we need to jump directly
     * to create a "possible new outgoing buffer".
     */
    matched = -1;
    for (i = 0; i < map.via.map.size; i++) {
        k = map.via.map.ptr[i].key;
        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        /* Try to match this key name with decoder's rule */
        mk_list_foreach(head, decoders) {
            dec = mk_list_entry(head, struct flb_parser_dec, _head);
            if (dec->key_len == k.via.str.size &&
                strncmp(dec->key_name, k.via.str.ptr, dec->key_len) == 0) {
                /* we have a match, stop the check */
                matched = i;
                break;
            }
            else {
                matched = -1;
            }
        }

        if (matched >= 0) {
            break;
        }
    }

    /* No matches, no need to continue */
    if (matched == -1) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* Create new outgoing buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Register the map (same size) */
    msgpack_pack_map(&mp_pck, map.via.map.size);

    /* Compose new outgoing buffer */
    for (i = 0; i < map.via.map.size; i++) {
        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;

        /* Pack right away previous fields in the map */
        if (i < matched) {
            msgpack_pack_object(&mp_pck, k);
            msgpack_pack_object(&mp_pck, v);
            continue;
        }

        /* Process current key names and decoder rules */
        if (k.type != MSGPACK_OBJECT_STR || v.type != MSGPACK_OBJECT_STR) {
            msgpack_pack_object(&mp_pck, k);
            msgpack_pack_object(&mp_pck, v);
            continue;
        }

        /* Check if the current key name matches some decoder rule */
        decoded = FLB_FALSE;
        mk_list_foreach(head, decoders) {
            dec = mk_list_entry(head, struct flb_parser_dec, _head);
            if (dec->key_len != k.via.str.size ||
                strncmp(dec->key_name, k.via.str.ptr, dec->key_len) != 0) {
                continue;
            }

            /* We got a match: 'key name' == 'decoder field name' */
            if (dec->buf_size < v.via.str.size) {
                tmp = flb_realloc(dec->buf_data, v.via.str.size);
                if (!tmp) {
                    flb_errno();
                    break;
                }

                dec->buf_data = tmp;
                dec->buf_size = v.via.str.size;
            }

            ret = -1;
            decoded = FLB_FALSE;
            dec_buf = NULL;

            /* Choose decoder */
            if (dec->type == FLB_PARSER_DEC_JSON) {
                ret = decode_json(dec, (char *) v.via.str.ptr, v.via.str.size,
                                  &dec_buf, &dec_size);
            }
            else if (dec->type == FLB_PARSER_DEC_ESCAPED) {
                ret = decode_escaped(dec, (char *) v.via.str.ptr, v.via.str.size,
                                     &dec_buf, &dec_size);
            }

            /* Check decoder status */
            if (ret == -1) {
                /* Current decoder failed, should we try the next one ? */
                if (dec->action == FLB_PARSER_ACT_TRY_NEXT) {
                    continue;
                }
            }
            else {
                decoded = FLB_TRUE;
                msgpack_pack_object(&mp_pck, k);
                if (dec_buf == dec->buf_data) {
                    msgpack_pack_str(&mp_pck, dec_size);
                    msgpack_pack_str_body(&mp_pck, dec_buf, dec_size);
                }
                else {
                    msgpack_sbuffer_write(&mp_sbuf, dec_buf, dec_size);
                }
            }
            break;
        }

        if (decoded == FLB_TRUE) {
            if (dec_buf != dec->buf_data) {
                flb_free(dec_buf);
            }
            dec_buf = NULL;
            dec_size = 0;
        }
        else {
            msgpack_pack_object(&mp_pck, k);
            msgpack_pack_object(&mp_pck, v);
        }

    }

    msgpack_unpacked_destroy(&result);
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

struct mk_list *flb_parser_decoder_list_create(struct mk_rconf_section *section)
{
    int c = 0;
    int type;
    int size;
    struct mk_rconf_entry *entry;
    struct mk_list *head;
    struct mk_list *list = NULL;
    struct mk_list *split;
    struct flb_split_entry *decoder;
    struct flb_split_entry *field;
    struct flb_split_entry *action;
    struct flb_parser_dec *dec;

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);
        if (strcasecmp(entry->key, "Decode_Field") != 0) {
            continue;
        }

        /* Split the value */
        split = flb_utils_split(entry->val, ' ', 3);
        if (!split) {
            flb_error("[parser] invalid number of parameters in decoder");
            flb_free(list);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* We expect at least two values: decoder name and target field */
        size = mk_list_size(split);
        if (size < 2) {
            flb_error("[parser] invalid number of parameters in decoder");
            flb_utils_split_free(split);
            flb_free(list);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* Get entry references */
        decoder = mk_list_entry_first(split, struct flb_split_entry, _head);
        field = mk_list_entry_next(&decoder->_head, struct flb_split_entry,
                                   _head, list);
        if (size >= 3) {
            action = mk_list_entry_next(&field->_head, struct flb_split_entry,
                                        _head, list);
        }
        else {
            action = NULL;
        }

        /* Get decoder */
        if (strcasecmp(decoder->value, "json") == 0) {
            type = FLB_PARSER_DEC_JSON;
        }
        else if (strcasecmp(decoder->value, "escaped") == 0) {
            type = FLB_PARSER_DEC_ESCAPED;
        }
        else {
            flb_error("[parser] field decoder '%s' unknown", decoder->value);
            flb_utils_split_free(split);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* Create decoder context */
        dec = flb_calloc(1, sizeof(struct flb_parser_dec));
        if (!dec) {
            flb_errno();
            flb_free(list);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        dec->type = type;
        if (action) {
            if (strcasecmp(action->value, "try_next") == 0) {
                dec->action = FLB_PARSER_ACT_TRY_NEXT;
            }
            else {
                dec->action = FLB_PARSER_ACT_NONE;
            }
        }

        dec->key_name = flb_strdup(field->value);
        dec->key_len  = strlen(field->value);
        dec->buf_data = flb_malloc(FLB_PARSER_DEC_BUF_SIZE);
        dec->buf_size = FLB_PARSER_DEC_BUF_SIZE;

        /* Remove temporal split */
        flb_utils_split_free(split);

        if (!dec->buf_data) {
            flb_errno();
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        mk_list_add(&dec->_head, list);
        c++;
    }

    if (c == 0) {
        flb_free(list);
        return NULL;
    }

    return list;
}

int flb_parser_decoder_list_destroy(struct mk_list *list)
{
    int c = 0;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_parser_dec *dec;

    mk_list_foreach_safe(head, tmp, list) {
        dec = mk_list_entry(head, struct flb_parser_dec, _head);
        mk_list_del(&dec->_head);
        flb_free(dec->key_name);
        flb_free(dec->buf_data);
        flb_free(dec);
        c++;
    }

    flb_free(list);
    return c;
}
