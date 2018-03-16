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
    len = unescape_string(in_buf, in_size, &dec->buffer);

    /* Is it JSON valid ? (pre validation to avoid mem allocation on tokens */
    ret = flb_pack_json_valid(dec->buffer, len);
    if (ret == -1) {
        /* Invalid or no JSON Message */
        return -1;
    }

    /* It must be a map */
    if (dec->buffer[0] != '{') {
        return -1;
    }

    /* Convert from unescaped JSON to MessagePack */
    ret = flb_pack_json(dec->buffer, len, &buf, &size);
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
    len = unescape_string(in_buf, in_size, &dec->buffer);
    *out_buf = dec->buffer;
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
    int is_decoded;
    int is_decoded_as;
    int count_new_keys;
    size_t off = 0;
    char *dec_buf;
    size_t dec_size;
    char *tmp;
    flb_sds_t tmp_sds;
    struct mk_list *head;
    struct mk_list *r_head;
    struct flb_parser_dec *dec;
    struct flb_parser_dec_rule *rule;
    msgpack_object k;
    msgpack_object v;
    msgpack_object map;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;
    /* Contexts to handle extra keys to be appended at the end of the log */
    size_t extra_off;
    msgpack_sbuffer extra_mp_sbuf;
    msgpack_packer  extra_mp_pck;
    msgpack_unpacked extra_result;

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
            int r = flb_sds_cmp(dec->key, (char *) k.via.str.ptr,
                                k.via.str.size);
            if (flb_sds_cmp(dec->key, (char *) k.via.str.ptr,
                            k.via.str.size) == 0) {
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

        /* New keys counter: used for a successful Decode_Field case */
        count_new_keys = 0;

        /*
         * Per key, we allow only one successful 'Decode_Field' and one
         * successful 'Decode_Field_As' rules. Otherwise it may lead
         * to duplicated entries in the final map.
         *
         * is_decoded    => Decode_Field successul ?
         * is_decoded_as => Decode_Field_As successful ?
         */
        is_decoded = FLB_FALSE;
        is_decoded_as = FLB_FALSE;

        /* Lookup for decoders associated to the current 'key' */
        mk_list_foreach(head, decoders) {
            dec = mk_list_entry(head, struct flb_parser_dec, _head);
            if (flb_sds_cmp(dec->key, (char *) k.via.str.ptr,
                            k.via.str.size) == 0) {
                break;
            }
            dec = NULL;
        }

        /* No decoder found, pack content */
        if (!dec) {
            msgpack_pack_object(&mp_pck, k);
            msgpack_pack_object(&mp_pck, v);
            continue;
        }

        /*
         * We got a match: 'key name' == 'decoder field name', validate
         * that we have enough space in our temporal buffer.
         */
        if (flb_sds_alloc(dec->buffer) < v.via.str.size) {
            /* Increase buffer size */
            size_t diff = (v.via.str.size - flb_sds_alloc(dec->buffer));
            tmp_sds = flb_sds_increase(dec->buffer, diff);
            if (!tmp_sds) {
                flb_errno();
                break;
            }
            dec->buffer = tmp_sds;
        }

        /* Process decoder rules */
        ret = -1;
        decoded = FLB_FALSE;
        dec_buf = NULL;

        /*
         * If some rule type is FLB_PARSER_DEC_DEFAULT, means that it will
         * try to register some extra fields as part of the record. For such
         * case we prepare a temporal buffer to hold these extra keys.
         *
         * The content of this buffer is just a serialized number of maps.
         */
        if (dec->add_extra_keys == FLB_TRUE) {
            msgpack_sbuffer_init(&extra_mp_sbuf);
            msgpack_packer_init(&extra_mp_pck, &extra_mp_sbuf,
                                msgpack_sbuffer_write);
        }

        mk_list_foreach(r_head, &dec->rules) {
            rule = mk_list_entry(r_head, struct flb_parser_dec_rule, _head);

            /* Process using defined decoder backend */
            if (rule->backend == FLB_PARSER_DEC_JSON) {
                ret = decode_json(dec, (char *) v.via.str.ptr, v.via.str.size,
                                  &dec_buf, &dec_size);
            }
            else if (rule->backend == FLB_PARSER_DEC_ESCAPED) {
                ret = decode_escaped(dec, (char *) v.via.str.ptr, v.via.str.size,
                                     &dec_buf, &dec_size);
            }

            /* Check decoder status */
            if (ret == -1) {
                /* Current decoder failed, should we try the next one ? */
                if (rule->action == FLB_PARSER_ACT_TRY_NEXT ||
                    rule->action == FLB_PARSER_ACT_DO_NEXT) {
                    continue;
                }

                /* Stop: no more rules should be applied */
                break;
            }

            decoded = FLB_TRUE;

            /* Pack the key */
            msgpack_pack_object(&mp_pck, k);

            /* Content was decoded, now.. where to pack the results ? */
            if (rule->type == FLB_PARSER_DEC_AS) {
                /* The value of the key will be replaced with the results */
                if (dec_buf == dec->buffer) {
                    msgpack_pack_str(&mp_pck, dec_size);
                    msgpack_pack_str_body(&mp_pck, dec_buf, dec_size);
                }
                else {
                    msgpack_sbuffer_write(&mp_sbuf, dec_buf, dec_size);
                }

                is_decoded_as = FLB_TRUE;
            }
            else if (rule->type == FLB_PARSER_DEC_DEFAULT) {
                /*
                 * Decoded results will be packaged as separate key/values,
                 * but it keeps the original value in place.
                 */
                msgpack_pack_object(&mp_pck, v);

                /* Pack the content into the extra msgpack buffer */
                if (dec_buf == dec->buffer) {
                    msgpack_pack_str(&extra_mp_pck, dec_size);
                    msgpack_pack_str_body(&extra_mp_pck, dec_buf, dec_size);
                }
                else {
                    msgpack_sbuffer_write(&extra_mp_sbuf, dec_buf, dec_size);
                }

                is_decoded = FLB_TRUE;
            }

            /* Apply more rules ? */
            if (rule->action == FLB_PARSER_ACT_DO_NEXT) {
                continue;
            }
            break;
        }

        flb_pack_print(extra_mp_sbuf.data, extra_mp_sbuf.size);

        if (decoded == FLB_TRUE) {
            if (dec_buf != dec->buffer) {
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

/*
 * Iterate decoders list and lookup for an existing context for 'key_name',
 * if it does not exists, create and link a new one
 */
static struct flb_parser_dec *get_decoder_key_context(char *key_name, int key_len,
                                                      struct mk_list *list)
{
    struct mk_list *head;
    struct flb_parser_dec *dec = NULL;

    mk_list_foreach(head, list) {
        dec = mk_list_entry(head, struct flb_parser_dec, _head);

        /* Check if the decoder matches the requested key name */
        if (flb_sds_cmp(dec->key, key_name, key_len) != 0) {
            dec = NULL;
            continue;
        }
        else {
            break;
        }
    }

    if (!dec) {
        dec = flb_malloc(sizeof(struct flb_parser_dec));
        if (!dec) {
            flb_errno();
            return NULL;
        }

        dec->key = flb_sds_create_len(key_name, key_len);
        if (!dec->key) {
            flb_errno();
            flb_free(dec);
            return NULL;
        }

        dec->buffer = flb_sds_create_size(FLB_PARSER_DEC_BUF_SIZE);
        if (!dec->buffer) {
            flb_errno();
            flb_sds_destroy(dec->key);
            flb_free(dec);
            return NULL;
        }
        dec->add_extra_keys = FLB_FALSE;
        mk_list_init(&dec->rules);
        mk_list_add(&dec->_head, list);
    }

    return dec;
}

struct mk_list *flb_parser_decoder_list_create(struct mk_rconf_section *section)
{
    int c = 0;
    int type;
    int backend;
    int size;
    struct mk_rconf_entry *entry;
    struct mk_list *head;
    struct mk_list *list = NULL;
    struct mk_list *split;
    struct flb_split_entry *decoder;
    struct flb_split_entry *field;
    struct flb_split_entry *action;
    struct flb_parser_dec *dec;
    struct flb_parser_dec_rule *dec_rule;

    /* Global list to be referenced by parent parser definition */
    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);


    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);

        /* Lookup for specific Decode rules */
        if (strcasecmp(entry->key, "Decode_Field") == 0) {
            type = FLB_PARSER_DEC_DEFAULT;
        }
        else if (strcasecmp(entry->key, "Decode_Field_As") == 0) {
            type = FLB_PARSER_DEC_AS;
        }
        else {
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

        /*
         * Get the rule/entry references:
         *
         * decoder: specify the backend that handle decoding (json, escaped..)
         * field  : the 'key' where decoding should happen
         * action : optional rules to follow on success or failure
         */
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
            backend = FLB_PARSER_DEC_JSON;
        }
        else if (strcasecmp(decoder->value, "escaped") == 0) {
            backend = FLB_PARSER_DEC_ESCAPED;
        }
        else {
            flb_error("[parser] field decoder '%s' unknown", decoder->value);
            flb_utils_split_free(split);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* Get the parent decoder that will hold the rules defined */
        dec = get_decoder_key_context(field->value, strlen(field->value), list);
        if (!dec) {
            /* Unexpected error */
            flb_error("[parser] unexpected error, could not get a decoder");
            flb_utils_split_free(split);
            flb_free(list);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* Create decoder context */
        dec_rule = flb_calloc(1, sizeof(struct flb_parser_dec_rule));
        if (!dec_rule) {
            flb_errno();
            flb_free(list);
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        if (type == FLB_PARSER_DEC_DEFAULT) {
            dec->add_extra_keys = FLB_TRUE;
        }

        dec_rule->type = type;
        dec_rule->backend = backend;
        if (action) {
            if (strcasecmp(action->value, "try_next") == 0) {
                dec_rule->action = FLB_PARSER_ACT_TRY_NEXT;
            }
            else if (strcasecmp(action->value, "do_next") == 0) {
                dec_rule->action = FLB_PARSER_ACT_DO_NEXT;
            }
            else {
                dec_rule->action = FLB_PARSER_ACT_NONE;
            }
        }

        /* Remove temporal split */
        flb_utils_split_free(split);
        mk_list_add(&dec_rule->_head, &dec->rules);
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
    struct mk_list *r_head;
    struct mk_list *tmp;
    struct mk_list *r_tmp;
    struct flb_parser_dec *dec;
    struct flb_parser_dec_rule *dec_rule;

    mk_list_foreach_safe(head, tmp, list) {
        dec = mk_list_entry(head, struct flb_parser_dec, _head);

        /* Destroy rules */
        mk_list_foreach_safe(r_head, r_tmp, &dec->rules) {
            dec_rule = mk_list_entry(r_head, struct flb_parser_dec_rule,
                                     _head);
            mk_list_del(&dec_rule->_head);
            flb_free(dec_rule);
        }

        mk_list_del(&dec->_head);
        flb_sds_destroy(dec->key);
        flb_free(dec);
        c++;
    }

    flb_free(list);
    return c;
}
