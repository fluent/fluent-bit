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
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

#define TYPE_OUT_STRING  0  /* unstructured text         */
#define TYPE_OUT_OBJECT  1  /* structured msgpack object */

/* Decode a stringified JSON message */
static int decode_json(struct flb_parser_dec *dec,
                       char *in_buf, size_t in_size,
                       char **out_buf, size_t *out_size, int *out_type)
{
    int len;
    int ret;
    char *buf;
    size_t size;

    /* JSON Decoder: content may be escaped */
    len = flb_unescape_string(in_buf, in_size, &dec->buffer);

    /* It must be a map or array */
    if (dec->buffer[0] != '{' && dec->buffer[0] != '[') {
        return -1;
    }

    /* Convert from unescaped JSON to MessagePack */
    ret = flb_pack_json(dec->buffer, len, &buf, &size);
    if (ret != 0) {
        return -1;
    }

    *out_buf = buf;
    *out_size = size;
    *out_type = TYPE_OUT_OBJECT;

    return 0;
}

static int decode_escaped(struct flb_parser_dec *dec,
                          char *in_buf, size_t in_size,
                          char **out_buf, size_t *out_size, int *out_type)
{
    int len;

    /* Unescape string */
    len = flb_unescape_string(in_buf, in_size, &dec->buffer);
    *out_buf = dec->buffer;
    *out_size = len;
    *out_type = TYPE_OUT_STRING;

    return 0;
}

static int decode_escaped_utf8(struct flb_parser_dec *dec,
                          char *in_buf, size_t in_size,
                          char **out_buf, size_t *out_size, int *out_type)
{
    int len;

    len = flb_unescape_string_utf8(in_buf, in_size, dec->buffer);
    *out_buf = dec->buffer;
    *out_size = len;
    *out_type = TYPE_OUT_STRING;

    return 0;
}

static int merge_record_and_extra_keys(char *in_buf, size_t in_size,
                                       char *extra_buf, size_t extra_size,
                                       char **out_buf, size_t *out_size)
{
    int i;
    int ret;
    int map_size = 0;
    size_t in_off = 0;
    size_t extra_off = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;
    msgpack_unpacked in_result;
    msgpack_unpacked extra_result;
    msgpack_object k;
    msgpack_object v;
    msgpack_object map;

    msgpack_unpacked_init(&in_result);
    msgpack_unpacked_init(&extra_result);

    /* Check if the extra buffer have some serialized data */
    ret = msgpack_unpack_next(&extra_result, extra_buf, extra_size, &extra_off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&in_result);
        msgpack_unpacked_destroy(&extra_result);
        return -1;
    }
    ret = msgpack_unpack_next(&in_result, in_buf, in_size, &in_off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }


    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    map_size = in_result.data.via.map.size;
    map_size += extra_result.data.via.map.size;

    msgpack_pack_map(&mp_pck, map_size);
    map = in_result.data;
    for (i = 0; i < map.via.map.size; i++) {
        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;
        msgpack_pack_object(&mp_pck, k);
        msgpack_pack_object(&mp_pck, v);
    }

    map = extra_result.data;
    for (i = 0; i < map.via.map.size; i++) {
        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;
        msgpack_pack_object(&mp_pck, k);
        msgpack_pack_object(&mp_pck, v);
    }

    msgpack_unpacked_destroy(&in_result);
    msgpack_unpacked_destroy(&extra_result);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

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
    int is_decoded;
    int is_decoded_as;
    int in_type;
    int out_type;
    int dec_type;
    int extra_keys = FLB_FALSE;
    size_t off = 0;
    char *dec_buf;
    size_t dec_size;
    flb_sds_t tmp_sds = NULL;
    flb_sds_t data_sds = NULL;
    flb_sds_t in_sds = NULL;
    flb_sds_t out_sds = NULL;
    struct mk_list *head;
    struct mk_list *r_head;
    struct flb_parser_dec *dec = NULL;
    struct flb_parser_dec_rule *rule;
    msgpack_object k;
    msgpack_object v;
    msgpack_object map;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;
    /* Contexts to handle extra keys to be appended at the end of the log */
    msgpack_sbuffer extra_mp_sbuf;
    msgpack_packer  extra_mp_pck;

    /* Initialize unpacker */
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, in_buf, in_size, &off) < 0)
        return -1;
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

        if (!in_sds) {
            in_sds  = flb_sds_create_size(v.via.str.size);
            if (!in_sds) {
                break;
            }
            out_sds = flb_sds_create_size(v.via.str.size);
            if (!out_sds) {
                break;
            }
            data_sds = flb_sds_create_size(v.via.str.size);
        }

        /* Copy original content */
        tmp_sds = flb_sds_copy(data_sds, (char *) v.via.str.ptr,
                               v.via.str.size);
        if (tmp_sds != data_sds) {
            data_sds = tmp_sds;
        }

        /*
         * We got a match: 'key name' == 'decoder field name', validate
         * that we have enough space in our temporal buffer.
         */
        if (flb_sds_alloc(dec->buffer) < flb_sds_alloc(data_sds)) {
            /* Increase buffer size */
            size_t diff;
            diff = (flb_sds_alloc(data_sds) - flb_sds_alloc(dec->buffer));
            tmp_sds = flb_sds_increase(dec->buffer, diff);
            if (!tmp_sds) {
                flb_errno();
                break;
            }
            if (tmp_sds != dec->buffer) {
                dec->buffer = tmp_sds;
            }
        }

        /* Process decoder rules */
        ret = -1;
        dec_buf = NULL;

        /*
         * If some rule type is FLB_PARSER_DEC_DEFAULT, means that it will
         * try to register some extra fields as part of the record. For such
         * case we prepare a temporal buffer to hold these extra keys.
         *
         * The content of this buffer is just a serialized number of maps.
         */
        if (dec->add_extra_keys == FLB_TRUE) {
            extra_keys = FLB_TRUE;
            msgpack_sbuffer_init(&extra_mp_sbuf);
            msgpack_packer_init(&extra_mp_pck, &extra_mp_sbuf,
                                msgpack_sbuffer_write);
        }

        mk_list_foreach(r_head, &dec->rules) {
            rule = mk_list_entry(r_head, struct flb_parser_dec_rule, _head);

            if (rule->type == FLB_PARSER_DEC_DEFAULT &&
                rule->action == FLB_PARSER_ACT_DO_NEXT &&
                is_decoded == FLB_TRUE) {
                continue;
            }

            if (is_decoded_as == FLB_TRUE && in_type != TYPE_OUT_STRING) {
                continue;
            }

            /* Process using defined decoder backend */
            if (rule->backend == FLB_PARSER_DEC_JSON) {
                ret = decode_json(dec, (char *) data_sds, flb_sds_len(data_sds),
                                  &dec_buf, &dec_size, &dec_type);
            }
            else if (rule->backend == FLB_PARSER_DEC_ESCAPED) {
                ret = decode_escaped(dec,
                                     (char *) data_sds, flb_sds_len(data_sds),
                                     &dec_buf, &dec_size, &dec_type);
            }
            else if (rule->backend == FLB_PARSER_DEC_ESCAPED_UTF8) {
                ret = decode_escaped_utf8(dec,
                                     (char *) data_sds, flb_sds_len(data_sds),
                                     &dec_buf, &dec_size, &dec_type);
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

            /* Internal packing: replace value content in the same key */
            if (rule->type == FLB_PARSER_DEC_AS) {
                tmp_sds = flb_sds_copy(in_sds, dec_buf, dec_size);
                if (tmp_sds != in_sds) {
                    in_sds = tmp_sds;
                }
                tmp_sds = flb_sds_copy(data_sds, dec_buf, dec_size);
                if (tmp_sds != data_sds) {
                    data_sds = tmp_sds;
                }
                in_type = dec_type;
                is_decoded_as = FLB_TRUE;
            }
            else if (rule->type == FLB_PARSER_DEC_DEFAULT) {
                tmp_sds = flb_sds_copy(out_sds, dec_buf, dec_size);
                if (tmp_sds != out_sds) {
                    out_sds = tmp_sds;
                }
                out_type = dec_type;
                is_decoded = FLB_TRUE;
            }


            if (dec_buf != dec->buffer) {
                flb_free(dec_buf);
            }
            dec_buf = NULL;
            dec_size = 0;

            /* Apply more rules ? */
            if (rule->action == FLB_PARSER_ACT_DO_NEXT) {
                continue;
            }
            break;
        }

        /* Package the key */
        msgpack_pack_object(&mp_pck, k);

        /* We need to place some value for the key in question */
        if (is_decoded_as == FLB_TRUE) {
            if (in_type == TYPE_OUT_STRING) {
                msgpack_pack_str(&mp_pck, flb_sds_len(in_sds));
                msgpack_pack_str_body(&mp_pck,
                                      in_sds, flb_sds_len(in_sds));
            }
            else if (in_type == TYPE_OUT_OBJECT) {
                msgpack_sbuffer_write(&mp_sbuf,
                                      in_sds, flb_sds_len(in_sds));
            }
        }
        else {
            /* Pack original value */
            msgpack_pack_object(&mp_pck, v);
        }

        /* Package as external keys */
        if (is_decoded == FLB_TRUE) {
            if (out_type == TYPE_OUT_STRING) {
                flb_error("[parser_decoder] string type is not allowed");
            }
            else if (out_type == TYPE_OUT_OBJECT) {
                msgpack_sbuffer_write(&extra_mp_sbuf,
                                      out_sds, flb_sds_len(out_sds));
            }
        }
    }

    if (in_sds) {
        flb_sds_destroy(in_sds);
    }
    if (out_sds) {
        flb_sds_destroy(out_sds);
    }
    if (data_sds) {
        flb_sds_destroy(data_sds);
    }

    msgpack_unpacked_destroy(&result);
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    if (extra_keys == FLB_TRUE) {
        ret = merge_record_and_extra_keys(mp_sbuf.data, mp_sbuf.size,
                                          extra_mp_sbuf.data, extra_mp_sbuf.size,
                                          out_buf, out_size);
        msgpack_sbuffer_destroy(&extra_mp_sbuf);
        if (ret == 0) {
            msgpack_sbuffer_destroy(&mp_sbuf);
            return 0;
        }
    }

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
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* We expect at least two values: decoder name and target field */
        size = mk_list_size(split);
        if (size < 2) {
            flb_error("[parser] invalid number of parameters in decoder");
            flb_utils_split_free(split);
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
        else if (strcasecmp(decoder->value, "escaped_utf8") == 0) {
            backend = FLB_PARSER_DEC_ESCAPED_UTF8;
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
            flb_parser_decoder_list_destroy(list);
            return NULL;
        }

        /* Create decoder context */
        dec_rule = flb_calloc(1, sizeof(struct flb_parser_dec_rule));
        if (!dec_rule) {
            flb_errno();
            flb_utils_split_free(split);
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
        flb_sds_destroy(dec->buffer);
        flb_free(dec);
        c++;
    }

    flb_free(list);
    return c;
}
