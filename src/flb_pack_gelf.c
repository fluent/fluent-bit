/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_unescape.h>

#include <ctype.h>

static char gelf_valid_key_char[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static flb_sds_t flb_msgpack_gelf_key(flb_sds_t *s, int in_array,
                                      const char *prefix_key, int prefix_key_len,
                                      int concat,
                                      const char *key, int key_len)
{
    int i;
    flb_sds_t tmp;
    int start_len, end_len;

    if (in_array == FLB_FALSE) {
        tmp = flb_sds_cat(*s, ", \"", 3);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
    }

    if (prefix_key_len > 0) {
        start_len = flb_sds_len(*s);

        tmp = flb_sds_cat(*s, prefix_key, prefix_key_len);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;

        end_len = flb_sds_len(*s);
        for(i=start_len; i < end_len; i++) {
            if (!gelf_valid_key_char[(unsigned char)(*s)[i]]) {
                (*s)[i] = '_';
            }
        }
    }

    if (concat == FLB_TRUE) {
        tmp = flb_sds_cat(*s, "_", 1);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
    }

    if (key_len > 0) {
        start_len = flb_sds_len(*s);

        tmp = flb_sds_cat(*s, key, key_len);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;

        end_len = flb_sds_len(*s);
        for(i=start_len; i < end_len; i++) {
            if (!gelf_valid_key_char[(unsigned char)(*s)[i]]) {
                (*s)[i] = '_';
            }
        }
    }

    if (in_array == FLB_FALSE) {
        tmp = flb_sds_cat(*s, "\":", 2);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
    }
    else {
        tmp = flb_sds_cat(*s, "=", 1);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
    }

    return *s;
}

static flb_sds_t flb_msgpack_gelf_value(flb_sds_t *s, int quote,
                                        const char *val, int val_len)
{
    flb_sds_t tmp;

    if (quote == FLB_TRUE) {
        tmp = flb_sds_cat(*s, "\"", 1);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;

        if (val_len > 0) {
            tmp = flb_sds_cat_utf8(s, val, val_len);
            if (tmp == NULL) {
                return NULL;
            }
            *s = tmp;
        }

        tmp = flb_sds_cat(*s, "\"", 1);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
    }
    else {
        tmp = flb_sds_cat(*s, val, val_len);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
    }

    return *s;
}

static flb_sds_t flb_msgpack_gelf_value_ext(flb_sds_t *s, int quote,
                                            const char *val, int val_len)
{
    static const char int2hex[] = "0123456789abcdef";
    flb_sds_t tmp;

    if (quote == FLB_TRUE) {
        tmp = flb_sds_cat(*s, "\"", 1);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
    }
    /* ext body. fortmat is similar to printf(1) */
    {
        int i;
        char temp[5];
        for(i=0; i < val_len; i++) {
            char c = (char)val[i];
            temp[0] = '\\';
            temp[1] = 'x';
            temp[2] = int2hex[ (unsigned char) ((c & 0xf0) >> 4)];
            temp[3] = int2hex[ (unsigned char) (c & 0x0f)];
            temp[4] = '\0';
            tmp = flb_sds_cat(*s, temp, 4);
            if (tmp == NULL) {
                return NULL;
            }
            *s = tmp;
        }
    }
    if (quote == FLB_TRUE) {
        tmp = flb_sds_cat(*s, "\"", 1);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
    }

    return *s;
}

static flb_sds_t flb_msgpack_gelf_flatten(flb_sds_t *s, msgpack_object *o,
                                          const char *prefix, int prefix_len,
                                          int in_array)
{
    int i;
    int loop;
    flb_sds_t tmp;

    switch(o->type) {
    case MSGPACK_OBJECT_NIL:
        tmp = flb_sds_cat(*s, "null", 4);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
        break;

    case MSGPACK_OBJECT_BOOLEAN:
        if (o->via.boolean) {
            tmp = flb_msgpack_gelf_value(s, !in_array, "true", 4);
        }
        else {
            tmp = flb_msgpack_gelf_value(s, !in_array, "false", 5);
        }
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
        break;

    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        tmp = flb_sds_printf(s, "%lu", (unsigned long)o->via.u64);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
        break;

    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        tmp = flb_sds_printf(s, "%ld", (signed long)o->via.i64);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
        break;

    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        tmp = flb_sds_printf(s, "%f", o->via.f64);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
        break;

    case MSGPACK_OBJECT_STR:
        tmp = flb_msgpack_gelf_value(s, !in_array,
                                     o->via.str.ptr,
                                     o->via.str.size);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
        break;

    case MSGPACK_OBJECT_BIN:
        tmp = flb_msgpack_gelf_value(s, !in_array,
                                     o->via.bin.ptr,
                                     o->via.bin.size);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
        break;

    case MSGPACK_OBJECT_EXT:
        tmp = flb_msgpack_gelf_value_ext(s, !in_array,
                                         o->via.ext.ptr,
                                         o->via.ext.size);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
        break;

    case MSGPACK_OBJECT_ARRAY:
        loop = o->via.array.size;

        if (!in_array) {
            tmp = flb_sds_cat(*s, "\"", 1);
            if (tmp == NULL) {
                return NULL;
            }
            *s = tmp;
        }
        if (loop != 0) {
            msgpack_object* p = o->via.array.ptr;
            for (i=0; i<loop; i++) {
                if (i > 0) {
                     tmp = flb_sds_cat(*s, ", ", 2);
                     if (tmp == NULL) {
                         return NULL;
                     }
                     *s = tmp;
                }
                tmp = flb_msgpack_gelf_flatten(s, p+i,
                                               prefix, prefix_len,
                                               FLB_TRUE);
                if (tmp == NULL) {
                    return NULL;
                }
                *s = tmp;
            }
        }

        if (!in_array) {
            tmp = flb_sds_cat(*s, "\"", 1);
            if (tmp == NULL) {
                return NULL;
            }
            *s = tmp;
        }
        break;

    case MSGPACK_OBJECT_MAP:
        loop = o->via.map.size;
        if (loop != 0) {
            msgpack_object_kv *p = o->via.map.ptr;
            for (i = 0; i < loop; i++) {
                msgpack_object *k = &((p+i)->key);
                msgpack_object *v = &((p+i)->val);

                if (k->type != MSGPACK_OBJECT_STR) {
                    continue;
                }

                const char *key = k->via.str.ptr;
                int key_len = k->via.str.size;

                if (v->type == MSGPACK_OBJECT_MAP) {
                    char *obj_prefix = NULL;
                    int obj_prefix_len = 0;

                    obj_prefix_len = key_len;
                    if (prefix_len > 0) {
                        obj_prefix_len += prefix_len + 1;
                    }

                    obj_prefix = flb_malloc(obj_prefix_len + 1);
                    if (obj_prefix == NULL) {
                       return NULL;
                    }

                    if (prefix_len > 0) {
                        memcpy(obj_prefix, prefix, prefix_len);
                        obj_prefix[prefix_len] = '_';
                        memcpy(obj_prefix + prefix_len + 1, key, key_len);
                    }
                    else {
                        memcpy(obj_prefix, key, key_len);
                    }
                    obj_prefix[obj_prefix_len] = '\0';

                    tmp = flb_msgpack_gelf_flatten(s, v,
                                                   obj_prefix, obj_prefix_len,
                                                   in_array);
                    if (tmp == NULL) {
                        flb_free(obj_prefix);
                        return NULL;
                    }
                    *s = tmp;

                    flb_free(obj_prefix);
                }
                else {
                    if (in_array == FLB_TRUE && i > 0) {
                        tmp = flb_sds_cat(*s, " ", 1);
                        if (tmp == NULL) {
                            return NULL;
                        }
                        *s = tmp;
                    }
                    if (in_array && prefix_len <= 0) {
                        tmp = flb_msgpack_gelf_key(s, in_array,
                                                   NULL, 0,
                                                   FLB_FALSE,
                                                   key, key_len);
                    }
                    else {
                        tmp = flb_msgpack_gelf_key(s, in_array,
                                                   prefix, prefix_len,
                                                   FLB_TRUE,
                                                   key, key_len);
                    }
                    if (tmp == NULL) {
                        return NULL;
                    }
                    *s = tmp;

                    tmp = flb_msgpack_gelf_flatten(s, v, NULL, 0, in_array);
                    if (tmp == NULL) {
                        return NULL;
                    }
                    *s = tmp;
                }
            }
        }
        break;

    default:
        flb_warn("[%s] unknown msgpack type %i", __FUNCTION__, o->type);
    }

    return *s;
}

flb_sds_t flb_msgpack_to_gelf(flb_sds_t *s, msgpack_object *o,
                              struct flb_time *tm,
                              struct flb_gelf_fields *fields)
{
    int i;
    int loop;
    flb_sds_t tmp;

    int host_key_found = FLB_FALSE;
    int timestamp_key_found = FLB_FALSE;
    int level_key_found = FLB_FALSE;
    int short_message_key_found = FLB_FALSE;
    int full_message_key_found = FLB_FALSE;

    char *host_key = NULL;
    char *timestamp_key = NULL;
    char *level_key = NULL;
    char *short_message_key = NULL;
    char *full_message_key = NULL;

    int host_key_len = 0;
    int timestamp_key_len = false;
    int level_key_len = 0;
    int short_message_key_len = 0;
    int full_message_key_len = 0;

    if (s == NULL || o == NULL) {
        return NULL;
    }

    /* Make sure the incoming object is a map */
    if (o->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    if (fields != NULL && fields->host_key != NULL) {
        host_key = fields->host_key;
        host_key_len = flb_sds_len(fields->host_key);
    }
    else {
        host_key = "host";
        host_key_len = 4;
    }

    if (fields != NULL && fields->timestamp_key != NULL) {
        timestamp_key = fields->timestamp_key;
        timestamp_key_len = flb_sds_len(fields->timestamp_key);
    }
    else {
        timestamp_key = "timestamp";
        timestamp_key_len = 9;
    }

    if (fields != NULL && fields->level_key != NULL) {
        level_key = fields->level_key;
        level_key_len = flb_sds_len(fields->level_key);
    }
    else {
        level_key = "level";
        level_key_len = 5;
    }

    if (fields != NULL && fields->short_message_key != NULL) {
        short_message_key = fields->short_message_key;
        short_message_key_len = flb_sds_len(fields->short_message_key);
    }
    else {
        short_message_key = "short_message";
        short_message_key_len = 13;
    }

    if (fields != NULL && fields->full_message_key != NULL) {
        full_message_key = fields->full_message_key;
        full_message_key_len = flb_sds_len(fields->full_message_key);
    }
    else {
        full_message_key = "full_message";
        full_message_key_len = 12;
    }

    tmp = flb_sds_cat(*s, "{\"version\":\"1.1\"", 16);
    if (tmp == NULL) {
        return NULL;
    }
    *s = tmp;

    loop = o->via.map.size;
    if (loop != 0) {
        msgpack_object_kv *p = o->via.map.ptr;

        for (i = 0; i < loop; i++) {
            const char *key = NULL;
            int key_len;
            const char *val = NULL;
            int val_len = 0;
            int quote = FLB_FALSE;
            int custom_key = FLB_FALSE;

            msgpack_object *k = &p[i].key;
            msgpack_object *v = &p[i].val;
            msgpack_object vtmp; // used when converting level value from string to int

            if (k->type != MSGPACK_OBJECT_BIN && k->type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (k->type == MSGPACK_OBJECT_STR) {
                key = k->via.str.ptr;
                key_len = k->via.str.size;
            }
            else {
                key = k->via.bin.ptr;
                key_len = k->via.bin.size;
            }

            if ((key_len == host_key_len) &&
                !strncmp(key, host_key, host_key_len)) {
                if (host_key_found == FLB_TRUE) {
                    continue;
                }
                host_key_found = FLB_TRUE;
                key = "host";
                key_len = 4;
            }
            else if ((key_len == short_message_key_len) &&
                     !strncmp(key, short_message_key, short_message_key_len)) {
                if (short_message_key_found == FLB_TRUE) {
                    continue;
                }
                short_message_key_found = FLB_TRUE;
                key = "short_message";
                key_len = 13;
            }
            else if ((key_len == timestamp_key_len) &&
                     !strncmp(key, timestamp_key, timestamp_key_len)) {
                if (timestamp_key_found == FLB_TRUE) {
                    continue;
                }
                timestamp_key_found = FLB_TRUE;
                key = "timestamp";
                key_len = 9;
            }
            else if ((key_len == level_key_len) &&
                     !strncmp(key, level_key, level_key_len )) {
                if (level_key_found == FLB_TRUE) {
                    continue;
                }
                level_key_found = FLB_TRUE;
                key = "level";
                key_len = 5;
                if (v->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    if ( v->via.u64 > 7 ) {
                        flb_warn("[flb_msgpack_to_gelf] level is %" PRIu64 ", "
                                  "but should be in 0..7 or a syslog keyword", v->via.u64);
                    }
                }
                else if (v->type == MSGPACK_OBJECT_STR) {
                    val     = v->via.str.ptr;
                    val_len = v->via.str.size;
                    if (val_len == 1 && val[0] >= '0' && val[0] <= '7') {
                        v = &vtmp;
                        v->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
                        v->via.u64 = (uint64_t)(val[0] - '0');
                    }
                    else {
                        int n;
                        char* allowed_levels[] = {
                            "emerg", "alert", "crit", "err",
                            "warning", "notice", "info", "debug",
                            NULL
                        };
                        for (n = 0; allowed_levels[n] != NULL; ++n) {
                            if (val_len == strlen(allowed_levels[n]) &&
                                !strncasecmp(val, allowed_levels[n], val_len)) {
                                v = &vtmp;
                                v->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
                                v->via.u64 = (uint64_t)n;
                                break;
                            }
                        }
                        if (allowed_levels[n] == NULL) {
                            flb_warn("[flb_msgpack_to_gelf] level is '%.*s', "
                                      "but should be in 0..7 or a syslog keyword", val_len, val);
                        }
                    }
                }
                else {
                    flb_error("[flb_msgpack_to_gelf] level must be a non-negative integer or a string");
                    return NULL;
                }
            }
            else if ((key_len == full_message_key_len) &&
                     !strncmp(key, full_message_key, full_message_key_len)) {
                if (full_message_key_found == FLB_TRUE) {
                    continue;
                }
                full_message_key_found = FLB_TRUE;
                key = "full_message";
                key_len = 12;
            }
            else if ((key_len == 2)  && !strncmp(key, "id", 2)) {
                /* _id key not allowed */
                continue;
            }
            else {
                custom_key = FLB_TRUE;
            }

            if (v->type == MSGPACK_OBJECT_MAP) {
                char *prefix = NULL;
                int prefix_len = 0;

                prefix_len = key_len + 1;
                prefix = flb_calloc(1, prefix_len + 1);
                if (prefix == NULL) {
                    return NULL;
                }

                prefix[0] = '_';
                strncpy(prefix + 1, key, key_len);
                prefix[prefix_len] = '\0';

                tmp = flb_msgpack_gelf_flatten(s, v,
                                               prefix, prefix_len, FLB_FALSE);
                if (tmp == NULL) {
                    flb_free(prefix);
                    return NULL;
                }
                *s = tmp;
                flb_free(prefix);

            }
            else if (v->type == MSGPACK_OBJECT_ARRAY) {
                if (custom_key == FLB_TRUE) {
                    tmp = flb_msgpack_gelf_key(s, FLB_FALSE, "_", 1, FLB_FALSE,
                                             key, key_len);
                }
                else {
                    tmp = flb_msgpack_gelf_key(s, FLB_FALSE, NULL, 0, FLB_FALSE,
                                             key, key_len);
                }
                if (tmp == NULL) {
                    return NULL;
                }
                *s = tmp;

                tmp = flb_msgpack_gelf_flatten(s, v, NULL, 0, FLB_FALSE);
                if (tmp == NULL) {
                    return NULL;
                }
                *s = tmp;
            }
            else {
                char temp[48] = {0};
                if (v->type == MSGPACK_OBJECT_NIL) {
                    val = "null";
                    val_len = 4;
                    continue;
                }
                else if (v->type == MSGPACK_OBJECT_BOOLEAN) {
                    quote   = FLB_TRUE;
                    val = v->via.boolean ? "true" : "false";
                    val_len = v->via.boolean ? 4 : 5;
                }
                else if (v->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    val = temp;
                    val_len = snprintf(temp, sizeof(temp) - 1,
                                       "%" PRIu64, v->via.u64);
                    /*
                     * Check if the value length is larger than our string.
                     * this is needed to avoid stack-based overflows.
                     */
                    if (val_len > sizeof(temp)) {
                        return NULL;
                    }
                }
                else if (v->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                    val = temp;
                    val_len = snprintf(temp, sizeof(temp) - 1,
                                       "%" PRId64, v->via.i64);
                    /*
                     * Check if the value length is larger than our string.
                     * this is needed to avoid stack-based overflows.
                     */
                    if (val_len > sizeof(temp)) {
                        return NULL;
                    }
                }
                else if (v->type == MSGPACK_OBJECT_FLOAT) {
                    val = temp;
                    val_len = snprintf(temp, sizeof(temp) - 1,
                                       "%f", v->via.f64);
                    /*
                     * Check if the value length is larger than our string.
                     * this is needed to avoid stack-based overflows.
                     */
                    if (val_len > sizeof(temp)) {
                        return NULL;
                    }
                }
                else if (v->type == MSGPACK_OBJECT_STR) {
                    /* String value */
                    quote   = FLB_TRUE;
                    val     = v->via.str.ptr;
                    val_len = v->via.str.size;
                }
                else if (v->type == MSGPACK_OBJECT_BIN) {
                    /* Bin value */
                    quote   = FLB_TRUE;
                    val     = v->via.bin.ptr;
                    val_len = v->via.bin.size;
                }
                else if (v->type == MSGPACK_OBJECT_EXT) {
                    quote   = FLB_TRUE;
                    val     = v->via.ext.ptr;
                    val_len = v->via.ext.size;
                }

                if (!val || !key) {
                  continue;
                }

                if (custom_key == FLB_TRUE) {
                    tmp = flb_msgpack_gelf_key(s, FLB_FALSE, "_", 1, FLB_FALSE,
                                             key, key_len);
                }
                else {
                    tmp = flb_msgpack_gelf_key(s, FLB_FALSE, NULL, 0, FLB_FALSE,
                                             key, key_len);
                }
                if (tmp == NULL) {
                    return NULL;
                }
                *s = tmp;

                if (v->type == MSGPACK_OBJECT_EXT) {
                    tmp = flb_msgpack_gelf_value_ext(s, quote, val, val_len);
                }
                else {
                    tmp = flb_msgpack_gelf_value(s, quote, val, val_len);
                }
                if (tmp == NULL) {
                    return NULL;
                }
                *s = tmp;
            }
        }
    }

    if (timestamp_key_found == FLB_FALSE && tm != NULL) {
        tmp = flb_msgpack_gelf_key(s, FLB_FALSE, NULL, 0, FLB_FALSE,
                                   "timestamp", 9);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;

        /* gelf supports milliseconds */
        tmp = flb_sds_printf(s, "%" PRIu32".%03lu",
                             tm->tm.tv_sec, tm->tm.tv_nsec / 1000000);
        if (tmp == NULL) {
            return NULL;
        }
        *s = tmp;
    }

    if (short_message_key_found == FLB_FALSE) {
        flb_error("[flb_msgpack_to_gelf] missing short_message key");
        return NULL;
    }

    tmp = flb_sds_cat(*s, "}", 1);
    if (tmp == NULL) {
        return NULL;
    }
    *s = tmp;

    return *s;
}

flb_sds_t flb_msgpack_raw_to_gelf(char *buf, size_t buf_size,
                                  struct flb_time *tm, struct flb_gelf_fields *fields)
{
    int ret;
    size_t off = 0;
    size_t gelf_size;
    msgpack_unpacked result;
    flb_sds_t s;
    flb_sds_t tmp;

    if (!buf || buf_size <= 0) {
        return NULL;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        return NULL;
    }

    gelf_size = (buf_size * 1.3);
    s = flb_sds_create_size(gelf_size);
    if (s == NULL) {
        msgpack_unpacked_destroy(&result);
        return NULL;
    }

    tmp = flb_msgpack_to_gelf(&s, &result.data, tm, fields);
    if (tmp == NULL) {
        flb_sds_destroy(s);
        msgpack_unpacked_destroy(&result);
        return NULL;
    }
    s = tmp;

    msgpack_unpacked_destroy(&result);

    return s;
}

static inline int flb_gelf_pack_string_token(struct flb_pack_state *state,
                                             const char *str, int len,
                                             msgpack_packer *pck)
{
    int s;
    int out_len;
    char *tmp;
    char *out_buf;

    if (state->buf_size < len + 1) {
        s = len + 1;
        tmp = flb_realloc(state->buf_data, s);
        if (!tmp) {
            flb_errno();
            return -1;
        }
        else {
            state->buf_data = tmp;
            state->buf_size = s;
        }
    }
    out_buf = state->buf_data;

    /* Always decode any UTF-8 or special characters */
    out_len = flb_unescape_string_utf8(str, len, out_buf);

    /* Pack decoded text */
    msgpack_pack_str(pck, out_len);
    msgpack_pack_str_body(pck, out_buf, out_len);

    return out_len;
}

static inline int flb_gelf_is_integer(const char *buf, int len)
{
    const char *end = buf + len;
    const char *p = buf;

    while (p < end) {
        if (!isdigit(*p)) {
            return 0;
        }
        p++;
    }

    return 1;
}

int flb_gelf_to_msgpack(const char *js, size_t len, struct flb_time *tm,
                        char **buffer, size_t *size, bool strict)
{
    int i, n;
    int ret = -1;
    int pairs;
    size_t key_len, value_len;
    const char *key_str, *value_str;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;
    jsmntok_t *tokens;
    jsmntok_t *key;
    jsmntok_t *value;
    struct flb_pack_state state;
    bool found_version = false;
    bool found_host = false;
    bool found_short_message = false;

    ret = flb_pack_state_init(&state);
    if (ret != 0) {
        return -1;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    ret = flb_json_tokenise(js, len, &state);
    if (ret != 0) {
        flb_error("[flb_gelf_to_msgpack] error parsing message");
        ret = -1;
        goto flb_pack_gelf_end;
    }

    if (state.tokens_count == 0) {
        flb_error("[flb_gelf_to_msgpack] message is empty");
        ret = -1;
        goto flb_pack_gelf_end;
    }

    if (state.tokens[0].type != JSMN_OBJECT) {
        flb_error("[flb_gelf_to_msgpack] message is not an json object");
        ret = -1;
        goto flb_pack_gelf_end;
    }

    if (state.tokens[0].size == 0) {
        flb_error("[flb_gelf_to_msgpack] message has an empty json object");
        ret = -1;
        goto flb_pack_gelf_end;
    }

    if ((state.tokens_count - 1) != (state.tokens[0].size * 2)) {
        flb_error("[flb_gelf_to_msgpack] parsed message "
                  "has an incorrect number of tokens");
        ret = -1;
        goto flb_pack_gelf_end;
    }

    tokens = state.tokens;
    pairs = state.tokens[0].size;

    for (i = 0; i < tokens->size; i++) {
        key = &tokens[i*2+1];

        if ((key->start == -1) || (key->end == -1) ||
            ((key->start == 0) && (key->end == 0))) {
            break;
        }
        key_len = key->end - key->start;
        key_str = js + key->start;

        value = &tokens[i*2+2];
        if ((value->start == -1) || (value->end == -1) ||
            ((value->start == 0) && (value->end == 0))) {
            break;
        }
        value_len = value->end - value->start;
        value_str = js + value->start;

        if ((key_len == strlen("version")) &&
            (!strncmp(key_str, "version", key_len))) {
            pairs--;
        }
        else if ((key_len == strlen("timestamp")) &&
                 (!strncmp(key_str, "timestamp", key_len))) {
            pairs--;
        }
        else if ((key_len == 1) && (key_str[0] == '_')) {
            pairs--;
        }
    }

    if (pairs <= 0) {
        flb_error("[flb_gelf_to_msgpack] message is empty");
        ret = -1;
        goto flb_pack_gelf_end;
    }

    msgpack_pack_map(&pck, pairs);

    for (i = 0; i < state.tokens[0].size; i++) {
        key = &tokens[i*2+1];

        if ((key->start == -1) || (key->end == -1) ||
            ((key->start == 0) && (key->end == 0))) {
            break;
        }

        key_len = key->end - key->start;
        key_str = js + key->start;

        if (key->type != JSMN_STRING) {
           flb_error("[flb_gelf_to_msgpack] key \"%.*s\" must be a string",
                     key_len, key_str);
            ret = -1;
            goto flb_pack_gelf_end;
        }

        if (key->size == 0) {
           flb_error("[flb_gelf_to_msgpack] key is empty");
            ret = -1;
            goto flb_pack_gelf_end;
        }

        if (key_len <= 0) {
           flb_error("[flb_gelf_to_msgpack] key is empty");
            ret = -1;
            goto flb_pack_gelf_end;
        }

        value = &tokens[i*2+2];
        if ((value->start == -1) || (value->end == -1) ||
            ((value->start == 0) && (value->end == 0))) {
            break;
        }

        value_len = value->end - value->start;
        value_str = js + value->start;

        if ((key_len == strlen("version")) &&
            (!strncmp(key_str, "version", key_len))) {
            if (strict) {
                if (value->type != JSMN_STRING) {
                    flb_error("[flb_gelf_to_msgpack] version value "
                              "must be a string");
                    ret = -1;
                    goto flb_pack_gelf_end;
                }
                if (!((value_len == 3) &&
                      !strncmp(value_str, "1.1", value_len))) {
                    flb_error("[flb_gelf_to_msgpack] version value "
                               "must be \"1.1\"");
                    ret = -1;
                    goto flb_pack_gelf_end;
                }
            }
            found_version = true;
            continue;
        }
        else if ((key_len == strlen("host")) &&
                 (!strncmp(key_str, "host", key_len))) {
            if (value->type != JSMN_STRING) {
                flb_error("[flb_gelf_to_msgpack] host value must be a string");
                ret = -1;
                goto flb_pack_gelf_end;
            }
            found_host = true;
        }
        else if ((key_len == strlen("short_message")) &&
                 (!strncmp(key_str, "short_message", key_len))) {
            if (strict) {
                 if (value->type != JSMN_STRING) {
                     flb_error("[flb_gelf_to_msgpack] short_message value "
                               "must be a string");
                     ret = -1;
                     goto flb_pack_gelf_end;
                 }
            }
            found_short_message = true;
        }
        else if ((key_len == strlen("full_message")) &&
                 (!strncmp(key_str, "full_message", key_len))) {
            if (strict) {
                 if (value->type != JSMN_STRING) {
                     flb_error("[flb_gelf_to_msgpack] full_message value "
                               "must be a string");
                     ret = -1;
                     goto flb_pack_gelf_end;
                 }
            }
        }
        else if ((key_len == strlen("timestamp")) &&
                 (!strncmp(key_str, "timestamp", key_len))) {
            if (strict) {
                if ((value->type != JSMN_PRIMITIVE) || (*value_str == 'f') ||
                    (*value_str == 't') || (*value_str == 'n')) {
                    flb_error("[flb_gelf_to_msgpack] timestamp value "
                              "must be a number");
                    ret = -1;
                    goto flb_pack_gelf_end;
                }
            }
            flb_time_from_double(tm, atof(value_str));
            continue;
        }
        else if ((key_len == strlen("level")) &&
                 (!strncmp(key_str, "level", key_len))) {
            if (strict) {
                if (value->type != JSMN_PRIMITIVE) {
                    flb_error("[flb_gelf_to_msgpack] level value "
                              "must be a number");
                    ret = -1;
                    goto flb_pack_gelf_end;
                }
            }
        }
        else if ((key_len == strlen("facility")) &&
                 (!strncmp(key_str, "facility", key_len))) {
            if (strict) {
                if (value->type != JSMN_STRING) {
                    flb_error("[flb_gelf_to_msgpack] facility value "
                              "must be a string");
                    ret = -1;
                    goto flb_pack_gelf_end;
                }
            }
        }
        else if ((key_len == strlen("line")) &&
                 (!strncmp(key_str, "line", key_len))) {
            if (strict) {
                if (value->type != JSMN_PRIMITIVE) {
                    flb_error("[flb_gelf_to_msgpack] line value must be a string");
                    ret = -1;
                    goto flb_pack_gelf_end;
                }
            }
        }
        else if ((key_len == strlen("file")) &&
                 (!strncmp(key_str, "file", key_len))) {
            if (strict) {
                 if (value->type != JSMN_STRING) {
                     flb_error("[flb_gelf_to_msgpack] file value must be a string");
                     ret = -1;
                     goto flb_pack_gelf_end;
                 }
            }
        }
        else {
            if (key_str[0] != '_') {
                if (strict) {
                    flb_error("[flb_gelf_to_msgpack] key \"%.*s\" it's not "
                              "prefix with an underscore \"_\"", key_len, key_str);
                    ret = -1;
                    goto flb_pack_gelf_end;
                }
            }
            else {
                key_str++;
                key_len--;
            }

            if (key_len == 0) {
                continue;
            }

            if (strict) {
                for(n=0; n < key_len; n++) {
                    if (!gelf_valid_key_char[(unsigned char)(key_str[n])]) {
                        flb_error("[flb_gelf_to_msgpack] key \"%.*s\" has "
                                  "invalid characters", key_len, key_str);
                        ret = -1;
                        goto flb_pack_gelf_end;
                    }
                }
            }
        }

        msgpack_pack_str(&pck, key_len);
        msgpack_pack_str_body(&pck, key_str, key_len);

        if (value->type == JSMN_STRING) {
            flb_gelf_pack_string_token(&state, value_str, value_len, &pck);
        }
        else if (value->type == JSMN_PRIMITIVE) {
            if (*value_str == 'f')  {
                msgpack_pack_false(&pck);
            }
            else if (*value_str == 't') {
                msgpack_pack_true(&pck);
            }
            else if (*value_str == 'n') {
                msgpack_pack_nil(&pck);
            }
            else {
                char *tmp_str;
                tmp_str = flb_strndup(value_str, value_len);
                if (flb_gelf_is_integer(value_str, value_len)) {
                    msgpack_pack_int64(&pck, atoll(tmp_str));
                }
                else {
                    msgpack_pack_double(&pck, atof(tmp_str));
                }
                flb_free(tmp_str);
            }
        }
        else {
            flb_error("[flb_gelf_to_msgpack] key \"%.*s\" "
                      "use an unsupported value type", key_len, key_str);
            ret = -1;
            goto flb_pack_gelf_end;
        }
    }

    if (strict) {
        if (!found_version) {
            flb_error("[flb_gelf_to_msgpack] missing version key");
            ret = -1;
            goto flb_pack_gelf_end;
        }
        if (!found_host) {
            flb_error("[flb_gelf_to_msgpack] missing host key");
            ret = -1;
            goto flb_pack_gelf_end;
        }
        if (!found_short_message) {
            flb_error("[flb_gelf_to_msgpack] missing short_message key");
            ret = -1;
            goto flb_pack_gelf_end;
        }
    }

    *buffer = sbuf.data;
    *size = sbuf.size;
    ret = 0;
 flb_pack_gelf_end:
    if (ret < 0) {
        msgpack_sbuffer_destroy(&sbuf);
    }
    flb_pack_state_reset(&state);
    return ret;
}
