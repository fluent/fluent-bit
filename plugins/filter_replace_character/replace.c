/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>

#include <monkey/mk_core/mk_list.h>
#include <msgpack.h>

#include <stdlib.h>
#include <errno.h>

#include "replace.h"

static int cb_replace_init(struct flb_filter_instance *f_ins,
                           struct flb_config *config,
                           void *data)
{
    struct flb_filter_replace_char *ctx = NULL;
    struct mk_list *head;
    struct flb_kv *kv;
    char *tmp;
    char old;
    char new;
    (void) data;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        // TODO: better names for these options...
        if (strcasecmp(kv->key, "old") == 0) {
            tmp = kv->val;
            if (strlen(tmp) != 1) {
                flb_error("[filter_replace_character] 'old' should be a single"
                          " character");
                return -1;
            }
            old = tmp[0];
        }
        if (strcasecmp(kv->key, "new") == 0) {
            tmp = kv->val;
            if (strlen(tmp) != 1) {
                flb_error("[filter_replace_character] 'new' should be a "
                          "single character");
                return -1;
            }
            new = tmp[0];
        }
    }

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_filter_replace_char));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->old = old;
    ctx->new = new;

    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int cb_replace_filter(const void *data, size_t bytes,
                             const char *tag, int tag_len,
                             void **out_buf, size_t *out_size,
                             struct flb_filter_instance *f_ins,
                             void *context,
                             struct flb_config *config)
{
    struct flb_filter_replace_char *ctx = context;
    (void) f_ins;
    (void) config;
    size_t off = 0;
    int i = 0;
    int j = 0;
    int ret;
    struct flb_time tm;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object  *key;
    msgpack_object_kv *kv;
    char *key_str = NULL;
    size_t key_str_size = 0;
    int modify = FLB_FALSE;
    char *key_buf = NULL;
    size_t key_buf_size = 256;

    key_buf = flb_malloc(key_buf_size + 1);
    if (!key_buf) {
        flb_errno();
        return FLB_FILTER_NOTOUCH;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate over each item */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)
           == MSGPACK_UNPACK_SUCCESS) {
        /*
         * Each record is a msgpack array [timestamp, map] of the
         * timestamp and record map. We 'unpack' each record, and then re-pack
         * it with the keys modified.
         */

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* obj should now be the record map */
        if (obj->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* re-pack the array into a new buffer */
        msgpack_pack_array(&tmp_pck, 2);
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        /* new record map size is old size + the new keys we will add */
        msgpack_pack_map(&tmp_pck, obj->via.map.size);

        /* iterate through the old record map and add it to the new buffer */
        kv = obj->via.map.ptr;
        for(i=0; i < obj->via.map.size; i++) {
            modify = FLB_FALSE;
            key = &(kv+i)->key;
            if (key->type == MSGPACK_OBJECT_BIN) {
                key_str  = (char *) key->via.bin.ptr;
                key_str_size = key->via.bin.size;
                modify = FLB_TRUE;
            }
            else if (key->type == MSGPACK_OBJECT_STR) {
                key_str  = (char *) key->via.str.ptr;
                key_str_size = key->via.str.size;
                modify = FLB_TRUE;
            }
            if (modify == FLB_TRUE) {
                /* increase key_buf if it is too small */
                if (key_str_size > key_buf_size) {
                    key_buf_size = key_str_size;
                    key_buf = flb_malloc(key_buf_size + 1);
                    if (!key_buf) {
                        flb_errno();
                        msgpack_unpacked_destroy(&result);
                        msgpack_sbuffer_destroy(&tmp_sbuf);
                        return FLB_FILTER_NOTOUCH;
                    }
                }

                /* copy to temporary buffer */
                memcpy(key_buf, key_str, key_str_size);
                key_buf[key_str_size] = '\0';
                for (j=0; j<key_str_size; j++) {
                    if (key_buf[j] == ctx->old) {
                        key_buf[j] = ctx->new;
                    }
                }
                /* Append the new key */
                msgpack_pack_str(&tmp_pck, key_str_size);
                msgpack_pack_str_body(&tmp_pck, key_buf, key_str_size);
            } else {
                msgpack_pack_object(&tmp_pck, (kv+i)->key);
            }
            msgpack_pack_object(&tmp_pck, (kv+i)->val);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf  = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
    return FLB_FILTER_MODIFIED;
}

static void flb_filter_replace_char_destroy(struct flb_filter_replace_char *ctx)
{
    if (!ctx) {
        return;
    }

    flb_free(ctx);
}

static int cb_replace_exit(void *data, struct flb_config *config)
{
    struct flb_filter_replace_char *ctx = data;

    if (ctx != NULL) {
        flb_filter_replace_char_destroy(ctx);
    }
    return 0;
}

struct flb_filter_plugin filter_replace_character_plugin = {
    .name         = "replace_character",
    .description  = "Replace characters in key names",
    .cb_init      = cb_replace_init,
    .cb_filter    = cb_replace_filter,
    .cb_exit      = cb_replace_exit,
    .flags        = 0
};
