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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>

void flb_kv_init(struct mk_list *list)
{
    mk_list_init(list);
}

struct flb_kv *flb_kv_item_create_len(struct mk_list *list,
                                      char *k_buf, size_t k_len,
                                      char *v_buf, size_t v_len)
{
    struct flb_kv *kv;

    kv = flb_calloc(1, sizeof(struct flb_kv));
    if (!kv) {
        flb_errno();
        return NULL;
    }

    kv->key = flb_sds_create_len(k_buf, k_len);
    if (!kv->key) {
        flb_free(kv);
        return NULL;
    }

    if (v_len > 0) {
        kv->val = flb_sds_create_len(v_buf, v_len);
        if (!kv->val) {
            flb_sds_destroy(kv->key);
            flb_free(kv);
            return NULL;
        }
    }

    mk_list_add(&kv->_head, list);
    return kv;
}

struct flb_kv *flb_kv_item_create(struct mk_list *list,
                                  char *k_buf, char *v_buf)
{
    int k_len;
    int v_len = 0;

    if (!k_buf) {
        return NULL;
    }
    k_len = strlen(k_buf);

    if (v_buf) {
        v_len = strlen(v_buf);
    }

    return flb_kv_item_create_len(list, k_buf, k_len, v_buf, v_len);
}

struct flb_kv *flb_kv_item_set(struct mk_list *list,
                               char *k_buf, char *v_buf)
{
    struct mk_list *head;
    struct flb_kv *kv;

    if (!k_buf) {
        return NULL;
    }

    mk_list_foreach(head, list) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp(kv->key, k_buf) == 0) {
            if (kv->val) {
                flb_sds_destroy(kv->val);
            }
            kv->val = flb_sds_create(v_buf);
            if (!kv->val) {
                mk_list_del(&kv->_head);
                flb_sds_destroy(kv->key);
                flb_free(kv);
                return NULL;
            }
            return kv;
        }
    }

    return flb_kv_item_create(list, k_buf, v_buf);
}

void flb_kv_item_destroy(struct flb_kv *kv)
{
    if (kv->key) {
        flb_sds_destroy(kv->key);
    }

    if (kv->val) {
        flb_sds_destroy(kv->val);
    }

    mk_list_del(&kv->_head);
    flb_free(kv);
}

void flb_kv_release(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_kv *kv;

    mk_list_foreach_safe(head, tmp, list) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        flb_kv_item_destroy(kv);
    }
}

const char *flb_kv_get_key_value(const char *key, struct mk_list *list)
{
    int len;
    struct mk_list *head;
    struct flb_kv *kv;

    if (!key) {
        return NULL;
    }

    len = strlen(key);
    if (len == 0) {
        return NULL;
    }

    mk_list_foreach(head, list) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (flb_sds_len(kv->key) != len) {
            continue;
        }

        if (strncasecmp(kv->key, key, len) == 0) {
            return kv->val;
        }
    }

    return NULL;
}
