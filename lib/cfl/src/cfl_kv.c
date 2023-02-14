/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

#include <cfl/cfl.h>
#include <cfl/cfl_kv.h>
#include <cfl/cfl_log.h>


void cfl_kv_init(struct cfl_list *list)
{
    cfl_list_init(list);
}

struct cfl_kv *cfl_kv_item_create_len(struct cfl_list *list,
                                      char *k_buf, size_t k_len,
                                      char *v_buf, size_t v_len)
{
    struct cfl_kv *kv;

    kv = calloc(1, sizeof(struct cfl_kv));

    if (kv == NULL) {
        cfl_report_runtime_error();

        return NULL;
    }

    kv->key = cfl_sds_create_len(k_buf, k_len);

    if (kv->key == NULL) {
        free(kv);

        return NULL;
    }

    if (v_len > 0) {
        kv->val = cfl_sds_create_len(v_buf, v_len);

        if (kv->val == NULL) {
            cfl_sds_destroy(kv->key);
            free(kv);

            return NULL;
        }
    }

    cfl_list_add(&kv->_head, list);

    return kv;
}

struct cfl_kv *cfl_kv_item_create(struct cfl_list *list,
                                  char *k_buf, char *v_buf)
{
    int k_len;
    int v_len;

    if (k_buf == NULL) {
        return NULL;
    }

    k_len = strlen(k_buf);

    if (v_buf != NULL) {
        v_len = strlen(v_buf);
    }
    else {
        v_len = 0;
    }

    return cfl_kv_item_create_len(list, k_buf, k_len, v_buf, v_len);
}

void cfl_kv_item_destroy(struct cfl_kv *kv)
{
    if (kv->key != NULL) {
        cfl_sds_destroy(kv->key);
    }

    if (kv->val != NULL) {
        cfl_sds_destroy(kv->val);
    }

    cfl_list_del(&kv->_head);

    free(kv);
}

void cfl_kv_release(struct cfl_list *list)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_kv   *kv;

    cfl_list_foreach_safe(head, tmp, list) {
        kv = cfl_list_entry(head, struct cfl_kv, _head);

        cfl_kv_item_destroy(kv);
    }
}

const char *cfl_kv_get_key_value(const char *key, struct cfl_list *list)
{
    struct cfl_list *head;
    int              len;
    struct cfl_kv   *kv;

    if (key == NULL) {
        return NULL;
    }

    len = strlen(key);

    if (len == 0) {
        return NULL;
    }

    cfl_list_foreach(head, list) {
        kv = cfl_list_entry(head, struct cfl_kv, _head);

        if (cfl_sds_len(kv->key) != len) {
            continue;
        }

        if (strncasecmp(kv->key, key, len) == 0) {
            return kv->val;
        }
    }

    return NULL;
}
