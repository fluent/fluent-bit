/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_label.h>

/*
 * This interface file provide helper functions to compose a dynamic list
 * of custom labels with specific keys and values. Note that this is not
 * about labels defined by metrics upon creation, but label lists to be
 * used by the encoders when formatting the data.
 */
struct cmt_labels *cmt_labels_create()
{
    struct cmt_labels *l;

    l = malloc(sizeof(struct cmt_labels));
    if (!l) {
        cmt_errno();
        return NULL;
    }
    cfl_list_init(&l->list);
    return l;
}

void cmt_labels_destroy(struct cmt_labels *labels)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_label *l;

    cfl_list_foreach_safe(head, tmp, &labels->list) {
        l = cfl_list_entry(head, struct cmt_label, _head);
        if (l->key) {
            cfl_sds_destroy(l->key);
        }
        if (l->val) {
            cfl_sds_destroy(l->val);
        }
        cfl_list_del(&l->_head);
        free(l);
    }

    free(labels);
}

int cmt_labels_add_kv(struct cmt_labels *labels, char *key, char *val)
{
    struct cmt_label *l;

    l = malloc(sizeof(struct cmt_label));
    if (!l) {
        cmt_errno();
        return -1;
    }

    l->key = cfl_sds_create(key);
    if (!l->key) {
        free(l);
        return -1;
    }

    l->val = cfl_sds_create(val);
    if (!l->val) {
        cfl_sds_destroy(l->key);
        free(l);
        return -1;
    }

    cfl_list_add(&l->_head, &labels->list);
    return 0;
}

int cmt_labels_count(struct cmt_labels *labels)
{
    int c = 0;
    struct cfl_list *head;

    cfl_list_foreach(head, &labels->list) {
        c++;
    }

    return c;
}
