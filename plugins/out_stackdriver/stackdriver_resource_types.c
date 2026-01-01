/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>

#include "stackdriver.h"
#include "stackdriver_resource_types.h"

static const struct resource_type resource_types[] = {
    { 
        .id = RESOURCE_TYPE_K8S,
        .resources = {"k8s_container", "k8s_node", "k8s_pod", "k8s_cluster"},
        .required_labels = {"cluster_name", "location"}
    },
    { 
        .id = RESOURCE_TYPE_GENERIC_NODE,
        .resources = {"generic_node"},
        .required_labels = {"location", "namespace", "node_id"}
    },
    { 
        .id = RESOURCE_TYPE_GENERIC_TASK,
        .resources = {"generic_task"},
        .required_labels = {"location", "namespace", "job", "task_id"}
    }
};

static char **get_required_labels(int resource_type)
{
    int i;
    int len;

    len = sizeof(resource_types) / sizeof(resource_types[0]);
    for(i = 0; i < len; i++) {
        if (resource_types[i].id == resource_type) {
            return (char **) resource_types[i].required_labels;
        }
    }
    return NULL;
}

/*
 *   set_resource_type():
 * - Iterates through resource_types that are set up for validation and sets the 
 *   resource_type if it matches one of them.
 * - A resource may not be in the resource types list but still be accepted
 *   and processed (e.g. global) if it does not require / is not set up for validation.
 */
void set_resource_type(struct flb_stackdriver *ctx)
{
    int i;
    int j;
    int len;
    char *resource;
    struct resource_type resource_type;

    len = sizeof(resource_types) / sizeof(resource_types[0]);
    for(i = 0; i < len; i++) {
        resource_type = resource_types[i];
        for(j = 0; j < MAX_RESOURCE_ENTRIES; j++) {
            if (resource_type.resources[j] != NULL) {
                resource = resource_type.resources[j];
                if (flb_sds_cmp(ctx->resource, resource, strlen(resource)) == 0) {
                    ctx->resource_type = resource_type.id;
                    return;
                }
            }
        }
    }
}

/*
 *   resource_api_has_required_labels():
 * - Determines if all required labels for the set resource type are present as
 *   keys on the resource labels key-value pairs.
 */
int resource_api_has_required_labels(struct flb_stackdriver *ctx)
{
    struct mk_list *head;
    struct flb_hash_table *ht;
    struct flb_kv *label_kv;
    char** required_labels;
    int i;
    int found;
    void *tmp_buf;
    size_t tmp_size;

    if (mk_list_size(&ctx->resource_labels_kvs) == 0) {
        return FLB_FALSE;
    }

    required_labels = get_required_labels(ctx->resource_type);
    if (required_labels == NULL) {
        flb_plg_warn(ctx->ins, "no validation applied to resource_labels "
                               "for set resource type");
        return FLB_FALSE;
    }

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, MAX_REQUIRED_LABEL_ENTRIES, 0);
    mk_list_foreach(head, &ctx->resource_labels_kvs) {
        label_kv = mk_list_entry(head, struct flb_kv, _head);
        for (i = 0; i < MAX_REQUIRED_LABEL_ENTRIES; i++) {
            if (required_labels[i] != NULL && flb_sds_cmp(label_kv->key,
                required_labels[i], strlen(required_labels[i])) == 0) {
                flb_hash_table_add(ht, required_labels[i], strlen(required_labels[i]),
                                   NULL, 0);
            }
        }
    }

    for (i = 0; i < MAX_REQUIRED_LABEL_ENTRIES; i++) {
        if (required_labels[i] != NULL) {
            found = flb_hash_table_get(ht, required_labels[i], strlen(required_labels[i]),
                                       &tmp_buf, &tmp_size);
            if (found == -1) {
                flb_plg_warn(ctx->ins, "labels set in resource_labels will not be applied" 
                  ", as the required resource label [%s] is missing", required_labels[i]);
                ctx->should_skip_resource_labels_api = FLB_TRUE;
                flb_hash_table_destroy(ht);
                return FLB_FALSE;
            }
        }
    }
    flb_hash_table_destroy(ht);
    return FLB_TRUE;
}
