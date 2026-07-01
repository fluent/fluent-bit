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


#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "cm.h"
#include "cm_utils.h"

#include <stdio.h>

struct cfl_variant *cm_otel_get_or_create_attributes(struct cfl_kvlist *kvlist)
{
    int ret;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *val;
    struct cfl_kvlist *kvlist_tmp;

    /* iterate resource to find the attributes field */
    cfl_list_foreach_safe(head, tmp, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (cfl_sds_len(kvpair->key) != 10) {
            continue;
        }

        if (strncmp(kvpair->key, "attributes", 10) == 0) {
            val = kvpair->val;
            if (val->type != CFL_VARIANT_KVLIST) {
                return NULL;
            }

            return val;
        }
    }

    /* create an empty kvlist as the value of attributes */
    kvlist_tmp = cfl_kvlist_create();
    if (!kvlist_tmp) {
        return NULL;
    }

    /* create the attributes kvpair */
    ret = cfl_kvlist_insert_kvlist_s(kvlist, "attributes", 10, kvlist_tmp);
    if (ret != 0) {
        cfl_kvlist_destroy(kvlist_tmp);
        return NULL;
    }

    /* get the last kvpair from the list */
    kvpair = cfl_list_entry_last(&kvlist->list, struct cfl_kvpair, _head);
    if (!kvpair) {
        return NULL;
    }

    return kvpair->val;
}

static struct cfl_variant *otel_get_or_create_attributes(struct cfl_kvlist *kvlist)
{
    int ret;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *val = NULL;
    struct cfl_kvlist *kvlist_tmp;

    /* iterate resource to find the attributes field */
    cfl_list_foreach_safe(head, tmp, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (cfl_sds_len(kvpair->key) != 10) {
            continue;
        }

        if (strncmp(kvpair->key, "attributes", 10) == 0) {
            val = kvpair->val;
            if (val->type != CFL_VARIANT_KVLIST) {
                return NULL;
            }
            return val;
        }
    }

    /* create an empty kvlist as the value of attributes */
    kvlist_tmp = cfl_kvlist_create();
    if (!kvlist_tmp) {
        return NULL;
    }

    /* create the attributes kvpair */
    ret = cfl_kvlist_insert_kvlist_s(kvlist, "attributes", 10, kvlist_tmp);
    if (ret != 0) {
        cfl_kvlist_destroy(kvlist_tmp);
        return NULL;
    }

    /* get the last kvpair from the list */
    kvpair = cfl_list_entry_last(&kvlist->list, struct cfl_kvpair, _head);
    if (!kvpair) {
        return NULL;
    }

    return kvpair->val;
}

/*
 * get attributes for resources and scope, context must be one of:
 *
 *  - CM_CONTEXT_OTEL_RESOURCE_ATTR
 *  - CM_CONTEXT_OTEL_SCOPE_ATTR
 */
struct cfl_variant *cm_otel_get_attributes(int telemetry_type, int context, struct cfl_kvlist *kvlist)
{
    int key_len;
    const char *key_buf;
    struct cfl_variant *var;
    struct cfl_variant *var_attr = NULL;

    if (context == CM_CONTEXT_OTEL_RESOURCE_ATTR) {
        key_buf = "resource";
        key_len = 8;
    }
    else if (context == CM_CONTEXT_OTEL_SCOPE_ATTR) {
        key_buf = "scope";
        key_len = 5;
    }
    else {
        return NULL;
    }

    var = cfl_kvlist_fetch_s(kvlist, (char *) key_buf, key_len);
    if (!var) {
        return NULL;
    }

    if (var->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    var_attr = otel_get_or_create_attributes(var->data.as_kvlist);
    if (!var_attr) {
        return NULL;
    }

    return var_attr;
}

static struct cfl_variant *otel_get_or_create_scope_metadata(int telemetry_type, struct cfl_kvlist *kvlist)
{
    int ret;
    struct cfl_variant *var;
    struct cfl_kvpair *kvpair;
    struct cfl_kvlist *kvlist_tmp;

    /* kvlist is the value of 'scope', lookup for scope->metadata */

    var  = cfl_kvlist_fetch(kvlist, "metadata");
    if (var) {
        if (var->type != CFL_VARIANT_KVLIST) {
            return NULL;
        }

        return var;
    }

    /* metadata don't exists, create it */
    kvlist_tmp = cfl_kvlist_create();
    if (!kvlist_tmp) {
        return NULL;
    }

    ret = cfl_kvlist_insert_kvlist_s(kvlist, "metadata", 8, kvlist_tmp);
    if (ret != 0) {
        cfl_kvlist_destroy(kvlist_tmp);
        return NULL;
    }

    kvpair = cfl_list_entry_last(&kvlist->list, struct cfl_kvpair, _head);
    if (!kvpair) {
        return NULL;
    }

    return kvpair->val;
}

/*
 * Retrieve the kvlist that contains the scope metadata such as name and version,
 * based on the telemetry type, the kvlist is expected to be in the following format:
 *
 *  - Logs: scope -> {name, version}
 *  - Metrics: scope -> metadata -> {name, version}
 *
 *  If the paths are not found, those are "created".
 */
struct cfl_variant *cm_otel_get_scope_metadata(int telemetry_type, struct cfl_kvlist *kvlist)
{
    int ret;
    struct cfl_variant *var = NULL;
    struct cfl_kvpair *kvpair = NULL;
    struct cfl_kvlist *kvlist_tmp;

    if (!kvlist) {
        return NULL;
    }

    /* retrieve the scope if exists */
    var = cfl_kvlist_fetch(kvlist, "scope");
    if (var) {
        if (var->type != CFL_VARIANT_KVLIST) {
            /* if exists and is not valid just fail */
            return NULL;
        }
    }
    else {
        /* create "scope" inside kvlist */
        kvlist_tmp = cfl_kvlist_create();
        if (!kvlist_tmp) {
            return NULL;
        }

        ret = cfl_kvlist_insert_kvlist_s(kvlist, "scope", 5, kvlist_tmp);
        if (ret != 0) {
            cfl_kvlist_destroy(kvlist_tmp);
            return NULL;
        }

        kvpair = cfl_list_entry_last(&kvlist->list, struct cfl_kvpair, _head);
        if (!kvpair) {
            return NULL;
        }

        var = kvpair->val;
    }

    /*
     * 'var' points to the value of 'scope', for logs telemetry data, just return
     * the current variant, for metrics lookup for 'metadata' kvpair (or create it)
     */

    if (telemetry_type == CM_TELEMETRY_LOGS) {
        return var;
    }
    else if (telemetry_type == CM_TELEMETRY_METRICS) {
        var = otel_get_or_create_scope_metadata(telemetry_type, var->data.as_kvlist);
    }

    return var;
}
