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


#include <fluent-bit/flb_processor_plugin.h>
#include <cfl/cfl.h>

/* Processor initialization */
static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    return FLB_PROCESSOR_SUCCESS;
}

/* Processor exit */
static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    return FLB_PROCESSOR_SUCCESS;
}

/* Create an group start with OTLP style-signature */
static struct flb_mp_chunk_record *envelop_init(struct cfl_list *list, struct flb_mp_chunk_record *active_record)
{
    int ret;
    struct cfl_kvlist *kvlist_meta = NULL;
    struct cfl_kvlist *kvlist_record = NULL;
    struct cfl_kvlist *kvlist_resource = NULL;
    struct cfl_kvlist *kvlist_scope = NULL;
    struct cfl_object *cobj_meta = NULL;
    struct cfl_object *cobj_record = NULL;
    struct flb_mp_chunk_record *record = NULL;
    struct flb_time tm;

    /* metadata */
    kvlist_meta = cfl_kvlist_create();
    if (!kvlist_meta) {
        return NULL;
    }

    cfl_kvlist_insert_string(kvlist_meta, "schema", "otlp");
    cfl_kvlist_insert_int64(kvlist_meta, "resource_id", 0);
    cfl_kvlist_insert_int64(kvlist_meta, "scope_id", 0);

    /* empty content */
    kvlist_record = cfl_kvlist_create();
    if (!kvlist_record) {
        goto failure;
    }

    kvlist_resource = cfl_kvlist_create();
    if (!kvlist_resource) {
        goto failure;
    }

    kvlist_scope = cfl_kvlist_create();
    if (!kvlist_scope) {
        goto failure;
    }

    cfl_kvlist_insert_kvlist(kvlist_record, "resource", kvlist_resource);
    cfl_kvlist_insert_kvlist(kvlist_record, "scope", kvlist_scope);

    record = flb_mp_chunk_record_create(NULL);
    if (!record) {
        goto failure;
    }

    cobj_meta = cfl_object_create();
    if (!cobj_meta) {
        goto failure;
    }
    ret = cfl_object_set(cobj_meta, CFL_OBJECT_KVLIST, kvlist_meta);
    if (ret != 0) {
        goto failure;
    }

    cobj_record = cfl_object_create();
    if (!cobj_record) {
        goto failure;
    }
    ret = cfl_object_set(cobj_record, CFL_OBJECT_KVLIST, kvlist_record);
    if (ret != 0) {
        goto failure;
    }

    /* set the group flag in the timestamp field */
    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_START, 0);
    flb_time_copy(&record->event.timestamp, &tm);

    record->modified  = FLB_TRUE;
    record->cobj_metadata = cobj_meta;
    record->cobj_record = cobj_record;

    /* add the envelop before the active record */
    cfl_list_add_before(&record->_head, &active_record->_head, list);

    return record;

failure:
    if (kvlist_meta) {
        cfl_kvlist_destroy(kvlist_meta);
    }
    if (kvlist_record) {
        cfl_kvlist_destroy(kvlist_record);
    }
    if (kvlist_resource) {
        cfl_kvlist_destroy(kvlist_resource);
    }
    if (kvlist_scope) {
        cfl_kvlist_destroy(kvlist_scope);
    }
    if (cobj_meta) {
        cfl_object_destroy(cobj_meta);
    }
    if (cobj_record) {
        cfl_object_destroy(cobj_record);
    }
    if (record) {
        flb_mp_chunk_cobj_record_destroy(NULL, record);
    }

    return NULL;
}

/* Create an group end */
static void envelop_end(struct cfl_list *list, struct flb_mp_chunk_record *active_record)
{
    struct flb_time tm;
    struct flb_mp_chunk_record *record;

    /* set the group flag in the timestamp field */
    record = flb_mp_chunk_record_create(NULL);
    if (!record) {
        return;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_END, 0);
    flb_time_copy(&record->event.timestamp, &tm);

    record->modified  = FLB_TRUE;
    record->cobj_metadata = NULL;
    record->cobj_record = NULL;

    /* add the envelop before the active record */
    cfl_list_add_after(&record->_head, &active_record->_head, list);
}


#include <fluent-bit/flb_pack.h>

/* Logs callback */
static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data, const char *tag, int tag_len)
{
    int ret;
    int record_type;
    int grouped = FLB_FALSE;
    struct flb_mp_chunk_record *prev_record;
    struct flb_mp_chunk_record *record;
    struct flb_mp_chunk_cobj *chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;


    /* Iterate records */
    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) == FLB_MP_CHUNK_RECORD_OK) {
        prev_record = record;

        /* get record type */
        ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
        if (ret != 0) {
            flb_plg_error(ins, "record has invalid event type");
            continue;
        }

        if (record_type == FLB_LOG_EVENT_NORMAL && grouped == FLB_FALSE) {
            envelop_init(&chunk_cobj->records, record);
            grouped = FLB_TRUE;
        }
        else if (record_type == FLB_LOG_EVENT_GROUP_START && grouped == FLB_TRUE) {
            envelop_end(&chunk_cobj->records, record);
            grouped = FLB_FALSE;
        }
    }

    if (grouped == FLB_TRUE) {
        envelop_end(&chunk_cobj->records, prev_record);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int metrics_add_kvlist(struct cfl_kvlist *kvlist, char *kv1, char *sub_kv1, char *sub_kv2)
{
    int ret;
    struct cfl_variant *var;
    struct cfl_kvlist *tmp_kvlist;

    var = cfl_kvlist_fetch(kvlist, kv1);
    if (!var) {
        tmp_kvlist = cfl_kvlist_create();
        if (!tmp_kvlist) {
            return -1;
        }
        ret = cfl_kvlist_insert_kvlist(kvlist, kv1, tmp_kvlist);
        if (ret != 0) {
            return -1;
        }

        /* retrieve the last kv inserted */
        var = cfl_kvlist_fetch(kvlist, kv1);
    }
    else if (var->type != CFL_VARIANT_KVLIST) {
        return -1;
    }

    if (!var) {
        return -1;
    }

    if (sub_kv1) {
        ret = metrics_add_kvlist(var->data.as_kvlist, sub_kv1, NULL, NULL);
        if (ret != 0) {
            return -1;
        }
    }

    if (sub_kv2) {
        ret = metrics_add_kvlist(var->data.as_kvlist, sub_kv2, NULL, NULL);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

static int cb_process_metrics(struct flb_processor_instance *processor_instance,
                              struct cmt *cmt,
                              struct cmt **out_context,
                              const char *tag, int tag_len)
{
    (void) out_context;
    (void) tag;
    (void) tag_len;
    int ret;
    struct cfl_variant *var = NULL;

    /* Check internal metadata, look for some producer, if no one is set, add it */
    if (!cmt->internal_metadata) {
        cmt->internal_metadata = cfl_kvlist_create();
        if (!cmt->internal_metadata) {
            return FLB_PROCESSOR_FAILURE;
        }
    }
    else {
        var = cfl_kvlist_fetch(cmt->internal_metadata, "producer");
    }
    if (!var) {
        cfl_kvlist_insert_string(cmt->internal_metadata, "producer", "fluent-bit");
    }

    /* externl metadata */
    if (!cmt->external_metadata) {
        cmt->external_metadata = cfl_kvlist_create();
        if (!cmt->external_metadata) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    /* scope */
    ret = metrics_add_kvlist(cmt->external_metadata, "scope", "metadata", "attributes");
    if (ret != 0) {
        return FLB_PROCESSOR_FAILURE;
    }

    /* scope_metrics */
    ret = metrics_add_kvlist(cmt->external_metadata, "scope_metrics", "metadata", NULL);
    if (ret != 0) {
        return FLB_PROCESSOR_FAILURE;
    }

    /* resource */
    ret = metrics_add_kvlist(cmt->external_metadata, "resource", "metadata", "attributes");
    if (ret != 0) {
        return FLB_PROCESSOR_FAILURE;
    }

    /* resource_metrics */
    ret = metrics_add_kvlist(cmt->external_metadata, "resource_metrics", "metadata", NULL);
    if (ret != 0) {
        return FLB_PROCESSOR_FAILURE;
    }

    *out_context = NULL;
    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    /* EOF */
    {0}
};

struct flb_processor_plugin processor_opentelemetry_envelope_plugin = {
    .name               = "opentelemetry_envelope",
    .description        = "Package log records inside an OpenTelemetry Logs schema",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = cb_process_metrics,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0,
};