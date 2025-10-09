/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include "sampling.h"
#include "sampling_span_registry.h"

struct sampling_ctrace_entry {
    struct ctrace *ctr;
    struct cfl_list _head; /* sampling_settings->list_ctraces */
};

struct sampling_settings {
    int decision_wait;
    uint64_t max_traces;

    /* internal */
    void *parent;                   /* struct sampling *ctx */
    uint64_t decision_wait_ms;

    /* linked list with a reference to all the ctraces contexts */
    struct cfl_list list_ctraces;

    /* span registry */
    struct sampling_span_registry *span_reg;
};

static struct flb_config_map settings_config_map[] = {
    {
        FLB_CONFIG_MAP_TIME, "decision_wait", "30s",
        0, FLB_TRUE, offsetof(struct sampling_settings, decision_wait),
    },

    {
        FLB_CONFIG_MAP_INT, "max_traces", "50000",
        0, FLB_TRUE, offsetof(struct sampling_settings, max_traces),
    },

    /* EOF */
    {0}
};

/* delete a list ctrace entry */
static void list_ctrace_delete_entry(struct sampling *ctx, struct sampling_ctrace_entry *ctrace_entry)
{
    ctr_destroy(ctrace_entry->ctr);
    cfl_list_del(&ctrace_entry->_head);
    flb_free(ctrace_entry);
}

/* delete ctrace entries with no spans */
static void list_ctrace_delete_empty(struct sampling *ctx, struct sampling_settings *settings)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct sampling_ctrace_entry *ctrace_entry;

    cfl_list_foreach_safe(head, tmp, &settings->list_ctraces) {
        ctrace_entry = cfl_list_entry(head, struct sampling_ctrace_entry, _head);
        if (cfl_list_size(&ctrace_entry->ctr->span_list) == 0) {
           list_ctrace_delete_entry(ctx, ctrace_entry);
        }
    }
}

static void list_ctrace_delete_all(struct sampling *ctx, struct sampling_settings *settings)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct sampling_ctrace_entry *ctrace_entry;

    cfl_list_foreach_safe(head, tmp, &settings->list_ctraces) {
        ctrace_entry = cfl_list_entry(head, struct sampling_ctrace_entry, _head);
        list_ctrace_delete_entry(ctx, ctrace_entry);
    }
}

static struct ctrace *reconcile_and_create_ctrace(struct sampling *ctx, struct sampling_settings *settings, struct trace_entry *t_entry)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct trace_span *t_span;
    struct ctrace *ctr = NULL;
    struct ctrace_resource_span *resource_span = NULL;
    struct ctrace_resource *resource = NULL;
    struct ctrace_scope_span *scope_span = NULL;
    struct ctrace_instrumentation_scope *instrumentation_scope = NULL;
    struct ctrace_span *span;
    struct ctrace_attributes *attr;

    /* for each complete trace, reconcile, convert to ctrace context and enqueue it */
    cfl_list_foreach_safe(head, tmp, &t_entry->span_list) {
        t_span = cfl_list_entry(head, struct trace_span, _head);
        span = t_span->span;

        /* create a new ctraces context if does not exists */
        if (!ctr) {
            ctr = ctr_create(NULL);
            if (!ctr) {
                flb_plg_error(ctx->ins, "could not create ctrace context");
                return NULL;
            }
        }

        /* create a resource span */
        if (!resource_span) {
            resource_span = ctr_resource_span_create(ctr);
            if (!resource_span) {
                flb_plg_error(ctx->ins, "could not create resource span");
                ctr_destroy(ctr);
                return NULL;
            }
        }

        if (!resource) {
            resource = ctr_resource_span_get_resource(resource_span);
            if (!resource) {
                flb_plg_error(ctx->ins, "could not get resource");
                ctr_destroy(ctr);
                return NULL;
            }

            /* resource attributes */
            attr = span->scope_span->resource_span->resource->attr;
            if (attr) {
                ctr_resource_set_attributes(resource, ctr_attributes_acquire(attr));
            }

            /* resource dropped attributes count */
            if (span->scope_span->resource_span->resource->dropped_attr_count) {
                ctr_resource_set_dropped_attr_count(resource, span->scope_span->resource_span->resource->dropped_attr_count);
            }

            /* resource schema url */
            if (span->scope_span->resource_span->schema_url) {
                ctr_resource_span_set_schema_url(resource_span, span->scope_span->resource_span->schema_url);
            }
        }

        if (!scope_span) {
            scope_span = ctr_scope_span_create(resource_span);
            if (!scope_span) {
                flb_plg_error(ctx->ins, "could not create scope span");
                ctr_destroy(ctr);
                return NULL;
            }
        }

        if (!instrumentation_scope) {
            /* this is optional, check in the original span context if we have some instrumentation associated */
            if (span->scope_span->instrumentation_scope) {
                attr = NULL;
                if (span->scope_span->instrumentation_scope->attr) {
                    attr = ctr_attributes_acquire(span->scope_span->instrumentation_scope->attr);
                }

                instrumentation_scope = ctr_instrumentation_scope_create(span->scope_span->instrumentation_scope->name,
                                                                         span->scope_span->instrumentation_scope->version,
                                                                         span->scope_span->instrumentation_scope->dropped_attr_count,
                                                                         attr);
                if (instrumentation_scope) {
                    ctr_scope_span_set_instrumentation_scope(scope_span, instrumentation_scope);
                }
            }
        }

        /*
         * Detach the span from its previous context completely and
         * re-attach it to the new one. If we only move the local list
         * reference (span->_head) the span would still belong to the
         * original ctrace context which later on might lead to use after
         * free issues when the new context is destroyed. Make sure to
         * update all references.
         */

        /* detach from the original scope span and global list */
        cfl_list_del(&span->_head);
        cfl_list_del(&span->_head_global);

        /* update parent references */
        span->scope_span = scope_span;
        span->ctx = ctr;

        /* link to the new scope span and ctrace context */
        cfl_list_add(&span->_head, &scope_span->spans);
        cfl_list_add(&span->_head_global, &ctr->span_list);

        /* reset all the contexts */
        resource_span = NULL;
        resource = NULL;
        scope_span = NULL;
        instrumentation_scope = NULL;

        /* remote t_span entry */
        cfl_list_del(&t_span->_head);
        flb_free(t_span);
    }

    sampling_span_registry_delete_entry(ctx, settings->span_reg, t_entry, FLB_FALSE);

    return ctr;
}

static int check_conditions(struct sampling *ctx, struct trace_entry *t_entry)
{
    int ret;
    struct cfl_list *head;
    struct trace_span *t_span;

    cfl_list_foreach(head, &t_entry->span_list) {
        t_span = cfl_list_entry(head, struct trace_span, _head);
        ret = sampling_conditions_check(ctx, ctx->sampling_conditions, t_entry, t_span->span);
        if (ret == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int reconcile_and_dispatch_traces(struct sampling *ctx, struct sampling_settings *settings)
{
    int ret;
    time_t now;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct trace_entry *t_entry;
    struct ctrace *ctr = NULL;

    now = time(NULL);

    /* for each complete trace, reconcile, convert to ctraces contexts (plural) and enqueue them */
    cfl_list_foreach_safe(head, tmp, &settings->span_reg->trace_list) {
        t_entry = cfl_list_entry(head, struct trace_entry, _head);

        /* check if this trace still need to wait */
        if (t_entry->ts_created + settings->decision_wait > now) {
            continue;
        }

        /*
         * check if the spans registered to this trace entry matches the conditions: if only one span
         * matches, we keep the trace entry, otherwise we discard it
         */
        ret = check_conditions(ctx, t_entry);
        if (ret == FLB_FALSE) {
            /* discard the trace and delete all associated spans */
            sampling_span_registry_delete_entry(ctx, settings->span_reg, t_entry, FLB_TRUE);
            continue;
        }

        /* Compose a new ctrace context using the spans associated to the same trace_id */
        ctr = reconcile_and_create_ctrace(ctx, settings, t_entry);
        if (!ctr) {
            flb_plg_error(ctx->ins, "could not reconcile and create ctrace context");
            return -1;
        }

        /* add the new ctrace contex to the pipeline */
        ret = flb_input_trace_append_skip_processor_stages(ctx->input_ins, ctx->ins->pu->stage + 1, NULL, 0, ctr);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "could not enqueue ctrace context");
            ctr_destroy(ctr);
            return -1;
        }
    }

    return 0;
}

static void cb_timer_flush(struct flb_config *config, void *data)
{
    int ret;
    struct sampling_settings *settings;
    struct sampling *ctx;

    settings = (struct sampling_settings *) data;
    ctx = settings->parent;

    ret = reconcile_and_dispatch_traces(ctx, settings);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not reconcile and dispatch traces");
    }

    /* delete empty ctraces contexts */
    list_ctrace_delete_empty(ctx, settings);
}

static int cb_init(struct flb_config *config, struct sampling *ctx)
{
    int ret;
    struct sampling_settings *settings;
    struct flb_sched *sched;

    flb_plg_info(ctx->ins, "initializing 'tail' sampling processor");

    settings = flb_calloc(1, sizeof(struct sampling_settings));
    if (!settings) {
        flb_errno();
        return -1;
    }
    settings->parent = ctx;
    cfl_list_init(&settings->list_ctraces);

    /* get the scheduler context */
    sched = flb_sched_ctx_get();
    if (!sched) {
        flb_plg_error(ctx->ins, "could not get scheduler context");
        return -1;
    }

    ret = flb_config_map_set(&ctx->plugin_settings_properties, ctx->plugin_config_map, (void *) settings);
    if (ret == -1) {
        flb_free(settings);
        return -1;
    }

    /* convert decision wait to milliseconds*/
    settings->decision_wait_ms = settings->decision_wait * 1000;

    /* set a timer callback */
    ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                    settings->decision_wait_ms, cb_timer_flush,
                                    settings, NULL);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not create timer");
        flb_free(settings);
        return -1;
    }

    settings->span_reg = sampling_span_registry_create(settings->max_traces);
    if (!settings->span_reg) {
        flb_plg_error(ctx->ins, "could not span registry");
        flb_free(settings);
        return -1;
    }

    sampling_set_context(ctx, settings);
    return 0;
}

static int cb_do_sampling(struct sampling *ctx, void *plugin_context,
                          struct ctrace *in_ctr, struct ctrace **out_ctr)
{
    int ret;
    struct sampling_ctrace_entry *ctrace_entry;
    struct sampling_settings *settings = plugin_context;

    ret = sampling_span_registry_add_trace(ctx, settings->span_reg, in_ctr);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to add trace to span registry");
        return FLB_PROCESSOR_FAILURE;
    }

    /* register the ctrace context */
    ctrace_entry = flb_malloc(sizeof(struct sampling_ctrace_entry));
    if (!ctrace_entry) {
        flb_errno();
        return FLB_PROCESSOR_FAILURE;
    }
    ctrace_entry->ctr = in_ctr;
    cfl_list_add(&ctrace_entry->_head, &settings->list_ctraces);

    /* caller must not destroy the ctrace reference */
    *out_ctr = NULL;

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_config *config, void *data)
{
     struct sampling_settings *settings = data;

     if (!settings) {
        return 0;
     }

     if (settings->span_reg) {
        sampling_span_registry_destroy(settings->span_reg);
     }

     list_ctrace_delete_all(settings->parent, settings);


     flb_free(settings);
     return 0;
}

struct sampling_plugin sampling_tail_plugin = {
    .type           = SAMPLING_TYPE_TAIL,
    .name           = "tail",
    .config_map     = settings_config_map,
    .cb_init        = cb_init,
    .cb_do_sampling = cb_do_sampling,
    .cb_exit        = cb_exit,
};
