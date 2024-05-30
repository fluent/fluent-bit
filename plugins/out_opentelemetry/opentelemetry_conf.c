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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_record_accessor.h>

#include "opentelemetry.h"
#include "opentelemetry_conf.h"

/* create a single entry of log_body_key */
static int log_body_key_create(struct opentelemetry_context *ctx, char *ra_pattern)
{
    struct opentelemetry_body_key *bk;

    bk = flb_calloc(1, sizeof(struct opentelemetry_body_key));
    if (!bk) {
        flb_errno();
        return -1;
    }

    bk->key = flb_sds_create(ra_pattern);
    if (!bk->key) {
        flb_free(bk);
        return -1;
    }

    bk->ra = flb_ra_create(ra_pattern, FLB_TRUE);
    if (!bk->ra) {
        flb_plg_error(ctx->ins,
                      "could not process event_field with pattern '%s'",
                      ra_pattern);
        flb_sds_destroy(bk->key);
        flb_free(bk);
        return -1;
    }

    mk_list_add(&bk->_head, &ctx->log_body_key_list);

    return 0;
}

/* process and instance the list of body key patterns */
static int log_body_key_list_create(struct opentelemetry_context *ctx)
{
    int ret;
    struct mk_list *head;
    struct flb_config_map_val *mv;

    /* If no log_body_key are defined, set the default ones */
    if (!ctx->log_body_key_list_str || mk_list_size(ctx->log_body_key_list_str) == 0) {
        ret = log_body_key_create(ctx, "$log");
        if (ret != 0) {
            return -1;
        }

        ret = log_body_key_create(ctx, "$message");
        if (ret != 0) {
            return -1;
        }

        return 0;
    }

    /* Iterate the list of log body keys defined in the configuration and initiate them */
    flb_config_map_foreach(head, mv, ctx->log_body_key_list_str) {
        ret = log_body_key_create(ctx, mv->val.str);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

static void log_body_key_list_destroy(struct opentelemetry_context *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct opentelemetry_body_key *bk;

    mk_list_foreach_safe(head, tmp, &ctx->log_body_key_list) {
        bk = mk_list_entry(head, struct opentelemetry_body_key, _head);
        flb_sds_destroy(bk->key);
        flb_ra_destroy(bk->ra);
        mk_list_del(&bk->_head);
        flb_free(bk);
    }
}

static int metadata_mp_accessor_create(struct opentelemetry_context *ctx)
{
    int ret;
    struct mk_list *head;
    struct mk_list slist;
    struct opentelemetry_body_key *bk;
    struct flb_mp_accessor *mpa;

    ret = flb_slist_create(&slist);
    if (ret != 0) {
        return -1;
    }

    /* Iterate the list of log body keys and create a mp_accessor for each one */
    mk_list_foreach(head, &ctx->log_body_key_list) {
        bk = mk_list_entry(head, struct opentelemetry_body_key, _head);

        ret = flb_slist_add(&slist, bk->key);
        if (ret != 0) {
            flb_slist_destroy(&slist);
            return -1;
        }
    }

    mpa = flb_mp_accessor_create(&slist);
    if (!mpa) {
        flb_slist_destroy(&slist);
        return -1;
    }

    ctx->mp_accessor = mpa;
    flb_slist_destroy(&slist);

    return 0;
}

static int config_add_labels(struct flb_output_instance *ins,
                             struct opentelemetry_context *ctx)
{
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *k = NULL;
    struct flb_slist_entry *v = NULL;
    struct flb_kv *kv;

    if (!ctx->add_labels || mk_list_size(ctx->add_labels) == 0) {
        return 0;
    }

    /* iterate all 'add_label' definitions */
    flb_config_map_foreach(head, mv, ctx->add_labels) {
        if (mk_list_size(mv->val.list) != 2) {
            flb_plg_error(ins, "'add_label' expects a key and a value, "
                          "e.g: 'add_label version 1.8.0'");
            return -1;
        }

        k = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        v = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        kv = flb_kv_item_create(&ctx->kv_labels, k->str, v->str);
        if (!kv) {
            flb_plg_error(ins, "could not append label %s=%s\n", k->str, v->str);
            return -1;
        }
    }

    return 0;
}

/*
* Check if a Proxy have been set, if so the Upstream manager will use
* the Proxy end-point and then we let the HTTP client know about it, so
* it can adjust the HTTP requests.
*/

static void check_proxy(struct flb_output_instance *ins,
                        struct opentelemetry_context *ctx,
                        char *host, char *port,
                        char *protocol, char *uri){

    const char *tmp = NULL;
    int ret;
    tmp = flb_output_get_property("proxy", ins);
    if (tmp) {
        ret = flb_utils_url_split(tmp, &protocol, &host, &port, &uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            flb_free(ctx);
        }

        ctx->proxy_host = host;
        ctx->proxy_port = atoi(port);
        ctx->proxy = tmp;
        flb_free(protocol);
        flb_free(port);
        flb_free(uri);
        uri = NULL;
    }
    else {
        flb_output_net_default("127.0.0.1", 80, ins);
    }
}

static char *sanitize_uri(char *uri){
    char *new_uri;
    int   uri_len;

    if (uri == NULL) {
        uri = flb_strdup("/");
    }
    else if (uri[0] != '/') {
        uri_len = strlen(uri);
        new_uri = flb_calloc(uri_len + 2, sizeof(char));

        if (new_uri != NULL) {
            new_uri[0] = '/';

            strncat(new_uri, uri, uri_len + 1);
        }

        uri = new_uri;
    }

    /* This function could return NULL if flb_calloc fails */

    return uri;
}

struct opentelemetry_context *flb_opentelemetry_context_create(struct flb_output_instance *ins, struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *metrics_uri = NULL;
    char *traces_uri = NULL;
    char *logs_uri = NULL;
    struct flb_upstream *upstream;
    struct opentelemetry_context *ctx = NULL;
    const char *tmp = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct opentelemetry_context));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->kv_labels);
    mk_list_init(&ctx->log_body_key_list);

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Parse 'add_label' */
    ret = config_add_labels(ins, ctx);
    if (ret == -1) {
        return NULL;
    }


    check_proxy(ins, ctx, host, port, protocol, metrics_uri);
    check_proxy(ins, ctx, host, port, protocol, logs_uri);

    /* Check if SSL/TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }
#else
    io_flags = FLB_IO_TCP;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    if (ctx->proxy) {
        flb_plg_trace(ctx->ins, "Upstream Proxy=%s:%i",
                      ctx->proxy_host, ctx->proxy_port);
        upstream = flb_upstream_create(config,
                                       ctx->proxy_host,
                                       ctx->proxy_port,
                                       io_flags, ins->tls);
    }
    else {
        upstream = flb_upstream_create(config,
                                       ins->host.name,
                                       ins->host.port,
                                       io_flags, ins->tls);
    }

    if (!upstream) {
        flb_free(ctx);
        return NULL;
    }

    logs_uri = sanitize_uri(ctx->logs_uri);
    traces_uri = sanitize_uri(ctx->traces_uri);
    metrics_uri = sanitize_uri(ctx->metrics_uri);

    ctx->u = upstream;
    ctx->host = ins->host.name;
    ctx->port = ins->host.port;


    /* Logs Properties */
    if (logs_uri == NULL) {
        flb_plg_trace(ctx->ins,
                      "Could not allocate memory for sanitized "
                      "log endpoint uri");
    }
    else {
        ctx->logs_uri = logs_uri;
    }

    /* list of 'logs_body_key' */
    ret = log_body_key_list_create(ctx);
    if (ret != 0) {
        flb_opentelemetry_context_destroy(ctx);
        return NULL;
    }

    /*
     * Add the pattern to the mp_accessor list: for every key that populates the log body, we need
     * it also in the mp_accessor list so remaining keys are set into the metadata field.
     *
     * This process is far from being optimal since we are kind of duplicating the logic, however
     * we can simply use the API already exists in place, let's optimize later (if needed).
     */
    ret = metadata_mp_accessor_create(ctx);
    if (ret != 0) {
        flb_opentelemetry_context_destroy(ctx);
        return NULL;
    }

    if (traces_uri == NULL) {
        flb_plg_trace(ctx->ins,
                      "Could not allocate memory for sanitized "
                      "trace endpoint uri");
    }
    else {
        ctx->traces_uri = traces_uri;
    }

    if (metrics_uri == NULL) {
        flb_plg_trace(ctx->ins,
                      "Could not allocate memory for sanitized "
                      "metric endpoint uri");
    }
    else {
        ctx->metrics_uri = metrics_uri;
    }


    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    tmp = flb_output_get_property("compress", ins);
    ctx->compress_gzip = FLB_FALSE;
    if (tmp) {
        if (strcasecmp(tmp, "gzip") == 0) {
            ctx->compress_gzip = FLB_TRUE;
        }
    }

    ctx->ra_observed_timestamp_metadata = flb_ra_create((char*)ctx->logs_observed_timestamp_metadata_key,
                                                        FLB_FALSE);
    if (ctx->ra_observed_timestamp_metadata == NULL) {
        flb_plg_error(ins, "failed to create ra for observed timestamp");
    }
    ctx->ra_timestamp_metadata = flb_ra_create((char*)ctx->logs_timestamp_metadata_key,
                                               FLB_FALSE);
    if (ctx->ra_timestamp_metadata == NULL) {
        flb_plg_error(ins, "failed to create ra for timestamp");
    }
    ctx->ra_severity_text_metadata = flb_ra_create((char*)ctx->logs_severity_text_metadata_key,
                                                   FLB_FALSE);
    if (ctx->ra_severity_text_metadata == NULL) {
        flb_plg_error(ins, "failed to create ra for severity text");
    }
    ctx->ra_severity_number_metadata = flb_ra_create((char*)ctx->logs_severity_number_metadata_key,
                                                   FLB_FALSE);
    if (ctx->ra_severity_number_metadata == NULL) {
        flb_plg_error(ins, "failed to create ra for severity number");
    }
    ctx->ra_trace_flags_metadata = flb_ra_create((char*)ctx->logs_trace_flags_metadata_key,
                                                 FLB_FALSE);
    if (ctx->ra_trace_flags_metadata == NULL) {
        flb_plg_error(ins, "failed to create ra for trace flags");
    }
    ctx->ra_span_id_metadata = flb_ra_create((char*)ctx->logs_span_id_metadata_key,
                                             FLB_FALSE);
    if (ctx->ra_span_id_metadata == NULL) {
        flb_plg_error(ins, "failed to create ra for span id");
    }
    ctx->ra_trace_id_metadata = flb_ra_create((char*)ctx->logs_trace_id_metadata_key,
                                              FLB_FALSE);
    if (ctx->ra_trace_id_metadata == NULL) {
        flb_plg_error(ins, "failed to create ra for trace id");
    }
    ctx->ra_attributes_metadata = flb_ra_create((char*) ctx->logs_attributes_metadata_key,
                                                FLB_FALSE);
    if (ctx->ra_attributes_metadata == NULL) {
        flb_plg_error(ins, "failed to create ra for attributes");
    }
    ctx->ra_span_id_message = flb_ra_create((char*)ctx->logs_span_id_message_key,
                                             FLB_FALSE);
    if (ctx->ra_span_id_message == NULL) {
        flb_plg_error(ins, "failed to create ra for message span id");
    }
    ctx->ra_trace_id_message = flb_ra_create((char*)ctx->logs_trace_id_message_key,
                                              FLB_FALSE);
    if (ctx->ra_trace_id_message == NULL) {
        flb_plg_error(ins, "failed to create ra for message trace id");
    }
    ctx->ra_severity_text_message = flb_ra_create((char*)ctx->logs_severity_text_message_key,
                                              FLB_FALSE);
    if (ctx->ra_severity_text_message == NULL) {
        flb_plg_error(ins, "failed to create ra for message severity text");
    }
    ctx->ra_severity_number_message = flb_ra_create((char*)ctx->logs_severity_number_message_key,
                                              FLB_FALSE);
    if (ctx->ra_severity_number_message == NULL) {
        flb_plg_error(ins, "failed to create ra for message severity number");
    }

    /* record accessor: group metadata */
    ctx->ra_meta_schema = flb_ra_create("$schema", FLB_FALSE);
    if (ctx->ra_meta_schema == NULL) {
        flb_plg_error(ins, "failed to create record accessor for schema");
    }

    ctx->ra_meta_resource_id = flb_ra_create((char *) "$resource_id", FLB_FALSE);
    if (ctx->ra_meta_resource_id == NULL) {
        flb_plg_error(ins, "failed to create record accessor for resource_id");
    }

    ctx->ra_meta_scope_id = flb_ra_create((char *) "$scope_id", FLB_FALSE);
    if (ctx->ra_meta_scope_id == NULL) {
        flb_plg_error(ins, "failed to create record accessor for scope_id");
    }

    /* record accessor: group body */
    ctx->ra_resource_attr = flb_ra_create("$resource['attributes']", FLB_FALSE);
    if (ctx->ra_resource_attr == NULL) {
        flb_plg_error(ins, "failed to create record accessor for resource attributes");
    }

    ctx->ra_resource_schema_url = flb_ra_create("$schema_url", FLB_FALSE);
    if (ctx->ra_resource_schema_url == NULL) {
        flb_plg_error(ins, "failed to create record accessor for resource schema url");
    }

    ctx->ra_scope_name = flb_ra_create("$scope['name']", FLB_FALSE);
    if (ctx->ra_scope_name == NULL) {
        flb_plg_error(ins, "failed to create record accessor for scope name");
    }

    ctx->ra_scope_version = flb_ra_create("$scope['version']", FLB_FALSE);
    if (ctx->ra_scope_version == NULL) {
        flb_plg_error(ins, "failed to create record accessor for scope version");
    }

    ctx->ra_scope_attr = flb_ra_create("$scope['attributes']", FLB_FALSE);
    if (ctx->ra_scope_attr == NULL) {
        flb_plg_error(ins, "failed to create record accessor for scope attributes");
    }

    /* log metadata under $otlp (set by in_opentelemetry) */

    ctx->ra_log_meta_otlp_observed_ts = flb_ra_create("$otlp['observed_timestamp']", FLB_FALSE);
    if (ctx->ra_log_meta_otlp_observed_ts == NULL) {
        flb_plg_error(ins, "failed to create record accessor for otlp observed timestamp");
    }

    ctx->ra_log_meta_otlp_timestamp = flb_ra_create("$otlp['timestamp']", FLB_FALSE);
    if (ctx->ra_log_meta_otlp_timestamp == NULL) {
        flb_plg_error(ins, "failed to create record accessor for otlp timestamp");
    }

    ctx->ra_log_meta_otlp_severity_number = flb_ra_create("$otlp['severity_number']", FLB_FALSE);
    if (ctx->ra_log_meta_otlp_severity_number == NULL) {
        flb_plg_error(ins, "failed to create record accessor for otlp severity number");
    }

    ctx->ra_log_meta_otlp_severity_text = flb_ra_create("$otlp['severity_text']", FLB_FALSE);
    if (ctx->ra_log_meta_otlp_severity_text == NULL) {
        flb_plg_error(ins, "failed to create record accessor for otlp severity text");
    }

    ctx->ra_log_meta_otlp_attr = flb_ra_create("$otlp['attributes']", FLB_FALSE);
    if (ctx->ra_log_meta_otlp_attr == NULL) {
        flb_plg_error(ins, "failed to create record accessor for otlp attributes");
    }

    ctx->ra_log_meta_otlp_trace_id = flb_ra_create("$otlp['trace_id']", FLB_FALSE);
    if (ctx->ra_log_meta_otlp_trace_id == NULL) {
        flb_plg_error(ins, "failed to create record accessor for otlp trace id");
    }

    ctx->ra_log_meta_otlp_span_id = flb_ra_create("$otlp['span_id']", FLB_FALSE);
    if (ctx->ra_log_meta_otlp_span_id == NULL) {
        flb_plg_error(ins, "failed to create record accessor for otlp span id");
    }

    ctx->ra_log_meta_otlp_trace_flags = flb_ra_create("$otlp['trace_flags']", FLB_FALSE);
    if (ctx->ra_log_meta_otlp_trace_flags == NULL) {
        flb_plg_error(ins, "failed to create record accessor for otlp trace flags");
    }

    return ctx;
}

void flb_opentelemetry_context_destroy(struct opentelemetry_context *ctx)
{
    if (!ctx) {
        return;
    }

    flb_kv_release(&ctx->kv_labels);

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    /* release log_body_key_list */
    log_body_key_list_destroy(ctx);

    if (ctx->mp_accessor) {
        flb_mp_accessor_destroy(ctx->mp_accessor);
    }
    if (ctx->ra_observed_timestamp_metadata) {
        flb_ra_destroy(ctx->ra_observed_timestamp_metadata);
    }
    if (ctx->ra_timestamp_metadata) {
        flb_ra_destroy(ctx->ra_timestamp_metadata);
    }
    if (ctx->ra_severity_text_metadata) {
        flb_ra_destroy(ctx->ra_severity_text_metadata);
    }
    if (ctx->ra_severity_number_metadata) {
        flb_ra_destroy(ctx->ra_severity_number_metadata);
    }
    if (ctx->ra_trace_flags_metadata) {
        flb_ra_destroy(ctx->ra_trace_flags_metadata);
    }
    if (ctx->ra_span_id_metadata) {
        flb_ra_destroy(ctx->ra_span_id_metadata);
    }
    if (ctx->ra_trace_id_metadata) {
        flb_ra_destroy(ctx->ra_trace_id_metadata);
    }
    if (ctx->ra_attributes_metadata) {
        flb_ra_destroy(ctx->ra_attributes_metadata);
    }
    if (ctx->ra_span_id_message) {
        flb_ra_destroy(ctx->ra_span_id_message);
    }
    if (ctx->ra_trace_id_message) {
        flb_ra_destroy(ctx->ra_trace_id_message);
    }
    if (ctx->ra_severity_text_message) {
        flb_ra_destroy(ctx->ra_severity_text_message);
    }
    if (ctx->ra_severity_number_message) {
        flb_ra_destroy(ctx->ra_severity_number_message);
    }

    if (ctx->ra_meta_schema) {
        flb_ra_destroy(ctx->ra_meta_schema);
    }
    if (ctx->ra_meta_resource_id) {
        flb_ra_destroy(ctx->ra_meta_resource_id);
    }
    if (ctx->ra_meta_scope_id) {
        flb_ra_destroy(ctx->ra_meta_scope_id);
    }
    if (ctx->ra_resource_attr) {
        flb_ra_destroy(ctx->ra_resource_attr);
    }
    if (ctx->ra_resource_schema_url) {
        flb_ra_destroy(ctx->ra_resource_schema_url);
    }
    if (ctx->ra_scope_name) {
        flb_ra_destroy(ctx->ra_scope_name);
    }
    if (ctx->ra_scope_version) {
        flb_ra_destroy(ctx->ra_scope_version);
    }
    if (ctx->ra_scope_attr) {
        flb_ra_destroy(ctx->ra_scope_attr);
    }

    if (ctx->ra_log_meta_otlp_observed_ts) {
        flb_ra_destroy(ctx->ra_log_meta_otlp_observed_ts);
    }

    if (ctx->ra_log_meta_otlp_timestamp) {
        flb_ra_destroy(ctx->ra_log_meta_otlp_timestamp);
    }

    if (ctx->ra_log_meta_otlp_severity_number) {
        flb_ra_destroy(ctx->ra_log_meta_otlp_severity_number);
    }

    if (ctx->ra_log_meta_otlp_severity_text) {
        flb_ra_destroy(ctx->ra_log_meta_otlp_severity_text);
    }

    if (ctx->ra_log_meta_otlp_attr) {
        flb_ra_destroy(ctx->ra_log_meta_otlp_attr);
    }

    if (ctx->ra_log_meta_otlp_trace_id) {
        flb_ra_destroy(ctx->ra_log_meta_otlp_trace_id);
    }

    if (ctx->ra_log_meta_otlp_span_id) {
        flb_ra_destroy(ctx->ra_log_meta_otlp_span_id);
    }

    if (ctx->ra_log_meta_otlp_trace_flags) {
        flb_ra_destroy(ctx->ra_log_meta_otlp_trace_flags);
    }

    flb_free(ctx->proxy_host);
    flb_free(ctx);
}
