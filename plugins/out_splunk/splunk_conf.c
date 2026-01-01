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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>

#include "splunk.h"
#include "splunk_conf.h"

static int event_fields_create(struct flb_splunk *ctx)
{
    int i = 0;
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *pattern;
    struct flb_config_map_val *mv;
    struct flb_splunk_field *f;

    if (!ctx->event_fields) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->event_fields) {
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        pattern = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct flb_splunk_field));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key_name = flb_sds_create(kname->str);
        if (!f->key_name) {
            flb_free(f);
            return -1;
        }

        f->ra = flb_ra_create(pattern->str, FLB_TRUE);
        if (!f->ra) {
            flb_plg_error(ctx->ins,
                          "could not process event_field number #%i with "
                          "pattern '%s'",
                          i, pattern->str);
            flb_sds_destroy(f->key_name);
            flb_free(f);
            return -1;
        }

        mk_list_add(&f->_head, &ctx->fields);
    }

    return 0;
}

static void event_fields_destroy(struct flb_splunk *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_splunk_field *f;

    mk_list_foreach_safe(head, tmp, &ctx->fields) {
        f = mk_list_entry(head, struct flb_splunk_field, _head);
        flb_sds_destroy(f->key_name);
        flb_ra_destroy(f->ra);
        mk_list_del(&f->_head);
        flb_free(f);
    }
}

struct flb_splunk *flb_splunk_conf_create(struct flb_output_instance *ins,
                                          struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    size_t size;
    flb_sds_t t;
    const char *tmp;
    struct flb_upstream *upstream;
    struct flb_splunk *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_splunk));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->fields);

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Set default network configuration */
    flb_output_net_default(FLB_SPLUNK_DEFAULT_HOST, FLB_SPLUNK_DEFAULT_PORT, ins);

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   ins->tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        flb_splunk_conf_destroy(ctx);
        return NULL;
    }

    /* Set manual Index and Type */
    ctx->u = upstream;

    tmp = flb_output_get_property("http_buffer_size", ins);
    if (!tmp) {
        ctx->buffer_size = 0;
    }
    else {
        size = flb_utils_size_to_bytes(tmp);
        if (size == -1) {
            flb_plg_error(ctx->ins, "invalid 'buffer_size' value");
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
        if (size < 4 *1024) {
            size = 4 * 1024;
        }
        ctx->buffer_size = size;
    }

    /* Compress (gzip) */
    tmp = flb_output_get_property("compress", ins);
    ctx->compress_gzip = FLB_FALSE;
    if (tmp) {
        if (strcasecmp(tmp, "gzip") == 0) {
            ctx->compress_gzip = FLB_TRUE;
        }
    }

    /* Event key */
    if (ctx->event_key) {
        if (ctx->event_key[0] != '$') {
            flb_plg_error(ctx->ins,
                          "invalid event_key pattern, it must start with '$'");
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
        ctx->ra_event_key = flb_ra_create(ctx->event_key, FLB_TRUE);
        if (!ctx->ra_event_key) {
            flb_plg_error(ctx->ins,
                          "cannot create record accessor for event_key pattern: '%s'",
                          ctx->event_key);
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
    }

    /* Event host */
    if (ctx->event_host) {
        ctx->ra_event_host = flb_ra_create(ctx->event_host, FLB_TRUE);
        if (!ctx->ra_event_host) {
            flb_plg_error(ctx->ins,
                          "cannot create record accessor for event_key pattern: '%s'",
                          ctx->event_host);
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
    }

    /* Event source */
    if (ctx->event_source) {
        ctx->ra_event_source = flb_ra_create(ctx->event_source, FLB_TRUE);
        if (!ctx->ra_event_source) {
            flb_plg_error(ctx->ins,
                          "cannot create record accessor for event_source pattern: '%s'",
                          ctx->event_host);
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
    }

    /* Event source (key lookup) */
    if (ctx->event_sourcetype_key) {
        ctx->ra_event_sourcetype_key = flb_ra_create(ctx->event_sourcetype_key, FLB_TRUE);
        if (!ctx->ra_event_sourcetype_key) {
            flb_plg_error(ctx->ins,
                          "cannot create record accessor for "
                          "event_sourcetype_key pattern: '%s'",
                          ctx->event_host);
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
    }

    /* Event index (key lookup) */
    if (ctx->event_index_key) {
        ctx->ra_event_index_key = flb_ra_create(ctx->event_index_key, FLB_TRUE);
        if (!ctx->ra_event_index_key) {
            flb_plg_error(ctx->ins,
                          "cannot create record accessor for "
                          "event_index_key pattern: '%s'",
                          ctx->event_host);
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
    }

    /* Event fields */
    ret = event_fields_create(ctx);
    if (ret == -1) {
        flb_splunk_conf_destroy(ctx);
        return NULL;
    }

    ctx->metadata_auth_header = NULL;

    /* No http_user is set, fallback to splunk_token, if splunk_token is unset, fail. */
    if (!ctx->http_user) {
        /* Splunk Auth Token */
        tmp = flb_output_get_property("splunk_token", ins);
        if(!tmp) {
            flb_plg_error(ctx->ins, "either splunk_token or http_user should be set");
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
        ctx->auth_header = flb_sds_create("Splunk ");
        t = flb_sds_cat(ctx->auth_header, tmp, strlen(tmp));
        if (t) {
            ctx->auth_header = t;
        }
        else {
            flb_plg_error(ctx->ins, "error on token generation");
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
    }

    pthread_mutex_init(&ctx->mutex_hec_token, NULL);

    /* Currently, Splunk HEC token is stored in a fixed key, hec_token. */
    ctx->metadata_auth_key = "$hec_token";
    if (ctx->metadata_auth_key) {
        ctx->ra_metadata_auth_key = flb_ra_create(ctx->metadata_auth_key, FLB_TRUE);
        if (!ctx->ra_metadata_auth_key) {
            flb_plg_error(ctx->ins,
                          "cannot create record accessor for "
                          "metadata_auth_key pattern: '%s'",
                          ctx->event_host);
            flb_splunk_conf_destroy(ctx);
            return NULL;
        }
    }


    /* channel */
    if (ctx->channel != NULL) {
        ctx->channel_len = flb_sds_len(ctx->channel);
    }

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    return ctx;
}

int flb_splunk_conf_destroy(struct flb_splunk *ctx)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->auth_header) {
        flb_sds_destroy(ctx->auth_header);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->ra_event_key) {
        flb_ra_destroy(ctx->ra_event_key);
    }

    if (ctx->ra_event_host) {
        flb_ra_destroy(ctx->ra_event_host);
    }

    if (ctx->ra_event_source) {
        flb_ra_destroy(ctx->ra_event_source);
    }

    if (ctx->ra_event_sourcetype_key) {
        flb_ra_destroy(ctx->ra_event_sourcetype_key);
    }

    if (ctx->ra_event_index_key) {
        flb_ra_destroy(ctx->ra_event_index_key);
    }

    if (ctx->ra_metadata_auth_key) {
        flb_ra_destroy(ctx->ra_metadata_auth_key);
    }

    if (ctx->metadata_auth_header) {
        flb_sds_destroy(ctx->metadata_auth_header);
    }

    event_fields_destroy(ctx);

    flb_free(ctx);

    return 0;
}
