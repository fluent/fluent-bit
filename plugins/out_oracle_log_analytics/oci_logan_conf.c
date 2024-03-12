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


#include <sys/stat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_file.h>

#include <monkey/mk_core/mk_list.h>
#include <monkey/mk_core/mk_string.h>
#include <fluent-bit/flb_utils.h>

#include "oci_logan.h"
#include "oci_logan_conf.h"
#include <fluent-bit/oracle/flb_oracle_client.h>


static int global_metadata_fields_create(struct flb_oci_logan *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_global_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_global_metadata) {
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->global_metadata_fields);
    }

    return 0;
}

static int log_event_metadata_create(struct flb_oci_logan *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *kname;
    struct flb_slist_entry *val;
    struct flb_config_map_val *mv;
    struct metadata_obj *f;

    if (!ctx->oci_la_metadata) {
        return 0;
    }

    flb_config_map_foreach(head, mv, ctx->oci_la_metadata) {
        kname = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        f = flb_malloc(sizeof(struct metadata_obj));
        if (!f) {
            flb_errno();
            return -1;
        }

        f->key = flb_sds_create(kname->str);
        if (!f->key) {
            flb_free(f);
            return -1;
        }
        f->val = flb_sds_create(val->str);
        if (!f->val) {
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->log_event_metadata_fields);
    }

    return 0;
}

int set_upstream_ctx(struct flb_oci_logan *ctx,
                     struct flb_output_instance *ins,
                     struct flb_config *config)
{
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp;
    int ret = 0;
    char *protocol = NULL;
    char *p_host = NULL;
    char *p_port = NULL;
    char *p_uri = NULL;

    if (ins->host.name) {
        host = ins->host.name;
    }
    else {
        if (!ctx->region ) {
            flb_errno();
            flb_plg_error(ctx->ins, "Region is required");
            return -1;
        }
        host = flb_sds_create_size(512);
        flb_sds_snprintf(&host, flb_sds_alloc(host), "loganalytics.%s.oci.oraclecloud.com", ctx->region);
    }

    io_flags = FLB_IO_TCP;
    default_port = 80;

#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        default_port = 443;
    }
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    flb_output_net_default(host, default_port, ins);
    flb_sds_destroy(host);

    if (ctx->proxy) {
        ret = flb_utils_url_split(tmp, &protocol, &p_host, &p_port, &p_uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            return -1;
        }

        ctx->proxy_host = p_host;
        ctx->proxy_port = atoi(p_port);
        flb_free(protocol);
        flb_free(p_port);
        flb_free(p_uri);
        flb_free(p_host);
    }

    if (ctx->proxy) {
        upstream = flb_upstream_create(config, ctx->proxy_host, ctx->proxy_port,
                                       io_flags, ins->tls);
    }
    else {
        /* Prepare an upstream handler */
        upstream = flb_upstream_create(config, ins->host.name, ins->host.port,
                                       io_flags, ins->tls);
    }

    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        return -1;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    return 0;
}

struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance *ins,
                                                struct flb_config *config) {
    struct flb_oci_logan *ctx;
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp;
    int ret = 0;
    char *protocol = NULL;
    char *p_host = NULL;
    char *p_port = NULL;
    char *p_uri = NULL;

    ctx = flb_calloc(1, sizeof(struct flb_oci_logan));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    build_region_table(&ctx->region_table);

    if (strcasecmp(ctx->auth_type, INSTANCE_PRINCIPAL) == 0) {
        ctx->cert_u = flb_upstream_create(config, METADATA_HOST_BASE, 80, FLB_IO_TCP, NULL);
    }

    if (ctx->oci_config_in_record == FLB_FALSE) {
        if (ctx->oci_la_log_source_name == NULL ||
            ctx->oci_la_log_group_id == NULL) {
            flb_errno();
            flb_plg_error(ctx->ins,
                          "log source name and log group id are required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }
    if (ctx->oci_la_global_metadata != NULL) {
        mk_list_init(&ctx->global_metadata_fields);
        ret = global_metadata_fields_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->oci_la_metadata != NULL) {
        mk_list_init(&ctx->log_event_metadata_fields);
        ret = log_event_metadata_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0) {
        if (!ctx->config_file_location) {
            flb_errno();
            flb_plg_error(ctx->ins, "config file location is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }

        ret = load_oci_credentials(ctx->ins, ctx->config_file_location,
                                   ctx->profile_name, &ctx->user,
                                   &ctx->tenancy, &ctx->key_file,
                                   &ctx->key_fingerprint,
                                   &ctx->region);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (!ctx->uri) {
        if (!ctx->namespace) {
            flb_errno();
            flb_plg_error(ctx->ins, "Namespace is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        ctx->uri = flb_sds_create_size(512);
        flb_sds_snprintf(&ctx->uri, flb_sds_alloc(ctx->uri),
                       "/20200601/namespaces/%s/actions/uploadLogEventsFile",
                       ctx->namespace);
    }

    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0) {
        if (create_pk_context(ctx->key_file, NULL,
                              ctx->ins, &ctx->private_key) < 0) {
            flb_plg_error(ctx->ins, "failed to create pk context");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    ctx->key_id = flb_sds_create_size(512*8);
    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0) {
        flb_sds_snprintf(&ctx->key_id, flb_sds_alloc(ctx->key_id),
                         "%s/%s/%s", ctx->tenancy, ctx->user, ctx->key_fingerprint);
    }

    if (strcasecmp(ctx->auth_type, USER_PRINCIPAL) == 0 ||
    strcasecmp(ctx->auth_type, WORKLOAD_IDENTITY) == 0) {
        ret = set_upstream_ctx(ctx, ins, config);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot create Upstream context");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    return ctx;
}

static void metadata_fields_destroy(struct flb_oci_logan *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct metadata_obj *f;

    mk_list_foreach_safe(head, tmp, &ctx->global_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        flb_sds_destroy(f->key);
        flb_sds_destroy(f->val);
        mk_list_del(&f->_head);
        flb_free(f);
    }

    mk_list_foreach_safe(head, tmp, &ctx->log_event_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        flb_sds_destroy(f->key);
        flb_sds_destroy(f->val);
        mk_list_del(&f->_head);
        flb_free(f);
    }

}

int flb_cert_ret_destroy(struct cert_retriever *cert_ret) {
    if (cert_ret->cert_pem) {
        flb_sds_destroy(cert_ret->cert_pem);
    }
    if (cert_ret->private_key_pem) {
        flb_sds_destroy(cert_ret->private_key_pem);
    }
    if (cert_ret->cert) {
        X509_free(cert_ret->cert);
    }
}
int flb_fed_client_destroy(struct federation_client *fd) {
    if (fd->security_token) {
        flb_sds_destroy(fd->security_token);
    }
    if (fd->leaf_cert_ret) {
        flb_cert_ret_destroy(fd->leaf_cert_ret);
    }
    if (fd->key_id) {
        flb_sds_destroy(fd->key_id);
    }
    if (fd->public_key) {
        flb_sds_destroy(fd->public_key);
    }
    if (fd->tenancy_id) {
        flb_sds_destroy(fd->tenancy_id);
    }
    if (fd->private_key) {
        flb_sds_destroy(fd->private_key);
    }
    if (fd->intermediate_cert_ret) {
        flb_cert_ret_destroy(fd->intermediate_cert_ret);
    }
    if (fd->region) {
        flb_sds_destroy(fd->region);
    }
}

int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx) {
    if(ctx == NULL) {
        return 0;
    }

    if (ctx->fed_client) {
        flb_fed_client_destroy(ctx->fed_client);
    }
    if (ctx->cert_u) {
        flb_upstream_destroy(ctx->cert_u);
    }
    if (ctx->fed_u) {
        flb_upstream_destroy(ctx->fed_u);
    }
    if (ctx->private_key) {
        flb_sds_destroy(ctx->private_key);
    }
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }
    if (ctx->key_id) {
        flb_sds_destroy(ctx->key_id);
    }
    if (ctx->key_file) {
        flb_sds_destroy(ctx->key_file);
    }
    if(ctx->user) {
        flb_sds_destroy(ctx->user);
    }
    if(ctx->key_fingerprint) {
        flb_sds_destroy(ctx->key_fingerprint);
    }
    if(ctx->tenancy) {
        flb_sds_destroy(ctx->tenancy);
    }
    if(ctx->region) {
        flb_sds_destroy(ctx->region);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    metadata_fields_destroy(ctx);

    flb_free(ctx);
    return 0;
}