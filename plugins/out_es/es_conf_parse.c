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

#include <string.h>

#include <monkey/mk_core/mk_list.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_aws_credentials.h>

#include "es.h"
#include "es_conf_parse.h"

int flb_es_conf_set_cloud_credentials(const char *cloud_auth,
                                      struct flb_elasticsearch_config *ec)
{
    /* extract strings */
    int items = 0;
    struct mk_list *toks;
    struct mk_list *head;
    struct flb_split_entry *entry;

    if (!cloud_auth) {
        return 0;
    }

    toks = flb_utils_split((const char *)cloud_auth, ':', -1);
    mk_list_foreach(head, toks) {
        items++;
        entry = mk_list_entry(head, struct flb_split_entry, _head);
        if (items == 1) {
            ec->cloud_user = flb_strdup(entry->value);
        }
        if (items == 2) {
            ec->cloud_passwd = flb_strdup(entry->value);
        }
    }
    flb_utils_split_free(toks);

    return 0;
}

/*
 * extract_cloud_host extracts the public hostname
 * of a deployment from a Cloud ID string.
 *
 * The Cloud ID string has the format "<deployment_name>:<base64_info>".
 * Once decoded, the "base64_info" string has the format "<deployment_region>$<elasticsearch_hostname>$<kibana_hostname>"
 * and the function returns "<elasticsearch_hostname>.<deployment_region>" token.
 */
static flb_sds_t extract_cloud_host(const char *cloud_id, struct flb_elasticsearch *ctx)
{

    char *colon;
    char *region;
    char *host;
    char *port = NULL;
    char buf[256] = {0};
    char cloud_host_buf[256] = {0};
    const char dollar[2] = "$";
    size_t len;
    int ret;

    /* keep only part after first ":" */
    colon = strchr(cloud_id, ':');
    if (colon == NULL) {
        return NULL;
    }
    colon++;

    /* decode base64 */
    ret = flb_base64_decode((unsigned char *)buf, sizeof(buf), &len,
                            (unsigned char *)colon, strlen(colon));
    if (ret) {
        flb_plg_error(ctx->ins, "cannot decode cloud_id");
        return NULL;
    }
    region = strtok(buf, dollar);
    if (region == NULL) {
        return NULL;
    }
    host = strtok(NULL, dollar);
    if (host == NULL) {
        return NULL;
    }

    /*
     * Some cloud id format is "<deployment_region>$<elasticsearch_hostname>:<port>$<kibana_hostname>" .
     *   e.g. https://github.com/elastic/beats/blob/v8.4.1/libbeat/cloudid/cloudid_test.go#L60
     *
     * It means the variable "host" can contains ':' and port number.
     */
    colon = strchr(host, ':');
    if (colon != NULL) {
        /* host contains host number */
        *colon = '\0'; /* remove port number from host */
        port = colon+1;
    }

    strcpy(cloud_host_buf, host);
    strcat(cloud_host_buf, ".");
    strcat(cloud_host_buf, region);
    if (port != NULL) {
        strcat(cloud_host_buf, ":");
        strcat(cloud_host_buf, port);
    }
    return flb_sds_create(cloud_host_buf);
}

int flb_es_conf_set_cloud_auth(const char *cloud_auth, struct flb_elasticsearch *ctx)
{
    char *cloud_host;
    int cloud_host_port = 0;
    char *cloud_port_char;
    int cloud_port = FLB_ES_DEFAULT_HTTPS_PORT;

    if (!cloud_auth) {
        return 0;
    }

    cloud_host = extract_cloud_host(cloud_auth, ctx);
    if (cloud_host == NULL) {
        flb_plg_error(ctx->ins, "cannot extract cloud_host");
        return -1;
    }
    flb_plg_debug(ctx->ins, "extracted cloud_host: '%s'", cloud_host);

    cloud_port_char = strchr(cloud_host, ':');

    if (cloud_port_char == NULL) {
        flb_plg_debug(ctx->ins, "cloud_host: '%s' does not contain a port: '%s'",
                      cloud_host, cloud_host);
    }
    else {
        cloud_port_char[0] = '\0';
        cloud_port_char = &cloud_port_char[1];
        flb_plg_debug(ctx->ins, "extracted cloud_port_char: '%s'", cloud_port_char);
        cloud_host_port = (int)strtol(cloud_port_char, (char **)NULL, 10);
        flb_plg_debug(ctx->ins, "converted cloud_port_char to port int: '%i'",
                      cloud_host_port);
    }

    if (cloud_host_port == 0) {
        cloud_host_port = cloud_port;
    }

    flb_plg_debug(ctx->ins,
                  "checked whether extracted port was null and set it to "
                  "default https port or not. Outcome: '%i' and cloud_host: '%s'.",
                  cloud_host_port, cloud_host);

    if (ctx->ins->host.name != NULL) {
        flb_sds_destroy(ctx->ins->host.name);
    }

    ctx->ins->host.name = cloud_host;
    ctx->ins->host.port = cloud_host_port;

    return 0;
}

#ifdef FLB_HAVE_AWS

int flb_es_set_aws_unsigned_headers(struct flb_elasticsearch_config *ec)
{
    int ret;

    /* AWS Auth Unsigned Headers */
    ec->aws_unsigned_headers = flb_malloc(sizeof(struct mk_list));
    if (!ec->aws_unsigned_headers) {
        flb_errno();
        return -1;
    }

    flb_slist_create(ec->aws_unsigned_headers);
    ret = flb_slist_add(ec->aws_unsigned_headers, "Content-Length");
    if (ret != 0) {
        return -1;
    }

    return 0;
}

static int set_aws_sts_provider(const char *aws_external_id,
                                const char *aws_role_arn,
                                struct flb_elasticsearch_config *ec,
                                struct flb_elasticsearch *ctx,
                                struct flb_config *config)
{
    char *aws_session_name = NULL;

    if (!aws_role_arn) {
        return 0;
    }

    /* Use the STS Provider */
    ec->base_aws_provider = ec->aws_provider;

    aws_session_name = flb_sts_session_name();
    if (!aws_session_name) {
        flb_error("[out_es] Failed to create aws iam role session name");
        return -1;
    }

    /* STS provider needs yet another separate TLS instance */
    ec->aws_sts_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                     FLB_TRUE,
                                     ctx->ins->tls_debug,
                                     ctx->ins->tls_vhost,
                                     ctx->ins->tls_ca_path,
                                     ctx->ins->tls_ca_file,
                                     ctx->ins->tls_crt_file,
                                     ctx->ins->tls_key_file,
                                     ctx->ins->tls_key_passwd);
    if (!ec->aws_sts_tls) {
        flb_errno();
        flb_free(aws_session_name);
        return -1;
    }

    ec->aws_provider = flb_sts_provider_create(config,
                                               ec->aws_sts_tls,
                                               ec->base_aws_provider,
                                               (char *)aws_external_id,
                                               (char *)aws_role_arn,
                                               aws_session_name,
                                               ec->aws_region,
                                               ec->aws_sts_endpoint,
                                               NULL,
                                               flb_aws_client_generator());
    /* Session name can be freed once provider is created */
    flb_free(aws_session_name);

    if (!ec->aws_provider) {
        flb_error("[out_es] Failed to create AWS STS Credential Provider");
        return -1;
    }

    return 0;
}

int flb_es_conf_set_aws_provider(const char *aws_external_id,
                                 const char *aws_role_arn,
                                 struct flb_elasticsearch_config *ec,
                                 struct flb_elasticsearch *ctx,
                                 struct flb_config *config)
{
    int ret;

    if (ec->has_aws_auth == FLB_FALSE) {
        return 0;
    }

    flb_debug("[out_es] Enabled AWS Auth");

    if (!ec->aws_region) {
        flb_error("[out_es] aws_auth enabled but aws_region not set");
        return -1;
    }

    /* AWS provider needs a separate TLS instance */
    ec->aws_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                 FLB_TRUE,
                                 ctx->ins->tls_debug,
                                 ctx->ins->tls_vhost,
                                 ctx->ins->tls_ca_path,
                                 ctx->ins->tls_ca_file,
                                 ctx->ins->tls_crt_file,
                                 ctx->ins->tls_key_file,
                                 ctx->ins->tls_key_passwd);
    if (!ec->aws_tls) {
        flb_errno();
        return -1;
    }

    ec->aws_provider = flb_standard_chain_provider_create(config,
                                                          ec->aws_tls,
                                                          ec->aws_region,
                                                          ec->aws_sts_endpoint,
                                                          NULL,
                                                          flb_aws_client_generator(),
                                                          ec->aws_profile);
    if (!ec->aws_provider) {
        flb_error("[out_es] Failed to create AWS Credential Provider");
        return -1;
    }

    ret = set_aws_sts_provider(aws_external_id, aws_role_arn, ec, ctx, config);
    if (ret != 0) {
        flb_error("[out_es] Failed to configure AWS role");
        return -1;
    }

    /* initialize credentials in sync mode */
    ec->aws_provider->provider_vtable->sync(ec->aws_provider);
    ec->aws_provider->provider_vtable->init(ec->aws_provider);
    /* set back to async */
    ec->aws_provider->provider_vtable->async(ec->aws_provider);
    ec->aws_provider->provider_vtable->upstream_set(ec->aws_provider, ctx->ins);

    return 0;
}

#endif
