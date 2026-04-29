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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <yyjson.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "stackdriver_external_account.h"
#include "gce_metadata.h"
#include "stackdriver.h"
#include "stackdriver_conf.h"
#include "stackdriver_resource_types.h"

/*
 * Read and parse a Google credentials JSON file. Handles both
 * service_account (SA-key) and external_account (Workload Identity
 * Federation) shapes from the same parser. Returns 0 on success, -1 on
 * any failure (file not found, malformed JSON, unsupported variant).
 */
static int read_credentials_file(const char *cred_file,
                                 struct flb_stackdriver *ctx)
{
    int ret;
    int rc = -1;
    size_t pk_len;
    size_t header_count;
    size_t header_written;
    size_t arr_size;
    size_t idx;
    size_t max;
    size_t delegates_written;
    const char *pk_str;
    char *buf = NULL;
    flb_sds_t tmp;
    struct stat st;
    yyjson_doc *doc = NULL;
    yyjson_val *root;
    yyjson_val *v;
    yyjson_val *cs;
    yyjson_val *fmt;
    yyjson_val *headers;
    yyjson_val *sai;
    yyjson_val *delegates;
    yyjson_val *hk;
    yyjson_val *hv;
    yyjson_val *item;
    yyjson_obj_iter hdr_iter;

    ret = stat(cred_file, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open credentials file: %s",
                      cred_file);
        return -1;
    }
    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "credentials file is not a valid file: %s",
                      cred_file);
        return -1;
    }

    buf = mk_file_to_buffer(cred_file);
    if (!buf) {
        flb_plg_error(ctx->ins, "error reading credentials file: %s",
                      cred_file);
        return -1;
    }

    doc = yyjson_read(buf, st.st_size, 0);
    if (!doc) {
        flb_plg_error(ctx->ins, "invalid JSON credentials file: %s",
                      cred_file);
        goto out;
    }
    root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        flb_plg_error(ctx->ins, "invalid JSON map on file: %s", cred_file);
        goto out;
    }

#define COPY_CREDS_STR(field, key)                                            \
    do {                                                                      \
        v = yyjson_obj_get(root, (key));                                      \
        if (yyjson_is_str(v)) {                                               \
            ctx->creds->field = flb_sds_create(yyjson_get_str(v));            \
        }                                                                     \
    } while (0)

    COPY_CREDS_STR(type,                              "type");
    COPY_CREDS_STR(private_key_id,                    "private_key_id");
    COPY_CREDS_STR(client_email,                      "client_email");
    COPY_CREDS_STR(client_id,                         "client_id");
    COPY_CREDS_STR(client_secret,                     "client_secret");
    COPY_CREDS_STR(auth_uri,                          "auth_uri");
    COPY_CREDS_STR(token_uri,                         "token_uri");
    COPY_CREDS_STR(audience,                          "audience");
    COPY_CREDS_STR(subject_token_type,                "subject_token_type");
    COPY_CREDS_STR(token_url,                         "token_url");
    COPY_CREDS_STR(service_account_impersonation_url,
                   "service_account_impersonation_url");
    COPY_CREDS_STR(workforce_pool_user_project,
                   "workforce_pool_user_project");
    COPY_CREDS_STR(quota_project_id,                  "quota_project_id");
    COPY_CREDS_STR(universe_domain,                   "universe_domain");

#undef COPY_CREDS_STR

    /* project_id lives on ctx itself (not ctx->creds) for the SA-key flow */
    v = yyjson_obj_get(root, "project_id");
    if (yyjson_is_str(v)) {
        ctx->project_id = flb_sds_create(yyjson_get_str(v));
    }

    /* private_key needs unescape (PEM newlines come through as "\n") */
    v = yyjson_obj_get(root, "private_key");
    if (yyjson_is_str(v)) {
        pk_len = yyjson_get_len(v);
        pk_str = yyjson_get_str(v);
        tmp = flb_sds_create_len(pk_str, pk_len);
        if (tmp) {
            ctx->creds->private_key = flb_sds_create_size(pk_len);
            flb_unescape_string(tmp, flb_sds_len(tmp),
                                &ctx->creds->private_key);
            flb_sds_destroy(tmp);
        }
    }

    /* credential_source — file or url, plus optional format and headers */
    cs = yyjson_obj_get(root, "credential_source");
    if (yyjson_is_obj(cs)) {
        v = yyjson_obj_get(cs, "file");
        if (yyjson_is_str(v)) {
            ctx->creds->cred_source_file =
                flb_sds_create(yyjson_get_str(v));
        }
        v = yyjson_obj_get(cs, "url");
        if (yyjson_is_str(v)) {
            ctx->creds->cred_source_url =
                flb_sds_create(yyjson_get_str(v));
        }

        fmt = yyjson_obj_get(cs, "format");
        if (yyjson_is_obj(fmt)) {
            v = yyjson_obj_get(fmt, "type");
            if (yyjson_is_str(v)) {
                ctx->creds->cred_source_format_type =
                    flb_sds_create(yyjson_get_str(v));
            }
            v = yyjson_obj_get(fmt, "subject_token_field_name");
            if (yyjson_is_str(v)) {
                ctx->creds->cred_source_format_subject_field =
                    flb_sds_create(yyjson_get_str(v));
            }
        }

        /* credential_source.headers — flat string -> string map */
        headers = yyjson_obj_get(cs, "headers");
        if (yyjson_is_obj(headers)) {
            header_count = yyjson_obj_size(headers);
            if (header_count > 0) {
                header_written = 0;
                ctx->creds->cred_source_headers_keys =
                    flb_calloc(header_count, sizeof(flb_sds_t));
                ctx->creds->cred_source_headers_vals =
                    flb_calloc(header_count, sizeof(flb_sds_t));
                if (!ctx->creds->cred_source_headers_keys ||
                    !ctx->creds->cred_source_headers_vals) {
                    flb_errno();
                    /*
                     * If only one calloc succeeded, free it now so the
                     * orphan does not leak — the conf_destroy iterator
                     * stops at cred_source_headers_count (still 0) and
                     * never reaches the surviving allocation.
                     */
                    flb_free(ctx->creds->cred_source_headers_keys);
                    flb_free(ctx->creds->cred_source_headers_vals);
                    ctx->creds->cred_source_headers_keys = NULL;
                    ctx->creds->cred_source_headers_vals = NULL;
                    goto out;
                }
                yyjson_obj_iter_init(headers, &hdr_iter);
                while ((hk = yyjson_obj_iter_next(&hdr_iter)) != NULL &&
                       header_written < header_count) {
                    hv = yyjson_obj_iter_get_val(hk);
                    if (!yyjson_is_str(hv)) {
                        continue;
                    }
                    ctx->creds->cred_source_headers_keys[header_written] =
                        flb_sds_create(yyjson_get_str(hk));
                    ctx->creds->cred_source_headers_vals[header_written] =
                        flb_sds_create(yyjson_get_str(hv));
                    header_written++;
                }
                ctx->creds->cred_source_headers_count = (int) header_written;
            }
        }

        /* Reject unsupported credential_source variants up front */
        if (ctx->creds->type &&
            strcmp(ctx->creds->type,
                   FLB_STD_CREDENTIAL_TYPE_EXTERNAL_ACCOUNT) == 0) {
            if (yyjson_is_obj(yyjson_obj_get(cs, "executable"))) {
                flb_plg_error(ctx->ins, "external_account: executable-"
                              "sourced credential_source is not supported");
                goto out;
            }
            if (yyjson_is_str(yyjson_obj_get(cs, "environment_id"))) {
                flb_plg_error(ctx->ins, "external_account: AWS-sourced "
                              "credential_source is not supported");
                goto out;
            }
            if (yyjson_is_obj(yyjson_obj_get(cs, "certificate"))) {
                flb_plg_error(ctx->ins, "external_account: certificate-"
                              "based credential_source is not supported");
                goto out;
            }
        }
    }

    /* service_account_impersonation — lifetime + delegation chain */
    sai = yyjson_obj_get(root, "service_account_impersonation");
    if (yyjson_is_obj(sai)) {
        v = yyjson_obj_get(sai, "token_lifetime_seconds");
        if (yyjson_is_int(v)) {
            ctx->creds->sa_impersonation_lifetime_seconds =
                (int) yyjson_get_int(v);
        }
        else if (v != NULL && !yyjson_is_null(v)) {
            flb_plg_warn(ctx->ins, "ignoring invalid token_lifetime_seconds "
                         "in %s", cred_file);
        }

        delegates = yyjson_obj_get(sai, "delegates");
        if (yyjson_is_arr(delegates)) {
            arr_size = yyjson_arr_size(delegates);
            if (arr_size > 0) {
                delegates_written = 0;
                ctx->creds->sa_impersonation_delegates =
                    flb_calloc(arr_size, sizeof(flb_sds_t));
                if (!ctx->creds->sa_impersonation_delegates) {
                    flb_errno();
                    goto out;
                }
                yyjson_arr_foreach(delegates, idx, max, item) {
                    if (!yyjson_is_str(item)) {
                        continue;
                    }
                    ctx->creds->sa_impersonation_delegates[delegates_written] =
                        flb_sds_create(yyjson_get_str(item));
                    delegates_written++;
                }
                ctx->creds->sa_impersonation_delegates_count =
                    (int) delegates_written;
            }
        }
    }

    rc = 0;

out:
    if (doc) {
        yyjson_doc_free(doc);
    }
    if (buf) {
        flb_free(buf);
    }
    return rc;
}
/*
 *   parse_key_value_list():
 * - Parses an origin list of comma seperated string specifying key=value.
 * - Appends the parsed key value pairs into the destination list.
 * - Returns the length of the destination list.
 */
static int parse_key_value_list(struct flb_stackdriver *ctx,
                                struct mk_list *origin,
                                struct mk_list *dest,
                                int shouldTrim)
{
    char *p;
    flb_sds_t key;
    flb_sds_t val;
    struct flb_kv *kv;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    if (origin) {
        mk_list_foreach(head, origin) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);

            p = strchr(entry->str, '=');
            if (!p) {
                flb_plg_error(ctx->ins, "invalid key value pair on '%s'",
                              entry->str);
                return -1;
            }

            key = flb_sds_create_size((p - entry->str) + 1);
            flb_sds_cat(key, entry->str, p - entry->str);
            val = flb_sds_create(p + 1);
            if (shouldTrim) {
                flb_sds_trim(key);
                flb_sds_trim(val);
            }
            if (!key || flb_sds_len(key) == 0) {
                flb_plg_error(ctx->ins,
                              "invalid key value pair on '%s'",
                              entry->str);
                return -1;
            }
            if (!val || flb_sds_len(val) == 0) {
                flb_plg_error(ctx->ins,
                              "invalid key value pair on '%s'",
                              entry->str);
                flb_sds_destroy(key);
                return -1;
            }

            kv = flb_kv_item_create(dest, key, val);
            flb_sds_destroy(key);
            flb_sds_destroy(val);

            if (!kv) {
                return -1;
            }
        }
    }

    return mk_list_size(dest);
}

/*
 * parse_configuration_labels
 * - Parse labels set in configuration
 * - Returns the number of configuration labels
 */
static int parse_configuration_labels(struct flb_stackdriver *ctx)
{
    return parse_key_value_list(ctx, ctx->labels,
        &ctx->config_labels, FLB_FALSE);
}

/*
 *   parse_resource_labels():
 * - Parses resource labels set in configuration.
 * - Returns the number of resource label mappings.
 */
static int parse_resource_labels(struct flb_stackdriver *ctx)
{
    return parse_key_value_list(ctx, ctx->resource_labels,
        &ctx->resource_labels_kvs, FLB_TRUE);
}

struct flb_stackdriver *flb_stackdriver_conf_create(struct flb_output_instance *ins,
                                                    struct flb_config *config)
{
    int ret;
    const char *tmp;
    const char *backwards_compatible_env_var;
    struct flb_stackdriver *ctx;
    size_t http_request_key_size;
    struct cmt_histogram_buckets *buckets;
    flb_sds_t cloud_logging_base_url_str;
    size_t cloud_logging_base_url_size, cloud_logging_write_url_size;

    /* Allocate config context */
    ctx = flb_calloc(1, sizeof(struct flb_stackdriver));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->config = config;

    ret = flb_output_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_free(ctx);
        return NULL;
    }

    /* Compress (gzip) */
    tmp = flb_output_get_property("compress", ins);
    ctx->compress_gzip = FLB_FALSE;
    if (tmp && strcasecmp(tmp, "gzip") == 0) {
        ctx->compress_gzip = FLB_TRUE;
    }

    /* labels */
    flb_kv_init(&ctx->config_labels);
    ret = parse_configuration_labels((void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to parse configuration labels");
        flb_kv_release(&ctx->config_labels);
        flb_free(ctx);
        return NULL;
    }

    /* resource labels */
    flb_kv_init(&ctx->resource_labels_kvs);
    ret = parse_resource_labels((void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to parse resource label list");
        flb_kv_release(&ctx->resource_labels_kvs);
        flb_free(ctx);
        return NULL;
    }

    /* Lookup metadata server URL */
    ctx->metadata_server = NULL;
    tmp = flb_output_get_property("metadata_server", ins);
    if (tmp == NULL) {
        tmp = getenv("METADATA_SERVER");
        if(tmp) {
            if (ctx->env == NULL) {
                ctx->env = flb_calloc(1, sizeof(struct flb_stackdriver_env));
                if (ctx->env == NULL) {
                    flb_plg_error(ins, "unable to allocate env variables");
                    flb_free(ctx);
                    return NULL;
                }
            }
            ctx->env->metadata_server = flb_sds_create(tmp);
            ctx->metadata_server = ctx->env->metadata_server;
        }
        else {
            ctx->metadata_server = flb_sds_create(FLB_STD_METADATA_SERVER);
        }
    }
    else {
        ctx->metadata_server = flb_sds_create(tmp);
    }
    flb_plg_info(ctx->ins, "metadata_server set to %s", ctx->metadata_server);

    /* Lookup credentials file */
    if (ctx->credentials_file == NULL) {
        /*
         * Use GOOGLE_APPLICATION_CREDENTIALS to fetch the credentials.
         * GOOGLE_SERVICE_CREDENTIALS is checked for backwards compatibility.
         */
        tmp = getenv("GOOGLE_APPLICATION_CREDENTIALS");
        backwards_compatible_env_var = getenv("GOOGLE_SERVICE_CREDENTIALS");
        if (tmp && backwards_compatible_env_var) {
            flb_plg_warn(ctx->ins, "GOOGLE_APPLICATION_CREDENTIALS and "
                "GOOGLE_SERVICE_CREDENTIALS are both defined. "
                "Defaulting to GOOGLE_APPLICATION_CREDENTIALS");
        }
        if ((tmp || backwards_compatible_env_var) && (ctx->env == NULL)) {
            ctx->env = flb_calloc(1, sizeof(struct flb_stackdriver_env));
            if (ctx->env == NULL) {
                flb_plg_error(ins, "unable to allocate env variables");
                flb_free(ctx);
                return NULL;
            }
        }
        if (tmp) {
            ctx->env->creds_file = flb_sds_create(tmp);
            ctx->credentials_file = ctx->env->creds_file;
        }
        else if (backwards_compatible_env_var) {
            ctx->env->creds_file = flb_sds_create(backwards_compatible_env_var);
            ctx->credentials_file = ctx->env->creds_file;
        }
    }

    if (ctx->credentials_file) {
        ctx->creds = flb_calloc(1, sizeof(struct flb_stackdriver_oauth_credentials));
        if (ctx->creds == NULL) {
            flb_plg_error(ctx->ins, "unable to allocate credentials");
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }
        ret = read_credentials_file(ctx->credentials_file, ctx);
        if (ret != 0) {
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }
        ctx->type = ctx->creds->type;
        ctx->private_key_id = ctx->creds->private_key_id;
        ctx->private_key = ctx->creds->private_key;
        ctx->client_email = ctx->creds->client_email;
        ctx->client_id = ctx->creds->client_id;
        ctx->auth_uri = ctx->creds->auth_uri;
        ctx->token_uri = ctx->creds->token_uri;
    }
    else {
        /*
         * If no credentials file has been defined, do manual lookup of the
         * client email and the private key
         */
        ctx->creds = flb_calloc(1, sizeof(struct flb_stackdriver_oauth_credentials));
        if (ctx->creds == NULL) {
            flb_plg_error(ctx->ins, "unable to allocate credentials");
            flb_stackdriver_conf_destroy(ctx);
            return NULL;
        }

        /* Service Account Email */
        if (ctx->client_email == NULL) {
            tmp = getenv("SERVICE_ACCOUNT_EMAIL");
            if (tmp) {
                ctx->creds->client_email = flb_sds_create(tmp);
                ctx->client_email = ctx->creds->client_email;
            }
        }

        /* Service Account Secret */
        if (ctx->private_key == NULL) {
            tmp = getenv("SERVICE_ACCOUNT_SECRET");
            if (tmp) {
                ctx->creds->private_key = flb_sds_create(tmp);
                ctx->private_key = ctx->creds->private_key;
            }
        }
    }

    /*
     * If only client email has been provided, fetch token from
     * the GCE metadata server.
     *
     * If no credentials have been provided, fetch token from the GCE
     * metadata server for default account.
     */
    if (!ctx->client_email && ctx->private_key) {
        flb_plg_error(ctx->ins, "client_email is not defined");
        flb_stackdriver_conf_destroy(ctx);
        return NULL;
    }

    if (!ctx->client_email) {
        flb_plg_warn(ctx->ins, "client_email is not defined, using "
                     "a default one");
        if (ctx->creds == NULL) {
            ctx->creds = flb_calloc(1, sizeof(struct flb_stackdriver_oauth_credentials));
            if (ctx->creds == NULL) {
                flb_plg_error(ctx->ins, "unable to allocate credentials");
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }
        }
        ctx->creds->client_email = flb_sds_create("default");
        ctx->client_email = ctx->creds->client_email;
    }
    if (!ctx->private_key) {
        if (stackdriver_external_account_is_configured(ctx)) {
            flb_plg_info(ctx->ins, "using Workload Identity Federation "
                         "(external_account credentials)");

            /* Required-field validation for external_account credentials. */
            if (!ctx->creds->audience ||
                flb_sds_len(ctx->creds->audience) == 0) {
                flb_plg_error(ctx->ins, "external_account: 'audience' is "
                              "required");
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }
            if (!ctx->creds->subject_token_type ||
                flb_sds_len(ctx->creds->subject_token_type) == 0) {
                flb_plg_error(ctx->ins, "external_account: "
                              "'subject_token_type' is required");
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }
            /*
             * workforce_pool_user_project only makes sense for workforce
             * pool audiences. Audiences pointing at workload identity pools
             * carry their own project context via the pool path itself, so
             * setting workforce_pool_user_project there is a configuration
             * mistake.
             */
            if (ctx->creds->workforce_pool_user_project &&
                flb_sds_len(ctx->creds->workforce_pool_user_project) > 0 &&
                strstr(ctx->creds->audience,
                       "//iam.googleapis.com/locations/") == NULL) {
                flb_plg_error(ctx->ins, "external_account: "
                              "workforce_pool_user_project is only valid "
                              "for workforce pool audiences");
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }

            /*
             * If the credential_source uses JSON format, the field name
             * to extract from must be set. Validating here surfaces the
             * misconfiguration at init time rather than on the first
             * flush attempt.
             */
            if (ctx->creds->cred_source_format_type &&
                strcasecmp(ctx->creds->cred_source_format_type,
                           "json") == 0 &&
                (!ctx->creds->cred_source_format_subject_field ||
                 flb_sds_len(ctx->creds->cred_source_format_subject_field)
                     == 0)) {
                flb_plg_error(ctx->ins, "external_account: "
                              "credential_source.format.subject_token_field_name "
                              "is required when format.type is 'json'");
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }

            /*
             * external_account credentials carry no "project_id" field
             * (unlike a service-account JSON), so the SA-key-derived
             * fallback that fills ctx->project_id at parse time never
             * fires. Default it to export_to_project_id when set, so the
             * init-time validation in cb_stackdriver_init() succeeds and
             * the monitored_resource.project_id label gets the same
             * destination project the user already configured.
             */
            if (!ctx->project_id && ctx->export_to_project_id) {
                ctx->project_id = flb_sds_create(ctx->export_to_project_id);
                flb_plg_info(ctx->ins, "external_account: defaulting "
                             "project_id to export_to_project_id (%s)",
                             ctx->project_id);
            }
        }
        else {
            flb_plg_warn(ctx->ins, "private_key is not defined, fetching "
                         "it from metadata server");
            ctx->metadata_server_auth = true;
        }
    }

    if (ctx->http_request_key) {
        http_request_key_size = flb_sds_len(ctx->http_request_key);
        if (http_request_key_size >= INT_MAX) {
            flb_plg_error(ctx->ins, "http_request_key is too long");
            flb_sds_destroy(ctx->http_request_key);
            ctx->http_request_key = NULL;
            ctx->http_request_key_size = 0;
        } else {
            ctx->http_request_key_size = http_request_key_size;
        }
    }

    if (ctx->cloud_logging_base_url) {
        /*
         * An alternate base URL was specified in the config. To avoid the confusion of a user
         * not knowing whether the trailing `/` should be present, check whether the user
         * provided it and remove it if it is.
         */
        cloud_logging_base_url_size = flb_sds_len(ctx->cloud_logging_base_url);
        if (FLB_SDS_HEADER(
                ctx->cloud_logging_base_url
            )->buf[cloud_logging_base_url_size-1] == '/') {
            cloud_logging_base_url_size -= 1;
        }
        cloud_logging_base_url_str = flb_sds_create_size(cloud_logging_base_url_size);

        /* Note: The size calculated from `flb_sds_len` does not include the null terminator character,
         * `size` argument for `flb_sds_snprintf` needs to be the size including the null terminator.
         * Hence the +1 added to each size argument here.
         */
        flb_sds_snprintf(&cloud_logging_base_url_str, cloud_logging_base_url_size+1,
                         "%s", ctx->cloud_logging_base_url);
        cloud_logging_write_url_size = cloud_logging_base_url_size + FLB_STD_WRITE_URI_SIZE;
        ctx->cloud_logging_write_url = flb_sds_create_size(cloud_logging_write_url_size);
        flb_sds_snprintf(&ctx->cloud_logging_write_url, cloud_logging_write_url_size+1,
                         "%s%s", cloud_logging_base_url_str, FLB_STD_WRITE_URI);

        flb_sds_destroy(cloud_logging_base_url_str);
    }
    else if (ctx->creds && ctx->creds->universe_domain &&
             flb_sds_len(ctx->creds->universe_domain) > 0 &&
             strcmp(ctx->creds->universe_domain, "googleapis.com") != 0) {
        /*
         * Non-default Cloud universe and no explicit override: derive the
         * Logging API endpoint from universe_domain so sovereign/GDU
         * tenants reach their own logging.<universe> host.
         */
        ctx->cloud_logging_write_url = flb_sds_create_size(96);
        flb_sds_snprintf(&ctx->cloud_logging_write_url, 96,
                         "https://logging.%s%s",
                         ctx->creds->universe_domain, FLB_STD_WRITE_URI);
    }
    else {
        ctx->cloud_logging_write_url = flb_sds_create(FLB_STD_WRITE_URL);
    }

    set_resource_type(ctx);

    if (resource_api_has_required_labels(ctx) == FLB_FALSE) {

        if (ctx->resource_type == RESOURCE_TYPE_K8S) {
            if (!ctx->cluster_name || !ctx->cluster_location) {
                flb_plg_error(ctx->ins, "missing k8s_cluster_name "
                            "or k8s_cluster_location in configuration");
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }
        }

        else if (ctx->resource_type == RESOURCE_TYPE_GENERIC_NODE
            || ctx->resource_type == RESOURCE_TYPE_GENERIC_TASK) {

            if (ctx->location == NULL) {
                flb_plg_error(ctx->ins, "missing generic resource's location");
            }

            if (ctx->namespace_id == NULL) {
                flb_plg_error(ctx->ins, "missing generic resource's namespace");
            }

            if (ctx->resource_type == RESOURCE_TYPE_GENERIC_NODE) {
                if (ctx->node_id == NULL) {
                    flb_plg_error(ctx->ins, "missing generic_node's node_id");
                    flb_stackdriver_conf_destroy(ctx);
                    return NULL;
                }
            }
            else {
                if (ctx->job == NULL) {
                    flb_plg_error(ctx->ins, "missing generic_task's job");
                }

                if (ctx->task_id == NULL) {
                    flb_plg_error(ctx->ins, "missing generic_task's task_id");
                }

                if (!ctx->job || !ctx->task_id) {
                    flb_stackdriver_conf_destroy(ctx);
                    return NULL;
                }
            }

            if (!ctx->location || !ctx->namespace_id) {
                flb_stackdriver_conf_destroy(ctx);
                return NULL;
            }
        }
    }

    if (ctx->tag_prefix == NULL && ctx->resource_type == RESOURCE_TYPE_K8S) {
        /* allocate the flb_sds_t to tag_prefix_k8s so we can safely deallocate it */
        ctx->tag_prefix_k8s = flb_sds_create(ctx->resource);
        ctx->tag_prefix_k8s = flb_sds_cat(ctx->tag_prefix_k8s, ".", 1);
        ctx->tag_prefix = ctx->tag_prefix_k8s;
    }

    /* Register metrics */
#ifdef FLB_HAVE_METRICS
    ctx->cmt_successful_requests = cmt_counter_create(ins->cmt,
                                                      "fluentbit",
                                                      "stackdriver",
                                                      "successful_requests",
                                                      "Total number of successful "
                                                      "requests.",
                                                      1, (char *[]) {"name"});

    ctx->cmt_failed_requests = cmt_counter_create(ins->cmt,
                                                  "fluentbit",
                                                  "stackdriver",
                                                  "failed_requests",
                                                  "Total number of failed "
                                                  "requests.",
                                                  1, (char *[]) {"name"});

    ctx->cmt_requests_total = cmt_counter_create(ins->cmt,
                                                 "fluentbit",
                                                 "stackdriver",
                                                 "requests_total",
                                                 "Total number of requests.",
                                                  2, (char *[]) {"status", "name"});

    ctx->cmt_proc_records_total = cmt_counter_create(ins->cmt,
                                                     "fluentbit",
                                                     "stackdriver",
                                                     "proc_records_total",
                                                     "Total number of processed records.",
                                                     3, (char *[]) {"grpc_code" ,"status", "name"});

    ctx->cmt_retried_records_total = cmt_counter_create(ins->cmt,
                                                        "fluentbit",
                                                        "stackdriver",
                                                        "retried_records_total",
                                                        "Total number of retried records.",
                                                        2, (char *[]) {"status", "name"});

    buckets = cmt_histogram_buckets_create(7, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0);
    ctx->cmt_write_entries_latency = cmt_histogram_create(ins->cmt,
                                                          "fluentbit",
                                                          "stackdriver",
                                                          "write_entries_latency",
                                                          "Latency of Cloud Logging WriteLogEntries HTTP request.",
                                                          buckets,
                                                          1, (char *[]) {"name"});


    /* OLD api */
    flb_metrics_add(FLB_STACKDRIVER_SUCCESSFUL_REQUESTS,
                    "stackdriver_successful_requests", ctx->ins->metrics);
    flb_metrics_add(FLB_STACKDRIVER_FAILED_REQUESTS,
                    "stackdriver_failed_requests", ctx->ins->metrics);
#endif

    return ctx;
}

int flb_stackdriver_conf_destroy(struct flb_stackdriver *ctx)
{
    int d;
    int h;

    if (!ctx) {
        return -1;
    }

    if (ctx->creds) {
        if (ctx->creds->type) {
            flb_sds_destroy(ctx->creds->type);
        }
        if (ctx->creds->private_key_id) {
            flb_sds_destroy(ctx->creds->private_key_id);
        }
        if (ctx->creds->private_key) {
            flb_sds_destroy(ctx->creds->private_key);
        }
        if (ctx->creds->client_email) {
            flb_sds_destroy(ctx->creds->client_email);
        }
        if (ctx->creds->client_id) {
            flb_sds_destroy(ctx->creds->client_id);
        }
        if (ctx->creds->client_secret) {
            flb_sds_destroy(ctx->creds->client_secret);
        }
        if (ctx->creds->auth_uri) {
            flb_sds_destroy(ctx->creds->auth_uri);
        }
        if (ctx->creds->token_uri) {
            flb_sds_destroy(ctx->creds->token_uri);
        }
        if (ctx->creds->audience) {
            flb_sds_destroy(ctx->creds->audience);
        }
        if (ctx->creds->subject_token_type) {
            flb_sds_destroy(ctx->creds->subject_token_type);
        }
        if (ctx->creds->token_url) {
            flb_sds_destroy(ctx->creds->token_url);
        }
        if (ctx->creds->service_account_impersonation_url) {
            flb_sds_destroy(ctx->creds->service_account_impersonation_url);
        }
        if (ctx->creds->sa_impersonation_delegates) {
            for (d = 0;
                 d < ctx->creds->sa_impersonation_delegates_count;
                 d++) {
                if (ctx->creds->sa_impersonation_delegates[d]) {
                    flb_sds_destroy(
                        ctx->creds->sa_impersonation_delegates[d]);
                }
            }
            flb_free(ctx->creds->sa_impersonation_delegates);
        }
        if (ctx->creds->cred_source_file) {
            flb_sds_destroy(ctx->creds->cred_source_file);
        }
        if (ctx->creds->cred_source_url) {
            flb_sds_destroy(ctx->creds->cred_source_url);
        }
        if (ctx->creds->cred_source_headers_keys) {
            for (h = 0; h < ctx->creds->cred_source_headers_count; h++) {
                if (ctx->creds->cred_source_headers_keys[h]) {
                    flb_sds_destroy(
                        ctx->creds->cred_source_headers_keys[h]);
                }
                if (ctx->creds->cred_source_headers_vals[h]) {
                    flb_sds_destroy(
                        ctx->creds->cred_source_headers_vals[h]);
                }
            }
            flb_free(ctx->creds->cred_source_headers_keys);
            flb_free(ctx->creds->cred_source_headers_vals);
        }
        if (ctx->creds->cred_source_format_type) {
            flb_sds_destroy(ctx->creds->cred_source_format_type);
        }
        if (ctx->creds->cred_source_format_subject_field) {
            flb_sds_destroy(ctx->creds->cred_source_format_subject_field);
        }
        if (ctx->creds->workforce_pool_user_project) {
            flb_sds_destroy(ctx->creds->workforce_pool_user_project);
        }
        if (ctx->creds->quota_project_id) {
            flb_sds_destroy(ctx->creds->quota_project_id);
        }
        if (ctx->creds->universe_domain) {
            flb_sds_destroy(ctx->creds->universe_domain);
        }
        flb_free(ctx->creds);
    }

    if (ctx->env) {
        if (ctx->env->creds_file) {
            flb_sds_destroy(ctx->env->creds_file);
        }
        if (ctx->env->metadata_server) {
            flb_sds_destroy(ctx->env->metadata_server);
            /*
             * If ctx->env is not NULL,
             * ctx->metadata_server points ctx->env->metadata_server.
             *
             * We set ctx->metadata_server to NULL to prevent double free.
             */
            ctx->metadata_server = NULL;
        }
        flb_free(ctx->env);
    }

    if (ctx->metadata_server) {
        flb_sds_destroy(ctx->metadata_server);
    }

    if (ctx->resource_type == RESOURCE_TYPE_K8S){
        flb_sds_destroy(ctx->namespace_name);
        flb_sds_destroy(ctx->pod_name);
        flb_sds_destroy(ctx->container_name);
        flb_sds_destroy(ctx->node_name);
        flb_sds_destroy(ctx->local_resource_id);
    }

    if (ctx->metadata_server_auth) {
        flb_sds_destroy(ctx->zone);
        flb_sds_destroy(ctx->instance_id);
    }

    if (ctx->metadata_u) {
        flb_upstream_destroy(ctx->metadata_u);
    }

    if (ctx->wif_sts_u) {
        flb_upstream_destroy(ctx->wif_sts_u);
    }

    if (ctx->wif_iam_u) {
        flb_upstream_destroy(ctx->wif_iam_u);
    }

    if (ctx->wif_subject_url_u) {
        flb_upstream_destroy(ctx->wif_subject_url_u);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->o) {
        flb_oauth2_destroy(ctx->o);
    }

    if (ctx->regex) {
        flb_regex_destroy(ctx->regex);
    }

    if (ctx->project_id) {
        flb_sds_destroy(ctx->project_id);
    }

    if (ctx->tag_prefix_k8s) {
        flb_sds_destroy(ctx->tag_prefix_k8s);
    }

    if (ctx->cloud_logging_write_url) {
        flb_sds_destroy(ctx->cloud_logging_write_url);
    }

    flb_kv_release(&ctx->config_labels);
    flb_kv_release(&ctx->resource_labels_kvs);
    if (ctx->token_mutex_initialized) {
        pthread_mutex_destroy(&ctx->token_mutex);
    }
    flb_free(ctx);

    return 0;
}
