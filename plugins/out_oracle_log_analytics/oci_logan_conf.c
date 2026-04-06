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

static int create_pk_context(flb_sds_t filepath, const char *key_passphrase,
                             struct flb_oci_logan *ctx)
{
    int ret;
    struct stat st;
    struct file_info finfo;
    FILE *fp;
    flb_sds_t kbuffer;


    ret = stat(filepath, &st);
    if (ret == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open key file %s", filepath);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_plg_error(ctx->ins, "key file is not a valid file: %s", filepath);
        return -1;
    }

    /* Read file content */
    if (mk_file_get_info(filepath, &finfo, MK_FILE_READ) != 0) {
        flb_plg_error(ctx->ins, "error to read key file: %s", filepath);
        return -1;
    }

    if (!(fp = fopen(filepath, "rb"))) {
        flb_plg_error(ctx->ins, "error to open key file: %s", filepath);
        return -1;
    }

    kbuffer = flb_sds_create_size(finfo.size + 1);
    if (!kbuffer) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    ret = fread(kbuffer, finfo.size, 1, fp);
    if (ret < 1) {
        flb_sds_destroy(kbuffer);
        fclose(fp);
        flb_plg_error(ctx->ins, "fail to read key file: %s", filepath);
        return -1;
    }
    fclose(fp);

    /* In mbedtls, for PEM, the buffer must contains a null-terminated string */
    kbuffer[finfo.size] = '\0';
    flb_sds_len_set(kbuffer, finfo.size + 1);

    ctx->private_key = kbuffer;

    return 0;
}

static int load_oci_credentials(struct flb_oci_logan *ctx)
{
    flb_sds_t content;
    int found_profile = 0, res = 0;
    char *line, *profile = NULL;
    int eq_pos = 0;
    char* key = NULL;
    char* val;

    content = flb_file_read(ctx->config_file_location);
    if (content == NULL || flb_sds_len(content) == 0)
    {
        return -1;
    }
    flb_plg_debug(ctx->ins, "content = %s", content);
    line = strtok(content, "\n");
    while(line != NULL) {
        /* process line */
        flb_plg_debug(ctx->ins, "line = %s", line);
        if(!found_profile && line[0] == '[') {
            profile = mk_string_copy_substr(line, 1, strlen(line) - 1);
            if(!strcmp(profile, ctx->profile_name)) {
                flb_plg_info(ctx->ins, "found profile");
                found_profile = 1;
                goto iterate;
            }
            mk_mem_free(profile);
            profile = NULL;
        }
        if(found_profile) {
            if(line[0] == '[') {
                break;
            }
            eq_pos = mk_string_char_search(line, '=', strlen(line));
            flb_plg_debug(ctx->ins, "eq_pos %d", eq_pos);
            key = mk_string_copy_substr(line, 0, eq_pos);
            flb_plg_debug(ctx->ins, "key = %s", key);
            val = line + eq_pos + 1;
            if (!key || !val) {
                res = -1;
                break;
            }
            if (strcmp(key, FLB_OCI_PARAM_USER) == 0) {
                ctx->user = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_TENANCY) == 0) {
                ctx->tenancy = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FILE) == 0) {
                ctx->key_file = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_KEY_FINGERPRINT) == 0) {
                ctx->key_fingerprint = flb_sds_create(val);
            }
            else if (strcmp(key, FLB_OCI_PARAM_REGION) == 0) {
                ctx->region = flb_sds_create(val);
            }
            else {
                goto iterate;
            }
        }
        iterate:
        if (profile) {
            mk_mem_free(profile);
            profile = NULL;
        }
        if (key) {
            mk_mem_free(key);
            key = NULL;
        }
        line = strtok(NULL, "\n");
    }
    if (!found_profile) {
        flb_errno();
        res = -1;
    }

    flb_sds_destroy(content);
    if (profile) {
        mk_mem_free(profile);
    }
    if (key) {
        mk_mem_free(key);
    }
    return res;
}

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
            flb_sds_destroy(f->key);
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
            flb_sds_destroy(f->key);
            flb_free(f);
            return -1;
        }


        mk_list_add(&f->_head, &ctx->log_event_metadata_fields);
    }

    return 0;
}
struct flb_oci_logan *flb_oci_logan_conf_create(struct flb_output_instance *ins,
                                                struct flb_config *config) {
    struct flb_oci_logan *ctx;
    struct flb_upstream *upstream;
    flb_sds_t host = NULL;
    int io_flags = 0, default_port;
    const char *tmp = NULL;
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
    mk_list_init(&ctx->global_metadata_fields);
    mk_list_init(&ctx->log_event_metadata_fields);

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    if (ctx->oci_config_in_record == FLB_FALSE) {
        if (ctx->oci_la_log_source_name == NULL ||
            ctx->oci_la_log_group_id == NULL) {
            flb_plg_error(ctx->ins,
                          "log source name and log group id are required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->oci_la_global_metadata != NULL) {
        ret = global_metadata_fields_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->oci_la_metadata != NULL) {
        ret = log_event_metadata_create(ctx);
        if (ret != 0) {
            flb_errno();
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
    }

    if (!ctx->config_file_location) {
        flb_plg_error(ctx->ins, "config file location is required");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    ret = load_oci_credentials(ctx);
    if(ret != 0) {
        flb_errno();
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }

    if (ins->host.name) {
        host = ins->host.name;
    }
    else {
        if (!ctx->region) {
            flb_plg_error(ctx->ins, "Region is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        host = flb_sds_create_size(512);
        flb_sds_snprintf(&host, flb_sds_alloc(host), "loganalytics.%s.oci.oraclecloud.com", ctx->region);
    }

    if (!ctx->uri) {
        if (!ctx->namespace) {
            flb_plg_error(ctx->ins, "Namespace is required");
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
        }
        ctx->uri = flb_sds_create_size(512);
        flb_sds_snprintf(&ctx->uri, flb_sds_alloc(ctx->uri),
                       "/20200601/namespaces/%s/actions/uploadLogEventsFile",
                       ctx->namespace);
    }



    if (create_pk_context(ctx->key_file, NULL, ctx) < 0) {
        flb_plg_error(ctx->ins, "failed to create pk context");
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }


    ctx->key_id = flb_sds_create_size(512);
    flb_sds_snprintf(&ctx->key_id, flb_sds_alloc(ctx->key_id),
                     "%s/%s/%s", ctx->tenancy, ctx->user, ctx->key_fingerprint);


    /* Check if SSL/TLS is enabled */
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
        tmp = ctx->proxy;
        ret = flb_utils_url_split(tmp, &protocol, &p_host, &p_port, &p_uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            flb_oci_logan_conf_destroy(ctx);
            return NULL;
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
        flb_oci_logan_conf_destroy(ctx);
        return NULL;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    return ctx;
}

static void metadata_fields_destroy(struct flb_oci_logan *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct metadata_obj *f;

    mk_list_foreach_safe(head, tmp, &ctx->global_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        if (f->key) {
            flb_sds_destroy(f->key);
        }
        if (f->val) {
            flb_sds_destroy(f->val);
        }
        mk_list_del(&f->_head);
        flb_free(f);
    }

    mk_list_foreach_safe(head, tmp, &ctx->log_event_metadata_fields) {
        f = mk_list_entry(head, struct metadata_obj, _head);
        if (f->key) {
            flb_sds_destroy(f->key);
        }
        if (f->val) {
            flb_sds_destroy(f->val);
        }
        mk_list_del(&f->_head);
        flb_free(f);
    }

}

int flb_oci_logan_conf_destroy(struct flb_oci_logan *ctx) {
    if(ctx == NULL) {
        return 0;
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
