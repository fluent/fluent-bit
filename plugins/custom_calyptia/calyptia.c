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

#include <fluent-bit/flb_custom_plugin.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_router.h>

/* pipeline plugins */
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_custom_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_hash.h>

#include <fluent-bit/calyptia/calyptia_constants.h>

#include "calyptia.h"

#define UUID_BUFFER_SIZE 38 /* Maximum length of UUID string + null terminator */

/* Function wrappers to enable mocking for unit test filesystem access */
int (*flb_access)(const char *pathname, int mode) = access;
int (*flb_open)(const char *pathname, int flags, ...) = open;
ssize_t (*flb_write)(int fd, const void *buf, size_t count) = write;
int (*flb_close)(int fd) = close;
int (*flb_utils_read_file_wrapper)(char *path, char **out_buf, size_t *out_size) = flb_utils_read_file;

/*
 * Check if the key belongs to a sensitive data field, if so report it. We never
 * share any sensitive data.
 */
static int is_sensitive_property(char *key)
{

    if (strcasecmp(key, "password") == 0 ||
        strcasecmp(key, "passwd") == 0   ||
        strcasecmp(key, "user") == 0 ||
        strcasecmp(key, "http_user") == 0 ||
        strcasecmp(key, "http_passwd") == 0 ||
        strcasecmp(key, "shared_key") == 0 ||
        strcasecmp(key, "endpoint") == 0 ||
        strcasecmp(key, "apikey") == 0 ||
        strcasecmp(key, "private_key") == 0 ||
        strcasecmp(key, "service_account_secret") == 0 ||
        strcasecmp(key, "splunk_token") == 0 ||
        strcasecmp(key, "logdna_host") == 0 ||
        strcasecmp(key, "api_key") == 0 ||
        strcasecmp(key, "hostname") == 0 ||
        strcasecmp(key, "license_key") == 0 ||
        strcasecmp(key, "base_uri") == 0 ||
        strcasecmp(key, "api") == 0) {

        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static void pipeline_config_add_properties(flb_sds_t *buf, struct mk_list *props)
{
    struct mk_list *head;
    struct flb_kv *kv;

    mk_list_foreach(head, props) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (kv->key != NULL && kv->val != NULL) {
            flb_sds_printf(buf, "    %s ", kv->key);

            if (is_sensitive_property(kv->key)) {
                flb_sds_cat_safe(buf, "--redacted--", strlen("--redacted--"));
            }
            else {
                flb_sds_cat_safe(buf, kv->val, strlen(kv->val));
            }

            flb_sds_cat_safe(buf, "\n", 1);
        }
    }
}

flb_sds_t custom_calyptia_pipeline_config_get(struct flb_config *ctx)
{
    char tmp[32];
    flb_sds_t buf;
    struct mk_list *head;
    struct flb_input_instance *i_ins;
    struct flb_filter_instance *f_ins;
    struct flb_output_instance *o_ins;

    buf = flb_sds_create_size(2048);

    if (!buf) {
        return NULL;
    }

    /* [INPUT] */
    mk_list_foreach(head, &ctx->inputs) {
        i_ins = mk_list_entry(head, struct flb_input_instance, _head);
        flb_sds_printf(&buf, "[INPUT]\n");
        flb_sds_printf(&buf, "    name %s\n", i_ins->name);

        if (i_ins->alias) {
            flb_sds_printf(&buf, "    alias %s\n", i_ins->alias);
        }

        if (i_ins->tag) {
            flb_sds_printf(&buf, "    tag %s\n", i_ins->tag);
        }

        if (i_ins->mem_buf_limit > 0) {
            flb_utils_bytes_to_human_readable_size(i_ins->mem_buf_limit,
                                                   tmp, sizeof(tmp) - 1);
            flb_sds_printf(&buf, "    mem_buf_limit %s\n", tmp);
        }

        pipeline_config_add_properties(&buf, &i_ins->properties);
    }
    flb_sds_printf(&buf, "\n");

    /* Config: [FILTER] */
    mk_list_foreach(head, &ctx->filters) {
        f_ins = mk_list_entry(head, struct flb_filter_instance, _head);

        flb_sds_printf(&buf, "[FILTER]\n");
        flb_sds_printf(&buf, "    name  %s\n", f_ins->name);
        flb_sds_printf(&buf, "    match %s\n", f_ins->match);

        pipeline_config_add_properties(&buf, &f_ins->properties);
    }
    flb_sds_printf(&buf, "\n");

    /* Config: [OUTPUT] */
    mk_list_foreach(head, &ctx->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);

        flb_sds_printf(&buf, "[OUTPUT]\n");
        flb_sds_printf(&buf, "    name  %s\n", o_ins->name);

        if (o_ins->match) {
            flb_sds_printf(&buf, "    match %s\n", o_ins->match);
        }
        else {
            flb_sds_printf(&buf, "    match *\n");
        }

#ifdef FLB_HAVE_TLS
        if (o_ins->use_tls == FLB_TRUE) {
            flb_sds_printf(&buf, "    tls   %s\n", o_ins->use_tls ? "on" : "off");
            flb_sds_printf(&buf, "    tls.verify     %s\n",
                             o_ins->tls_verify ? "on": "off");

            if (o_ins->tls_ca_file) {
                flb_sds_printf(&buf, "    tls.ca_file    %s\n",
                               o_ins->tls_ca_file);
            }

            if (o_ins->tls_crt_file) {
                flb_sds_printf(&buf, "    tls.crt_file   %s\n",
                               o_ins->tls_crt_file);
            }

            if (o_ins->tls_key_file) {
                flb_sds_printf(&buf, "    tls.key_file   %s\n",
                               o_ins->tls_key_file);
            }

            if (o_ins->tls_key_passwd) {
                flb_sds_printf(&buf, "    tls.key_passwd --redacted--\n");
            }
        }
#endif

        if (o_ins->retry_limit == FLB_OUT_RETRY_UNLIMITED) {
            flb_sds_printf(&buf, "    retry_limit no_limits\n");
        }
        else if (o_ins->retry_limit == FLB_OUT_RETRY_NONE) {
            flb_sds_printf(&buf, "    retry_limit no_retries\n");
        }
        else {
            flb_sds_printf(&buf, "    retry_limit %i\n", o_ins->retry_limit);
        }

        if (o_ins->host.name) {
            flb_sds_printf(&buf, "    host  --redacted--\n");
        }

        pipeline_config_add_properties(&buf, &o_ins->properties);
        flb_sds_printf(&buf, "\n");
    }

    return buf;
}

int set_fleet_input_properties(struct calyptia *ctx, struct flb_input_instance *fleet)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_kv *keyval;

    if (!fleet) {
        flb_plg_error(ctx->ins, "invalid fleet input instance");
        return -1;
    }

    if (ctx->fleet_name) {
        flb_input_set_property(fleet, "fleet_name", ctx->fleet_name);
    }

    if (ctx->fleet_id) {
        flb_input_set_property(fleet, "fleet_id", ctx->fleet_id);
    }

    flb_input_set_property(fleet, "api_key", ctx->api_key);
    flb_input_set_property(fleet, "host", ctx->cloud_host);
    flb_input_set_property(fleet, "port", ctx->cloud_port);
    flb_input_set_property(fleet, "config_dir", ctx->fleet_config_dir);
    flb_input_set_property(fleet, "fleet_config_legacy_format", ctx->fleet_config_legacy_format == 1 ? "on" : "off");

    /* Set TLS properties */
    flb_input_set_property(fleet, "tls", ctx->cloud_tls == 1 ? "on" : "off");
    flb_input_set_property(fleet, "tls.verify", ctx->cloud_tls_verify == 1 ? "on" : "off");

    /* Optional configurations */
    if (ctx->fleet_max_http_buffer_size) {
        flb_input_set_property(fleet, "max_http_buffer_size", ctx->fleet_max_http_buffer_size);
    }

    if (ctx->machine_id) {
        flb_input_set_property(fleet, "machine_id", ctx->machine_id);
    }

    if (ctx->fleet_interval_sec) {
        flb_input_set_property(fleet, "interval_sec", ctx->fleet_interval_sec);
    }

    if (ctx->fleet_interval_nsec) {
        flb_input_set_property(fleet, "interval_nsec", ctx->fleet_interval_nsec);
    }

    mk_list_foreach(head, &ctx->ins->net_properties) {
        keyval = mk_list_entry(head, struct flb_kv, _head);
        flb_debug("set fleet net property: %s=%s", keyval->key, keyval->val);
        flb_input_set_property(fleet, keyval->key, keyval->val);
    }

    return 0;
}

static struct flb_output_instance *setup_cloud_output(struct flb_config *config, struct calyptia *ctx)
{
    int ret;
    struct flb_output_instance *cloud;
    struct mk_list *head;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;
    flb_sds_t label;
    struct flb_config_map_val *mv;
    struct mk_list *tmp;
    struct flb_kv *keyval;

    cloud = flb_output_new(config, "calyptia", ctx, FLB_FALSE);

    if (!cloud) {
        flb_plg_error(ctx->ins, "could not load Calyptia Cloud connector");
        return NULL;
    }

    /* direct connect / routing */
    ret = flb_router_connect_direct(ctx->i, cloud);

    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not load Calyptia Cloud connector");
        return NULL;
    }

    if (ctx->add_labels && mk_list_size(ctx->add_labels) > 0) {

        /* iterate all 'add_label' definitions */
        flb_config_map_foreach(head, mv, ctx->add_labels) {
            key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
            val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

            label = flb_sds_create_size(strlen(key->str) + strlen(val->str) + 1);

            if (!label) {
                return NULL;
            }

            flb_sds_printf(&label, "%s %s", key->str, val->str);
            flb_output_set_property(cloud, "add_label", label);
            flb_sds_destroy(label);
        }
    }

    flb_output_set_property(cloud, "match", "_calyptia_cloud");
    flb_output_set_property(cloud, "api_key", ctx->api_key);

    if (ctx->register_retry_on_flush) {
        flb_output_set_property(cloud, "register_retry_on_flush", "true");
    } else {
        flb_output_set_property(cloud, "register_retry_on_flush", "false");
    }

    if (ctx->store_path) {
        flb_output_set_property(cloud, "store_path", ctx->store_path);
    }

    if (ctx->machine_id) {
        flb_output_set_property(cloud, "machine_id", ctx->machine_id);
    }

    /* Override network details: development purposes only */
    if (ctx->cloud_host) {
        flb_output_set_property(cloud, "cloud_host", ctx->cloud_host);
    }

    if (ctx->cloud_port) {
        flb_output_set_property(cloud, "cloud_port", ctx->cloud_port);
    }

    if (ctx->cloud_tls) {
        flb_output_set_property(cloud, "tls", "true");
    }
    else {
        flb_output_set_property(cloud, "tls", "false");
    }

    if (ctx->cloud_tls_verify) {
        flb_output_set_property(cloud, "tls.verify", "true");
    }
    else {
        flb_output_set_property(cloud, "tls.verify", "false");
    }

    if (ctx->fleet_id) {
        label = flb_sds_create_size(strlen("fleet_id") + strlen(ctx->fleet_id) + 1);

        if (!label) {
            return NULL;
        }

        flb_sds_printf(&label, "fleet_id %s", ctx->fleet_id);
        flb_output_set_property(cloud, "add_label", label);
        flb_sds_destroy(label);
    }

    mk_list_foreach(head, &ctx->ins->net_properties) {
        keyval = mk_list_entry(head, struct flb_kv, _head);
        flb_debug("set cloud net property: %s=%s", keyval->key, keyval->val);
        flb_output_set_property(cloud, keyval->key, keyval->val);
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    flb_output_set_property(cloud, "pipeline_id", ctx->pipeline_id);
#endif /* FLB_HAVE_CHUNK_TRACE */

    return cloud;
}

static flb_sds_t sha256_to_hex(unsigned char *sha256)
{
    int idx;
    flb_sds_t hex;
    flb_sds_t tmp;

    hex = flb_sds_create_size(64);

    if (!hex) {
        return NULL;
    }

    for (idx = 0; idx < 32; idx++) {
        tmp = flb_sds_printf(&hex, "%02x", sha256[idx]);

        if (!tmp) {
            flb_sds_destroy(hex);
            return NULL;
        }

        hex = tmp;
    }

    flb_sds_len_set(hex, 64);
    return hex;
}

static flb_sds_t generate_base_agent_directory(struct calyptia *ctx, flb_sds_t *fleet_dir)
{
    flb_sds_t ret = NULL;

    if (ctx == NULL || fleet_dir == NULL) {
        return NULL;
    }

    if (*fleet_dir == NULL) {
        *fleet_dir = flb_sds_create_size(CALYPTIA_MAX_DIR_SIZE);
        if (*fleet_dir == NULL) {
            return NULL;
        }
    }

    ret = flb_sds_printf(fleet_dir, "%s", ctx->fleet_config_dir);
    if (ret == NULL) {
        flb_sds_destroy(*fleet_dir);
        return NULL;
    }

    return ret;
}

flb_sds_t agent_config_filename(struct calyptia *ctx, char *fname)
{
    flb_sds_t cfgname = NULL;
    flb_sds_t ret;

    if (ctx == NULL || fname == NULL) {
        return NULL;
    }

    if (generate_base_agent_directory(ctx, &cfgname) == NULL) {
        return NULL;
    }

    ret = flb_sds_printf(&cfgname, PATH_SEPARATOR "%s.conf", fname);
    if (ret == NULL) {
        flb_sds_destroy(cfgname);
        return NULL;
    }

    return cfgname;
}

static char* generate_uuid() {
    char* uuid = flb_malloc(UUID_BUFFER_SIZE);
    if (!uuid) {
        flb_errno();
        return NULL;
    }

    /* create new UUID for fleet */
    if (flb_utils_uuid_v4_gen(uuid) != 0 || strlen(uuid) == 0) {
        flb_free(uuid);
        return NULL;
    }
    return uuid;
}

static int write_uuid_to_file(flb_sds_t fleet_machine_id, char* uuid) {
    int fd;
    size_t uuid_len;

    if (fleet_machine_id == NULL || uuid == NULL) {
        return FLB_FALSE;
    }

    /* write uuid to file */
    fd = flb_open(fleet_machine_id, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd == -1) {
        return FLB_FALSE;
    }

    uuid_len = strlen(uuid);

    if (flb_write(fd, uuid, uuid_len) != uuid_len) {
        flb_close(fd);
        return FLB_FALSE;
    }

    flb_close(fd);
    return FLB_TRUE;
}

static int create_agent_directory(struct calyptia *ctx)
{
    if( ctx == NULL ) {
        return -1;
    }

    /* If it exists just return */
    if (access(ctx->fleet_config_dir, F_OK) == 0) {
        return 0;
    }

    /* Create the directory if it does not exist */
    if (flb_utils_mkdir(ctx->fleet_config_dir, 0700) != 0) {
        flb_plg_error(ctx->ins, "failed to create directory: %s", ctx->fleet_config_dir);
        return -1;
    }

    return 0;
}

flb_sds_t get_machine_id(struct calyptia *ctx)
{
    int ret = -1;
    char *buf = NULL;
    size_t blen = 0;
    unsigned char sha256_buf[64] = {0};

#if defined(FLB_SYSTEM_WINDOWS)
    /* retrieve raw machine id */
    ret = flb_utils_get_machine_id(&buf, &blen);
#else
    /* /etc/machine-id is not guaranteed to be unique so we generate one */
    flb_sds_t fleet_machine_id = NULL;

    /** ensure we have the directory created */
    if (create_agent_directory(ctx) != 0) {
        return NULL;
    }

    /** now get the agent filename */
    fleet_machine_id = machine_id_fleet_config_filename(ctx);
    if (fleet_machine_id == NULL) {
        flb_plg_error(ctx->ins, "unable to allocate machine id file");
        return NULL;
    }

    /* check if the file exists first, if it does not we generate a UUID */
    if (flb_access(fleet_machine_id, F_OK) != 0) {

        /* create new UUID for fleet */
        buf = generate_uuid();
        if( buf == NULL ) {
            flb_plg_error(ctx->ins, "failed to create uuid for fleet machine id");
            flb_sds_destroy(fleet_machine_id);
            return NULL;
        }
        flb_plg_info(ctx->ins, "generated UUID for machine ID: %s", buf);

        /* write uuid to file */
        if (write_uuid_to_file(fleet_machine_id, buf ) != FLB_TRUE) {
            flb_plg_error(ctx->ins, "failed to write fleet machine id file: %s", fleet_machine_id);
            flb_free(buf);
            flb_sds_destroy(fleet_machine_id);
            return NULL;
        }

        flb_free(buf);
        buf = NULL;

        flb_plg_info(ctx->ins, "written machine ID to file: %s", fleet_machine_id);
    }

    /* now check file exists (it always should) and read from it */
    if (flb_access(fleet_machine_id, F_OK) == 0) {
        ret = flb_utils_read_file_wrapper(fleet_machine_id, &buf, &blen);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to read fleet machine id file: %s", fleet_machine_id);
            flb_sds_destroy(fleet_machine_id);
            return NULL;
        }
        flb_plg_info(ctx->ins, "read UUID (%s) from file: %s", buf, fleet_machine_id);
    }
    else { /* fall back to machine-id */
        flb_plg_warn(ctx->ins, "unable to get uuid from file (%s) so falling back to machine id", fleet_machine_id);
        ret = flb_utils_get_machine_id(&buf, &blen);
    }

    /* Clean up no longer required filename */
    flb_sds_destroy(fleet_machine_id);
#endif

    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not obtain machine id");
        return NULL;
    }

    ret = flb_hash_simple(FLB_HASH_SHA256,
                          (unsigned char *) buf,
                          blen,
                          sha256_buf,
                          sizeof(sha256_buf));
    flb_free(buf);

    if (ret != FLB_CRYPTO_SUCCESS) {
        return NULL;
    }

    /* convert to hex */
    return sha256_to_hex(sha256_buf);
}

static int cb_calyptia_init(struct flb_custom_instance *ins,
                         struct flb_config *config,
                         void *data)
{
    int ret;
    struct calyptia *ctx;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct calyptia));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    /* Load the config map */
    ret = flb_custom_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* map instance and local context */
    flb_custom_set_context(ins, ctx);

    /* If no machine_id has been provided via a configuration option get it from the local machine-id. */
    if (!ctx->machine_id) {
        ctx->machine_id = get_machine_id(ctx);
        if (ctx->machine_id == NULL) {
            flb_plg_error(ctx->ins, "unable to retrieve machine_id");
            flb_free(ctx);
            return -1;
        }
        ctx->machine_id_auto_configured = FLB_TRUE;
    }

    /* input collector */
    ctx->i = flb_input_new(config, "fluentbit_metrics", NULL, FLB_TRUE);
    if (!ctx->i) {
        flb_plg_error(ctx->ins, "could not load metrics collector");
        flb_free(ctx);
        return -1;
    }

    flb_input_set_property(ctx->i, "tag", "_calyptia_cloud");
    flb_input_set_property(ctx->i, "scrape_on_start", "true");
    // This scrape interval should be configurable.
    flb_input_set_property(ctx->i, "scrape_interval", "30");

    /* Setup cloud output if needed */
    if (ctx->fleet_id != NULL || !ctx->fleet_name) {
        ctx->o = setup_cloud_output(config, ctx);
        if (ctx->o == NULL) {
            flb_free(ctx);
            return -1;
        }
        /* Set fleet_id for output if present */
        if (ctx->fleet_id) {
            flb_output_set_property(ctx->o, "fleet_id", ctx->fleet_id);
        }
    }

    /* Setup fleet input if needed */
    if (ctx->fleet_id || ctx->fleet_name) {
        ctx->fleet = flb_input_new(config, "calyptia_fleet", NULL, FLB_FALSE);
        if (!ctx->fleet) {
            flb_plg_error(ctx->ins, "could not load Calyptia Fleet plugin");
            return -1;
        }

        ret = set_fleet_input_properties(ctx, ctx->fleet);
        if (ret == -1) {
            return -1;
        }
    }

    if (ctx->o) {
        flb_router_connect(ctx->i, ctx->o);
    }

    flb_plg_info(ins, "custom initialized!");
    return 0;
}

static int cb_calyptia_exit(void *data, struct flb_config *config)
{
    struct calyptia *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->machine_id && ctx->machine_id_auto_configured) {
        flb_sds_destroy(ctx->machine_id);
    }

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "api_key", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, api_key),
     "Calyptia Cloud API Key."
    },

    {
     FLB_CONFIG_MAP_STR, "store_path", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, store_path)
    },

    {
     FLB_CONFIG_MAP_STR, "calyptia_host", DEFAULT_CALYPTIA_HOST,
     0, FLB_TRUE, offsetof(struct calyptia, cloud_host),
     ""
    },

    {
     FLB_CONFIG_MAP_STR, "calyptia_port", DEFAULT_CALYPTIA_PORT,
     0, FLB_TRUE, offsetof(struct calyptia, cloud_port),
     ""
    },

    {
     FLB_CONFIG_MAP_BOOL, "calyptia_tls", "true",
     0, FLB_TRUE, offsetof(struct calyptia, cloud_tls),
     ""
    },

    {
     FLB_CONFIG_MAP_BOOL, "calyptia_tls.verify", "true",
     0, FLB_TRUE, offsetof(struct calyptia, cloud_tls_verify),
     ""
    },

    {
     FLB_CONFIG_MAP_SLIST_1, "add_label", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct calyptia, add_labels),
     "Label to append to the generated metric."
    },

    {
     FLB_CONFIG_MAP_STR, "machine_id", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, machine_id),
     "Custom machine_id to be used when registering agent"
    },
    {
     FLB_CONFIG_MAP_STR, "fleet_id", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, fleet_id),
     "Fleet id to be used when registering agent in a fleet"
    },
    {
     FLB_CONFIG_MAP_STR, "fleet.config_dir", FLEET_DEFAULT_CONFIG_DIR,
     0, FLB_TRUE, offsetof(struct calyptia, fleet_config_dir),
     "Base path for the configuration directory."
    },
    {
      FLB_CONFIG_MAP_STR, "fleet.interval_sec", "-1",
      0, FLB_TRUE, offsetof(struct calyptia, fleet_interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_STR, "fleet.interval_nsec", "-1",
      0, FLB_TRUE, offsetof(struct calyptia, fleet_interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    {
      FLB_CONFIG_MAP_STR, "fleet.max_http_buffer_size", NULL,
      0, FLB_TRUE, offsetof(struct calyptia, fleet_max_http_buffer_size),
      "Max HTTP buffer size for fleet"
    },
    {
     FLB_CONFIG_MAP_STR, "fleet_name", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, fleet_name),
     "Fleet name to be used when registering agent in a fleet"
    },

#ifdef FLB_HAVE_CHUNK_TRACE
    {
     FLB_CONFIG_MAP_STR, "pipeline_id", NULL,
     0, FLB_TRUE, offsetof(struct calyptia, pipeline_id),
     "Pipeline ID for reporting to calyptia cloud."
    },
#endif /* FLB_HAVE_CHUNK_TRACE */
    {
     FLB_CONFIG_MAP_BOOL, "register_retry_on_flush", "true",
     0, FLB_TRUE, offsetof(struct calyptia, register_retry_on_flush),
     "Retry agent registration on flush if failed on init."
    },
    {
     FLB_CONFIG_MAP_BOOL, "fleet_config_legacy_format", "true",
     0, FLB_TRUE, offsetof(struct calyptia, fleet_config_legacy_format),
     "If set, use legacy (TOML) format for configuration files."
    },
    /* EOF */
    {0}
};

struct flb_custom_plugin custom_calyptia_plugin = {
    .name         = "calyptia",
    .description  = "Calyptia Cloud",
    .config_map   = config_map,
    .cb_init      = cb_calyptia_init,
    .cb_exit      = cb_calyptia_exit,
    .flags        = FLB_CUSTOM_NET_CLIENT,
};
