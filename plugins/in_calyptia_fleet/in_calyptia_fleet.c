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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_custom.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_strptime.h>
#include <fluent-bit/flb_reload.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/config_format/flb_cf_fluentbit.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_utils.h>

#include <fluent-bit/calyptia/calyptia_constants.h>

#include "in_calyptia_fleet.h"

/* Glob support */
#ifndef _MSC_VER
#include <glob.h>
#endif

#ifdef _WIN32
#include <Windows.h>
#include <strsafe.h>
#define PATH_MAX MAX_PATH
#endif

#define DEFAULT_INTERVAL_SEC  "15"
#define DEFAULT_INTERVAL_NSEC "0"

#define DEFAULT_MAX_HTTP_BUFFER_SIZE "10485760"

static int fleet_cur_chdir(struct flb_in_calyptia_fleet_config *ctx);
static int get_calyptia_files(struct flb_in_calyptia_fleet_config *ctx,
                              time_t timestamp);

#ifndef FLB_SYSTEM_WINDOWS

static int is_link(const char *path) {
    struct stat st = { 0 };

    if (lstat(path, &st) != 0) {
        return -1;
    }

    if ((st.st_mode & S_IFMT) == S_IFLNK) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}
#else
/* symlinks are too difficult to use on win32 so we skip their use entirely. */
static int is_link(const char *path) {
    return FLB_FALSE;
}
#endif


static char *find_case_header(struct flb_http_client *cli, const char *header)
{
    char *ptr;
    char *headstart;


    headstart = strstr(cli->resp.data, "\r\n");
    if (headstart == NULL) {
        return NULL;
    }

    /* Lookup the beginning of the header */
    for (ptr = headstart; ptr != NULL && ptr+2 < cli->resp.payload; ptr = strstr(ptr, "\r\n")) {
        if (ptr + 4 < cli->resp.payload && strcmp(ptr, "\r\n\r\n") == 0) {
            return NULL;
        }
        ptr+=2;

        /* no space left for header */
        if (ptr + strlen(header)+2 >= cli->resp.payload) {
            return NULL;
        }

        /* matched header and the delimiter */
        if (strncasecmp(ptr, header, strlen(header)) == 0) {
            if (ptr[strlen(header)] == ':' && ptr[strlen(header)+1] == ' ') {
                return ptr;
            }
        }
    }

    return NULL;
}

/* Try to find a header value in the buffer. Copied from flb_http_client.c. */
static int case_header_lookup(struct flb_http_client *cli,
                         const char *header, int header_len,
                         const char **out_val, int *out_len)
{
    char *ptr;
    char *crlf;
    char *end;

    if (!cli->resp.data) {
        return -1;
    }

    ptr = find_case_header(cli, header);
    end = strstr(cli->resp.data, "\r\n\r\n");
    if (!ptr) {
        if (end) {
            /* The headers are complete but the header is not there */
            return -1;
        }

        /* We need more data */
        return -1;
    }

    /* Exclude matches in the body */
    if (end && ptr > end) {
        return -1;
    }

    /* Lookup CRLF (end of line \r\n) */
    crlf = strstr(ptr, "\r\n");
    if (!crlf) {
        return -1;
    }

    /* sanity check that the header_len does not exceed the headers. */
    if (ptr + header_len + 2 > end) {
        return -1;
    }

    ptr += header_len + 2;

    *out_val = ptr;
    *out_len = (crlf - ptr);

    return 0;
}


static flb_sds_t generate_base_fleet_directory(struct flb_in_calyptia_fleet_config *ctx, flb_sds_t *fleet_dir)
{
    if (fleet_dir == NULL) {
        return NULL;
    }

    if (*fleet_dir == NULL) {
        *fleet_dir = flb_sds_create_size(CALYPTIA_MAX_DIR_SIZE);
        if (*fleet_dir == NULL) {
            return NULL;
        }
    }

    /* Ensure we have a valid value */
    if (ctx->config_dir == NULL) {
        ctx->config_dir = FLEET_DEFAULT_CONFIG_DIR;
    }

    if (ctx->fleet_name != NULL) {
        return flb_sds_printf(fleet_dir, "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "%s",
                              ctx->config_dir, ctx->machine_id, ctx->fleet_name);
    }
    return flb_sds_printf(fleet_dir, "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "%s",
                          ctx->config_dir, ctx->machine_id, ctx->fleet_id);
}

flb_sds_t fleet_config_filename(struct flb_in_calyptia_fleet_config *ctx, char *fname)
{
    flb_sds_t cfgname = NULL;
    flb_sds_t ret;

    if (ctx == NULL || fname == NULL) {
        return NULL;
    }

    if (generate_base_fleet_directory(ctx, &cfgname) == NULL) {
        return NULL;
    }

    if (ctx->fleet_config_legacy_format) {
        ret = flb_sds_printf(&cfgname, PATH_SEPARATOR "%s.conf", fname);
    }
    else {
        ret = flb_sds_printf(&cfgname, PATH_SEPARATOR "%s.yaml", fname);
    }

    if (ret == NULL) {
        flb_sds_destroy(cfgname);
        return NULL;
    }

    return cfgname;
}
static flb_sds_t time_fleet_config_filename(struct flb_in_calyptia_fleet_config *ctx, time_t t)
{
    char s_last_modified[32];

    snprintf(s_last_modified, sizeof(s_last_modified)-1, "%d", (int)t);
    return fleet_config_filename(ctx, s_last_modified);
}

static int is_new_fleet_config(struct flb_in_calyptia_fleet_config *ctx, struct flb_config *cfg)
{
    flb_sds_t cfgnewname;
    int ret = FLB_FALSE;


    if (cfg == NULL) {
        return FLB_FALSE;
    }

    if (cfg->conf_path_file == NULL) {
        return FLB_FALSE;
    }

    cfgnewname = new_fleet_config_filename(ctx);
    if (cfgnewname == NULL) {
        flb_plg_error(ctx->ins, "unable to allocate configuration name");
        return FLB_FALSE;
    }

    if (strcmp(cfgnewname, cfg->conf_path_file) == 0) {
        ret = FLB_TRUE;
    }

    flb_sds_destroy(cfgnewname);

    return ret;
}

static int is_cur_fleet_config(struct flb_in_calyptia_fleet_config *ctx, struct flb_config *cfg)
{
    flb_sds_t cfgcurname;
    int ret = FLB_FALSE;

    if (cfg == NULL) {
        return FLB_FALSE;
    }

    if (cfg->conf_path_file == NULL) {
        return FLB_FALSE;
    }

    cfgcurname = cur_fleet_config_filename(ctx);
    if (cfgcurname == NULL) {
        flb_plg_error(ctx->ins, "unable to allocate configuration name");
        return FLB_FALSE;
    }

    if (strcmp(cfgcurname, cfg->conf_path_file) == 0) {
        ret = FLB_TRUE;
    }

    flb_sds_destroy(cfgcurname);

    return ret;
}

static int is_old_fleet_config(struct flb_in_calyptia_fleet_config *ctx, struct flb_config *cfg)
{
    flb_sds_t cfgcurname;
    int ret = FLB_FALSE;


    if (cfg == NULL) {
        return FLB_FALSE;
    }

    if (cfg->conf_path_file == NULL) {
        return FLB_FALSE;
    }

    cfgcurname = old_fleet_config_filename(ctx);
    if (cfgcurname == NULL) {
        flb_plg_error(ctx->ins, "unable to allocate configuration name");
        return FLB_FALSE;
    }

    if (strcmp(cfgcurname, cfg->conf_path_file) == 0) {
        ret = FLB_TRUE;
    }

    flb_sds_destroy(cfgcurname);

    return ret;
}

static int is_timestamped_fleet_config_path(struct flb_in_calyptia_fleet_config *ctx, const char *path)
{
    char *fname;
    char *end;
    long val;

    if (path == NULL || ctx == NULL) {
        return FLB_FALSE;
    }

    fname = strrchr(path, PATH_SEPARATOR[0]);

    if (fname == NULL) {
        return FLB_FALSE;
    }

    fname++;

    errno = 0;
    val = strtol(fname, &end, 10);
    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0)) {
        return FLB_FALSE;
    }

    if (ctx->fleet_config_legacy_format) {
        if (strcmp(end, ".conf") == 0) {
           return FLB_TRUE;
        }
    }
    else if (strcmp(end, ".yaml") == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int is_timestamped_fleet_config(struct flb_in_calyptia_fleet_config *ctx, struct flb_config *cfg)
{
    if (cfg == NULL) {
        return FLB_FALSE;
    }

    if (cfg->conf_path_file == NULL) {
        return FLB_FALSE;
    }

    return is_timestamped_fleet_config_path(ctx, cfg->conf_path_file);
}

static int is_fleet_config(struct flb_in_calyptia_fleet_config *ctx, struct flb_config *cfg)
{
    if (cfg == NULL) {
        return FLB_FALSE;
    }

    if (cfg->conf_path_file == NULL) {
        return FLB_FALSE;
    }

    return is_new_fleet_config(ctx, cfg) ||
           is_cur_fleet_config(ctx, cfg) ||
           is_old_fleet_config(ctx, cfg) ||
           is_timestamped_fleet_config(ctx, cfg);
}

static int exists_new_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    int ret = FLB_FALSE;
    flb_sds_t cfgnewname;

    cfgnewname = new_fleet_config_filename(ctx);
    if (cfgnewname == NULL) {
        flb_plg_error(ctx->ins, "unable to allocate configuration name");
        return FLB_FALSE;
    }

    ret = access(cfgnewname, F_OK) == 0 ? FLB_TRUE : FLB_FALSE;
    flb_sds_destroy(cfgnewname);

    return ret;
}

static int exists_cur_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t cfgcurname;
    int ret = FLB_FALSE;


    cfgcurname = cur_fleet_config_filename(ctx);
    if (cfgcurname == NULL) {
        flb_plg_error(ctx->ins, "unable to allocate configuration name");
        return FLB_FALSE;
    }

    ret = access(cfgcurname, F_OK) == 0 ? FLB_TRUE : FLB_FALSE;

    flb_sds_destroy(cfgcurname);
    return ret;
}

static int exists_old_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    int ret = FLB_FALSE;
    flb_sds_t cfgoldname;

    cfgoldname = old_fleet_config_filename(ctx);
    if (cfgoldname == NULL) {
        flb_plg_error(ctx->ins, "unable to allocate configuration name");
        return FLB_FALSE;
    }

    ret = access(cfgoldname, F_OK) == 0 ? FLB_TRUE : FLB_FALSE;
    flb_sds_destroy(cfgoldname);

    return ret;
}

static int exists_header_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    int ret = FLB_FALSE;
    flb_sds_t cfgheadername;

    cfgheadername = hdr_fleet_config_filename(ctx);
    if (cfgheadername == NULL) {
        flb_plg_error(ctx->ins, "unable to allocate configuration name");
        return FLB_FALSE;
    }

    ret = access(cfgheadername, F_OK) == 0 ? FLB_TRUE : FLB_FALSE;
    flb_sds_destroy(cfgheadername);

    return ret;
}

static void *do_reload(void *data)
{
    struct reload_ctx *reload = (struct reload_ctx *)data;

    if (reload == NULL) {
        return NULL;
    }

    /* avoid reloading the current configuration... just use our new one! */
    flb_context_set(reload->flb);
    reload->flb->config->enable_hot_reload = FLB_TRUE;
    if (reload->flb->config->conf_path_file) {
        flb_sds_destroy(reload->flb->config->conf_path_file);
    }
    reload->flb->config->conf_path_file = reload->cfg_path;

    flb_free(reload);
    sleep(5);
#ifndef FLB_SYSTEM_WINDOWS
    kill(getpid(), SIGHUP);
#else
    GenerateConsoleCtrlEvent(1 /* CTRL_BREAK_EVENT_1 */, 0);
#endif
    return NULL;
}

static int test_config_is_valid(struct flb_in_calyptia_fleet_config *ctx,
                                flb_sds_t cfgpath)
{
    return FLB_TRUE;
    struct flb_cf *conf;
    int ret = FLB_FALSE;

    if (cfgpath == NULL) {
        return FLB_FALSE;
    }

    conf = flb_cf_create();
    if (conf == NULL) {
        flb_plg_debug(ctx->ins, "unable to create config during validation test: %s",
                      cfgpath);
        goto config_init_error;
    }

    conf = flb_cf_create_from_file(conf, cfgpath);
    if (conf == NULL) {
        flb_plg_debug(ctx->ins,
                      "unable to create config from file during validation test: %s",
                      cfgpath);
        goto cf_create_from_file_error;
    }

    ret = FLB_TRUE;

cf_create_from_file_error:
    flb_cf_destroy(conf);
config_init_error:
    return ret;
}

static int parse_config_name_timestamp(struct flb_in_calyptia_fleet_config *ctx,
                                      const char *cfgpath,
                                      long *config_timestamp)
{
    char *ext = NULL;
    long timestamp;
    char realname[CALYPTIA_MAX_DIR_SIZE] = {0};
    char *fname;
    ssize_t len;

    if (ctx == NULL || config_timestamp == NULL || cfgpath == NULL) {
        return FLB_FALSE;
    }

    switch (is_link(cfgpath)) {
    /* Prevent undefined references due to use of readlink */
#ifndef FLB_SYSTEM_WINDOWS
    case FLB_TRUE:

        len = readlink(cfgpath, realname, sizeof(realname));

        if (len > sizeof(realname)) {
            return FLB_FALSE;
        }
        break;
#endif /* FLB_SYSTEM_WINDOWS */
    case FLB_FALSE:
        strncpy(realname, cfgpath, sizeof(realname)-1);
        break;
    default:
        flb_errno();
        return FLB_FALSE;
    }

    fname = basename(realname);
    flb_plg_debug(ctx->ins, "parsing configuration timestamp from path: %s", fname);

    errno = 0;
    timestamp = strtol(fname, &ext, 10);

    if ((errno == ERANGE && (timestamp == LONG_MAX || timestamp == LONG_MIN)) ||
            (errno != 0 && timestamp == 0)) {
        flb_errno();
        return FLB_FALSE;
    }

    /* unable to parse the timstamp */
    if (errno == ERANGE) {
        return FLB_FALSE;
    }

    *config_timestamp = timestamp;

    return FLB_TRUE;
}

static int parse_config_timestamp(struct flb_in_calyptia_fleet_config *ctx,
                                  long *config_timestamp)
{
    flb_ctx_t *flb_ctx = flb_context_get();

    if (ctx == NULL || config_timestamp == NULL) {
        return FLB_FALSE;
    }

    return parse_config_name_timestamp(ctx, flb_ctx->config->conf_path_file, config_timestamp);
}

static int execute_reload(struct flb_in_calyptia_fleet_config *ctx, flb_sds_t cfgpath)
{
    struct reload_ctx *reload;
    pthread_t pth;
    pthread_attr_t ptha;
    flb_ctx_t *flb = flb_context_get();

    if (parse_config_name_timestamp(ctx, cfgpath, &ctx->config_timestamp) != FLB_TRUE) {
        flb_sds_destroy(cfgpath);
        return FLB_FALSE;
    }

    reload = flb_calloc(1, sizeof(struct reload_ctx));
    reload->flb = flb;
    reload->cfg_path = cfgpath;

    if (ctx->collect_fd > 0) {
        flb_input_collector_pause(ctx->collect_fd, ctx->ins);
    }

    if (flb == NULL) {
        flb_plg_error(ctx->ins, "unable to get fluent-bit context.");

        if (ctx->collect_fd > 0) {
            flb_input_collector_resume(ctx->collect_fd, ctx->ins);
        }

        flb_sds_destroy(cfgpath);
        return FLB_FALSE;
    }

    /* fix execution in valgrind...
     * otherwise flb_reload errors out with:
     *    [error] [reload] given flb context is NULL
     */
    flb_plg_info(ctx->ins, "loading configuration from %s.", reload->cfg_path);

    if (test_config_is_valid(ctx, reload->cfg_path) == FLB_FALSE) {
        flb_plg_error(ctx->ins, "unable to load configuration.");

        if (ctx->collect_fd > 0) {
            flb_input_collector_resume(ctx->collect_fd, ctx->ins);
        }

        flb_sds_destroy(cfgpath);
        return FLB_FALSE;
    }

    if (fleet_cur_chdir(ctx) == -1) {
        flb_errno();
        flb_plg_error(ctx->ins, "unable to change to configuration directory");
    }

    fleet_cur_chdir(ctx);

    pthread_attr_init(&ptha);
    pthread_attr_setdetachstate(&ptha, PTHREAD_CREATE_DETACHED);
    pthread_create(&pth, &ptha, do_reload, reload);

    return FLB_TRUE;
}

static msgpack_object *msgpack_lookup_map_key(msgpack_object *obj, const char *keyname)
{
    int idx;
    msgpack_object_kv *cur;
    msgpack_object_str *key;

    if (obj == NULL || keyname == NULL) {
        return NULL;
    }

    if (obj->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    for (idx = 0; idx < obj->via.map.size; idx++) {
        cur = &obj->via.map.ptr[idx];
        if (cur->key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        key = &cur->key.via.str;

        if (key->size != strlen(keyname)) {
            continue;
        }

        if (strncmp(key->ptr, keyname, key->size) == 0) {
            return &cur->val;
        }
    }

    return NULL;
}

static msgpack_object *msgpack_lookup_array_offset(msgpack_object *obj, size_t offset)
{
    if (obj == NULL) {
        return NULL;
    }

    if (obj->type != MSGPACK_OBJECT_ARRAY) {
        return NULL;
    }

    if (obj->via.array.size <= offset) {
        return NULL;
    }

    return &obj->via.array.ptr[offset];
}

static flb_sds_t parse_api_key_json(struct flb_in_calyptia_fleet_config *ctx,
                                    char *payload, size_t size)
{
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object *tmp;
    flb_sds_t project_id = NULL;

    if (ctx == NULL || payload == NULL) {
        return NULL;
    }

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART || ret == FLB_ERR_JSON_INVAL || ret == -1) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return NULL;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, out_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        tmp  = msgpack_lookup_map_key(&result.data, "ProjectID");
        if (tmp == NULL) {
            flb_plg_error(ctx->ins, "unable to find fleet by name");
            msgpack_unpacked_destroy(&result);
            return NULL;
        }

        if (tmp->type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "invalid fleet ID data type");
            msgpack_unpacked_destroy(&result);
            return NULL;
        }

        project_id = flb_sds_create_len(tmp->via.str.ptr, tmp->via.str.size);
        break;
    }

    msgpack_unpacked_destroy(&result);
    flb_free(pack);

    return project_id;
}

static ssize_t parse_fleet_search_json(struct flb_in_calyptia_fleet_config *ctx,
                                       char *payload, size_t size)
{
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object *map;
    msgpack_object *fleet;

    if (ctx == NULL || payload == NULL) {
        return -1;
    }

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART || ret == FLB_ERR_JSON_INVAL || ret == -1) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return -1;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, out_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        map = msgpack_lookup_array_offset(&result.data, 0);
        if (map == NULL) {
            break;
        }

        fleet = msgpack_lookup_map_key(map, "id");
        if (fleet == NULL) {
            flb_plg_error(ctx->ins, "unable to find fleet by name");
            break;
        }

        if (fleet->type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "unable to find fleet by name");
            break;
        }

        ctx->fleet_id = flb_sds_create_len(fleet->via.str.ptr, fleet->via.str.size);
        ctx->fleet_id_found = FLB_TRUE;
        break;
    }

    msgpack_unpacked_destroy(&result);
    flb_free(pack);

    if (ctx->fleet_id == NULL) {
        return -1;
    }

    return 0;
}

static flb_sds_t get_project_id_from_api_key(struct flb_in_calyptia_fleet_config *ctx)
{
    unsigned char encoded[256];
    unsigned char token[512] = {0};
    char *api_token_sep;
    size_t tlen;
    size_t elen;
    int ret;

    if (ctx == NULL) {
        return NULL;
    }

    api_token_sep = strchr(ctx->api_key, '.');
    if (api_token_sep == NULL) {
        return NULL;
    }

    elen = api_token_sep-ctx->api_key;
    elen = elen + (4 - (elen % 4));

    if (elen > sizeof(encoded)) {
        flb_plg_error(ctx->ins, "API Token is too large");
        return NULL;
    }

    memset(encoded, '=', sizeof(encoded));
    memcpy(encoded, ctx->api_key, api_token_sep-ctx->api_key);

    ret = flb_base64_decode(token, sizeof(token)-1, &tlen,
                            encoded, elen);

    if (ret != 0) {
        return NULL;
    }

    return parse_api_key_json(ctx, (char *)token, tlen);
}

static struct flb_http_client *fleet_http_do(struct flb_in_calyptia_fleet_config *ctx,
                                             flb_sds_t url)
{
    int ret = -1;
    size_t b_sent;
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    flb_sds_t config_version;

    if (ctx == NULL || url == NULL) {
        return NULL;
    }

    u_conn = flb_upstream_conn_get(ctx->u);
    if (u_conn == NULL) {
        flb_plg_error(ctx->ins, "unable to get upstream connection");
        return NULL;
    }

    client = flb_http_client(u_conn, FLB_HTTP_GET, url, NULL, 0,
                             ctx->ins->host.name, ctx->ins->host.port, NULL, 0);

    if (!client) {
        flb_plg_error(ctx->ins, "unable to create http client");
        goto http_client_error;
    }

    flb_http_buffer_size(client, ctx->max_http_buffer_size);

    config_version = flb_sds_create_size(32);
    flb_sds_printf(&config_version, "%ld", ctx->config_timestamp);
    flb_http_add_header(client,
                         FLEET_HEADERS_CONFIG_VERSION, sizeof(FLEET_HEADERS_CONFIG_VERSION) -1,
                         config_version, flb_sds_len(config_version));
    flb_sds_destroy(config_version);

    flb_http_add_header(client,
                        CALYPTIA_HEADERS_PROJECT, sizeof(CALYPTIA_HEADERS_PROJECT) - 1,
                        ctx->api_key, flb_sds_len(ctx->api_key));

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "http do error");
        goto http_do_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ctx->ins, "search http status code error: %d", client->resp.status);
        goto http_do_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ctx->ins, "empty response");
        goto http_do_error;
    }

    flb_upstream_conn_release(u_conn);
    return client;

http_do_error:
    flb_http_client_destroy(client);
http_client_error:
    flb_upstream_conn_release(u_conn);
    return NULL;
}

static int get_calyptia_fleet_id_by_name(struct flb_in_calyptia_fleet_config *ctx,
                                         struct flb_config *config)
{
    struct flb_http_client *client;
    flb_sds_t url;
    flb_sds_t project_id;

    if (ctx == NULL || config == NULL) {
        return -1;
    }

    project_id = get_project_id_from_api_key(ctx);
    if (project_id == NULL) {
        return -1;
    }

    url = flb_sds_create_size(CALYPTIA_MAX_DIR_SIZE);
    if (url == NULL) {
        flb_sds_destroy(project_id);
        return -1;
    }

    flb_sds_printf(&url, CALYPTIA_ENDPOINT_FLEET_BY_NAME,
                   project_id, ctx->fleet_name);

    client = fleet_http_do(ctx, url);
    flb_sds_destroy(url);

    if (!client) {
        flb_sds_destroy(project_id);
        return -1;
    }

    if (parse_fleet_search_json(ctx, client->resp.payload, client->resp.payload_size) == -1) {
        flb_plg_error(ctx->ins, "unable to find fleet: %s", ctx->fleet_name);
        flb_http_client_destroy(client);
        flb_sds_destroy(project_id);
        return -1;
    }

    flb_http_client_destroy(client);
    flb_sds_destroy(project_id);

    if (ctx->fleet_id == NULL) {
        return -1;
    }

    return 0;
}

static int get_calyptia_file(struct flb_in_calyptia_fleet_config *ctx,
                             flb_sds_t url,
                             const char *hdr,
                             const char *dst,
                             time_t *time_last_modified)
{
    struct flb_http_client *client;
    size_t len;
    FILE *fp;
    int ret = -1;
    const char *fbit_last_modified;
    struct flb_tm tm_last_modified = { 0 };
    int fbit_last_modified_len;
    time_t last_modified;
    flb_sds_t fname;

    if (ctx == NULL || url == NULL) {
        return -1;
    }

    client = fleet_http_do(ctx, url);
    if (client == NULL) {
        return -1;
    }

    ret = case_header_lookup(client, "Last-modified", strlen("Last-modified"),
                             &fbit_last_modified, &fbit_last_modified_len);

    if (ret < 0) {
        goto client_error;
    }

    if (dst == NULL) {
        // Assuming this is the base Fleet config file
        flb_strptime(fbit_last_modified, "%a, %d %B %Y %H:%M:%S GMT", &tm_last_modified);
        last_modified = mktime(&tm_last_modified.tm);

        fname = time_fleet_config_filename(ctx, last_modified);
    }
    else {
        // Fleet File file
        fname = flb_sds_create_len(dst, strlen(dst));
    }

    if (fname == NULL) {
        goto file_name_error;
    }

    if (access(fname, F_OK) == 0) {
        ret = 0;
        goto file_error;
    }


    fp = fopen(fname, "w+");

    if (fp == NULL) {
        goto file_error;
    }

    if (hdr != NULL) {
        len = fwrite(hdr, strlen(hdr), 1, fp);
        if (len < 1) {
            flb_plg_error(ctx->ins, "truncated write: %s", dst);
            goto file_write_error;
        }
    }

    len = fwrite(client->resp.payload, client->resp.payload_size, 1, fp);
    if (len < 1) {
        flb_plg_error(ctx->ins, "truncated write: %s", dst);
        goto file_write_error;
    }

    if (time_last_modified) {
        *time_last_modified = last_modified;
    }

    ret = 1;

file_write_error:
    fclose(fp);
file_name_error:
file_error:
    flb_sds_destroy(fname);
client_error:
    flb_http_client_destroy(client);
    return ret;
}

#ifndef _WIN32
static struct cfl_array *read_glob(const char *path)
{
    int ret = -1;
    int ret_glb = -1;
    glob_t glb;
    size_t idx;
    struct cfl_array *list;


    ret_glb = glob(path, GLOB_NOSORT, NULL, &glb);

    if (ret_glb != 0) {
        switch(ret_glb){
        case GLOB_NOSPACE:
            flb_warn("[%s] glob: [%s] no space", __FUNCTION__, path);
            break;
        case GLOB_NOMATCH:
            flb_warn("[%s] glob: [%s] no match", __FUNCTION__, path);
            break;
        case GLOB_ABORTED:
            flb_warn("[%s] glob: [%s] aborted", __FUNCTION__, path);
            break;
        default:
            flb_warn("[%s] glob: [%s] other error", __FUNCTION__, path);
        }
        return NULL;
    }

    list = cfl_array_create(glb.gl_pathc);
    for (idx = 0; idx < glb.gl_pathc; idx++) {
        ret = cfl_array_append_string(list, glb.gl_pathv[idx]);
        if (ret < 0) {
            cfl_array_destroy(list);
            return NULL;
        }
    }

    globfree(&glb);
    return list;
}
#else
static char *dirname(char *path)
{
    char *ptr;

    ptr = strrchr(path, '\\');

    if (ptr == NULL) {
        return path;
    }
    *ptr++='\0';
    return path;
}

static struct cfl_array *read_glob_win(const char *path, struct cfl_array *list)
{
    char *star, *p0, *p1;
    char pattern[MAX_PATH];
    char buf[MAX_PATH];
    int ret;
    struct stat st;
    HANDLE hnd;
    WIN32_FIND_DATA data;

    if (strlen(path) > MAX_PATH - 1) {
        flb_error("path too long: %s", path);
        return NULL;
    }

    star = strchr(path, '*');
    if (star == NULL) {
        flb_error("path has no wild card: %s", path);
        return NULL;
    }

    /*
     * C:\data\tmp\input_*.conf
     *            0<-----|
     */
    p0 = star;
    while (path <= p0 && *p0 != '\\') {
        p0--;
    }

    /*
     * C:\data\tmp\input_*.conf
     *                   |---->1
     */
    p1 = star;
    while (*p1 && *p1 != '\\') {
        p1++;
    }

    memcpy(pattern, path, (p1 - path));
    pattern[p1 - path] = '\0';

    hnd = FindFirstFileA(pattern, &data);

    if (hnd == INVALID_HANDLE_VALUE) {
        flb_error("unable to open valid handle for: %s", path);
        return NULL;
    }

    if (list == NULL) {
        list = cfl_array_create(3);

        if (list == NULL) {
            flb_error("unable to allocate array");
            FindClose(hnd);
            return NULL;
        }

        /* cfl_array_resizable is hardcoded to return 0. */
        if (cfl_array_resizable(list, FLB_TRUE) != 0) {
            flb_error("unable to make array resizable");
            FindClose(hnd);
            cfl_array_destroy(list);
            return NULL;
        }
    }

    do {
        /* Ignore the current and parent dirs */
        if (!strcmp(".", data.cFileName) || !strcmp("..", data.cFileName)) {
            continue;
        }

        /* Avoid an infinite loop */
        if (strchr(data.cFileName, '*')) {
            continue;
        }

        /* Create a path (prefix + filename + suffix) */
        memcpy(buf, path, p0 - path + 1);
        buf[p0 - path + 1] = '\0';

        if (FAILED(StringCchCatA(buf, MAX_PATH, data.cFileName))) {
            continue;
        }

        if (FAILED(StringCchCatA(buf, MAX_PATH, p1))) {
            continue;
        }

        if (strchr(p1, '*')) {
            if (read_glob_win(path, list) == NULL) {
                cfl_array_destroy(list);
                FindClose(hnd);
                return NULL;
            }
            continue;
        }

        ret = stat(buf, &st);

        if (ret == 0 && (st.st_mode & S_IFMT) == S_IFREG) {
            cfl_array_append_string(list, buf);
        }
    } while (FindNextFileA(hnd, &data) != 0);

    FindClose(hnd);
    return list;
}

static struct cfl_array *read_glob(const char *path)
{
    return read_glob_win(path, NULL);
}

#endif

static int cfl_array_qsort_conf_files(const void *arg_a, const void *arg_b)
{
    struct cfl_variant *var_a = (struct cfl_variant *)*(void **)arg_a;
    struct cfl_variant *var_b = (struct cfl_variant *)*(void **)arg_b;

    if (var_a == NULL && var_b == NULL) {
        return 0;
    }
    else if (var_a == NULL) {
        return -1;
    }
    else if (var_b == NULL) {
        return 1;
    }
    else if (var_a->type != CFL_VARIANT_STRING &&
             var_b->type != CFL_VARIANT_STRING) {
        return 0;
    }
    else if (var_a->type != CFL_VARIANT_STRING) {
        return -1;
    }
    else if (var_b->type != CFL_VARIANT_STRING) {
        return 1;
    }

    return strcmp(var_a->data.as_string, var_b->data.as_string);
}

static int calyptia_config_delete_old_dir(const char *cfgpath)
{
    flb_sds_t cfg_glob;
    char *ext;
    struct cfl_array *files;
    int idx;

    if (cfgpath == NULL) {
        return FLB_FALSE;
    }

    ext = strrchr(cfgpath, '.');
    if (ext == NULL) {
        return FLB_FALSE;
    }

    cfg_glob = flb_sds_create_len(cfgpath, ext - cfgpath);
    if (cfg_glob == NULL) {
        return FLB_FALSE;
    }

    if (flb_sds_cat_safe(&cfg_glob, PATH_SEPARATOR "*", strlen(PATH_SEPARATOR "*")) != 0) {
        flb_sds_destroy(cfg_glob);
        return FLB_FALSE;
    }

    files = read_glob(cfg_glob);

    if (files != NULL) {
        for (idx = 0; idx < ((ssize_t)files->entry_count); idx++) {
                unlink(files->entries[idx]->data.as_string);
        }
    }

    /* attempt to delete the main directory */
    ext = strrchr(cfg_glob, PATH_SEPARATOR[0]);
    if (ext) {
        *ext = '\0';
        rmdir(cfg_glob);
    }

    /* attempt to delete the main directory */
    ext = strrchr(cfg_glob, '/');
    if (ext) {
        *ext = '\0';
        rmdir(cfg_glob);
    }

    flb_sds_destroy(cfg_glob);
    cfl_array_destroy(files);

    return FLB_TRUE;
}

static int calyptia_config_delete_old(struct flb_in_calyptia_fleet_config *ctx)
{
    struct cfl_array *confs;
    struct cfl_array *tconfs;
    flb_sds_t glob_files = NULL;
    int idx;

    if (ctx == NULL) {
        return -1;
    }

    if (generate_base_fleet_directory(ctx, &glob_files) == NULL) {
        flb_sds_destroy(glob_files);
        return -1;
    }

    if (ctx->fleet_config_legacy_format) {
        if (flb_sds_cat_safe(&glob_files, PATH_SEPARATOR "*.conf", strlen(PATH_SEPARATOR "*.conf")) != 0) {
            flb_sds_destroy(glob_files);
            return -1;
        }
    } else if (flb_sds_cat_safe(&glob_files, PATH_SEPARATOR "*.yaml", strlen(PATH_SEPARATOR "*.yaml")) != 0) {
        flb_sds_destroy(glob_files);
        return -1;
    }

    confs = read_glob(glob_files);
    if (confs == NULL) {
        flb_sds_destroy(glob_files);
        return -1;
    }

    tconfs = cfl_array_create(1);
    if (tconfs == NULL) {
        flb_sds_destroy(glob_files);
        cfl_array_destroy(confs);
        return -1;
    }

    if (cfl_array_resizable(tconfs, FLB_TRUE) != 0) {
        flb_sds_destroy(glob_files);
        cfl_array_destroy(confs);
        return -1;
    }

    for (idx = 0; idx < confs->entry_count; idx++) {
        if (is_timestamped_fleet_config_path(ctx, confs->entries[idx]->data.as_string) == FLB_TRUE) {
            cfl_array_append_string(tconfs, confs->entries[idx]->data.as_string);
        }
    }

    qsort(tconfs->entries, tconfs->entry_count,
          sizeof(struct cfl_variant *),
          cfl_array_qsort_conf_files);

    for (idx = 0; idx < (((ssize_t)tconfs->entry_count) -3); idx++) {
        unlink(tconfs->entries[idx]->data.as_string);
        calyptia_config_delete_old_dir(tconfs->entries[idx]->data.as_string);
    }

    cfl_array_destroy(confs);
    cfl_array_destroy(tconfs);
    flb_sds_destroy(glob_files);

    return 0;
}

static flb_sds_t calyptia_config_get_newest(struct flb_in_calyptia_fleet_config *ctx)
{
    struct cfl_array *inis;
    flb_sds_t glob_conf_files = NULL;
    flb_sds_t cfgnewname = NULL;
    const char *curconf;
    int idx;

    if (ctx == NULL) {
        return NULL;
    }

    if (generate_base_fleet_directory(ctx, &glob_conf_files) == NULL) {
        flb_plg_error(ctx->ins, "unable to generate fleet directory name");
        flb_sds_destroy(glob_conf_files);
        return NULL;
    }

    if (ctx->fleet_config_legacy_format) {
        if (flb_sds_cat_safe(&glob_conf_files, PATH_SEPARATOR "*.conf", strlen(PATH_SEPARATOR "*.conf")) != 0) {
            flb_plg_error(ctx->ins, "unable to concatenate fleet glob");
            flb_sds_destroy(glob_conf_files);
            return NULL;
        }
    }
    else if (flb_sds_cat_safe(&glob_conf_files, PATH_SEPARATOR "*.yaml", strlen(PATH_SEPARATOR "*.yaml")) != 0) {
        flb_plg_error(ctx->ins, "unable to concatenate fleet glob");
        flb_sds_destroy(glob_conf_files);
        return NULL;
    }

    inis = read_glob(glob_conf_files);
    if (inis == NULL) {
        flb_plg_error(ctx->ins, "unable to read fleet directory for config files: %s",
                      glob_conf_files);
        flb_sds_destroy(glob_conf_files);
        return NULL;
    }

    qsort(inis->entries, inis->entry_count,
          sizeof(struct cfl_variant *),
          cfl_array_qsort_conf_files);

    for (idx = inis->entry_count-1; idx >= 0; idx--) {
        curconf = inis->entries[idx]->data.as_string;
        if (is_timestamped_fleet_config_path(ctx, curconf)) {
            cfgnewname = flb_sds_create(curconf);
            break;
        }
    }

    cfl_array_destroy(inis);
    flb_sds_destroy(glob_conf_files);

    return cfgnewname;
}

#ifndef FLB_SYSTEM_WINDOWS

static int calyptia_config_add(struct flb_in_calyptia_fleet_config *ctx,
                               const char *cfgname)
{
    int rc = FLB_FALSE;

    flb_sds_t cfgnewname = NULL;
    flb_sds_t cfgoldname = NULL;
    flb_sds_t cfgcurname = NULL;

    cfgnewname = new_fleet_config_filename(ctx);
    cfgcurname = cur_fleet_config_filename(ctx);
    cfgoldname = old_fleet_config_filename(ctx);

    if (cfgnewname == NULL || cfgcurname == NULL || cfgoldname == NULL) {
        goto error;
    }

    if (exists_new_fleet_config(ctx) == FLB_TRUE) {

        if (rename(cfgnewname, cfgoldname)) {
            goto error;
        }
    }
    else if (exists_cur_fleet_config(ctx) == FLB_TRUE) {

        if (rename(cfgcurname, cfgoldname)) {
            goto error;
        }
    }

    if (symlink(cfgname, cfgnewname)) {
        flb_plg_error(ctx->ins, "unable to create new configuration symlink.");
        goto error;
    }

    rc = FLB_TRUE;

error:
    if (cfgnewname) {
        flb_sds_destroy(cfgnewname);
    }

    if (cfgcurname) {
        flb_sds_destroy(cfgcurname);
    }

    if (cfgoldname) {
        flb_sds_destroy(cfgoldname);
    }

    return rc;
}

static int calyptia_config_commit(struct flb_in_calyptia_fleet_config *ctx)
{
    int rc = FLB_FALSE;
    flb_sds_t cfgnewname = NULL;
    flb_sds_t cfgcurname = NULL;
    flb_sds_t cfgoldname = NULL;

    cfgnewname = new_fleet_config_filename(ctx);
    cfgcurname = cur_fleet_config_filename(ctx);
    cfgoldname = old_fleet_config_filename(ctx);

    if (cfgnewname == NULL ||
        cfgcurname == NULL ||
        cfgoldname == NULL) {
        goto error;
    }

    if (exists_old_fleet_config(ctx) == FLB_TRUE) {
        unlink(cfgoldname);
    }

    if (exists_new_fleet_config(ctx) == FLB_TRUE) {
        if (rename(cfgnewname, cfgcurname)) {
            goto error;
        }
    }

    calyptia_config_delete_old(ctx);
    rc = FLB_TRUE;

error:
    if (cfgnewname) {
        flb_sds_destroy(cfgnewname);
    }

    if (cfgcurname) {
        flb_sds_destroy(cfgcurname);
    }

    if (cfgoldname) {
        flb_sds_destroy(cfgoldname);
    }

    return rc;
}

static int calyptia_config_rollback(struct flb_in_calyptia_fleet_config *ctx,
                                    const char *cfgname)
{
    int rc = FLB_TRUE;
    flb_sds_t cfgnewname;
    flb_sds_t cfgcurname;
    flb_sds_t cfgoldname;

    cfgnewname = new_fleet_config_filename(ctx);
    cfgcurname = cur_fleet_config_filename(ctx);
    cfgoldname = old_fleet_config_filename(ctx);

    if (cfgnewname == NULL || cfgcurname == NULL || cfgoldname == NULL) {
        goto error;
    }

    if (exists_new_fleet_config(ctx) == FLB_TRUE) {
        unlink(cfgnewname);
    }

    if (exists_old_fleet_config(ctx) == FLB_TRUE) {
        rename(cfgoldname, cfgcurname);
    }

    rc = FLB_TRUE;

error:
    if (cfgnewname) {
        flb_sds_destroy(cfgnewname);
    }

    if (cfgcurname) {
        flb_sds_destroy(cfgcurname);
    }

    if (cfgoldname) {
        flb_sds_destroy(cfgoldname);
    }

    return rc;
}
#else
static int calyptia_config_add(struct flb_in_calyptia_fleet_config *ctx,
                               const char *cfgname)
{
    return FLB_TRUE;
}

static int calyptia_config_commit(struct flb_in_calyptia_fleet_config *ctx)
{
    calyptia_config_delete_old(ctx);
    return FLB_TRUE;
}

static int calyptia_config_rollback(struct flb_in_calyptia_fleet_config *ctx,
                                    const char *cfgname)
{
    unlink(cfgname);
    return FLB_TRUE;
}
#endif

static void fleet_config_get_properties(flb_sds_t *buf, struct mk_list *props, int fleet_config_legacy_format)
{
    struct mk_list *head;
    struct flb_kv *kv;

    mk_list_foreach(head, props) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (kv->key != NULL && kv->val != NULL) {
            if (fleet_config_legacy_format) {
                flb_sds_printf(buf, "    %s ", kv->key);
            }
            else {
                flb_sds_printf(buf, "      %s: ", kv->key);
            }
            flb_sds_cat_safe(buf, kv->val, strlen(kv->val));
            flb_sds_cat_safe(buf, "\n", 1);
        }
    }
}

static flb_sds_t get_fleet_id_from_header(struct flb_in_calyptia_fleet_config *ctx)
{
    struct mk_list *head;
    struct flb_cf_section *section;
    flb_sds_t fleet_id;
    flb_sds_t name;
    struct flb_cf *cf_hdr;
    flb_sds_t cfgheadername;


    if (exists_header_fleet_config(ctx)) {
        cfgheadername = hdr_fleet_config_filename(ctx);
        if (cfgheadername == NULL) {
            return NULL;
        }

        cf_hdr = flb_cf_create_from_file(NULL, cfgheadername);
        flb_sds_destroy(cfgheadername);

        if (cf_hdr == NULL) {
            return NULL;
        }

        mk_list_foreach(head, &cf_hdr->sections) {
            section = mk_list_entry(head, struct flb_cf_section, _head);

            if (strcasecmp(section->name, "custom") != 0) {
                continue;
            }

            name = flb_cf_section_property_get_string(cf_hdr, section, "name");

            if (!name) {
                flb_plg_error(ctx->ins, "no name in fleet header");
                flb_cf_destroy(cf_hdr);
                return NULL;
            }

            if (strcasecmp(name, "calyptia") != 0) {
                flb_sds_destroy(name);
                continue;
            }
            flb_sds_destroy(name);

            fleet_id = flb_cf_section_property_get_string(cf_hdr, section, "fleet_id");

            if (!fleet_id) {
                flb_plg_error(ctx->ins, "no fleet_id in fleet header");
                flb_cf_destroy(cf_hdr);
                return NULL;
            }

            flb_cf_destroy(cf_hdr);
            return fleet_id;
        }

        flb_cf_destroy(cf_hdr);
    }

    return NULL;
}

flb_sds_t fleet_config_get(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t buf;
    struct mk_list *head;
    struct flb_custom_instance *c_ins;
    flb_ctx_t *flb = flb_context_get();
    flb_sds_t fleet_id = NULL;

    if (!ctx) {
        return NULL;
    }

    buf = flb_sds_create_size(CALYPTIA_MAX_DIR_SIZE);

    if (!buf) {
        return NULL;
    }

    mk_list_foreach(head, &flb->config->customs) {
        c_ins = mk_list_entry(head, struct flb_custom_instance, _head);
        if (strcasecmp(c_ins->p->name, "calyptia")) {
            continue;
        }
        if (ctx->fleet_config_legacy_format) {
            flb_sds_printf(&buf, "[CUSTOM]\n");
            flb_sds_printf(&buf, "    name %s\n", c_ins->p->name);
        }
        else {
            flb_sds_printf(&buf, "customs:\n");
            flb_sds_printf(&buf, "    - name: %s\n", c_ins->p->name);
        }

        fleet_config_get_properties(&buf, &c_ins->properties, ctx->fleet_config_legacy_format);

        if (flb_config_prop_get("fleet_id", &c_ins->properties) == NULL) {
            if (ctx->fleet_id != NULL) {
                if (ctx->fleet_config_legacy_format) {
                    flb_sds_printf(&buf, "    fleet_id %s\n", ctx->fleet_id);
                } else {
                    flb_sds_printf(&buf, "      fleet_id: %s\n", ctx->fleet_id);
                }
            }
            else {
                fleet_id = get_fleet_id_from_header(ctx);

                if (fleet_id == NULL) {
                    flb_plg_error(ctx->ins, "unable to get fleet_id from header");
                    return NULL;
                }

                if (ctx->fleet_config_legacy_format) {
                    flb_sds_printf(&buf, "    fleet_id %s\n", fleet_id);
                } else {
                    flb_sds_printf(&buf, "      fleet_id: %s\n", fleet_id);
                }
                flb_sds_destroy(fleet_id);
            }
        }
    }
    flb_sds_printf(&buf, "\n");

    return buf;
}

static int create_fleet_header(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t hdrname;
    FILE *fp;
    flb_sds_t header;
    int rc = FLB_FALSE;


    hdrname = fleet_config_filename(ctx, "header");
    if (hdrname == NULL) {
        goto hdrname_error;
    }

    header = fleet_config_get(ctx);
    if (header == NULL) {
        goto header_error;
    }

    fp = fopen(hdrname, "w+");
    if (fp == NULL) {
        goto file_open_error;
    }

    if (fwrite(header, strlen(header), 1, fp) < 1) {
        goto file_error;
    }

    rc = FLB_TRUE;

file_error:
    fclose(fp);
file_open_error:
    flb_sds_destroy(header);
header_error:
    flb_sds_destroy(hdrname);
hdrname_error:
    return rc;
}

int get_calyptia_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t cfgname;
    flb_sds_t cfgnewname;
    flb_sds_t header;
    flb_sds_t hdrname;
    time_t time_last_modified;
    int ret = -1;

    if (ctx->fleet_url == NULL) {
        ctx->fleet_url = flb_sds_create_size(CALYPTIA_MAX_DIR_SIZE);

        if (ctx->fleet_url == NULL) {
            return -1;
        }

        if (ctx->fleet_config_legacy_format) {
            flb_sds_printf(&ctx->fleet_url, CALYPTIA_ENDPOINT_FLEET_CONFIG_INI, ctx->fleet_id);
        }
        else {
            flb_sds_printf(&ctx->fleet_url, CALYPTIA_ENDPOINT_FLEET_CONFIG_YAML, ctx->fleet_id);
        }
    }

    if (ctx->fleet_files_url == NULL) {
        ctx->fleet_files_url = flb_sds_create_size(CALYPTIA_MAX_DIR_SIZE);

        if (ctx->fleet_files_url == NULL) {
            return -1;
        }

        flb_sds_printf(&ctx->fleet_files_url, CALYPTIA_ENDPOINT_FLEET_FILES, ctx->fleet_id);
    }

    create_fleet_header(ctx);

    hdrname = fleet_config_filename(ctx, "header");
    header = flb_sds_create_size(CALYPTIA_MAX_DIR_SIZE);
    if (ctx->fleet_config_legacy_format) {
        flb_sds_printf(&header, "@include %s\n\n", hdrname);
    }
    else {
        flb_sds_printf(&header, "includes: \n    - %s\n", hdrname);
    }
    flb_sds_destroy(hdrname);

    /* create the base file. */
    ret = get_calyptia_file(ctx, ctx->fleet_url, header, NULL, &time_last_modified);
    flb_sds_destroy(header);

    /* new file created! */
    if (ret == 1) {
        if (ctx->config_timestamp > 0) {
            if (ctx->config_timestamp < time_last_modified) {
                flb_plg_info(ctx->ins, "fleet API returned config with newer timestamp than current config (%ld -> %ld)", ctx->config_timestamp, time_last_modified);
            }
            else if (ctx->config_timestamp == time_last_modified) {
                flb_plg_debug(ctx->ins, "fleet API returned config with same timestamp as current config (%ld)", time_last_modified);
            }
            else {
                flb_plg_warn(ctx->ins, "fleet API returned config with earlier timestamp than current config (%ld -> %ld)", ctx->config_timestamp, time_last_modified);
            }
        } else {
            flb_plg_info(ctx->ins, "fleet API returned new config (none -> %ld)", time_last_modified);
        }
        get_calyptia_files(ctx, time_last_modified);

        cfgname = time_fleet_config_filename(ctx, time_last_modified);

        if (calyptia_config_add(ctx, cfgname) == FLB_FALSE) {
            flb_plg_error(ctx->ins, "unable to add config: %s", cfgname);
            flb_sds_destroy(cfgname);
            return -1;
        }

#ifndef FLB_SYSTEM_WINDOWS
        cfgnewname = new_fleet_config_filename(ctx);
        if (execute_reload(ctx, cfgnewname) == FLB_FALSE) {
            calyptia_config_rollback(ctx, cfgname);
            flb_sds_destroy(cfgname);
            return -1;
        }
#else
        if (execute_reload(ctx, cfgname) == FLB_FALSE) {
            calyptia_config_rollback(ctx, cfgname);
            flb_sds_destroy(cfgname);
            return -1;
        }
#endif

        flb_sds_destroy(cfgname);
    }

    return 0;
}

/* cb_collect callback */
static int in_calyptia_fleet_collect(struct flb_input_instance *ins,
                                     struct flb_config *config,
                                     void *in_context)
{
    int ret = -1;
    struct flb_in_calyptia_fleet_config *ctx = in_context;

    if (ctx->fleet_id == NULL) {
        if (get_calyptia_fleet_id_by_name(ctx, config) == -1) {
            flb_plg_error(ctx->ins, "unable to find fleet: %s", ctx->fleet_name);
            goto fleet_id_error;
         }
    }

    ret = get_calyptia_fleet_config(ctx);

fleet_id_error:
    FLB_INPUT_RETURN(ret);
}

static int create_fleet_directory(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t myfleetdir = NULL;

    if (access(ctx->config_dir, F_OK) != 0) {
        if (flb_utils_mkdir(ctx->config_dir, 0700) != 0) {
            return -1;
        }
    }

    if (generate_base_fleet_directory(ctx, &myfleetdir) == NULL) {
        flb_sds_destroy(myfleetdir);
        return -1;
    }

    if (access(myfleetdir, F_OK) != 0) {
        if (flb_utils_mkdir(myfleetdir, 0700) !=0) {
            return -1;
        }
    }

    flb_sds_destroy(myfleetdir);
    return 0;
}

static flb_sds_t fleet_gendir(struct flb_in_calyptia_fleet_config *ctx, time_t timestamp)
{
    flb_sds_t fleetdir = NULL;
    flb_sds_t fleetcurdir;


    if (generate_base_fleet_directory(ctx, &fleetdir) == NULL) {
        return NULL;
    }

    fleetcurdir = flb_sds_create_size(strlen(fleetdir) + 32);

    if (fleetcurdir == NULL) {
        flb_sds_destroy(fleetdir);
        return NULL;
    }

    if (flb_sds_printf(&fleetcurdir, "%s" PATH_SEPARATOR "%ld", fleetdir, timestamp) == NULL) {
        flb_sds_destroy(fleetdir);
        flb_sds_destroy(fleetcurdir);
        return NULL;
    }

    flb_sds_destroy(fleetdir);

    return fleetcurdir;
}

static int fleet_mkdir(struct flb_in_calyptia_fleet_config *ctx, time_t timestamp)
{
    int ret = -1;
    flb_sds_t fleetcurdir;

    fleetcurdir = fleet_gendir(ctx, timestamp);

    if (fleetcurdir != NULL) {
        if (flb_utils_mkdir(fleetcurdir, 0700) == 0) {
            ret = 0;
        }
        flb_sds_destroy(fleetcurdir);
    }

    return ret;
}

static int fleet_cur_chdir(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t fleetcurdir;
    int ret;

    fleetcurdir = fleet_gendir(ctx, ctx->config_timestamp);
    flb_plg_info(ctx->ins, "changing to config dir: %s", fleetcurdir);

    if (fleetcurdir == NULL) {
        return -1;
    }

    ret = chdir(fleetcurdir);
    flb_sds_destroy(fleetcurdir);

    return ret;
}

static int load_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_ctx_t *flb_ctx = flb_context_get();
    flb_sds_t cfgnewname = NULL;

    /* check if we are already using the fleet configuration file. */
    if (is_fleet_config(ctx, flb_ctx->config) == FLB_FALSE) {
        flb_plg_debug(ctx->ins, "loading configuration file");
        /* check which one and load it */
        if (exists_cur_fleet_config(ctx) == FLB_TRUE) {
            return execute_reload(ctx, cur_fleet_config_filename(ctx));
        }
        else if (exists_new_fleet_config(ctx) == FLB_TRUE) {
            return execute_reload(ctx, new_fleet_config_filename(ctx));
        }
        else {
            cfgnewname = calyptia_config_get_newest(ctx);

            if (cfgnewname != NULL) {
                flb_plg_debug(ctx->ins, "loading newest configuration: %s", cfgnewname);
                return execute_reload(ctx, cfgnewname);
            }
            else {
                flb_plg_warn(ctx->ins, "unable to find latest configuration file");
            }
        }
    }
    else {
        flb_plg_debug(ctx->ins, "we are already using a configuration file: %s",
                     flb_ctx->config->conf_path_file);
        parse_config_timestamp(ctx, &ctx->config_timestamp);
    }

    return FLB_FALSE;
}

static int create_fleet_file(flb_sds_t fleetdir,
                             const char *name,
                             int nlen,
                             const char *b64_content,
                             int blen)
{
    flb_sds_t fname;
    flb_sds_t dst;
    size_t dlen = 2 * blen;
    FILE *fp;
    int ret;

    fname = flb_sds_create_size(strlen(fleetdir) + nlen + 2);
    if (fname == NULL) {
        return -1;
    }

    if (flb_sds_cat_safe(&fname, fleetdir, strlen(fleetdir)) < 0) {
        flb_sds_destroy(fname);
        return -1;
    }

    if (flb_sds_cat_safe(&fname, "/", 1) < 0) {
        flb_sds_destroy(fname);
        return -1;
    }

    if (flb_sds_cat_safe(&fname, name, nlen) < 0) {
        flb_sds_destroy(fname);
        return -1;
    }

    fp = fopen(fname, "w+");
    if (fp == NULL) {
        return -1;
    }

    dst = flb_sds_create_size(dlen);
    ret = flb_base64_decode((unsigned char *)dst, dlen, &dlen,
                            (unsigned char *)b64_content, blen);

    if (ret != 0) {
        fclose(fp);
        flb_sds_destroy(dst);
        flb_sds_destroy(fname);

        return -1;
    }

    fwrite(dst, dlen, 1, fp);

    fclose(fp);
    flb_sds_destroy(dst);
    flb_sds_destroy(fname);

    return 0;
}

static int create_fleet_files(struct flb_in_calyptia_fleet_config *ctx,
                              char *payload, size_t size, time_t timestamp)
{
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;
    size_t off = 0;
    int idx;
    flb_sds_t fleetdir;
    msgpack_unpacked result;
    msgpack_object *map;
    msgpack_object *name;
    msgpack_object *contents;

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART || ret == FLB_ERR_JSON_INVAL || ret == -1) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return -1;
    }

    fleetdir = fleet_gendir(ctx, timestamp);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, out_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }
        for (idx = 0; idx < result.data.via.array.size; idx++) {
            map = msgpack_lookup_array_offset(&result.data, idx);

            if (map == NULL) {
                flb_sds_destroy(fleetdir);
                return -1;
            }

            name = msgpack_lookup_map_key(map, "name");
            if (name == NULL) {
                flb_sds_destroy(fleetdir);
                return -1;
            }
            if (name->type != MSGPACK_OBJECT_STR) {
                flb_sds_destroy(fleetdir);
                return -1;
            }

            contents = msgpack_lookup_map_key(map, "contents");
            if (contents == NULL) {
                flb_sds_destroy(fleetdir);
                return -1;
            }
            if (contents->type != MSGPACK_OBJECT_STR) {
                flb_sds_destroy(fleetdir);
                return -1;
            }

            create_fleet_file(fleetdir,
                              name->via.str.ptr,
                              name->via.str.size,
                              contents->via.str.ptr,
                              contents->via.str.size);
        }
    }

    msgpack_unpacked_destroy(&result);
    flb_sds_destroy(fleetdir);
    flb_free(pack);

    return 0;
}

static int get_calyptia_files(struct flb_in_calyptia_fleet_config *ctx,
                              time_t timestamp)
{
    struct flb_http_client *client;
    int ret = -1;

    if (ctx == NULL || ctx->fleet_files_url == NULL) {
        return -1;
    }

    client = fleet_http_do(ctx, ctx->fleet_files_url);
    if (client == NULL) {
        return -1;
    }

    fleet_mkdir(ctx, timestamp);
    ret = create_fleet_files(ctx, client->resp.payload, client->resp.payload_size, timestamp);
    if (ret != 0) {
        goto file_error;
    }

    ret = 1;

file_error:
    flb_http_client_destroy(client);
    return ret;
}

static int in_calyptia_fleet_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    int upstream_flags;
    struct flb_in_calyptia_fleet_config *ctx;
    (void) data;

#ifdef _WIN32
    char *tmpdir;
#endif

    flb_plg_info(in, "initializing calyptia fleet input.");

    if (in->host.name == NULL) {
        flb_plg_error(in, "no input 'Host' provided");
        return -1;
    }

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_calyptia_fleet_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;
    ctx->collect_fd = -1;
    ctx->fleet_id_found = FLB_FALSE;
    ctx->config_timestamp = -1;

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        flb_plg_error(in, "unable to load configuration");
        return -1;
    }

#ifdef _WIN32
    if (ctx->config_dir == NULL) {
        tmpdir = getenv("TEMP");

        if (tmpdir == NULL) {
            flb_plg_error(in, "unable to find temporary directory (%%TEMP%%).");
            flb_free(ctx);
            return -1;
        }

        ctx->config_dir = flb_sds_create_size(CALYPTIA_MAX_DIR_SIZE);

        if (ctx->config_dir == NULL) {
            flb_plg_error(in, "unable to allocate config-dir.");
            flb_free(ctx);
            return -1;
        }
        flb_sds_printf(&ctx->config_dir, "%s" PATH_SEPARATOR "%s", tmpdir, "calyptia-fleet");
    }
#endif

    upstream_flags = FLB_IO_TCP;

    if (in->use_tls) {
        upstream_flags |= FLB_IO_TLS;
    }

    ctx->u = flb_upstream_create(config, in->host.name, in->host.port,
                                 upstream_flags, in->tls);

    if (!ctx->u) {
        flb_plg_error(ctx->ins, "could not initialize upstream");
        flb_free(ctx);
        return -1;
    }

    /* Log initial interval values */
    flb_plg_debug(ctx->ins, "initial collector interval: sec=%d nsec=%d",
                  ctx->interval_sec, ctx->interval_nsec);

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
        flb_plg_info(ctx->ins, "invalid interval settings, using defaults: sec=%d nsec=%d",
                    ctx->interval_sec, ctx->interval_nsec);
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* create fleet directory before creating the fleet header. */
    if (create_fleet_directory(ctx) != 0) {
        flb_plg_error(ctx->ins, "unable to create fleet directories");
        return -1;
    }

    /* refresh calyptia settings before attempting to load the fleet
     * configuration file.
     */
    if (exists_header_fleet_config(ctx) == FLB_TRUE) {
        create_fleet_header(ctx);
    }

    /* if we load a new configuration then we will be reloaded anyways */
    if (load_fleet_config(ctx) == FLB_TRUE) {
        return 0;
    }

    if (is_fleet_config(ctx, config)) {
        calyptia_config_commit(ctx);
    }

    /* Set our collector based on time */
    ret = flb_input_set_collector_time(in,
                                       in_calyptia_fleet_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not initialize collector for fleet input plugin");
        flb_upstream_destroy(ctx->u);
        flb_free(ctx);
        return -1;
    }

    ctx->collect_fd = ret;
    flb_plg_info(ctx->ins, "fleet collector initialized with interval: %d sec %d nsec",
                 ctx->interval_sec, ctx->interval_nsec);

    return 0;
}

static void cb_in_calyptia_fleet_pause(void *data, struct flb_config *config)
{
    struct flb_in_calyptia_fleet_config *ctx = data;
    flb_input_collector_pause(ctx->collect_fd, ctx->ins);
}

static void cb_in_calyptia_fleet_resume(void *data, struct flb_config *config)
{
    struct flb_in_calyptia_fleet_config *ctx = data;
    flb_input_collector_resume(ctx->collect_fd, ctx->ins);
}

static int in_calyptia_fleet_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_calyptia_fleet_config *ctx = (struct flb_in_calyptia_fleet_config *)data;

    if (ctx->fleet_url) {
        flb_sds_destroy(ctx->fleet_url);
    }

    if (ctx->fleet_files_url) {
        flb_sds_destroy(ctx->fleet_files_url);
    }

    if (ctx->fleet_id && ctx->fleet_id_found) {
        flb_sds_destroy(ctx->fleet_id);
    }

    flb_input_collector_delete(ctx->collect_fd, ctx->ins);
    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "api_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, api_key),
     "Calyptia Cloud API Key."
    },
    {
     FLB_CONFIG_MAP_STR, "config_dir", FLEET_DEFAULT_CONFIG_DIR,
     0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, config_dir),
     "Base path for the configuration directory."
    },
    {
     FLB_CONFIG_MAP_STR, "fleet_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, fleet_id),
     "Calyptia Fleet ID."
    },
    {
     FLB_CONFIG_MAP_STR, "fleet_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, fleet_name),
     "Calyptia Fleet Name (used to lookup the fleet ID via the cloud API)."
    },
    {
     FLB_CONFIG_MAP_STR, "machine_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, machine_id),
     "Agent Machine ID."
    },
    {
      FLB_CONFIG_MAP_INT, "max_http_buffer_size", DEFAULT_MAX_HTTP_BUFFER_SIZE,
      0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, max_http_buffer_size),
      "Set the maximum size for http buffers when communicating with the API"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    {
     FLB_CONFIG_MAP_BOOL, "fleet_config_legacy_format", "true",
     0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, fleet_config_legacy_format),
     "If set, use legacy (TOML) format for configuration files."
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_calyptia_fleet_plugin = {
    .name         = "calyptia_fleet",
    .description  = "Calyptia Fleet Input",
    .cb_init      = in_calyptia_fleet_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_calyptia_fleet_collect,
    .cb_resume    = cb_in_calyptia_fleet_resume,
    .cb_pause     = cb_in_calyptia_fleet_pause,
    .cb_flush_buf = NULL,
    .cb_exit      = in_calyptia_fleet_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET|FLB_INPUT_CORO|FLB_IO_OPT_TLS|FLB_INPUT_PRIVATE
};
