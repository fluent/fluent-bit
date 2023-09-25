/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_strptime.h>
#include <fluent-bit/flb_reload.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/config_format/flb_cf_fluentbit.h>
#include <fluent-bit/flb_base64.h>


#define CALYPTIA_H_PROJECT       "X-Project-Token"
#define CALYPTIA_H_CTYPE         "Content-Type"
#define CALYPTIA_H_CTYPE_JSON    "application/json"

#define DEFAULT_INTERVAL_SEC  "15"
#define DEFAULT_INTERVAL_NSEC "0"

#define CALYPTIA_HOST "cloud-api.calyptia.com"
#define CALYPTIA_PORT "443"

#ifndef _WIN32
#define PATH_SEPARATOR "/"
#define DEFAULT_CONFIG_DIR "/tmp/calyptia-fleet"
#else
#define DEFAULT_CONFIG_DIR NULL
#define PATH_SEPARATOR "\\"
#endif

struct flb_in_calyptia_fleet_config {
    /* Time interval check */
    int interval_sec;
    int interval_nsec;

    /* Grabbed from the cfg_path, used to check if configuration has
     * has been updated.
     */
    long config_timestamp;

    flb_sds_t api_key;
    flb_sds_t fleet_id;
    flb_sds_t fleet_name;
    flb_sds_t machine_id;
    flb_sds_t config_dir;
    flb_sds_t cloud_host;
    flb_sds_t cloud_port;

    flb_sds_t fleet_url;

    struct flb_input_instance *ins;       /* plugin instance */
    struct flb_config *config;            /* Fluent Bit context */

    /* Networking */
    struct flb_upstream *u;

    int event_fd;

    int collect_fd;
};

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

struct reload_ctx {
    flb_ctx_t *flb;
    flb_sds_t cfg_path;
};

static flb_sds_t fleet_config_filename(struct flb_in_calyptia_fleet_config *ctx, char *fname)
{
    flb_sds_t cfgname;

    cfgname = flb_sds_create_size(4096);

    if (ctx->fleet_name != NULL) {
        flb_sds_printf(&cfgname,
                       "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "%s.ini",
                       ctx->config_dir, ctx->machine_id, ctx->fleet_name, fname);
    }
    else {
        flb_sds_printf(&cfgname,
                       "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "%s.ini",
                       ctx->config_dir, ctx->machine_id, ctx->fleet_id, fname);
    }

    return cfgname;
}

static flb_sds_t new_fleet_config_filename(struct flb_in_calyptia_fleet_config *ctx)
{
    return fleet_config_filename(ctx, "new");
}

static flb_sds_t cur_fleet_config_filename(struct flb_in_calyptia_fleet_config *ctx)
{
    return fleet_config_filename(ctx, "cur");
}

static flb_sds_t old_fleet_config_filename(struct flb_in_calyptia_fleet_config *ctx)
{
    return fleet_config_filename(ctx, "old");
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


    if (cfg->conf_path_file == NULL) {
        return FLB_FALSE;
    }

    cfgnewname = new_fleet_config_filename(ctx);

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


    if (cfg->conf_path_file == NULL) {
        return FLB_FALSE;
    }

    cfgcurname = cur_fleet_config_filename(ctx);

    if (strcmp(cfgcurname, cfg->conf_path_file) == 0) {
        ret = FLB_TRUE;
    }

    flb_sds_destroy(cfgcurname);

    return ret;
}

static int is_timestamped_fleet_config(struct flb_in_calyptia_fleet_config *ctx, struct flb_config *cfg)
{
    char *fname;
    char *end;
    long val;

    if (cfg->conf_path_file == NULL) {
        return FLB_FALSE;
    }

    fname = strrchr(cfg->conf_path_file, PATH_SEPARATOR[0]);

    if (fname == NULL) {
        return FLB_FALSE;
    }

    fname++;

    errno = 0;
    val = strtol(fname, &end, 10);

    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
         (errno != 0 && val == 0)) {
        flb_errno();
        return FLB_FALSE;
    }

    if (strcmp(end, ".ini") == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int is_fleet_config(struct flb_in_calyptia_fleet_config *ctx, struct flb_config *cfg)
{
    if (cfg->conf_path_file == NULL) {
        return FLB_FALSE;
    }

    return is_new_fleet_config(ctx, cfg) ||
           is_cur_fleet_config(ctx, cfg) ||
           is_timestamped_fleet_config(ctx, cfg);
}

static int exists_new_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t cfgnewname;
    int ret = FLB_FALSE;


    cfgnewname = new_fleet_config_filename(ctx);
    ret = access(cfgnewname, F_OK) == 0 ? FLB_TRUE : FLB_FALSE;

    flb_sds_destroy(cfgnewname);
    return ret;
}

static int exists_cur_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t cfgcurname;
    int ret = FLB_FALSE;


    cfgcurname = cur_fleet_config_filename(ctx);
    ret = access(cfgcurname, F_OK) == 0 ? FLB_TRUE : FLB_FALSE;

    flb_sds_destroy(cfgcurname);
    return ret;
}

static void *do_reload(void *data)
{
    struct reload_ctx *reload = (struct reload_ctx *)data;

    /* avoid reloading the current configuration... just use our new one! */
    flb_context_set(reload->flb);
    reload->flb->config->enable_hot_reload = FLB_TRUE;
    reload->flb->config->conf_path_file = reload->cfg_path;

    sleep(5);
#ifndef FLB_SYSTEM_WINDOWS
    kill(getpid(), SIGHUP);
#else
	GenerateConsoleCtrlEvent(1 /* CTRL_BREAK_EVENT_1 */, 0);
#endif
    return NULL;
}

static int test_config_is_valid(flb_sds_t cfgpath)
{
    struct flb_config *config;
    struct flb_cf *conf;
    int ret = FLB_FALSE;


    config = flb_config_init();

    if (config == NULL) {
        goto config_init_error;
    }

    conf = flb_cf_create();

    if (conf == NULL) {
        goto cf_create_error;
    } 

    conf = flb_cf_create_from_file(conf, cfgpath);

    if (conf == NULL) {
        goto cf_create_from_file_error;
    } 

    if (flb_config_load_config_format(config, conf)) {
        goto cf_load_config_format_error;
    }

    if (flb_reload_property_check_all(config)) {
       goto cf_property_check_error;
    }

    ret = FLB_TRUE;

cf_property_check_error:
cf_load_config_format_error:
cf_create_from_file_error:
    flb_cf_destroy(conf);
cf_create_error:
    flb_config_exit(config);
config_init_error:
    return ret;
}

static int execute_reload(struct flb_in_calyptia_fleet_config *ctx, flb_sds_t cfgpath)
{
    struct reload_ctx *reload;
    pthread_t pth;
    pthread_attr_t ptha;
    flb_ctx_t *flb = flb_context_get();

    if (ctx->collect_fd > 0) {
        flb_input_collector_pause(ctx->collect_fd, ctx->ins);
    }

    if (flb == NULL) {
        flb_plg_error(ctx->ins, "unable to get fluent-bit context.");

        if (ctx->collect_fd > 0) {
            flb_input_collector_resume(ctx->collect_fd, ctx->ins);
        }

        return FLB_FALSE;
    }

    /* fix execution in valgrind...
     * otherwise flb_reload errors out with:
     *    [error] [reload] given flb context is NULL
     */
    flb_plg_info(ctx->ins, "loading configuration from %s.", cfgpath);

    if (test_config_is_valid(cfgpath) == FLB_FALSE) {
        flb_plg_error(ctx->ins, "unable to load configuration.");

        if (ctx->collect_fd > 0) {
            flb_input_collector_resume(ctx->collect_fd, ctx->ins);
        }

        return FLB_FALSE;
    }

    reload = flb_calloc(1, sizeof(struct reload_ctx));
    reload->flb = flb;
    reload->cfg_path = cfgpath;

    pthread_attr_init(&ptha);
    pthread_attr_setdetachstate(&ptha, PTHREAD_CREATE_DETACHED);
    pthread_create(&pth, &ptha, do_reload, reload);

    return FLB_TRUE;
}

static char *tls_setting_string(int use_tls)
{
    if (use_tls) {
        return "On";
    }

    return "Off";
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
    msgpack_object_kv *cur;
    msgpack_object_str *key;
    flb_sds_t project_id;
    int idx = 0;

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_warn(ctx->ins, "JSON data is incomplete, skipping");
        return NULL;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return NULL;
    }
    else if (ret == -1) {
        return NULL;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, out_size, &off) == MSGPACK_UNPACK_SUCCESS) {

        if (result.data.type == MSGPACK_OBJECT_MAP) {
            for (idx = 0; idx < result.data.via.map.size; idx++) {
                cur = &result.data.via.map.ptr[idx];
                key = &cur->key.via.str;

                if (strncmp(key->ptr, "ProjectID", key->size) == 0) {

                    if (cur->val.type != MSGPACK_OBJECT_STR) {
                        flb_plg_error(ctx->ins, "unable to find fleet by name");
                        msgpack_unpacked_destroy(&result);
                        return NULL;
                    }

                    project_id = flb_sds_create_len(cur->val.via.str.ptr, 
                                                    cur->val.via.str.size);
                    msgpack_unpacked_destroy(&result);
                    flb_free(pack);

                    return project_id;
                }
            }
        }
    }

    msgpack_unpacked_destroy(&result);
    flb_free(pack);

    return NULL;
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
    msgpack_object_array *results;
    msgpack_object_kv *cur;
    msgpack_object_str *key;
    int idx = 0;

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_warn(ctx->ins, "JSON data is incomplete, skipping");
        return -1;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return -1;
    }
    else if (ret == -1) {
        return -1;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, out_size, &off) == MSGPACK_UNPACK_SUCCESS) {

        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            results = &result.data.via.array;

            if (results->ptr[0].type == MSGPACK_OBJECT_MAP) {

                for (idx = 0; idx < results->ptr[0].via.map.size; idx++) {
                    cur = &results->ptr[0].via.map.ptr[idx];
                    key = &cur->key.via.str;

                    if (strncasecmp(key->ptr, "id", key->size) == 0) {

                        if (cur->val.type != MSGPACK_OBJECT_STR) {
                            flb_plg_error(ctx->ins, "unable to find fleet by name");
                            msgpack_unpacked_destroy(&result);
                            return -1;
                        }

                        ctx->fleet_id = flb_sds_create_len(cur->val.via.str.ptr,
                                                           cur->val.via.str.size);
                        break;
                    }
                    break;
                }
                break;
            }
        }
    }

    msgpack_unpacked_destroy(&result);
    flb_free(pack);

    if (ctx->fleet_id == NULL) {
        return -1;
    }

    return 0;
}

static int get_calyptia_fleet_id_by_name(struct flb_in_calyptia_fleet_config *ctx,
                                         struct flb_connection *u_conn,
                                         struct flb_config *config)
{
    struct flb_http_client *client;
    flb_sds_t url;
    flb_sds_t project_id;
    unsigned char token[512] = {0};
    unsigned char encoded[256];
    size_t elen;
    size_t tlen;
    char *api_token_sep;
    size_t b_sent;
    int ret;

    api_token_sep = strchr(ctx->api_key, '.');

    if (api_token_sep == NULL) {
        return -1;
    }

    elen = api_token_sep-ctx->api_key;
    elen = elen + (4 - (elen % 4));

    if (elen > sizeof(encoded)) {
        flb_plg_error(ctx->ins, "API Token is too large");
        return -1;
    }

    memset(encoded, '=', sizeof(encoded));
    memcpy(encoded, ctx->api_key, api_token_sep-ctx->api_key);

    ret = flb_base64_decode(token, sizeof(token)-1, &tlen,
                            encoded, elen); 

    if (ret != 0) {
        return ret;
    }

    project_id = parse_api_key_json(ctx, (char *)token, tlen);

    if (project_id == NULL) {
        return -1;
    }

    url = flb_sds_create_size(4096);
    flb_sds_printf(&url, "/v1/search?project_id=%s&resource=fleet&term=%s", 
                   project_id, ctx->fleet_name);

    client = flb_http_client(u_conn, FLB_HTTP_GET, url, NULL, 0,
                             ctx->ins->host.name, ctx->ins->host.port, NULL, 0);

    if (!client) {
        flb_plg_error(ctx->ins, "unable to create http client");
        return -1;
    }

    flb_http_buffer_size(client, 8192);

    flb_http_add_header(client,
                        CALYPTIA_H_PROJECT, sizeof(CALYPTIA_H_PROJECT) - 1,
                        ctx->api_key, flb_sds_len(ctx->api_key));

    ret = flb_http_do(client, &b_sent);

    if (ret != 0) {
        flb_plg_error(ctx->ins, "http do error");
        return -1;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ctx->ins, "search http status code error: %d", client->resp.status);
        return -1;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ctx->ins, "empty response");
        return -1;
    }

    if (parse_fleet_search_json(ctx, client->resp.payload, client->resp.payload_size) == -1) {
        flb_plg_error(ctx->ins, "unable to find fleet: %s", ctx->fleet_name);
        return -1;
    }

    if (ctx->fleet_id == NULL) {
        return -1;
    }
    return 0;
}

#ifdef FLB_SYSTEM_WINDOWS
#define link(a, b) CreateHardLinkA(b, a, 0)

ssize_t readlink(const char *path, char *realpath, size_t srealpath) {
    HANDLE hFile;
    DWORD ret;

    hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                       FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }

    ret = GetFinalPathNameByHandleA(hFile, realpath, srealpath, VOLUME_NAME_NT);

    if (ret < srealpath) {
        CloseHandle(hFile);
        return -1;
    }

    CloseHandle(hFile);
    return ret;
}

#endif

#ifdef FLB_SYSTEM_WINDOWS
#define _mkdir(a, b) mkdir(a)
#else
#define _mkdir(a, b) mkdir(a, b)
#endif

/* recursively create directories, based on:
 *   https://stackoverflow.com/a/2336245
 * who found it at:
 *   http://nion.modprobe.de/blog/archives/357-Recursive-directory-creation.html
 */
static int __mkdir(const char *dir, int perms) {
    char tmp[255];
    char *ptr = NULL;
    size_t len;
    int ret;

    ret = snprintf(tmp, sizeof(tmp),"%s",dir);
    if (ret > sizeof(tmp)) {
        flb_error("directory too long for __mkdir: %s", dir);
        return -1;
    }

    len = strlen(tmp);

    if (tmp[len - 1] == PATH_SEPARATOR[0]) {
        tmp[len - 1] = 0;
    }

#ifndef FLB_SYSTEM_WINDOWS
    for (ptr = tmp + 1; *ptr; ptr++) {
#else
    for (ptr = tmp + 3; *ptr; ptr++) {
#endif

        if (*ptr == PATH_SEPARATOR[0]) {
            *ptr = 0;
            if (access(tmp, F_OK) != 0) {
                ret = _mkdir(tmp, perms);
                if (ret != 0) {
                    return ret;
                }
            }
            *ptr = PATH_SEPARATOR[0];
        }
    }

    return _mkdir(tmp, perms);
}

static int create_fleet_directory(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t myfleetdir;

    flb_plg_debug(ctx->ins, "checking for configuration directory=%s", ctx->config_dir);
    if (access(ctx->config_dir, F_OK) != 0) {
        if (__mkdir(ctx->config_dir, 0700) != 0) {
            flb_plg_error(ctx->ins, "unable to create fleet config directory");
            return -1;
        }
    }

    myfleetdir = flb_sds_create_size(256);

    if (ctx->fleet_name != NULL) {
        flb_sds_printf(&myfleetdir, "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "%s",
                       ctx->config_dir, ctx->machine_id, ctx->fleet_name);
    }
    else {
        flb_sds_printf(&myfleetdir, "%s" PATH_SEPARATOR "%s" PATH_SEPARATOR "%s",
                       ctx->config_dir, ctx->machine_id, ctx->fleet_id);
    }

    flb_plg_debug(ctx->ins, "checking for fleet directory=%s", myfleetdir);
    if (access(myfleetdir, F_OK) != 0) {
        if (__mkdir(myfleetdir, 0700) !=0) {
            flb_plg_error(ctx->ins, "unable to create fleet specific directory");
            return -1;
        }
    }

    flb_sds_destroy(myfleetdir);
    return 0;
}

/* cb_collect callback */
static int in_calyptia_fleet_collect(struct flb_input_instance *ins,
                                     struct flb_config *config, 
                                     void *in_context)
{
    struct flb_in_calyptia_fleet_config *ctx = in_context;
    struct flb_connection *u_conn;
    struct flb_http_client *client;
    flb_sds_t cfgname;
    flb_sds_t cfgnewname;
    flb_sds_t cfgoldname;
    flb_sds_t cfgcurname;
    flb_sds_t header;
    flb_sds_t hdr;
    FILE *cfgfp;
    const char *fbit_last_modified;
    int fbit_last_modified_len;
    struct flb_tm tm_last_modified = { 0 };
    time_t time_last_modified;
    char *data;
    size_t b_sent;
    int ret = -1;
#ifdef FLB_SYSTEM_WINDOWS
    DWORD err;
    LPSTR lpMsg;
#endif

    u_conn = flb_upstream_conn_get(ctx->u);

    if (!u_conn) {
        flb_plg_error(ctx->ins, "could not get an upstream connection to %s:%u",
                      ctx->ins->host.name, ctx->ins->host.port);
        goto conn_error;
    }

    if (ctx->fleet_id == NULL) {

        if (get_calyptia_fleet_id_by_name(ctx, u_conn, config) == -1) {
            flb_plg_error(ctx->ins, "unable to find fleet: %s", ctx->fleet_name);
            goto conn_error;
        }
    }

    if (ctx->fleet_url == NULL) {
        ctx->fleet_url = flb_sds_create_size(4096);
        flb_sds_printf(&ctx->fleet_url, "/v1/fleets/%s/config?format=ini", ctx->fleet_id);
    }

    client = flb_http_client(u_conn, FLB_HTTP_GET, ctx->fleet_url,
                             NULL, 0, 
                             ctx->ins->host.name, ctx->ins->host.port, NULL, 0);

    if (!client) {
        flb_plg_error(ins, "unable to create http client");
        goto client_error;
    }

    flb_http_buffer_size(client, 8192);

    flb_http_add_header(client,
                        CALYPTIA_H_PROJECT, sizeof(CALYPTIA_H_PROJECT) - 1,
                        ctx->api_key, flb_sds_len(ctx->api_key));

    ret = flb_http_do(client, &b_sent);

    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ins, "http status code error: %d", client->resp.status);
        goto http_error;
    }

    if (client->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto http_error;
    }

    /* copy and NULL terminate the payload */
    data = flb_sds_create_size(client->resp.payload_size + 1);

    if (!data) {
        goto http_error;
    }
    memcpy(data, client->resp.payload, client->resp.payload_size);
    data[client->resp.payload_size] = '\0';

    ret = case_header_lookup(client, "Last-modified", strlen("Last-modified"),
                        &fbit_last_modified, &fbit_last_modified_len);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "unable to get last-modified header");
        goto http_error;
    }

    flb_strptime(fbit_last_modified, "%a, %d %B %Y %H:%M:%S GMT", &tm_last_modified);
    time_last_modified = mktime(&tm_last_modified.tm);

    cfgname = time_fleet_config_filename(ctx, time_last_modified);

    if (access(cfgname, F_OK) == -1 && errno == ENOENT) {
        if (create_fleet_directory(ctx) != 0) {
            flb_plg_error(ctx->ins, "unable to create fleet directories");
            goto http_error;
        }
        cfgfp = fopen(cfgname, "w+");

        if (cfgfp == NULL) {
            flb_plg_error(ctx->ins, "unable to open configuration file: %s", cfgname);
            goto http_error;
        }

        header = flb_sds_create_size(4096);

        if (ctx->fleet_name == NULL) {
            hdr = flb_sds_printf(&header,
                        "[CUSTOM]\n"
                        "    Name             calyptia\n"
                        "    api_key          %s\n"
                        "    fleet_id         %s\n"
                        "    add_label        fleet_id %s\n"
                        "    fleet.config_dir %s\n"
                        "    calyptia_host    %s\n"
                        "    calyptia_port    %d\n"
                        "    calyptia_tls     %s\n",
                        ctx->api_key,
                        ctx->fleet_id,
                        ctx->fleet_id,
                        ctx->config_dir,
                        ctx->ins->host.name,
                        ctx->ins->host.port,
                        tls_setting_string(ctx->ins->use_tls)
            );
        }
        else {
            hdr = flb_sds_printf(&header,
                        "[CUSTOM]\n"
                        "    Name          calyptia\n"
                        "    api_key       %s\n"
                        "    fleet_name    %s\n"
                        "    fleet_id      %s\n"
                        "    add_label     fleet_id %s\n"
                        "    fleet.config_dir    %s\n"
                        "    calyptia_host %s\n"
                        "    calyptia_port %d\n"
                        "    calyptia_tls  %s\n",
                        ctx->api_key,
                        ctx->fleet_name,
                        ctx->fleet_id,
                        ctx->fleet_id,
                        ctx->config_dir,
                        ctx->ins->host.name,
                        ctx->ins->host.port,
                        tls_setting_string(ctx->ins->use_tls)
            );
        }
        if (hdr == NULL) {
            fclose(cfgfp);
            goto http_error;
        }
        if (ctx->machine_id) {
            hdr = flb_sds_printf(&header, "    machine_id %s\n", ctx->machine_id);
            if (hdr == NULL) {
                fclose(cfgfp);
                goto http_error;
            }
        }
        fwrite(header, strlen(header), 1, cfgfp);
        flb_sds_destroy(header);
        fwrite(data, client->resp.payload_size, 1, cfgfp);
        fclose(cfgfp);

        cfgnewname = new_fleet_config_filename(ctx);

        if (exists_new_fleet_config(ctx) == FLB_TRUE) {
            cfgoldname = old_fleet_config_filename(ctx);
            rename(cfgnewname, cfgoldname);
            unlink(cfgnewname);
            flb_sds_destroy(cfgoldname);
        }

        if (!link(cfgname, cfgnewname)) {
#ifdef FLB_SYSTEM_WINDOWS
            err = GetLastError();
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                          NULL, err, 0, &lpMsg, 0, NULL);
            flb_plg_error(ctx->ins, "unable to create hard link: %s", lpMsg);
#else
            flb_errno();
#endif
        }
    }

    if (ctx->config_timestamp < time_last_modified) {
        flb_plg_debug(ctx->ins, "new configuration is newer than current: %ld < %ld",
                      ctx->config_timestamp, time_last_modified);
        flb_plg_info(ctx->ins, "force the reloading of the configuration file=%d.", ctx->event_fd);
        flb_sds_destroy(data);

        if (execute_reload(ctx, cfgname) == FLB_FALSE) {
            cfgoldname = old_fleet_config_filename(ctx);
            cfgcurname = cur_fleet_config_filename(ctx);
            rename(cfgoldname, cfgcurname);
            flb_sds_destroy(cfgcurname);
            flb_sds_destroy(cfgoldname);
            goto reload_error;
        }
        else {
            FLB_INPUT_RETURN(0);
        }
    }

    ret = 0;

reload_error:
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    FLB_INPUT_RETURN(ret);
}

static int load_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_ctx_t *flb_ctx = flb_context_get();
    char *fname;
    char *ext;
    long timestamp;
    char realname[4096];
    ssize_t len;

    if (create_fleet_directory(ctx) != 0) {
        flb_plg_error(ctx->ins, "unable to create fleet directories");
        return -1;
    }

    /* check if we are already using the fleet configuration file. */
    if (is_fleet_config(ctx, flb_ctx->config) == FLB_FALSE) {
        /* check which one and load it */
        if (exists_cur_fleet_config(ctx) == FLB_TRUE) {
            return execute_reload(ctx, cur_fleet_config_filename(ctx));
        }
        else if (exists_new_fleet_config(ctx) == FLB_TRUE) {
            return execute_reload(ctx, new_fleet_config_filename(ctx));
        }
    }
    else {
        if (is_new_fleet_config(ctx, flb_ctx->config) || is_cur_fleet_config(ctx, flb_ctx->config)) {
            len = readlink(flb_ctx->config->conf_path_file, realname, sizeof(realname));

            if (len > sizeof(realname)) {
                return FLB_FALSE;
            }

            fname = basename(realname);
        }
        else {
            fname = basename(flb_ctx->config->conf_path_file);
        }

        if (fname == NULL) {
            return FLB_FALSE;
        }

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

        ctx->config_timestamp = timestamp;
    }

    return FLB_FALSE;
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


    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);

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
            return -1;
        }

        ctx->config_dir = flb_sds_create_size(4096);

        if (ctx->config_dir == NULL) {
            flb_plg_error(in, "unable to allocate config-dir.");
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

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }

    if (ctx->interval_sec < atoi(DEFAULT_INTERVAL_SEC)) {
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* if we load a new configuration then we will be reloaded anyways */
    if (load_fleet_config(ctx) == FLB_TRUE) {
        return 0;
    }

    /* Set our collector based on time */
    ret = flb_input_set_collector_time(in,
                                       in_calyptia_fleet_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not initialize collector for fleet input plugin");
        flb_free(ctx);
        return -1;
    }

    ctx->collect_fd = ret;

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
     FLB_CONFIG_MAP_STR, "config_dir", DEFAULT_CONFIG_DIR,
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
      FLB_CONFIG_MAP_INT, "event_fd", "-1",
      0, FLB_TRUE, offsetof(struct flb_in_calyptia_fleet_config, event_fd),
      "Used internally to set the event fd."
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
