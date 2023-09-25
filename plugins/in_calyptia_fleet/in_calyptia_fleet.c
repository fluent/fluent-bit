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
    /* flag used to mark fleet_id for release when found automatically. */
    int fleet_id_found;

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
           is_old_fleet_config(ctx, cfg) ||
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

static int exists_old_fleet_config(struct flb_in_calyptia_fleet_config *ctx)
{
    flb_sds_t cfgoldname;
    int ret = FLB_FALSE;


    cfgoldname = old_fleet_config_filename(ctx);
    ret = access(cfgoldname, F_OK) == 0 ? FLB_TRUE : FLB_FALSE;

    flb_sds_destroy(cfgoldname);
    return ret;
}

static void *do_reload(void *data)
{
    struct reload_ctx *reload = (struct reload_ctx *)data;

    /* avoid reloading the current configuration... just use our new one! */
    flb_context_set(reload->flb);
    reload->flb->config->enable_hot_reload = FLB_TRUE;
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

static int test_config_is_valid(flb_sds_t cfgpath)
{
    struct flb_cf *conf;
    int ret = FLB_FALSE;


    conf = flb_cf_create();

    if (conf == NULL) {
        goto config_init_error;
    }

    conf = flb_cf_create_from_file(conf, cfgpath);

    if (conf == NULL) {
        goto cf_create_from_file_error;
    } 

    ret = FLB_TRUE;

cf_create_from_file_error:
    flb_cf_destroy(conf);
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

        flb_sds_destroy(cfgpath);
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

        flb_sds_destroy(cfgpath);
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
    msgpack_object *projectID;
    flb_sds_t project_id = NULL;

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
        projectID  = msgpack_lookup_map_key(&result.data, "ProjectID");

        if (projectID == NULL) {
            flb_plg_error(ctx->ins, "unable to find fleet by name");
            msgpack_unpacked_destroy(&result);
            return NULL;
        }

        if (projectID->type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "invalid fleet ID");
            msgpack_unpacked_destroy(&result);
            return NULL;
        }

        project_id = flb_sds_create_len(projectID->via.str.ptr,
                                        projectID->via.str.size);
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

        fleet = msgpack_lookup_map_key(map, "ID");
        if (fleet == NULL) {
            flb_plg_error(ctx->ins, "unable to find fleet by name");
            break;
        }

        if (fleet->type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "unable to find fleet by name");
            break;
        }

        ctx->fleet_id = flb_sds_create_len(fleet->via.str.ptr, fleet->via.str.size);
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
                                             struct flb_connection *u_conn,
                                             flb_sds_t url)
{
    struct flb_http_client *client;
    size_t b_sent;
    int ret = -1;

    client = flb_http_client(u_conn, FLB_HTTP_GET, url, NULL, 0,
                             ctx->ins->host.name, ctx->ins->host.port, NULL, 0);

    if (!client) {
        flb_plg_error(ctx->ins, "unable to create http client");
        goto http_client_error;
    }

    flb_http_buffer_size(client, 8192);

    flb_http_add_header(client,
                        CALYPTIA_H_PROJECT, sizeof(CALYPTIA_H_PROJECT) - 1,
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
        flb_http_client_destroy(client);
        goto http_do_error;
    }

    return client;

http_do_error:
    flb_http_client_destroy(client);
http_client_error:
    return NULL;
}

static int get_calyptia_fleet_id_by_name(struct flb_in_calyptia_fleet_config *ctx,
                                         struct flb_connection *u_conn,
                                         struct flb_config *config)
{
    struct flb_http_client *client;
    flb_sds_t url;
    flb_sds_t project_id;

    project_id = get_project_id_from_api_key(ctx);

    if (project_id == NULL) {
        return -1;
    }

    url = flb_sds_create_size(4096);
    flb_sds_printf(&url, "/v1/search?project_id=%s&resource=fleet&term=%s", 
                   project_id, ctx->fleet_name);

    client = fleet_http_do(ctx, u_conn, url);

    if (!client) {
        return -1;
    }

    if (parse_fleet_search_json(ctx, client->resp.payload, client->resp.payload_size) == -1) {
        flb_plg_error(ctx->ins, "unable to find fleet: %s", ctx->fleet_name);
        flb_http_client_destroy(client);
        return -1;
    }

    flb_http_client_destroy(client);

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
static int get_calyptia_file(struct flb_in_calyptia_fleet_config *ctx,
                             struct flb_connection *u_conn,
                             const char *url,
                             const char *hdr,
                             const char *dst,
                             time_t *time_last_modified)
 {
    struct flb_http_client *client;
    char fname[4096] = { 0 };
    size_t len;
    FILE *fp;
    int ret = -1;
    const char *fbit_last_modified;
    struct flb_tm tm_last_modified = { 0 };
    int fbit_last_modified_len;
    time_t last_modified;

    if (ctx == NULL || u_conn == NULL || url == NULL || dst == NULL) {
        return -1;
    }

    client = fleet_http_do(ctx, u_conn, ctx->fleet_url);

    if (client == NULL) {
        return -1;
    }

    ret = case_header_lookup(client, "Last-modified", strlen("Last-modified"),
                                &fbit_last_modified, &fbit_last_modified_len);

    if (ret < 0) {
        goto client_error;
    }

    flb_strptime(fbit_last_modified, "%a, %d %B %Y %H:%M:%S GMT", &tm_last_modified);
    last_modified = mktime(&tm_last_modified.tm);

    /* skip the second PATH_SEPARATOR to allow creating files in the base 
     * fleet_config directory. */
    snprintf(fname, sizeof(fname)-1, "%s/%d%s", ctx->config_dir, (int)last_modified, dst);

    errno = 0;
    if (access(fname, F_OK) != -1 || errno == ENOENT) {
        ret = 0;
        goto client_error;
    }

    fp = fopen(fname, "w+");

    if (fp == NULL) {
        goto client_error;
    }

    if (hdr != NULL) {
        len = fwrite(hdr, strlen(hdr), 1, fp);
        if (len < strlen(hdr)) {
            flb_plg_error(ctx->ins, "truncated write: %s", dst);
            goto file_error;
        }
    }

    len = fwrite(client->resp.payload, client->resp.payload_size, 1, fp);
    if (len < client->resp.payload_size) {
        flb_plg_error(ctx->ins, "truncated write: %s", dst);
        goto file_error;
    }

    if (time_last_modified) {
        *time_last_modified = last_modified;
    }

    ret = 1;

file_error:
    fclose(fp);
client_error:
    flb_http_client_destroy(client);
    return ret;
}

static int calyptia_config_add(struct flb_in_calyptia_fleet_config *ctx,
                               const char *cfgname)
{
    flb_sds_t cfgnewname;
    flb_sds_t cfgoldname;

    cfgnewname = new_fleet_config_filename(ctx);

    if (exists_new_fleet_config(ctx) == FLB_TRUE) {
        cfgoldname = old_fleet_config_filename(ctx);
        rename(cfgnewname, cfgoldname);
        unlink(cfgnewname);
        flb_sds_destroy(cfgoldname);
    }

    link(cfgname, cfgnewname);
    flb_sds_destroy(cfgnewname);

    return 0;
}

static int calyptia_config_commit(struct flb_in_calyptia_fleet_config *ctx,
                                  const char *cfgname)
{
    flb_sds_t cfgnewname;
    flb_sds_t cfgcurname;
    flb_sds_t cfgoldname;

    cfgnewname = new_fleet_config_filename(ctx);
    cfgcurname = cur_fleet_config_filename(ctx);
    cfgoldname = old_fleet_config_filename(ctx);

    if (exists_new_fleet_config(ctx) == FLB_TRUE) {
        unlink(cfgnewname);
    }

    if (exists_old_fleet_config(ctx) == FLB_TRUE) {
        unlink(cfgoldname);
    }

    if (exists_cur_fleet_config(ctx) == FLB_TRUE) {
        unlink(cfgcurname);
    }

    link(cfgname, cfgcurname);

    flb_sds_destroy(cfgnewname);
    flb_sds_destroy(cfgcurname);
    flb_sds_destroy(cfgoldname);

    return 0;
}

static int calyptia_config_rollback(struct flb_in_calyptia_fleet_config *ctx,
                                    const char *cfgname)
{
    flb_sds_t cfgnewname;
    flb_sds_t cfgcurname;
    flb_sds_t cfgoldname;

    cfgnewname = new_fleet_config_filename(ctx);
    cfgcurname = cur_fleet_config_filename(ctx);
    cfgoldname = old_fleet_config_filename(ctx);

    if (exists_new_fleet_config(ctx) == FLB_TRUE) {
        unlink(cfgnewname);
    }

    if (exists_old_fleet_config(ctx) == FLB_TRUE) {
        rename(cfgoldname, cfgcurname);
    }

    flb_sds_destroy(cfgnewname);
    flb_sds_destroy(cfgcurname);
    flb_sds_destroy(cfgoldname);

    return 0;
}

static int get_calyptia_fleet_config(struct flb_in_calyptia_fleet_config *ctx,
                                     struct flb_connection *u_conn)
{
    flb_sds_t cfgname;
    flb_sds_t cfgnewname;
    flb_sds_t header;
    time_t time_last_modified;
    int ret = -1;

    if (ctx->fleet_url == NULL) {
        ctx->fleet_url = flb_sds_create_size(4096);
        flb_sds_printf(&ctx->fleet_url, "/v1/fleets/%s/config?format=ini", ctx->fleet_id);
    }

    header = flb_sds_create_size(4096);

    if (ctx->fleet_name == NULL) {
        flb_sds_printf(&header,
                    "[CUSTOM]\n"
                    "    Name          calyptia\n"
                    "    api_key       %s\n"
                    "    fleet_id      %s\n"
                    "    add_label     fleet_id %s\n"
                    "    fleet.config_dir    %s\n"
                    "    calyptia_host %s\n"
                    "    calyptia_port %d\n"
                    "    calyptia_tls  %s\n",
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
        flb_sds_printf(&header,
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

    /* create the base file. */
    ret = get_calyptia_file(ctx, u_conn, ctx->fleet_url, header, 
                            ".ini", &time_last_modified);

    /* new file created! */
    if (ret == 1) {
        cfgname = time_fleet_config_filename(ctx, time_last_modified);
        calyptia_config_add(ctx, cfgname);
        flb_sds_destroy(cfgname);

        cfgnewname = new_fleet_config_filename(ctx);
        if (execute_reload(ctx, cfgnewname) == FLB_FALSE) {
            calyptia_config_rollback(ctx, cfgname);
            flb_sds_destroy(cfgnewname);
            return -1;
        } else {
            calyptia_config_commit(ctx, cfgname);
            flb_sds_destroy(cfgnewname);
        }
    }

    return 0;
}

/* cb_collect callback */
static int in_calyptia_fleet_collect(struct flb_input_instance *ins,
                                     struct flb_config *config, 
                                     void *in_context)
{
    struct flb_in_calyptia_fleet_config *ctx = in_context;
    struct flb_connection *u_conn;
    int ret = -1;

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

    ret = get_calyptia_fleet_config(ctx, u_conn);

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
            flb_free(ctx);
            return -1;
        }

        ctx->config_dir = flb_sds_create_size(4096);

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
        flb_upstream_destroy(ctx->u);
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

    if (ctx->fleet_url) {
        flb_sds_destroy(ctx->fleet_url);
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
