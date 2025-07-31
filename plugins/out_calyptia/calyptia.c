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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_fstore.h>

#include "calyptia.h"

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_encode_influx.h>

flb_sds_t custom_calyptia_pipeline_config_get(struct flb_config *ctx);
static void calyptia_ctx_destroy(struct flb_calyptia *ctx);

static int get_io_flags(struct flb_output_instance *ins)
{
    int flags = 0;

    if (ins->use_tls) {
        flags = FLB_IO_TLS;
    }
    else {
        flags = FLB_IO_TCP;
    }

    return flags;
}

static int config_add_labels(struct flb_output_instance *ins,
                             struct flb_calyptia *ctx)
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
                          "e.g: 'add_label version 1.8.x'");
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

static void append_labels(struct flb_calyptia *ctx, struct cmt *cmt)
{
    struct flb_kv *kv;
    struct mk_list *head;

    mk_list_foreach(head, &ctx->kv_labels) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        cmt_label_add(cmt, kv->key, kv->val);
    }
}

static void pack_str(msgpack_packer *mp_pck, char *str)
{
    int len;

    len = strlen(str);
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, str, len);
}

static void pack_env(struct flb_env *env, char *prefix,  char *key,
                     struct flb_mp_map_header *h,
                     msgpack_packer *mp_pck)
{
    int len = 0;
    char *val;

    /* prefix set in the key, if set, adjust the key name */
    if (prefix) {
        len = strlen(prefix);
    }

    val = (char *) flb_env_get(env, key);
    if (val) {
        flb_mp_map_header_append(h);
        pack_str(mp_pck, key + len);
        pack_str(mp_pck, val);
    }
}

static void pack_env_metadata(struct flb_env *env,
                              struct flb_mp_map_header *mh, msgpack_packer *mp_pck)
{
    char *tmp;
    struct flb_mp_map_header h;
    struct flb_mp_map_header meta;

    /* Metadata */
    flb_mp_map_header_append(mh);
    pack_str(mp_pck, "metadata");

    flb_mp_map_header_init(&meta, mp_pck);

    /* Kubernetes */
    tmp = (char *) flb_env_get(env, "k8s");
    if (tmp && strcasecmp(tmp, "enabled") == 0) {
        flb_mp_map_header_append(&meta);
        pack_str(mp_pck, "k8s");

        /* adding k8s map */
        flb_mp_map_header_init(&h, mp_pck);

        pack_env(env, "k8s.", "k8s.namespace", &h, mp_pck);
        pack_env(env, "k8s.", "k8s.pod_name", &h, mp_pck);
        pack_env(env, "k8s.", "k8s.node_name", &h, mp_pck);

        flb_mp_map_header_end(&h);
    }

    /* AWS */
    tmp = (char *) flb_env_get(env, "aws");
    if (tmp && strcasecmp(tmp, "enabled") == 0) {
        flb_mp_map_header_append(&meta);
        pack_str(mp_pck, "aws");

        /* adding aws map */
        flb_mp_map_header_init(&h, mp_pck);

        pack_env(env, "aws.", "aws.az", &h, mp_pck);
        pack_env(env, "aws.", "aws.ec2_instance_id", &h, mp_pck);
        pack_env(env, "aws.", "aws.ec2_instance_type", &h, mp_pck);
        pack_env(env, "aws.", "aws.private_ip", &h, mp_pck);
        pack_env(env, "aws.", "aws.vpc_id", &h, mp_pck);
        pack_env(env, "aws.", "aws.ami_id", &h, mp_pck);
        pack_env(env, "aws.", "aws.account_id", &h, mp_pck);
        pack_env(env, "aws.", "aws.hostname", &h, mp_pck);

        flb_mp_map_header_end(&h);
    }
    flb_mp_map_header_end(&meta);
}

static flb_sds_t get_agent_metadata(struct flb_calyptia *ctx)
{
    int len;
    char *host;
    flb_sds_t conf;
    flb_sds_t meta;
    struct flb_mp_map_header mh;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_config *config = ctx->config;

    /* init msgpack */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* pack map */
    flb_mp_map_header_init(&mh, &mp_pck);

    host = (char *) flb_env_get(ctx->env, "HOSTNAME");
    if (!host) {
        host = "unknown";
    }
    len = strlen(host);

    /* name */
    flb_mp_map_header_append(&mh);
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "name", 4);
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, host, len);

    /* type */
    flb_mp_map_header_append(&mh);
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "type", 4);
    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "fluentbit", 9);

    /* rawConfig */
    conf = custom_calyptia_pipeline_config_get(ctx->config);
    if (conf) {
        flb_mp_map_header_append(&mh);
        len = flb_sds_len(conf);
        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "rawConfig", 9);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, conf, len);
    }
    flb_sds_destroy(conf);

    /* version */
    flb_mp_map_header_append(&mh);
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "version", 7);
    len = strlen(FLB_VERSION_STR);
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, FLB_VERSION_STR, len);

    /* edition */
    flb_mp_map_header_append(&mh);
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "edition", 7);
    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "community", 9);

    flb_mp_map_header_append(&mh);
    msgpack_pack_str(&mp_pck, 2);
    msgpack_pack_str_body(&mp_pck, "os", 2);
#ifdef FLB_SYSTEM_WINDOWS
    len = strlen("windows");
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, "windows", len);
#elif FLB_SYSTEM_MACOS
    len = strlen("macos");
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, "macos", len);
#elif __linux__
    len = strlen("linux");
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, "linux", len);
#else
    len = strlen("unknown");
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, "unknown", len);
#endif

    flb_mp_map_header_append(&mh);
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "arch", 4);
#if defined(__arm__) || defined(_M_ARM)
    len = strlen("arm");
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, "arm", len);
#elif defined(__aarch64__)
    len = strlen("arm64");
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, "arm64", len);
#elif defined(__amd64__) || defined(_M_AMD64)
    len = strlen("x86_64");
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, "x86_64", len);
#elif defined(__i686__) || defined(_M_I86)
    len = strlen("x86");
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, "x86", len);
#else
    len = strlen("unknown");
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, "unknown", len);
#endif

    /* machineID */
    flb_mp_map_header_append(&mh);
    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "machineID", 9);
    len = flb_sds_len(ctx->machine_id);
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, ctx->machine_id, len);

    /* fleetID */
    if (ctx->fleet_id) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "fleetID", 7);
        len = flb_sds_len(ctx->fleet_id);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, ctx->fleet_id, len);
    }

    /* pack environment metadata */
    pack_env_metadata(config->env, &mh, &mp_pck);

    /* finalize */
    flb_mp_map_header_end(&mh);

    /* convert to json */
    meta = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE); /* could be ASCII */
    msgpack_sbuffer_destroy(&mp_sbuf);

    return meta;
}

static int calyptia_http_do(struct flb_calyptia *ctx, struct flb_http_client *c,
                            int type)
{
    int ret;
    size_t b_sent;

    if( !ctx || !c ) {
        return FLB_ERROR;
    }

    /* Ensure agent_token is not empty when required */
    if ((type == CALYPTIA_ACTION_METRICS || type == CALYPTIA_ACTION_PATCH || type == CALYPTIA_ACTION_TRACE) &&
        !ctx->agent_token) {
        flb_plg_warn(ctx->ins, "agent_token is missing for action type %d", type);
        return FLB_ERROR;
    }

    /* append headers */
    if (type == CALYPTIA_ACTION_REGISTER) {
        // When registering a new agent api key is required
        if (!ctx->api_key) {
            flb_plg_error(ctx->ins, "api_key is missing");
            return FLB_ERROR;
        }
        flb_http_add_header(c,
                            CALYPTIA_HEADERS_CTYPE, sizeof(CALYPTIA_HEADERS_CTYPE) - 1,
                            CALYPTIA_HEADERS_CTYPE_JSON, sizeof(CALYPTIA_HEADERS_CTYPE_JSON) - 1);

        flb_http_add_header(c,
                            CALYPTIA_HEADERS_PROJECT, sizeof(CALYPTIA_HEADERS_PROJECT) - 1,
                            ctx->api_key, flb_sds_len(ctx->api_key));
    }
    else if (type == CALYPTIA_ACTION_PATCH) {
        flb_http_add_header(c,
                            CALYPTIA_HEADERS_CTYPE, sizeof(CALYPTIA_HEADERS_CTYPE) - 1,
                            CALYPTIA_HEADERS_CTYPE_JSON, sizeof(CALYPTIA_HEADERS_CTYPE_JSON) - 1);

        flb_http_add_header(c,
                            CALYPTIA_HEADERS_AGENT_TOKEN,
                            sizeof(CALYPTIA_HEADERS_AGENT_TOKEN) - 1,
                            ctx->agent_token, flb_sds_len(ctx->agent_token));
    }
    else if (type == CALYPTIA_ACTION_METRICS) {
        flb_http_add_header(c,
                            CALYPTIA_HEADERS_CTYPE, sizeof(CALYPTIA_HEADERS_CTYPE) - 1,
                            CALYPTIA_HEADERS_CTYPE_MSGPACK,
                            sizeof(CALYPTIA_HEADERS_CTYPE_MSGPACK) - 1);

        flb_http_add_header(c,
                            CALYPTIA_HEADERS_AGENT_TOKEN,
                            sizeof(CALYPTIA_HEADERS_AGENT_TOKEN) - 1,
                            ctx->agent_token, flb_sds_len(ctx->agent_token));
    }
#ifdef FLB_HAVE_CHUNK_TRACE
    else if (type == CALYPTIA_ACTION_TRACE)  {
        flb_http_add_header(c,
                            CALYPTIA_HEADERS_CTYPE, sizeof(CALYPTIA_HEADERS_CTYPE) - 1,
                            CALYPTIA_HEADERS_CTYPE_JSON, sizeof(CALYPTIA_HEADERS_CTYPE_JSON) - 1);

        flb_http_add_header(c,
                            CALYPTIA_HEADERS_AGENT_TOKEN,
                            sizeof(CALYPTIA_HEADERS_AGENT_TOKEN) - 1,
                            ctx->agent_token, flb_sds_len(ctx->agent_token));
    }
#endif

    /* Map debug callbacks */
    flb_http_client_debug(c, ctx->ins->callback);

    /* Perform HTTP request */
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        return FLB_RETRY;
    }

    if (c->resp.status != 200 && c->resp.status != 201 && c->resp.status != 204) {
        if (c->resp.payload_size > 0) {
            flb_plg_warn(ctx->ins, "http_status=%i:\n%s",
                         c->resp.status, c->resp.payload);
        }
        else {
            flb_plg_warn(ctx->ins, "http_status=%i", c->resp.status);
        }

        /* invalid metrics */
        if (c->resp.status == 422) {
            return FLB_ERROR;
        }
        return FLB_RETRY;;
    }

    return FLB_OK;
}

static flb_sds_t get_agent_info(char *buf, size_t size, char *k)
{
    int i;
    int ret;
    int type;
    int len;
    char *out_buf;
    flb_sds_t v = NULL;
    size_t off = 0;
    size_t out_size;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object key;
    msgpack_object val;

    len = strlen(k);

    ret = flb_pack_json(buf, size, &out_buf, &out_size, &type, NULL);
    if (ret != 0) {
        return NULL;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_free(out_buf);
        msgpack_unpacked_destroy(&result);
        return NULL;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_free(out_buf);
        msgpack_unpacked_destroy(&result);
        return NULL;
    }

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        val = root.via.map.ptr[i].val;

        if (key.type != MSGPACK_OBJECT_STR || val.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (key.via.str.size != len) {
            continue;
        }

        if (strncmp(key.via.str.ptr, k, len) == 0) {
            v = flb_sds_create_len(val.via.str.ptr, val.via.str.size);
            break;
        }
    }

    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
    return v;
}

/* Set the session content */
static int store_session_set(struct flb_calyptia *ctx, char *buf, size_t size)
{
    int ret;
    int type;
    char *mp_buf;
    size_t mp_size;

    /* remove any previous session file */
    if (ctx->fs_file) {
        flb_fstore_file_delete(ctx->fs, ctx->fs_file);
    }

    /* create session file */
    ctx->fs_file = flb_fstore_file_create(ctx->fs, ctx->fs_stream,
                                          CALYPTIA_SESSION_FILE, 1024);
    if (!ctx->fs_file) {
        flb_plg_error(ctx->ins, "could not create new session file");
        return -1;
    }

    /* store meta */
    flb_fstore_file_meta_set(ctx->fs, ctx->fs_file,
                             FLB_VERSION_STR "\n", sizeof(FLB_VERSION_STR) - 1);

    /* encode */
    ret = flb_pack_json(buf, size, &mp_buf, &mp_size, &type, NULL);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not encode session information");
        return -1;
    }

    /* store content */
    ret = flb_fstore_file_append(ctx->fs_file, mp_buf, mp_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not store session information");
        flb_free(mp_buf);
        return -1;
    }

    flb_free(mp_buf);
    return 0;
}

static int store_session_get(struct flb_calyptia *ctx,
                             void **out_buf, size_t *out_size)
{
    int ret;
    void *buf;
    size_t size;
    flb_sds_t json;

    ret = flb_fstore_file_content_copy(ctx->fs, ctx->fs_file,
                                       &buf, &size);

    if (size == 0) {
        return -1;
    }

    /* decode */
    json = flb_msgpack_raw_to_json_sds(buf, size, FLB_TRUE); /* TODO: could be ASCII? */
    flb_free(buf);
    if (!json) {
        return -1;
    }

    *out_buf = json;
    *out_size = flb_sds_len(json);

    return ret;
}

static int store_init(struct flb_calyptia *ctx)
{
    int ret;
    struct flb_fstore *fs;
    struct flb_fstore_file *fsf;
    void *buf;
    size_t size;

    /* store context */
    fs = flb_fstore_create(ctx->store_path, FLB_FSTORE_FS);
    if (!fs) {
        flb_plg_error(ctx->ins,
                      "could not initialize 'store_path': %s",
                      ctx->store_path);
        return -1;
    }
    ctx->fs = fs;

    /* stream */
    ctx->fs_stream = flb_fstore_stream_create(ctx->fs, "calyptia");
    if (!ctx->fs_stream) {
        flb_plg_error(ctx->ins, "could not create storage stream");
        return -1;
    }

    /* lookup any previous file */
    fsf = flb_fstore_file_get(ctx->fs, ctx->fs_stream, CALYPTIA_SESSION_FILE,
                              sizeof(CALYPTIA_SESSION_FILE) - 1);
    if (!fsf) {
        flb_plg_debug(ctx->ins, "no session file was found");
        return 0;
    }
    ctx->fs_file = fsf;

    /* retrieve session info */
    ret = store_session_get(ctx, &buf, &size);
    if (ret == 0) {
        /* agent id */
        ctx->agent_id = get_agent_info(buf, size, "id");

        /* agent token */
        ctx->agent_token = get_agent_info(buf, size, "token");

        if (ctx->agent_id && ctx->agent_token) {
            flb_plg_info(ctx->ins, "session setup OK");
        }
        else {
            if (ctx->agent_id) {
                flb_sds_destroy(ctx->agent_id);
            }
            if (ctx->agent_token) {
                flb_sds_destroy(ctx->agent_token);
            }
        }
        flb_sds_destroy(buf);
    }

    return 0;
}

/* Agent creation is perform on initialization using a sync upstream connection */
static int api_agent_create(struct flb_config *config, struct flb_calyptia *ctx)
{
    int ret;
    int flb_ret;
    int flags;
    int action = CALYPTIA_ACTION_REGISTER;
    char uri[1024];
    flb_sds_t meta;
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    /* Meta */
    meta = get_agent_metadata(ctx);
    if (!meta) {
        flb_plg_error(ctx->ins, "could not retrieve metadata");
        return -1;
    }

    /* Upstream */
    flags = get_io_flags(ctx->ins);
    u = flb_upstream_create(ctx->config,
                            ctx->cloud_host, ctx->cloud_port,
                            flags, ctx->ins->tls);
    if (!u) {
        flb_plg_error(ctx->ins,
                      "could not create upstream connection on 'agent create'");
        flb_sds_destroy(meta);
        return -1;
    }

    /* Make it synchronous */
    flb_stream_disable_async_mode(&u->base);

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_upstream_destroy(u);
        flb_sds_destroy(meta);
        return -1;
    }

    if (ctx->agent_id && ctx->agent_token) {
        /* Patch */
        action = CALYPTIA_ACTION_PATCH;
        snprintf(uri, sizeof(uri) - 1, CALYPTIA_ENDPOINT_PATCH, ctx->agent_id);
        c = flb_http_client(u_conn, FLB_HTTP_PATCH, uri,
                            meta, flb_sds_len(meta), NULL, 0, NULL, 0);
    }
    else {
        /* Create */
        action = CALYPTIA_ACTION_REGISTER;
        c = flb_http_client(u_conn, FLB_HTTP_POST, CALYPTIA_ENDPOINT_CREATE,
                            meta, flb_sds_len(meta), NULL, 0, NULL, 0);
    }

    if (!c) {
        flb_upstream_conn_release(u_conn);
        flb_upstream_destroy(u);
        return -1;
    }

    /* perform request */
    flb_ret = calyptia_http_do(ctx, c, action);
    if (flb_ret == FLB_OK &&
        (c->resp.status == 200 || c->resp.status == 201 || c->resp.status == 204)) {
        if (c->resp.payload_size > 0) {
            if (action == CALYPTIA_ACTION_REGISTER) {
                /* agent id */
                ctx->agent_id = get_agent_info(c->resp.payload,
                                               c->resp.payload_size,
                                               "id");

                /* agent token */
                ctx->agent_token = get_agent_info(c->resp.payload,
                                                  c->resp.payload_size,
                                                  "token");

                if (ctx->agent_id && ctx->agent_token) {
                    flb_plg_info(ctx->ins, "connected to Calyptia, agent_id='%s'",
                                 ctx->agent_id);

                    if (ctx->store_path && ctx->fs) {
                        ret = store_session_set(ctx,
                                                c->resp.payload,
                                                c->resp.payload_size);
                        if (ret == -1) {
                            flb_plg_warn(ctx->ins,
                                         "could not store Calyptia session");
                        }
                    }
                }
            }
        }

        if (action == CALYPTIA_ACTION_PATCH) {
            flb_plg_info(ctx->ins, "known agent registration successful");
        }
    }

    /* release resources */
    flb_sds_destroy(meta);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    flb_upstream_destroy(u);

    return flb_ret;
}

static struct flb_calyptia *config_init(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    int flags;
    struct flb_calyptia *ctx;

    /* Calyptia plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_calyptia));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->config = config;
    flb_kv_init(&ctx->kv_labels);

    /* Load the config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        calyptia_ctx_destroy(ctx);
        return NULL;
    }

    ctx->metrics_endpoint = flb_sds_create_size(256);
    if (!ctx->metrics_endpoint) {
        calyptia_ctx_destroy(ctx);
        return NULL;
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    ctx->trace_endpoint = flb_sds_create_size(256);
    if (!ctx->trace_endpoint) {
        calyptia_ctx_destroy(ctx);
        return NULL;
    }
#endif

    /* api_key */
    if (!ctx->api_key) {
        flb_plg_error(ctx->ins, "configuration 'api_key' is missing");
        calyptia_ctx_destroy(ctx);
        return NULL;
    }

    /* parse 'add_label' */
    ret = config_add_labels(ins, ctx);
    if (ret == -1) {
        calyptia_ctx_destroy(ctx);
        return NULL;
    }

    /* env reader */
    ctx->env = flb_env_create();

    /* Set context */
    flb_output_set_context(ins, ctx);

    /* Initialize optional storage */
    if (ctx->store_path) {
        ret = store_init(ctx);
        if (ret == -1) {
            flb_output_set_context(ins, NULL);
            calyptia_ctx_destroy(ctx);
            return NULL;
        }
    }

    /* the machine-id is provided by custom calyptia, which invokes this plugin. */
    if (!ctx->machine_id) {
        flb_plg_error(ctx->ins, "machine_id has not been set");
        flb_output_set_context(ins, NULL);
        calyptia_ctx_destroy(ctx);
        return NULL;
    }

    flb_plg_debug(ctx->ins, "machine_id=%s", ctx->machine_id);

    /* Upstream */
    flags = get_io_flags(ctx->ins);
    ctx->u = flb_upstream_create(ctx->config,
                                 ctx->cloud_host, ctx->cloud_port,
                                 flags, ctx->ins->tls);
    if (!ctx->u) {
        flb_output_set_context(ins, NULL);
        calyptia_ctx_destroy(ctx);
        return NULL;
    }

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    return ctx;
}

static int register_agent(struct flb_calyptia *ctx, struct flb_config *config)
{
    int ret;

    /* Try registration */
    ret = api_agent_create(config, ctx);
    if (ret != FLB_OK) {
        flb_plg_warn(ctx->ins, "agent registration failed");
        return FLB_ERROR;
    }

    /* Update endpoints */
    flb_sds_len_set(ctx->metrics_endpoint, 0);
    flb_sds_printf(&ctx->metrics_endpoint, CALYPTIA_ENDPOINT_METRICS,
                   ctx->agent_id);

#ifdef FLB_HAVE_CHUNK_TRACE
    if (ctx->pipeline_id) {
        flb_sds_len_set(ctx->trace_endpoint, 0);
        flb_sds_printf(&ctx->trace_endpoint, CALYPTIA_ENDPOINT_TRACE,
                       ctx->pipeline_id);
    }
#endif

    flb_plg_info(ctx->ins, "agent registration successful");
    return FLB_OK;
}

static int cb_calyptia_init(struct flb_output_instance *ins,
                           struct flb_config *config, void *data)
{
    struct flb_calyptia *ctx;
    (void) data;
    int ret;

    /* create config context */
    ctx = config_init(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "could not initialize configuration");
        return -1;
    }

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    ret = register_agent(ctx, config);
    if (ret != FLB_OK && !ctx->register_retry_on_flush) {
        flb_plg_error(ins, "agent registration failed and register_retry_on_flush=false");
        return -1;
    }

    return 0;
}

static void debug_payload(struct flb_calyptia *ctx, void *data, size_t bytes)
{
    int ret;
    size_t off = 0;
    struct cmt *cmt;
    cfl_sds_t out;

    ret = cmt_decode_msgpack_create(&cmt, (char *) data, bytes, &off);
    if (ret != CMT_DECODE_MSGPACK_SUCCESS) {
        flb_plg_warn(ctx->ins, "could not unpack debug payload");
        return;
    }

    out = cmt_encode_text_create(cmt);
    flb_plg_debug(ctx->ins, "debug payload:\n%s", out);
    cmt_encode_text_destroy(out);
    cmt_destroy(cmt);
}

static void calyptia_ctx_destroy(struct flb_calyptia *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->agent_id) {
        flb_sds_destroy(ctx->agent_id);
    }

    if (ctx->agent_token) {
        flb_sds_destroy(ctx->agent_token);
    }

    if (ctx->env) {
        flb_env_destroy(ctx->env);
    }

    if (ctx->metrics_endpoint) {
        flb_sds_destroy(ctx->metrics_endpoint);
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    if (ctx->trace_endpoint) {
        flb_sds_destroy(ctx->trace_endpoint);
    }
#endif

    if (ctx->fs) {
        flb_fstore_destroy(ctx->fs);
    }

    flb_kv_release(&ctx->kv_labels);
    flb_free(ctx);
}

static int cb_calyptia_exit(void *data, struct flb_config *config)
{
    (void) config;
    calyptia_ctx_destroy((struct flb_calyptia *) data);
    return 0;
}

static void cb_calyptia_flush(struct flb_event_chunk *event_chunk,
                             struct flb_output_flush *out_flush,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    int ret;
    size_t off = 0;
    size_t out_size = 0;
    char *out_buf = NULL;
    struct flb_connection *u_conn;
    struct flb_http_client *c = NULL;
    struct flb_calyptia *ctx = out_context;
    struct cmt *cmt;
    flb_sds_t json;
    (void) i_ins;
    (void) config;

    if ((!ctx->agent_id || !ctx->agent_token) && ctx->register_retry_on_flush) {
        flb_plg_info(ctx->ins, "missing agent_id or agent_token, attempting re-registration register_retry_on_flush=true");
        if (register_agent(ctx, config) != FLB_OK) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }
    else if (!ctx->agent_id || !ctx->agent_token) {
        flb_plg_error(ctx->ins, "missing agent_id or agent_token, and register_retry_on_flush=false");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    if (event_chunk->type == FLB_EVENT_TYPE_METRICS) {
        /* if we have labels append them */
        if (ctx->add_labels && mk_list_size(ctx->add_labels) > 0) {
            ret = cmt_decode_msgpack_create(&cmt,
                                            (char *) event_chunk->data,
                                            event_chunk->size,
                                            &off);
            if (ret != CMT_DECODE_MSGPACK_SUCCESS) {
                flb_upstream_conn_release(u_conn);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            /* append labels set by config */
            append_labels(ctx, cmt);

            /* encode back to msgpack */
            ret = cmt_encode_msgpack_create(cmt, &out_buf, &out_size);
            if (ret != 0) {
                cmt_destroy(cmt);
                flb_upstream_conn_release(u_conn);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
            cmt_destroy(cmt);
        }
        else {
            out_buf = (char *) event_chunk->data;
            out_size = event_chunk->size;
        }

        /* Compose HTTP Client request */
        c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->metrics_endpoint,
                           out_buf, out_size, NULL, 0, NULL, 0);
        if (!c) {
            if (out_buf != event_chunk->data) {
                cmt_encode_msgpack_destroy(out_buf);
            }
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        /* perform request */
        ret = calyptia_http_do(ctx, c, CALYPTIA_ACTION_METRICS);
        if (ret == FLB_OK) {
            flb_plg_debug(ctx->ins, "metrics delivered OK");
        }
        else {
            flb_plg_error(ctx->ins, "could not deliver metrics");
            debug_payload(ctx, out_buf, out_size);
        }

        if (out_buf != event_chunk->data) {
            cmt_encode_msgpack_destroy(out_buf);
        }
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    if (event_chunk->type & FLB_EVENT_TYPE_LOGS &&
        event_chunk->type & FLB_EVENT_TYPE_HAS_TRACE) {
        json = flb_pack_msgpack_to_json_format(event_chunk->data,
                                            event_chunk->size,
                                            FLB_PACK_JSON_FORMAT_STREAM,
                                            FLB_PACK_JSON_DATE_DOUBLE,
                                            NULL,
                                            FLB_TRUE); /* Trace is ASCII */
        if (json == NULL) {
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->trace_endpoint,
                           (char *) json, flb_sds_len(json),
                           NULL, 0, NULL, 0);

        if (!c) {
            flb_upstream_conn_release(u_conn);
            flb_sds_destroy(json);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        ret = calyptia_http_do(ctx, c, CALYPTIA_ACTION_TRACE);
        if (ret == FLB_OK) {
            flb_plg_debug(ctx->ins, "trace delivered OK");
        }
        else {
            flb_plg_error(ctx->ins, "could not deliver trace");
            debug_payload(ctx, (char *) json, flb_sds_len(json));
        }
        flb_sds_destroy(json);
    }
#endif /* FLB_HAVE_CHUNK_TRACE */

    flb_upstream_conn_release(u_conn);

    if (c) {
        flb_http_client_destroy(c);
    }

    FLB_OUTPUT_RETURN(ret);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "cloud_host", DEFAULT_CALYPTIA_HOST,
     0, FLB_TRUE, offsetof(struct flb_calyptia, cloud_host),
     "",
    },

    {
     FLB_CONFIG_MAP_INT, "cloud_port", DEFAULT_CALYPTIA_PORT,
     0, FLB_TRUE, offsetof(struct flb_calyptia, cloud_port),
     "",
    },

    {
     FLB_CONFIG_MAP_STR, "api_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_calyptia, api_key),
     "Calyptia Cloud API Key."
    },
    {
     FLB_CONFIG_MAP_STR, "machine_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_calyptia, machine_id),
     "Custom machine_id to be used when registering agent"
    },
    {
     FLB_CONFIG_MAP_STR, "fleet_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_calyptia, fleet_id),
     "Fleet ID for identifying as part of a managed fleet"
    },

    {
     FLB_CONFIG_MAP_STR, "store_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_calyptia, store_path),
     ""
    },

    {
     FLB_CONFIG_MAP_SLIST_1, "add_label", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_calyptia, add_labels),
     "Label to append to the generated metric."
    },

#ifdef FLB_HAVE_CHUNK_TRACE
    {
     FLB_CONFIG_MAP_STR, "pipeline_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_calyptia, pipeline_id),
     "Pipeline ID for calyptia core traces."
    },
#endif
    {
     FLB_CONFIG_MAP_BOOL, "register_retry_on_flush", "true",
     0, FLB_TRUE, offsetof(struct flb_calyptia, register_retry_on_flush),
     "Retry agent registration on flush if failed on init."
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_calyptia_plugin = {
    .name         = "calyptia",
    .description  = "Calyptia Cloud",
    .cb_init      = cb_calyptia_init,
    .cb_flush     = cb_calyptia_flush,
    .cb_exit      = cb_calyptia_exit,
    .config_map   = config_map,
    .flags        = FLB_OUTPUT_NET | FLB_OUTPUT_PRIVATE | FLB_IO_OPT_TLS,
    .event_type   = FLB_OUTPUT_METRICS
};
