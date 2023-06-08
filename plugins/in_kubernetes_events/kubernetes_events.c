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


#include <sys/types.h>
#include <sys/stat.h>

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_strptime.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_compat.h>

#include "kubernetes_events.h"
#include "kubernetes_events_conf.h"

#ifdef FLB_HAVE_SQLDB
#include "kubernetes_events_sql.h"
static int k8s_events_sql_insert_event(struct k8s_events *ctx, msgpack_object *item);
#endif

static int file_to_buffer(const char *path,
                          char **out_buf, size_t *out_size)
{
    int ret;
    int len;
    char *buf;
    ssize_t bytes;
    FILE *fp;
    struct stat st;

    if (!(fp = fopen(path, "r"))) {
        return -1;
    }

    ret = stat(path, &st);
    if (ret == -1) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    buf = flb_calloc(1, (st.st_size + 1));
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes < 1) {
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    // trim new lines
    for (len = st.st_size; len > 0; len--) {
        if (buf[len-1] != '\n' && buf[len-1] != '\r') {
            break;
        }
    }
    buf[len] = '\0';

    *out_buf = buf;
    *out_size = len;

    return 0;
}

/* Set K8s Authorization Token and get HTTP Auth Header */
static int get_http_auth_header(struct k8s_events *ctx)
{
    int ret;
    char *temp;
    char *tk = NULL;
    size_t tk_size = 0;

    if (!ctx->token_file) {
        return 0;
    }

    ret = file_to_buffer(ctx->token_file, &tk, &tk_size);
    if (ret == -1) {
        flb_plg_warn(ctx->ins, "cannot open %s", ctx->token_file);
        return -1;
    }
    ctx->token_created = time(NULL);

    /* Token */
    if (ctx->token != NULL) {
        flb_free(ctx->token);
    }
    ctx->token = tk;
    ctx->token_len = tk_size;

    /* HTTP Auth Header */
    if (ctx->auth == NULL) {
        ctx->auth = flb_malloc(tk_size + 32);
    }
    else if (ctx->auth_len < tk_size + 32) {
        temp = flb_realloc(ctx->auth, tk_size + 32);
        if (temp == NULL) {
            flb_errno();
            flb_free(ctx->auth);
            ctx->auth = NULL;
            return -1;
        }
        ctx->auth = temp;
    }

    if (!ctx->auth) {
        return -1;
    }

    ctx->auth_len = snprintf(ctx->auth, tk_size + 32, "Bearer %s", tk);
    return 0;
}

/* Refresh HTTP Auth Header if K8s Authorization Token is expired */
static int refresh_token_if_needed(struct k8s_events *ctx)
{
    int expired = FLB_FALSE;
    int ret;

    if (ctx->token_created > 0) {
        if (time(NULL) > ctx->token_created + ctx->token_ttl) {
            expired = FLB_TRUE;
        }
    }

    if (expired || ctx->token_created == 0) {
        ret = get_http_auth_header(ctx);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}
static int timestamp_lookup(struct k8s_events *ctx, char *ts, struct flb_time *time)
{
    struct flb_tm tm = { 0 };

    if (flb_strptime(ts, "%Y-%m-%dT%H:%M:%SZ", &tm) == NULL) {
        return -1;
    }

    time->tm.tv_sec = flb_parser_tm2time(&tm);
    time->tm.tv_nsec = 0;

    return 0;
}

static msgpack_object *record_get_field_ptr(msgpack_object *obj, const char *fieldname)
{
    int i;
    msgpack_object *k;
    msgpack_object *v;

    if (obj->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    for (i = 0; i < obj->via.map.size; i++) {
        k = &obj->via.map.ptr[i].key;
        if (k->type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (strncmp(k->via.str.ptr, fieldname, strlen(fieldname)) == 0) {
            v = &obj->via.map.ptr[i].val;
            return v;
        }
    }
    return NULL;
}

static int record_get_field_sds(msgpack_object *obj, const char *fieldname, flb_sds_t *val)
{
    msgpack_object *v;

    v = record_get_field_ptr(obj, fieldname);
    if (v == NULL) {
        return 0;
    }
    if (v->type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    *val = flb_sds_create_len(v->via.str.ptr, v->via.str.size);
    return 0;
}

static int record_get_field_time(msgpack_object *obj, const char *fieldname, time_t *val)
{
    msgpack_object *v;
    struct flb_tm tm = { 0 };

    v = record_get_field_ptr(obj, fieldname);
    if (v == NULL) {
        return -1;
    }
    if (v->type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    if (flb_strptime(v->via.str.ptr, "%Y-%m-%dT%H:%M:%SZ", &tm) == NULL) {
        return -2;
    }

    *val = mktime(&tm.tm);
    return 0;
}

static int record_get_field_uint64(msgpack_object *obj, const char *fieldname, uint64_t *val)
{
    msgpack_object *v;
    char *end;

    v = record_get_field_ptr(obj, fieldname);
    if (v == NULL) {
        return -1;
    }

    // attempt to parse string as number...
    if (v->type == MSGPACK_OBJECT_STR) {
        *val = strtoul(v->via.str.ptr, &end, 10);
        if (end == NULL || (end < v->via.str.ptr + v->via.str.size)) {
            return -1;
        }
        return 0;
    }

    if (v->type == MSGPACK_OBJECT_POSITIVE_INTEGER || MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *val = v->via.u64;
        return 0;
    }
    if (v->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *val = (uint64_t)v->via.i64;
        return 0;
    }
    return -1;
}

static int item_get_timestamp(msgpack_object *obj, time_t *event_time)
{
    int ret;
    msgpack_object *metadata;

    // some events can have lastTimestamp and firstTimestamp set to
    // NULL while having metadata.creationTimestamp set.
    ret = record_get_field_time(obj, "lastTimestamp", event_time);
    if (ret != -1) {
        return FLB_TRUE;
    }

    ret = record_get_field_time(obj, "firstTimestamp", event_time);
    if (ret != -1) {
        return FLB_TRUE;
    }

    metadata = record_get_field_ptr(obj, "metadata");
    if (metadata == NULL) {
        return FLB_FALSE;
    }

    ret = record_get_field_time(metadata, "creationTimestamp", event_time);
    if (ret != -1) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static bool check_event_is_filtered(struct k8s_events *ctx, msgpack_object *obj)
{
    int ret;
    time_t event_time;
    time_t now;
    msgpack_object *metadata;
    flb_sds_t uid;
    uint64_t resource_version;

    ret = item_get_timestamp(obj, &event_time);
    if (ret == -FLB_FALSE) {
        flb_plg_error(ctx->ins, "Cannot get timestamp for item in response");
        return FLB_FALSE;
    }

    now = (time_t)(cfl_time_now() / 1000000000);
    if (event_time < (now - ctx->retention_time)) {
        flb_plg_debug(ctx->ins, "Item is older than retention_time: %ld < %ld",
                      event_time,  (now - ctx->retention_time));
        return FLB_TRUE;
    }

    metadata = record_get_field_ptr(obj, "metadata");
    if (metadata == NULL) {
        flb_plg_error(ctx->ins, "Cannot unpack item metadata in response");
        return FLB_FALSE;
    }

    ret = record_get_field_uint64(metadata, "resourceVersion", &resource_version);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Cannot get resourceVersion for item in response");
        return FLB_FALSE;
    }

    ret = record_get_field_sds(metadata, "uid", &uid);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Cannot get resourceVersion for item in response");
        return FLB_FALSE;
    }


#ifdef FLB_HAVE_SQLDB
    bool exists;


    if (ctx->db) {
        sqlite3_bind_text(ctx->stmt_get_kubernetes_event_exists_by_uid,
                           1, uid, -1, NULL);
        ret = sqlite3_step(ctx->stmt_get_kubernetes_event_exists_by_uid);
        if (ret != SQLITE_ROW) {
            if (ret != SQLITE_DONE) {
                flb_plg_error(ctx->ins, "cannot execute kubernetes event exists");
            }
            sqlite3_clear_bindings(ctx->stmt_get_kubernetes_event_exists_by_uid);
            sqlite3_reset(ctx->stmt_get_kubernetes_event_exists_by_uid);
            flb_sds_destroy(uid);
            return FLB_FALSE;
        }

        exists = sqlite3_column_int64(ctx->stmt_get_kubernetes_event_exists_by_uid, 0);

        flb_plg_debug(ctx->ins, "is_filtered: uid=%s exists=%d", uid, exists);
        sqlite3_clear_bindings(ctx->stmt_get_kubernetes_event_exists_by_uid);
        sqlite3_reset(ctx->stmt_get_kubernetes_event_exists_by_uid);
        flb_sds_destroy(uid);

        return exists > 0 ? FLB_TRUE : FLB_FALSE;
    }
#endif

    // check if this is an old event.
    if (ctx->last_resource_version && resource_version <= ctx->last_resource_version) {
        flb_plg_debug(ctx->ins, "skipping old object: %lu (< %lu)", resource_version,
                        ctx->last_resource_version);
        flb_sds_destroy(uid);
        return FLB_TRUE;
    }

    flb_sds_destroy(uid);
    return FLB_FALSE;
}

static int process_events(struct k8s_events *ctx, char *in_data, size_t in_size, uint64_t *max_resource_version, flb_sds_t *continue_token)
{
    int i;
    int ret = -1;
    int root_type;
    size_t consumed = 0;
    char *buf_data;
    size_t buf_size;
    size_t off = 0;
    struct flb_time ts;
    struct flb_ra_value *rval;
    uint64_t resource_version;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object k;
    msgpack_object *items = NULL;
    msgpack_object *item = NULL;
    msgpack_object *item_metadata = NULL;
    msgpack_object *metadata = NULL;


    ret = flb_pack_json(in_data, in_size, &buf_data, &buf_size, &root_type, &consumed);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not process payload, incomplete or bad formed JSON");
        goto json_error;
    }

    /* unpack */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf_data, buf_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack response");
        goto unpack_error;
    }

    /* lookup the items array */
    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    // Traverse the EventList for the metadata (for the continue token) and the items.
    // https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/#EventList
    for (i = 0; i < root.via.map.size; i++) {
        k = root.via.map.ptr[i].key;
        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (strncmp(k.via.str.ptr, "items", 5) == 0) {
            items = &root.via.map.ptr[i].val;
            if (items->type != MSGPACK_OBJECT_ARRAY) {
                flb_plg_error(ctx->ins, "Cannot unpack items");
                goto msg_error;
            }
        }

        if (strncmp(k.via.str.ptr, "metadata", 8) == 0) {
            metadata = &root.via.map.ptr[i].val;
            if (metadata->type != MSGPACK_OBJECT_MAP) {
                flb_plg_error(ctx->ins, "Cannot unpack metadata");
                goto msg_error;
            }
        }
    }

    if (items == NULL) {
        flb_plg_error(ctx->ins, "Cannot find items in response");
        goto msg_error;
    }

    if (metadata == NULL) {
        flb_plg_error(ctx->ins, "Cannot find metatada in response");
        goto msg_error;
    }

    ret = record_get_field_sds(metadata, "continue", continue_token);
    if (ret == -1) {
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Cannot process continue token");
            goto msg_error;
        }
    }

    for (i = 0; i < items->via.array.size; i++) {
        if (items->via.array.ptr[i].type != MSGPACK_OBJECT_MAP) {
            flb_plg_warn(ctx->ins, "Event that is not a map");
            continue;
        }
        item_metadata = record_get_field_ptr(&items->via.array.ptr[i], "metadata");
        if (item_metadata == NULL) {
            flb_plg_warn(ctx->ins, "Event without metadata");
            continue;
        }
        ret = record_get_field_uint64(item_metadata,
                                      "resourceVersion", &resource_version);
        if (ret == -1) {
            continue;
        }
        if (resource_version > *max_resource_version) {
            *max_resource_version = resource_version;
        }
    }

    /* reset the log encoder */
    flb_log_event_encoder_reset(ctx->encoder);

    /* print every item from the items array */
    for (i = 0; i < items->via.array.size; i++) {
        item = &items->via.array.ptr[i];
        if (item->type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "Cannot unpack item in response");
            goto msg_error;
        }

        if (check_event_is_filtered(ctx, item) == FLB_TRUE) {
            continue;
        }

#ifdef FLB_HAVE_SQLDB
        if (ctx->db) {
            k8s_events_sql_insert_event(ctx, item);
        }
#endif

        /* get event timestamp */
        rval = flb_ra_get_value_object(ctx->ra_timestamp, *item);
        if (!rval || rval->type != FLB_RA_STRING) {
            flb_plg_error(ctx->ins, "cannot retrieve event timestamp");
            goto msg_error;
        }

        /* convert timestamp */
        ret = timestamp_lookup(ctx, rval->val.string, &ts);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot lookup event timestamp");
            flb_ra_key_value_destroy(rval);
            goto msg_error;
        }

        /* encode content as a log event */
        flb_log_event_encoder_begin_record(ctx->encoder);
        flb_log_event_encoder_set_timestamp(ctx->encoder, &ts);

        ret = flb_log_event_encoder_set_body_from_msgpack_object(ctx->encoder, item);
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(ctx->encoder);
        } else {
            flb_plg_warn(ctx->ins, "unable to encode: %lu", resource_version);
        }
        flb_ra_key_value_destroy(rval);
    }

    if (ctx->encoder->output_length > 0) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->encoder->output_buffer,
                             ctx->encoder->output_length);
    }

msg_error:
    msgpack_unpacked_destroy(&result);
unpack_error:
    flb_free(buf_data);
json_error:
    return ret;
}

static struct flb_http_client *make_event_api_request(struct k8s_events *ctx,
                                                      struct flb_connection *u_conn,
                                                      flb_sds_t continue_token)
{
    flb_sds_t url;
    struct flb_http_client *c;


    if (continue_token == NULL && ctx->limit_request == 0) {
        return flb_http_client(u_conn, FLB_HTTP_GET, K8S_EVENTS_KUBE_API_URI,
                               NULL, 0, ctx->api_host, ctx->api_port, NULL, 0);
    }

    url = flb_sds_create(K8S_EVENTS_KUBE_API_URI);
    flb_sds_cat_safe(&url, "?", 1);
    if (ctx->limit_request) {
        if (continue_token != NULL) {
            flb_sds_printf(&url, "continue=%s&", continue_token);
        }
        flb_sds_printf(&url, "limit=%d", ctx->limit_request);
    }
    c = flb_http_client(u_conn, FLB_HTTP_GET, url,
                        NULL, 0, ctx->api_host, ctx->api_port, NULL, 0);
    flb_sds_destroy(url);
    return c;
}

#ifdef FLB_HAVE_SQLDB

static int k8s_events_cleanup_db(struct flb_input_instance *ins,
                                 struct flb_config *config, void *in_context)
{
    int ret;
    struct k8s_events *ctx = (struct k8s_events *)in_context;
    time_t retention_time_ago;
    time_t now = (cfl_time_now() / 1000000000);

    if (ctx->db == NULL) {
        FLB_INPUT_RETURN(0);
    }

    retention_time_ago = now - (ctx->retention_time);
    sqlite3_bind_int64(ctx->stmt_delete_old_kubernetes_events,
                        1, (int64_t)retention_time_ago);
    ret = sqlite3_step(ctx->stmt_delete_old_kubernetes_events);
    if (ret != SQLITE_ROW && ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "cannot execute delete old kubernetes events");
    }

    sqlite3_clear_bindings(ctx->stmt_delete_old_kubernetes_events);
    sqlite3_reset(ctx->stmt_delete_old_kubernetes_events);

    FLB_INPUT_RETURN(0);
}

static int k8s_events_sql_insert_event(struct k8s_events *ctx, msgpack_object *item)
{
    int ret;
    uint64_t resource_version;
    time_t last;
    msgpack_object *meta;
    flb_sds_t uid;


    meta = record_get_field_ptr(item, "meta");
    if (meta == NULL) {
        flb_plg_error(ctx->ins, "unable to find metadata to save event");
        return -1;
    }

    ret = record_get_field_uint64(meta, "resourceVersion", &resource_version);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "unable to find resourceVersion in metadata to save event");
        return -1;
    }

    ret = record_get_field_sds(meta, "uid", &uid);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "unable to find uid in metadata to save event");
        return -1;
    }

    ret = item_get_timestamp(item, &last);
    if (ret == -FLB_FALSE) {
        flb_plg_error(ctx->ins, "Cannot get timestamp for item to save it");
        return -1;
    }

    if (ret == -2) {
        flb_plg_error(ctx->ins, "unable to parse lastTimestamp in item to save event");
        flb_sds_destroy(uid);
        return -1;
    }

    /* Bind parameters */
    sqlite3_bind_text(ctx->stmt_insert_kubernetes_event, 1, uid, -1, 0);
    sqlite3_bind_int64(ctx->stmt_insert_kubernetes_event, 2, resource_version);
    sqlite3_bind_int64(ctx->stmt_insert_kubernetes_event, 3, (int64_t)last);

    /* Run the insert */
    ret = sqlite3_step(ctx->stmt_insert_kubernetes_event);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_insert_kubernetes_event);
        sqlite3_reset(ctx->stmt_insert_kubernetes_event);
        flb_plg_error(ctx->ins, "cannot execute insert kubernetes event %s inode=%lu",
                      uid, resource_version);
        flb_sds_destroy(uid);
        return -1;
    }

    flb_plg_debug(ctx->ins,
                  "inserted k8s event: uid=%s, resource_version=%lu, last=%ld",
                  uid, resource_version, last);
    sqlite3_clear_bindings(ctx->stmt_insert_kubernetes_event);
    sqlite3_reset(ctx->stmt_insert_kubernetes_event);

    flb_sds_destroy(uid);
    return flb_sqldb_last_id(ctx->db);
}

#endif

static int k8s_events_collect(struct flb_input_instance *ins,
                              struct flb_config *config, void *in_context)
{
    int ret;
    size_t b_sent;
    struct flb_connection *u_conn = NULL;
    struct flb_http_client *c = NULL;
    struct k8s_events *ctx = in_context;
    flb_sds_t continue_token = NULL;
    uint64_t max_resource_version = 0;

    if (pthread_mutex_trylock(&ctx->lock) != 0) {
        FLB_INPUT_RETURN(0);
    }

    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto exit;
    }

    ret = refresh_token_if_needed(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to refresh token");
        goto exit;
    }

    do {
        c = make_event_api_request(ctx, u_conn, continue_token);
        if (continue_token != NULL) {
            flb_sds_destroy(continue_token);
            continue_token = NULL;
        }
        if (!c) {
            flb_plg_error(ins, "unable to create http client");
            goto exit;
        }
        flb_http_buffer_size(c, 0);

        flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
        if (ctx->auth_len > 0) {
            flb_http_add_header(c, "Authorization", 13, ctx->auth, ctx->auth_len);
        }

        ret = flb_http_do(c, &b_sent);
        if (ret != 0) {
            flb_plg_error(ins, "http do error");
            goto exit;
        }

        if (c->resp.status == 200) {
            ret = process_events(ctx, c->resp.payload, c->resp.payload_size, &max_resource_version, &continue_token);
        }
        else {
            if (c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "http_status=%i:\n%s", c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "http_status=%i", c->resp.status);
            }
        }
        flb_http_client_destroy(c);
        c = NULL;
    } while(continue_token != NULL);

    if (max_resource_version > ctx->last_resource_version) {
        flb_plg_debug(ctx->ins, "set last resourceVersion=%lu", max_resource_version);
        ctx->last_resource_version = max_resource_version;
    }

exit:
    pthread_mutex_unlock(&ctx->lock);
    if (c) {
        flb_http_client_destroy(c);
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    FLB_INPUT_RETURN(0);
}

static int k8s_events_init(struct flb_input_instance *ins,
                           struct flb_config *config, void *data)
{
    struct k8s_events *ctx = NULL;

    ctx = k8s_events_conf_create(ins);
    if (!ctx) {
        return -1;
    }

    ctx->coll_id = flb_input_set_collector_time(ins,
                                                k8s_events_collect,
                                                ctx->interval_sec,
                                                ctx->interval_nsec,
                                                config);

#ifdef FLB_HAVE_SQLDB
    if (ctx->db) {
        ctx->coll_cleanup_id = flb_input_set_collector_time(ins,
                                                            k8s_events_cleanup_db,
                                                            ctx->interval_sec,
                                                            ctx->interval_nsec,
                                                            config);
    }
#endif

    return 0;
}

static int k8s_events_exit(void *data, struct flb_config *config)
{
    struct k8s_events *ctx = data;

    if (!ctx) {
        return 0;
    }

    k8s_events_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    /* Full Kubernetes API server URL */
    {
     FLB_CONFIG_MAP_STR, "kube_url", "https://kubernetes.default.svc",
     0, FLB_FALSE, 0,
     "Kubernetes API server URL"
    },

    /* Refresh interval */
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct k8s_events, interval_sec),
      "Set the polling interval for each channel"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct k8s_events, interval_nsec),
      "Set the polling interval for each channel (sub seconds)"
    },

    /* TLS: set debug 'level' */
    {
     FLB_CONFIG_MAP_INT, "tls.debug", "0",
     0, FLB_TRUE, offsetof(struct k8s_events, tls_debug),
     "set TLS debug level: 0 (no debug), 1 (error), "
     "2 (state change), 3 (info) and 4 (verbose)"
    },

    /* TLS: enable verification */
    {
     FLB_CONFIG_MAP_BOOL, "tls.verify", "true",
     0, FLB_TRUE, offsetof(struct k8s_events, tls_verify),
     "enable or disable verification of TLS peer certificate"
    },

    /* TLS: set tls.vhost feature */
    {
     FLB_CONFIG_MAP_STR, "tls.vhost", NULL,
     0, FLB_TRUE, offsetof(struct k8s_events, tls_vhost),
     "set optional TLS virtual host"
    },

    /* Kubernetes TLS: CA file */
    {
     FLB_CONFIG_MAP_STR, "kube_ca_file", K8S_EVENTS_KUBE_CA,
     0, FLB_TRUE, offsetof(struct k8s_events, tls_ca_file),
     "Kubernetes TLS CA file"
    },

    /* Kubernetes TLS: CA certs path */
    {
     FLB_CONFIG_MAP_STR, "kube_ca_path", NULL,
     0, FLB_TRUE, offsetof(struct k8s_events, tls_ca_path),
     "Kubernetes TLS ca path"
    },

    /* Kubernetes Token file */
    {
     FLB_CONFIG_MAP_STR, "kube_token_file", K8S_EVENTS_KUBE_TOKEN,
     0, FLB_TRUE, offsetof(struct k8s_events, token_file),
     "Kubernetes authorization token file"
    },

    /* Kubernetes Token file TTL */
    {
     FLB_CONFIG_MAP_TIME, "kube_token_ttl", "10m",
     0, FLB_TRUE, offsetof(struct k8s_events, token_ttl),
     "kubernetes token ttl, until it is reread from the token file. Default: 10m"
    },

    {
     FLB_CONFIG_MAP_INT, "kube_request_limit", "0",
     0, FLB_TRUE, offsetof(struct k8s_events, limit_request),
     "kubernetes limit parameter for events query, no limit applied when set to 0"
    },

    {
      FLB_CONFIG_MAP_TIME, "kube_retention_time", "1h",
      0, FLB_TRUE, offsetof(struct k8s_events, retention_time),
      "kubernetes retention time for events. Default: 1h"
    },

#ifdef FLB_HAVE_SQLDB
    {
      FLB_CONFIG_MAP_STR, "db", NULL,
      0, FLB_FALSE, 0,
      "set a database file to keep track of recorded kubernetes events."
    },
    {
     FLB_CONFIG_MAP_STR, "db.sync", "normal",
     0, FLB_FALSE, 0,
     "set a database sync method. values: extra, full, normal and off."
    },
#endif

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_kubernetes_events_plugin = {
    .name         = "kubernetes_events",
    .description  = "Kubernetes Events",
    .cb_init      = k8s_events_init,
    .cb_pre_run   = NULL,
    .cb_collect   = k8s_events_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = k8s_events_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET | FLB_INPUT_CORO | FLB_INPUT_THREADED
};
