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
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <monkey/mk_core/mk_list.h>
#include <msgpack.h>
#include <stdlib.h>
#include <errno.h>

#include "ecs.h"

static int get_ecs_cluster_metadata(struct flb_filter_ecs *ctx);
static void flb_filter_ecs_destroy(struct flb_filter_ecs *ctx);

/* cluster meta is static so we can expose it on global ctx for other plugins to use */
static void expose_ecs_cluster_meta(struct flb_filter_ecs *ctx)
{
    struct flb_env *env;
    struct flb_config *config = ctx->ins->config;

    env = config->env;

    flb_env_set(env, "ecs", "enabled");

    if (ctx->cluster_metadata.cluster_name) {
        flb_env_set(env,
                    "aws.ecs.cluster_name",
                    ctx->cluster_metadata.cluster_name);
    }

    if (ctx->cluster_metadata.container_instance_arn) {
        flb_env_set(env,
                    "aws.ecs.container_instance_arn",
                    ctx->cluster_metadata.container_instance_arn);
    }

    if (ctx->cluster_metadata.container_instance_id) {
        flb_env_set(env,
                    "aws.ecs.container_instance_id",
                    ctx->cluster_metadata.container_instance_id);
    }

    if (ctx->cluster_metadata.ecs_agent_version) {
        flb_env_set(env,
                    "aws.ecs.ecs_agent_version",
                    ctx->cluster_metadata.container_instance_id);
    }
}

static int cb_ecs_init(struct flb_filter_instance *f_ins,
                       struct flb_config *config,
                       void *data)
{
    int ret;
    struct flb_filter_ecs *ctx = NULL;
    struct mk_list *head;
    struct mk_list *split;
    struct flb_kv *kv;
    struct flb_split_entry *sentry;
    int list_size;
    struct flb_ecs_metadata_key *ecs_meta = NULL;
    (void) data;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_filter_ecs));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = f_ins;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_filter_config_map_set(f_ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(f_ins, "configuration error");
        flb_free(ctx);
        return -1;
    }

    mk_list_init(&ctx->metadata_keys);
    ctx->metadata_keys_len = 0;
    mk_list_init(&ctx->metadata_buffers);

    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "add") == 0) {
            split = flb_utils_split(kv->val, ' ', 2);
            list_size = mk_list_size(split);

            if (list_size == 0 || list_size > 2) {
                flb_plg_error(ctx->ins, "Invalid config for %s", kv->key);
                flb_utils_split_free(split);
                goto error;
            }

            sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
            ecs_meta = flb_calloc(1, sizeof(struct flb_ecs_metadata_key));
            if (!ecs_meta) {
                flb_errno();
                flb_utils_split_free(split);
                goto error;
            }

            ecs_meta->key = flb_sds_create_len(sentry->value, sentry->len);
            if (!ecs_meta->key) {
                flb_errno();
                flb_utils_split_free(split);
                goto error;
            }

            sentry = mk_list_entry_last(split, struct flb_split_entry, _head);

            ecs_meta->template = flb_sds_create_len(sentry->value, sentry->len);
            if (!ecs_meta->template) {
                flb_errno();
                flb_utils_split_free(split);
                goto error;
            }

            ecs_meta->ra = flb_ra_create(ecs_meta->template, FLB_FALSE);
            if (ecs_meta->ra == NULL) {
                flb_plg_error(ctx->ins, "Could not parse template for `%s`", ecs_meta->key);
                flb_utils_split_free(split);
                goto error;
            }

            mk_list_add(&ecs_meta->_head, &ctx->metadata_keys);
            ctx->metadata_keys_len++;
            flb_utils_split_free(split);
        }
    }

    ctx->ecs_upstream = flb_upstream_create(config,
                                            ctx->ecs_host,
                                            ctx->ecs_port,
                                            FLB_IO_TCP,
                                            NULL);

    if (!ctx->ecs_upstream) {
        flb_errno();
        flb_plg_error(ctx->ins, "Could not create upstream connection to ECS Agent");
        goto error;
    }

    flb_stream_disable_async_mode(&ctx->ecs_upstream->base);
    ctx->has_cluster_metadata = FLB_FALSE;

    /* entries are only evicted when TTL is reached and a get is issued */
    ctx->container_hash_table = flb_hash_table_create_with_ttl(ctx->ecs_meta_cache_ttl,
                                                               FLB_HASH_TABLE_EVICT_OLDER,
                                                               FLB_ECS_FILTER_HASH_TABLE_SIZE,
                                                               FLB_ECS_FILTER_HASH_TABLE_SIZE);
    if (!ctx->container_hash_table) {
        flb_plg_error(f_ins, "failed to create container_hash_table");
        goto error;
    }

    ctx->failed_metadata_request_tags = flb_hash_table_create_with_ttl(ctx->ecs_meta_cache_ttl,
                                                                       FLB_HASH_TABLE_EVICT_OLDER,
                                                                       FLB_ECS_FILTER_HASH_TABLE_SIZE,
                                                                       FLB_ECS_FILTER_HASH_TABLE_SIZE);
    if (!ctx->failed_metadata_request_tags) {
        flb_plg_error(f_ins, "failed to create failed_metadata_request_tags table");
        goto error;
    }

    ctx->ecs_tag_prefix_len = strlen(ctx->ecs_tag_prefix);

    /* attempt to get metadata in init, can retry in cb_filter */
    ret = get_ecs_cluster_metadata(ctx);

    flb_filter_set_context(f_ins, ctx);
    return 0;

error:
    flb_plg_error(ctx->ins, "Initialization failed.");
    flb_filter_ecs_destroy(ctx);
    return -1;
}

static int plugin_under_test()
{
    if (getenv("FLB_ECS_PLUGIN_UNDER_TEST") != NULL) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static char *mock_error_response(char *error_env_var)
{
    char *err_val = NULL;
    char *error = NULL;
    int len = 0;

    err_val = getenv(error_env_var);
    if (err_val != NULL && strlen(err_val) > 0) {
        error = flb_malloc(strlen(err_val) + sizeof(char));
        if (error == NULL) {
            flb_errno();
            return NULL;
        }

        len = strlen(err_val);
        memcpy(error, err_val, len);
        error[len] = '\0';
        return error;
    }

    return NULL;
}

static struct flb_http_client *mock_http_call(char *error_env_var, char *api)
{
    /* create an http client so that we can set the response */
    struct flb_http_client *c = NULL;
    char *error = mock_error_response(error_env_var);

    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        flb_free(error);
        return NULL;
    }
    mk_list_init(&c->headers);

    if (error != NULL) {
        c->resp.status = 400;
        /* resp.data is freed on destroy, payload is supposed to reference it */
        c->resp.data = error;
        c->resp.payload = c->resp.data;
        c->resp.payload_size = strlen(error);
    }
    else {
        c->resp.status = 200;
        if (strcmp(api, "Cluster") == 0) {
            /* mocked success response */
            c->resp.payload = "{\"Cluster\": \"cluster_name\",\"ContainerInstanceArn\": \"arn:aws:ecs:region:aws_account_id:container-instance/cluster_name/container_instance_id\",\"Version\": \"Amazon ECS Agent - v1.30.0 (02ff320c)\"}";
            c->resp.payload_size = strlen(c->resp.payload);
        }
        else {
            c->resp.payload = "{\"Arn\": \"arn:aws:ecs:us-west-2:012345678910:task/default/e01d58a8-151b-40e8-bc01-22647b9ecfec\",\"Containers\": [{\"DockerId\": \"79c796ed2a7f864f485c76f83f3165488097279d296a7c05bd5201a1c69b2920\",\"DockerName\": \"ecs-nginx-efs-2-nginx-9ac0808dd0afa495f001\",\"Name\": \"nginx\"}],\"DesiredStatus\": \"RUNNING\",\"Family\": \"nginx-efs\",\"KnownStatus\": \"RUNNING\",\"Version\": \"2\"}";
            c->resp.payload_size = strlen(c->resp.payload);
        }
    }

    return c;
}

/*
 * Both container instance and task ARNs have the ID at the end after last '/'
 */
static flb_sds_t parse_id_from_arn(const char *arn, int len)
{
    int i;
    flb_sds_t ID = NULL;
    int last_slash = 0;
    int id_start = 0;

    for (i = 0; i < len; i++) {
        if (arn[i] == '/') {
            last_slash = i;
        }
    }

    if (last_slash == 0 || last_slash >= len - 2) {
        return NULL;
    }
    id_start = last_slash + 1;

    ID = flb_sds_create_len(arn + id_start, len - id_start);
    if (ID == NULL) {
        flb_errno();
        return NULL;
    }

    return ID;
}

/*
 * This deserializes the msgpack metadata buf to msgpack_object
 * which can be used with flb_ra_translate in the main filter callback
 */
static int flb_ecs_metadata_buffer_init(struct flb_filter_ecs *ctx,
                                        struct flb_ecs_metadata_buffer *meta)
{
    msgpack_unpacked result;
    msgpack_object root;
    size_t off = 0;
    int ret;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, meta->buf, meta->size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack flb_ecs_metadata_buffer");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "Cannot unpack flb_ecs_metadata_buffer, msgpack_type=%i",
                      root.type);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    meta->unpacked = result;
    meta->obj = root;
    meta->last_used_time = time(NULL);
    meta->free_packer = FLB_TRUE;

    return 0;
}

static void flb_ecs_metadata_buffer_destroy(struct flb_ecs_metadata_buffer *meta)
{
    if (meta) {
        flb_free(meta->buf);
        if (meta->free_packer == FLB_TRUE) {
            msgpack_unpacked_destroy(&meta->unpacked);
        }
        if (meta->id) {
            flb_sds_destroy(meta->id);
        }
        flb_free(meta);
    }
}

/*
 * Get cluster and container instance info, which are static and never change
 */
static int get_ecs_cluster_metadata(struct flb_filter_ecs *ctx)
{
    struct flb_http_client *c;
    struct flb_connection *u_conn;
    int ret;
    int root_type;
    int found_cluster = FLB_FALSE;
    int found_version = FLB_FALSE;
    int found_instance = FLB_FALSE;
    int free_conn = FLB_FALSE;
    int i;
    int len;
    char *buffer;
    size_t size;
    size_t b_sent;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object key;
    msgpack_object val;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    flb_sds_t container_instance_id = NULL;
    flb_sds_t tmp = NULL;
    
    /* Compose HTTP Client request*/
    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_CLUSTER_ERROR", "Cluster");
        ret = 0;
    }
    else {
        u_conn = flb_upstream_conn_get(ctx->ecs_upstream);

        if (!u_conn) {
            flb_plg_error(ctx->ins, "ECS agent introspection endpoint connection error");
            return -1;
        }
        free_conn = FLB_TRUE;
        c = flb_http_client(u_conn, FLB_HTTP_GET,
                            FLB_ECS_FILTER_CLUSTER_PATH,
                            NULL, 0, 
                            ctx->ecs_host, ctx->ecs_port,
                            NULL, 0);
        flb_http_buffer_size(c, 0); /* 0 means unlimited */

        flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

        ret = flb_http_do(c, &b_sent);
        flb_plg_debug(ctx->ins, "http_do=%i, "
                    "HTTP Status: %i",
                    ret, c->resp.status);
    }

    if (ret != 0 || c->resp.status != 200) {
        if (c->resp.payload_size > 0) {
            flb_plg_warn(ctx->ins, "Failed to get metadata from %s, will retry", 
                         FLB_ECS_FILTER_CLUSTER_PATH);
            flb_plg_debug(ctx->ins, "HTTP response\n%s",
                          c->resp.payload);
        } else {
            flb_plg_warn(ctx->ins, "%s response status was %d with no payload, will retry", 
                         FLB_ECS_FILTER_CLUSTER_PATH,
                         c->resp.status);
        }
        flb_http_client_destroy(c);
        if (free_conn == FLB_TRUE) {
            flb_upstream_conn_release(u_conn);
        }
        return -1;
    }

    if (free_conn == FLB_TRUE) {
        flb_upstream_conn_release(u_conn);
    }

    ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                        &buffer, &size, &root_type, NULL);

    if (ret < 0) {
        flb_plg_warn(ctx->ins, "Could not parse response from %s; response=\n%s", 
                     FLB_ECS_FILTER_CLUSTER_PATH, c->resp.payload);
        flb_http_client_destroy(c);
        return -1;
    }

    /* parse metadata response */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buffer, size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack %s response to find metadata\n%s",
                      FLB_ECS_FILTER_CLUSTER_PATH, c->resp.payload);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        flb_http_client_destroy(c);
        return -1;
    }

    flb_http_client_destroy(c);

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "%s response parsing failed, msgpack_type=%i",
                      FLB_ECS_FILTER_CLUSTER_PATH,
                      root.type);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* 
Metadata Response:
{
    "Cluster": "cluster_name",
    "ContainerInstanceArn": "arn:aws:ecs:region:aws_account_id:container-instance/cluster_name/container_instance_id",
    "Version": "Amazon ECS Agent - v1.30.0 (02ff320c)"
}
But our metadata keys names are:
{
    "ClusterName": "cluster_name",
    "ContainerInstanceArn": "arn:aws:ecs:region:aws_account_id:container-instance/cluster_name/container_instance_id",
    "ContainerInstanceID": "container_instance_id"
    "ECSAgentVersion": "Amazon ECS Agent - v1.30.0 (02ff320c)"
}
    */

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "%s response parsing failed, msgpack key type=%i",
                         FLB_ECS_FILTER_CLUSTER_PATH,
                         key.type);
            continue;
        }

        if (key.via.str.size == 7 && strncmp(key.via.str.ptr, "Cluster", 7) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Cluster' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            found_cluster = FLB_TRUE;
            if (ctx->cluster_metadata.cluster_name == NULL) {
                tmp = flb_sds_create_len(val.via.str.ptr, (int) val.via.str.size);
                if (!tmp) {
                    flb_errno();
                    flb_free(buffer);
                    msgpack_unpacked_destroy(&result);
                    return -1;
                }
                ctx->cluster_metadata.cluster_name = tmp;
            }

        }
        else if (key.via.str.size == 20 && strncmp(key.via.str.ptr, "ContainerInstanceArn", 20) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'ContainerInstanceArn' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            /* first the ARN */
            found_instance = FLB_TRUE;
            if (ctx->cluster_metadata.container_instance_arn == NULL) {
                tmp = flb_sds_create_len(val.via.str.ptr, (int) val.via.str.size);
                if (!tmp) {
                    flb_errno();
                    flb_free(buffer);
                    msgpack_unpacked_destroy(&result);
                    return -1;
                }
                ctx->cluster_metadata.container_instance_arn = tmp;
            }

            /* then the ID */
            if (ctx->cluster_metadata.container_instance_id == NULL) {
                container_instance_id = parse_id_from_arn(val.via.str.ptr,  (int) val.via.str.size);
                if (container_instance_id == NULL) {
                    flb_plg_error(ctx->ins, "metadata parsing: failed to get ID from %.*s",
                                (int) val.via.str.size, val.via.str.ptr);
                    flb_free(buffer);
                    msgpack_unpacked_destroy(&result);
                    return -1;
                }
                ctx->cluster_metadata.container_instance_id = container_instance_id;
            }

        } else if (key.via.str.size == 7 && strncmp(key.via.str.ptr, "Version", 7) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Version' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                return -1;
            }

            found_version = FLB_TRUE;
            if (ctx->cluster_metadata.ecs_agent_version == NULL) {
                tmp = flb_sds_create_len(val.via.str.ptr, (int) val.via.str.size);
                if (!tmp) {
                    flb_errno();
                    flb_free(buffer);
                    msgpack_unpacked_destroy(&result);
                    return -1;
                }
                ctx->cluster_metadata.ecs_agent_version = tmp;
            }
        }

    }

    flb_free(buffer);
    msgpack_unpacked_destroy(&result);

    if (found_cluster == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'Cluster' from %s response",
                      FLB_ECS_FILTER_CLUSTER_PATH);
        return -1;
    }
    if (found_instance == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'ContainerInstanceArn' from %s response",
                      FLB_ECS_FILTER_CLUSTER_PATH);
        return -1;
    }
    if (found_version == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'Version' from %s response",
                      FLB_ECS_FILTER_CLUSTER_PATH);
        return -1;
    }

    /* 
     * We also create a standalone cluster metadata msgpack object
     * This is used as a fallback for logs when we can't find the
     * task metadata for a log. It is valid to attach cluster meta
     * to eg. Docker daemon logs which are not an AWS ECS Task via
     * the `cluster_metadata_only` setting. 
     */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&tmp_pck, 4);

    msgpack_pack_str(&tmp_pck, 11);
    msgpack_pack_str_body(&tmp_pck,
                          "ClusterName",
                          11);
    len = flb_sds_len(ctx->cluster_metadata.cluster_name);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck,
                          ctx->cluster_metadata.cluster_name,
                          len);

    msgpack_pack_str(&tmp_pck, 20);
    msgpack_pack_str_body(&tmp_pck,
                          "ContainerInstanceArn",
                          20);
    len = flb_sds_len(ctx->cluster_metadata.container_instance_arn);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck,
                          ctx->cluster_metadata.container_instance_arn,
                          len);

    msgpack_pack_str(&tmp_pck, 19);
    msgpack_pack_str_body(&tmp_pck,
                          "ContainerInstanceID",
                          19);
    len = flb_sds_len(ctx->cluster_metadata.container_instance_id);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck,
                          ctx->cluster_metadata.container_instance_id,
                          len);

    msgpack_pack_str(&tmp_pck, 15);
    msgpack_pack_str_body(&tmp_pck,
                          "ECSAgentVersion",
                          15);
    len = flb_sds_len(ctx->cluster_metadata.ecs_agent_version);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck,
                          ctx->cluster_metadata.ecs_agent_version,
                          len);

    ctx->cluster_meta_buf.buf = tmp_sbuf.data;
    ctx->cluster_meta_buf.size =  tmp_sbuf.size;

    ret = flb_ecs_metadata_buffer_init(ctx, &ctx->cluster_meta_buf);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not init metadata buffer from %s response",
                      FLB_ECS_FILTER_CLUSTER_PATH);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        ctx->cluster_meta_buf.buf = NULL;
        ctx->cluster_meta_buf.size =  0;
        return -1;
    }

    ctx->has_cluster_metadata = FLB_TRUE;
    expose_ecs_cluster_meta(ctx);
    return 0;
}

/*
 * This is the helper function used by get_task_metadata()
 * that actually creates the final metadata msgpack buffer
 * with our final key names.
 * It collects cluster, task, and container metadata into one
The new metadata msgpack is flat and looks like:
{
    "ContainerID": "79c796ed2a7f864f485c76f83f3165488097279d296a7c05bd5201a1c69b2920",
    "DockerContainerName": "ecs-nginx-efs-2-nginx-9ac0808dd0afa495f001",
    "ECSContainerName": "nginx",

    "ClusterName": "cluster_name",
    "ContainerInstanceArn": "arn:aws:ecs:region:aws_account_id:container-instance/cluster_name/container_instance_id",
    "ContainerInstanceID": "container_instance_id"
    "ECSAgentVersion": "Amazon ECS Agent - v1.30.0 (02ff320c)"

    "TaskARN": "arn:aws:ecs:us-west-2:012345678910:task/default/example5-58ff-46c9-ae05-543f8example",
    "TaskID: "example5-58ff-46c9-ae05-543f8example",
    "TaskDefinitionFamily": "hello_world",
    "TaskDefinitionVersion": "8",
}
 */
static int process_container_response(struct flb_filter_ecs *ctx,
                                      msgpack_object container,
                                      struct flb_ecs_task_metadata task_meta)
{
    int ret;
    int found_id = FLB_FALSE;
    int found_ecs_name = FLB_FALSE;
    int found_docker_name = FLB_FALSE;
    int i;
    int len;
    struct flb_ecs_metadata_buffer *cont_meta_buf;
    msgpack_object key;
    msgpack_object val;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    flb_sds_t short_id = NULL;

    /* 
     * We copy the metadata response to a new buffer
     * So we can define the metadata key names
     */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* 3 container metadata keys, 4 for instance/cluster, 4 for the task */
    msgpack_pack_map(&tmp_pck, 11);

    /* 1st- process/pack the raw container metadata response */
    for (i = 0; i < container.via.map.size; i++) {
        key = container.via.map.ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "Container metadata parsing failed, msgpack key type=%i",
                         key.type);
            continue;
        }

        if (key.via.str.size == 8 && strncmp(key.via.str.ptr, "DockerId", 8) == 0) {
            val = container.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'DockerId' value type=%i",
                              val.type);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                if (short_id != NULL) {
                    flb_sds_destroy(short_id);
                }
                return -1;
            }

            /* save the short ID for hash table key */
            short_id = flb_sds_create_len(val.via.str.ptr, 12);
            if (!short_id) {
                flb_errno();
                msgpack_sbuffer_destroy(&tmp_sbuf);
                return -1;
            }

            found_id = FLB_TRUE;
            msgpack_pack_str(&tmp_pck, 11);
            msgpack_pack_str_body(&tmp_pck,
                                  "ContainerID",
                                  11);
            msgpack_pack_str(&tmp_pck, (int) val.via.str.size);
            msgpack_pack_str_body(&tmp_pck,
                                  val.via.str.ptr,
                                  (int) val.via.str.size);
        }
        else if (key.via.str.size == 10 && strncmp(key.via.str.ptr, "DockerName", 10) == 0) {
            val = container.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'DockerName' value type=%i",
                              val.type);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                if (short_id != NULL) {
                    flb_sds_destroy(short_id);
                }
                return -1;
            }

            /* first pack the ARN */
            found_docker_name = FLB_TRUE;
            msgpack_pack_str(&tmp_pck, 19);
            msgpack_pack_str_body(&tmp_pck,
                                  "DockerContainerName",
                                  19);
            msgpack_pack_str(&tmp_pck, (int) val.via.str.size);
            msgpack_pack_str_body(&tmp_pck,
                                  val.via.str.ptr,
                                  (int) val.via.str.size);
        } else if (key.via.str.size == 4 && strncmp(key.via.str.ptr, "Name", 4) == 0) {
            val = container.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Name' value type=%i",
                              val.type);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                if (short_id != NULL) {
                    flb_sds_destroy(short_id);
                }
                return -1;
            }

            found_ecs_name = FLB_TRUE;
            msgpack_pack_str(&tmp_pck, 16);
            msgpack_pack_str_body(&tmp_pck,
                                  "ECSContainerName",
                                  16);
            msgpack_pack_str(&tmp_pck, (int) val.via.str.size);
            msgpack_pack_str_body(&tmp_pck,
                                  val.via.str.ptr,
                                  (int) val.via.str.size);
        }
    }

    if (found_id == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse Task 'DockerId' from container response");
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return -1;
    }
    if (found_docker_name == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'DockerName' from container response");
        msgpack_sbuffer_destroy(&tmp_sbuf);
        if (short_id != NULL) {
            flb_sds_destroy(short_id);
        }
        return -1;
    }
    if (found_ecs_name == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'Name' from container response");
        msgpack_sbuffer_destroy(&tmp_sbuf);
        if (short_id != NULL) {
            flb_sds_destroy(short_id);
        }
        return -1;
    }

    /* 2nd - Add the task fields from the task_meta temp buf we were given */
    msgpack_pack_str(&tmp_pck, 20);
    msgpack_pack_str_body(&tmp_pck,
                          "TaskDefinitionFamily",
                          20);
    msgpack_pack_str(&tmp_pck, task_meta.task_def_family_len);
    msgpack_pack_str_body(&tmp_pck,
                          task_meta.task_def_family,
                          task_meta.task_def_family_len);

    msgpack_pack_str(&tmp_pck, 7);
    msgpack_pack_str_body(&tmp_pck,
                          "TaskARN",
                          7);
    msgpack_pack_str(&tmp_pck, task_meta.task_arn_len);
    msgpack_pack_str_body(&tmp_pck,
                          task_meta.task_arn,
                          task_meta.task_arn_len);
    msgpack_pack_str(&tmp_pck, 6);
    msgpack_pack_str_body(&tmp_pck,
                          "TaskID",
                          6);
    msgpack_pack_str(&tmp_pck, task_meta.task_id_len);
    msgpack_pack_str_body(&tmp_pck,
                          task_meta.task_id,
                          task_meta.task_id_len);

    msgpack_pack_str(&tmp_pck, 21);
    msgpack_pack_str_body(&tmp_pck,
                          "TaskDefinitionVersion",
                          21);
    msgpack_pack_str(&tmp_pck, task_meta.task_def_version_len);
    msgpack_pack_str_body(&tmp_pck,
                          task_meta.task_def_version,
                          task_meta.task_def_version_len);

    /* 3rd - Add the static cluster fields from the plugin context */
    msgpack_pack_str(&tmp_pck, 11);
    msgpack_pack_str_body(&tmp_pck,
                          "ClusterName",
                          11);
    len = flb_sds_len(ctx->cluster_metadata.cluster_name);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck,
                          ctx->cluster_metadata.cluster_name,
                          len);

    msgpack_pack_str(&tmp_pck, 20);
    msgpack_pack_str_body(&tmp_pck,
                          "ContainerInstanceArn",
                          20);
    len = flb_sds_len(ctx->cluster_metadata.container_instance_arn);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck,
                          ctx->cluster_metadata.container_instance_arn,
                          len);

    msgpack_pack_str(&tmp_pck, 19);
    msgpack_pack_str_body(&tmp_pck,
                          "ContainerInstanceID",
                          19);
    len = flb_sds_len(ctx->cluster_metadata.container_instance_id);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck,
                          ctx->cluster_metadata.container_instance_id,
                          len);

    msgpack_pack_str(&tmp_pck, 15);
    msgpack_pack_str_body(&tmp_pck,
                          "ECSAgentVersion",
                          15);
    len = flb_sds_len(ctx->cluster_metadata.ecs_agent_version);
    msgpack_pack_str(&tmp_pck, len);
    msgpack_pack_str_body(&tmp_pck,
                          ctx->cluster_metadata.ecs_agent_version,
                          len);

    cont_meta_buf = flb_calloc(1, sizeof(struct flb_ecs_metadata_buffer));
    if (!cont_meta_buf) {
        flb_errno();
        msgpack_sbuffer_destroy(&tmp_sbuf);
        flb_sds_destroy(short_id);
        return -1;
    }

    cont_meta_buf->buf = tmp_sbuf.data;
    cont_meta_buf->size = tmp_sbuf.size;

    ret = flb_ecs_metadata_buffer_init(ctx, cont_meta_buf);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not init metadata buffer from container response");
        msgpack_sbuffer_destroy(&tmp_sbuf);
        flb_free(cont_meta_buf);
        flb_sds_destroy(short_id);
        return -1;
    }
    cont_meta_buf->id = short_id;
    mk_list_add(&cont_meta_buf->_head, &ctx->metadata_buffers);
    
    /* 
     * Size is set to 0 so the table just stores our pointer 
     * Otherwise it will try to copy the memory to a new buffer
     */
    ret = flb_hash_table_add(ctx->container_hash_table,
                             short_id, strlen(short_id),
                             cont_meta_buf, 0);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not add container ID %s to metadata hash table",
                      short_id);
        flb_ecs_metadata_buffer_destroy(cont_meta_buf);
    } else {
        ret = 0;
        flb_plg_debug(ctx->ins, "Added `%s` to container metadata hash table",
                      short_id);
    }
    return ret;
}

/*
 * Gets the container and task metadata for a task via a container's
 * 12 char short ID. This can be used with the ECS Agent
 * Introspection API: http://localhost:51678/v1/tasks?dockerid={short_id}
 * Entries in the hash table will be added for all containers in the task
 */
static int get_task_metadata(struct flb_filter_ecs *ctx, char* short_id)
{
    struct flb_http_client *c;
    struct flb_connection *u_conn;
    int ret;
    int root_type;
    int found_task = FLB_FALSE;
    int found_version = FLB_FALSE;
    int found_family = FLB_FALSE;
    int found_containers = FLB_FALSE;
    int free_conn = FLB_FALSE;
    int i;
    int k;
    char *buffer;
    size_t size;
    size_t b_sent;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object key;
    msgpack_object val;
    msgpack_object container;
    flb_sds_t tmp;
    flb_sds_t http_path;
    flb_sds_t task_id = NULL;
    struct flb_ecs_task_metadata task_meta;

    tmp = flb_sds_create_size(64);
    if (!tmp) {
        return -1;
    }
    http_path = flb_sds_printf(&tmp, FLB_ECS_FILTER_TASK_PATH_FORMAT, short_id);
    if (!http_path) {
        flb_sds_destroy(tmp);
        return -1;
    }
    
    /* Compose HTTP Client request*/
    if (plugin_under_test() == FLB_TRUE) {
        c = mock_http_call("TEST_TASK_ERROR", "Task");
        ret = 0;
    }
    else {
        u_conn = flb_upstream_conn_get(ctx->ecs_upstream);

        if (!u_conn) {
            flb_plg_error(ctx->ins, "ECS agent introspection endpoint connection error");
            flb_sds_destroy(http_path);
            return -1;
        }
        free_conn = FLB_TRUE;
        c = flb_http_client(u_conn, FLB_HTTP_GET,
                            http_path,
                            NULL, 0, 
                            ctx->ecs_host, ctx->ecs_port,
                            NULL, 0);
        flb_http_buffer_size(c, 0); /* 0 means unlimited */

        flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

        ret = flb_http_do(c, &b_sent);
        flb_plg_debug(ctx->ins, "http_do=%i, "
                    "HTTP Status: %i",
                    ret, c->resp.status);
    }

    if (ret != 0 || c->resp.status != 200) {
        if (c->resp.payload_size > 0) {
            flb_plg_warn(ctx->ins, "Failed to get metadata from %s, will retry", 
                         http_path);
            flb_plg_debug(ctx->ins, "HTTP response\n%s",
                          c->resp.payload);
        } else {
            flb_plg_warn(ctx->ins, "%s response status was %d with no payload, will retry", 
                         http_path,
                         c->resp.status);
        }
        flb_http_client_destroy(c);
        if (free_conn == FLB_TRUE) {
            flb_upstream_conn_release(u_conn);
        }
        flb_sds_destroy(http_path);
        return -1;
    }

    if (free_conn == FLB_TRUE) {
        flb_upstream_conn_release(u_conn);
    }

    ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                        &buffer, &size, &root_type, NULL);

    if (ret < 0) {
        flb_plg_warn(ctx->ins, "Could not parse response from %s; response=\n%s", 
                     http_path, c->resp.payload);
        flb_sds_destroy(http_path);
        flb_http_client_destroy(c);
        return -1;
    }

    /* parse metadata response */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buffer, size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack %s response to find metadata\n%s",
                      http_path, c->resp.payload);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        flb_sds_destroy(http_path);
        flb_http_client_destroy(c);
        return -1;
    }

    flb_http_client_destroy(c);

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "%s response parsing failed, msgpack_type=%i",
                      http_path,
                      root.type);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        flb_sds_destroy(http_path);
        return -1;
    }

    /*
Metadata Response:
{
    "Arn": "arn:aws:ecs:us-west-2:012345678910:task/default/e01d58a8-151b-40e8-bc01-22647b9ecfec",
    "Containers": [
        {
            "DockerId": "79c796ed2a7f864f485c76f83f3165488097279d296a7c05bd5201a1c69b2920",
            "DockerName": "ecs-nginx-efs-2-nginx-9ac0808dd0afa495f001",
            "Name": "nginx"
        }
    ],
    "DesiredStatus": "RUNNING",
    "Family": "nginx-efs",
    "KnownStatus": "RUNNING",
    "Version": "2"
}
    */

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "%s response parsing failed, msgpack key type=%i",
                         http_path,
                         key.type);
            continue;
        }

        if (key.via.str.size == 6 && strncmp(key.via.str.ptr, "Family", 6) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Family' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                flb_sds_destroy(http_path);
                if (task_id) {
                    flb_sds_destroy(task_id);
                }
                return -1;
            }
            found_family = FLB_TRUE;
            task_meta.task_def_family = val.via.str.ptr;
            task_meta.task_def_family_len = (int) val.via.str.size;
        }
        else if (key.via.str.size == 3 && strncmp(key.via.str.ptr, "Arn", 3) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Arn' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                flb_sds_destroy(http_path);
                if (task_id) {
                    flb_sds_destroy(task_id);
                }
                return -1;
            }
            /* first get the ARN */
            found_task = FLB_TRUE;
            task_meta.task_arn = val.via.str.ptr;
            task_meta.task_arn_len = (int) val.via.str.size;

            /* then get the ID */
            task_id = parse_id_from_arn(val.via.str.ptr,  (int) val.via.str.size);
            if (task_id == NULL) {
                flb_plg_error(ctx->ins, "metadata parsing: failed to get ID from %.*s",
                              (int) val.via.str.size, val.via.str.ptr);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                flb_sds_destroy(http_path);
                if (task_id) {
                    flb_sds_destroy(task_id);
                }
                return -1;
            }

            task_meta.task_id = task_id;
            task_meta.task_id_len = flb_sds_len(task_id);
        } else if (key.via.str.size == 7 && strncmp(key.via.str.ptr, "Version", 7) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_STR) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Version' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                flb_sds_destroy(http_path);
                if (task_id) {
                    flb_sds_destroy(task_id);
                }
                return -1;
            }
            found_version = FLB_TRUE;
            task_meta.task_def_version = val.via.str.ptr;
            task_meta.task_def_version_len = (int) val.via.str.size;
        } else if (key.via.str.size == 10 && strncmp(key.via.str.ptr, "Containers", 10) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_ARRAY ) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Containers' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                flb_sds_destroy(http_path);
                if (task_id) {
                    flb_sds_destroy(task_id);
                }
                return -1;
            }
            found_containers = FLB_TRUE;
        }
    }

    if (found_task == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse Task 'Arn' from %s response",
                      http_path);
        flb_sds_destroy(http_path);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        return -1;
    }
    if (found_family == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'Family' from %s response",
                      http_path);
        flb_sds_destroy(http_path);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        if (task_id) {
            flb_sds_destroy(task_id);
        }
        return -1;
    }
    if (found_version == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'Version' from %s response",
                      http_path);
        flb_sds_destroy(http_path);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        if (task_id) {
            flb_sds_destroy(task_id);
        }
        return -1;
    }
    if (found_containers == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Could not parse 'Containers' from %s response",
                      http_path);
        flb_sds_destroy(http_path);
        flb_free(buffer);
        msgpack_unpacked_destroy(&result);
        if (task_id) {
            flb_sds_destroy(task_id);
        }
        return -1;
    }

    /* 
     * Process metadata response a 2nd time to get the Containers list 
     * This is because we need one complete metadata buf per container
     * with all task metadata. So we collect task before we process containers.
     */
    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "%s response parsing failed, msgpack key type=%i",
                         http_path,
                         key.type);
            continue;
        }

        if (key.via.str.size == 10 && strncmp(key.via.str.ptr, "Containers", 10) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_ARRAY ) {
                flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Containers' value type=%i",
                              val.type);
                flb_free(buffer);
                msgpack_unpacked_destroy(&result);
                flb_sds_destroy(http_path);
                flb_sds_destroy(task_id);
                return -1;
            }

            /* iterate through list of containers and process them*/
            for (k = 0; k < val.via.array.size; k++) {
                container = val.via.array.ptr[k];
                if (container.type != MSGPACK_OBJECT_MAP) {
                    flb_plg_error(ctx->ins, "metadata parsing: unexpected 'Containers[%d]' inner value type=%i",
                                  k,
                                  container.type);
                    flb_free(buffer);
                    msgpack_unpacked_destroy(&result);
                    flb_sds_destroy(http_path);
                    flb_sds_destroy(task_id);
                    return -1;
                }
                ret = process_container_response(ctx, container, task_meta);
                if (ret < 0) {
                    flb_plg_error(ctx->ins, "metadata parsing: failed to parse 'Containers[%d]'",
                                  k);
                    flb_free(buffer);
                    msgpack_unpacked_destroy(&result);
                    flb_sds_destroy(http_path);
                    flb_sds_destroy(task_id);
                    return -1;
                }
            }
        }
    }

    flb_free(buffer);
    msgpack_unpacked_destroy(&result);
    flb_sds_destroy(task_id);
    flb_sds_destroy(http_path);
    return 0;
}

static int get_metadata_by_id(struct flb_filter_ecs *ctx, 
                              const char *tag, int tag_len,
                              struct flb_ecs_metadata_buffer **metadata_buffer)
{
    flb_sds_t container_short_id = NULL;
    const char *tmp;
    int ret;
    size_t size;

    if (ctx->ecs_tag_prefix_len + 12 > tag_len) {
        flb_plg_warn(ctx->ins, "Tag '%s' length check failed: tag is expected "
                     "to be or be prefixed with '{ecs_tag_prefix}{12 character container short ID}'",
                     tag);
        return -1;
    }

    ret = strncmp(ctx->ecs_tag_prefix, tag, ctx->ecs_tag_prefix_len);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "Tag '%s' is not prefixed with ecs_tag_prefix '%s'",
                     tag, ctx->ecs_tag_prefix);
        return -1;
    }

    tmp = tag + ctx->ecs_tag_prefix_len;
    container_short_id = flb_sds_create_len(tmp, 12);
    if (!container_short_id) {
        flb_errno();
        return -1;
    }

    /* get metadata for this container */
    ret = flb_hash_table_get(ctx->container_hash_table,
                             container_short_id, flb_sds_len(container_short_id),
                             (void **) metadata_buffer, &size);

    if (ret == -1) {
        /* try fetch metadata */
        ret = get_task_metadata(ctx, container_short_id);
        if (ret < 0) {
            flb_plg_info(ctx->ins, "Requesting metadata from ECS Agent introspection endpoint failed for tag %s",
                         tag);
            flb_sds_destroy(container_short_id);
            return -1;
        }
        /* get from hash table */
        ret = flb_hash_table_get(ctx->container_hash_table,
                                 container_short_id, flb_sds_len(container_short_id),
                                 (void **) metadata_buffer, &size);
    }

    flb_sds_destroy(container_short_id);
    return ret;
}

static void clean_old_metadata_buffers(struct flb_filter_ecs *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ecs_metadata_buffer *buf;
    time_t now = time(NULL);

    mk_list_foreach_safe(head, tmp, &ctx->metadata_buffers) {
        buf = mk_list_entry(head, struct flb_ecs_metadata_buffer, _head);
        if (now > (buf->last_used_time + ctx->ecs_meta_cache_ttl)) {
            flb_plg_debug(ctx->ins, "cleaning buffer: now=%ld, ttl=%d, last_used_time=%ld",
                          (long)now, ctx->ecs_meta_cache_ttl, (long)buf->last_used_time);
            mk_list_del(&buf->_head);
            flb_hash_table_del(ctx->container_hash_table, buf->id);
            flb_ecs_metadata_buffer_destroy(buf);
        }
    }
}

static int is_tag_marked_failed(struct flb_filter_ecs *ctx,
                                const char *tag, int tag_len)
{
    int ret;
    int *val = NULL;
    size_t val_size;

    ret = flb_hash_table_get(ctx->failed_metadata_request_tags,
                             tag, tag_len,
                             (void **) &val, &val_size);
    if (ret != -1) {
        if (*val >= ctx->agent_endpoint_retries) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static void mark_tag_failed(struct flb_filter_ecs *ctx,
                            const char *tag, int tag_len)
{
    int ret;
    int *val = NULL;
    int *new_val = NULL;
    size_t val_size;

    ret = flb_hash_table_get(ctx->failed_metadata_request_tags,
                             tag, tag_len,
                             (void **) &val, &val_size);

    if (ret == -1) {
        /* hash table copies memory to new heap block */
        val = flb_malloc(sizeof(int));
        if (!val) {
            flb_errno();
            return;
        }
        *val = 1;
        flb_hash_table_add(ctx->failed_metadata_request_tags,
                          tag, tag_len,
                          val, sizeof(int));
        /* hash table will contain a copy */
        flb_free(val);
    } else {
        /* 
         * val is memory returned from hash table 
         * if we simply update the value here and call flb_hash_add
         * it first frees the old memory (which is what we passed it)
         * then tries to copy over the memory we passed in to a new location
         * flb_hash stores all entries as if they were strings, so we also
         * can't simply increment the value returned by flb_hash_get
         */
        new_val = flb_malloc(sizeof(int));
        if (!new_val) {
            flb_errno();
            return;
        }
        /* increment number of failed metadata requests for this tag */
        *new_val = *val + 1;
        flb_hash_table_add(ctx->failed_metadata_request_tags,
                           tag, tag_len,
                           new_val, sizeof(int));
        flb_plg_info(ctx->ins, "Failed to get ECS Metadata for tag %s %d times. "
                    "This might be because the logs for this tag do not come from an ECS Task Container. "
                    "This plugin will retry metadata requests at most %d times total for this tag.",
                    tag, *new_val, ctx->agent_endpoint_retries);
        flb_free(new_val);
    }
}

static int cb_ecs_filter(const void *data, size_t bytes,
                         const char *tag, int tag_len,
                         void **out_buf, size_t *out_size,
                         struct flb_filter_instance *f_ins,
                         struct flb_input_instance *i_ins,
                         void *context,
                         struct flb_config *config)
{
    struct flb_filter_ecs *ctx = context;
    int i = 0;
    int ret;
    int check = FLB_FALSE;
    msgpack_object  *obj;
    msgpack_object_kv *kv;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ecs_metadata_key *metadata_key;
    struct flb_ecs_metadata_buffer *metadata_buffer;
    flb_sds_t val;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    /* First check that the static cluster metadata has been retrieved */
    if (ctx->has_cluster_metadata == FLB_FALSE) {
        ret = get_ecs_cluster_metadata(ctx);
        if (ret < 0) {
            flb_plg_warn(ctx->ins, "Could not retrieve cluster metadata "
                         "from ECS Agent");
            return FLB_FILTER_NOTOUCH;
        }
    }

    /* check if the current tag is marked as failed */
    check = is_tag_marked_failed(ctx, tag, tag_len);
    if (check == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "Failed to get ECS Metadata for tag %s %d times. "
                      "Will not attempt to retry the metadata request. Will attach cluster metadata only.",
                      tag, ctx->agent_endpoint_retries);
    }

    if (check == FLB_FALSE && ctx->cluster_metadata_only == FLB_FALSE) {
        ret = get_metadata_by_id(ctx, tag, tag_len, &metadata_buffer);
        if (ret == -1) {
            flb_plg_info(ctx->ins, "Failed to get ECS Task metadata for %s, "
                        "falling back to process cluster metadata only. If "
                        "this is intentional, set `Cluster_Metadata_Only On`",
                        tag);
            mark_tag_failed(ctx, tag, tag_len);
            metadata_buffer = &ctx->cluster_meta_buf;
        }
    } else {
        metadata_buffer = &ctx->cluster_meta_buf;
    }

    metadata_buffer->last_used_time = time(NULL);

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        obj = log_event.body;

        ret = flb_log_event_encoder_begin_record(&log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_timestamp(
                    &log_encoder, &log_event.timestamp);
        }

        /* iterate through the old record map and add it to the new buffer */
        kv = obj->via.map.ptr;
        for(i=0;
            i < obj->via.map.size &&
            ret == FLB_EVENT_ENCODER_SUCCESS;
            i++) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].key),
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].val));
        }

        /* append new keys */
        mk_list_foreach_safe(head, tmp, &ctx->metadata_keys) {
            metadata_key = mk_list_entry(head, struct flb_ecs_metadata_key, _head);
            val = flb_ra_translate(metadata_key->ra, NULL, 0,
                                   metadata_buffer->obj, NULL);
            if (!val) {
                flb_plg_info(ctx->ins, "Translation failed for %s : %s",
                             metadata_key->key, metadata_key->template);

                flb_log_event_decoder_destroy(&log_decoder);
                flb_log_event_encoder_destroy(&log_encoder);

                return FLB_FILTER_NOTOUCH;
            }

            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_STRING_VALUE(metadata_key->key,
                                               flb_sds_len(metadata_key->key)),
                    FLB_LOG_EVENT_STRING_VALUE(val, flb_sds_len(val)));

            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_info(ctx->ins,
                             "Metadata appendage failed for %.*s",
                             (int) flb_sds_len(metadata_key->key),
                             metadata_key->key);

                flb_log_event_decoder_destroy(&log_decoder);
                flb_log_event_encoder_destroy(&log_encoder);

                return FLB_FILTER_NOTOUCH;
            }

            flb_sds_destroy(val);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_commit_record(&log_encoder);
        }
    }

    if (ctx->cluster_metadata_only == FLB_FALSE) {
        clean_old_metadata_buffers(ctx);
    }

    if (ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA &&
        log_decoder.offset == bytes) {
        ret = FLB_EVENT_ENCODER_SUCCESS;
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        *out_buf  = log_encoder.output_buffer;
        *out_size = log_encoder.output_length;

        ret = FLB_FILTER_MODIFIED;

        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
    }
    else {
        flb_plg_error(ctx->ins,
                      "Log event encoder error : %d", ret);

        ret = FLB_FILTER_NOTOUCH;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
}

static void flb_ecs_metadata_key_destroy(struct flb_ecs_metadata_key *metadata_key)
{
    if (metadata_key) {
        if (metadata_key->key) {
            flb_sds_destroy(metadata_key->key);
        }
        if (metadata_key->template) {
            flb_sds_destroy(metadata_key->template);
        }
        if (metadata_key->ra) {
             flb_ra_destroy(metadata_key->ra);
        }
        flb_free(metadata_key);
    }
}

static void flb_filter_ecs_destroy(struct flb_filter_ecs *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ecs_metadata_key *metadata_key;
    struct flb_ecs_metadata_buffer *buf;

    if (ctx) {
        if (ctx->ecs_upstream) {
            flb_upstream_destroy(ctx->ecs_upstream);
        }
        if (ctx->cluster_metadata.cluster_name) {
            flb_sds_destroy(ctx->cluster_metadata.cluster_name);
        }
        if (ctx->cluster_metadata.container_instance_arn) {
            flb_sds_destroy(ctx->cluster_metadata.container_instance_arn);
        }
        if (ctx->cluster_metadata.container_instance_id) {
            flb_sds_destroy(ctx->cluster_metadata.container_instance_id);
        }
        if (ctx->cluster_metadata.ecs_agent_version) {
            flb_sds_destroy(ctx->cluster_metadata.ecs_agent_version);
        }
        if (ctx->cluster_meta_buf.buf) {
            flb_free(ctx->cluster_meta_buf.buf);
            msgpack_unpacked_destroy(&ctx->cluster_meta_buf.unpacked);
        }
        mk_list_foreach_safe(head, tmp, &ctx->metadata_keys) {
            metadata_key = mk_list_entry(head, struct flb_ecs_metadata_key, _head);
            mk_list_del(&metadata_key->_head);
            flb_ecs_metadata_key_destroy(metadata_key);
        }
        mk_list_foreach_safe(head, tmp, &ctx->metadata_buffers) {
            buf = mk_list_entry(head, struct flb_ecs_metadata_buffer, _head);
            mk_list_del(&buf->_head);
            flb_hash_table_del(ctx->container_hash_table, buf->id);
            flb_ecs_metadata_buffer_destroy(buf);
        }
        if (ctx->container_hash_table) {
            flb_hash_table_destroy(ctx->container_hash_table);
        }
        if (ctx->failed_metadata_request_tags) {
            flb_hash_table_destroy(ctx->failed_metadata_request_tags);
        }
        flb_free(ctx);
    }
}

static int cb_ecs_exit(void *data, struct flb_config *config)
{
    struct flb_filter_ecs *ctx = data;

    flb_filter_ecs_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {

    {
     FLB_CONFIG_MAP_STR, "add", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Add a metadata key/value pair with the given key and given value from the given template. "
     "Format is `Add KEY TEMPLATE`."
    },

    {
     FLB_CONFIG_MAP_STR, "ecs_tag_prefix", "",
     0, FLB_TRUE, offsetof(struct flb_filter_ecs, ecs_tag_prefix),
     "This filter must obtain the 12 character container short ID to query "
     "for ECS Task metadata. The filter removes the prefx from the tag and then assumes "
     "the next 12 characters are the short container ID. If the container short ID, "
     "is not found in the tag, the filter can/must fallback to only attaching cluster metadata "
     "(cluster name, container instance ID/ARN, and ECS Agent version)."
    },

    {
     FLB_CONFIG_MAP_BOOL, "cluster_metadata_only", "false",
     0, FLB_TRUE, offsetof(struct flb_filter_ecs, cluster_metadata_only),
     "Only attempt to attach the cluster related metadata to logs "
     "(cluster name, container instance ID/ARN, and ECS Agent version). "
     "With this option off, if this filter can not obtain the task metadata for a log, it will "
     "output errors. Use this option if you have logs that are not part of an "
     "ECS task (ex: Docker Daemon logs)."
    },

    {
     FLB_CONFIG_MAP_TIME, "ecs_meta_cache_ttl", "3600",
     0, FLB_TRUE, offsetof(struct flb_filter_ecs, ecs_meta_cache_ttl),
     "Configurable TTL for cached ECS Task Metadata. Default 3600s (1 hour)" 
     "For example, set this value to 600 or 600s or 10m and cache entries " 
     "which have been created more than 10 minutes will be evicted."
     "Cache eviction is needed to purge task metadata for tasks that "
     "have been stopped."
    },

    {
     FLB_CONFIG_MAP_STR, "ecs_meta_host", FLB_ECS_FILTER_HOST,
     0, FLB_TRUE, offsetof(struct flb_filter_ecs, ecs_host),
     "The host name at which the ECS Agent Introspection endpoint is reachable. "
     "Defaults to 127.0.0.1"
    },

    {
     FLB_CONFIG_MAP_INT, "ecs_meta_port", FLB_ECS_FILTER_PORT,
     0, FLB_TRUE, offsetof(struct flb_filter_ecs, ecs_port),
     "The port at which the ECS Agent Introspection endpoint is reachable. "
     "Defaults to 51678"
    },

    {
     FLB_CONFIG_MAP_INT, "agent_endpoint_retries", FLB_ECS_FILTER_METADATA_RETRIES,
     0, FLB_TRUE, offsetof(struct flb_filter_ecs, agent_endpoint_retries),
     "Number of retries for failed metadata requests to ECS Agent Introspection "
     "endpoint. The most common cause of failed metadata requests is that the "
     "container the metadata request was made for is not part of an ECS Task. "
     "Check if you have non-task containers and docker dual logging enabled."
    },

    {0}
};

struct flb_filter_plugin filter_ecs_plugin = {
    .name         = "ecs",
    .description  = "Add AWS ECS Metadata",
    .cb_init      = cb_ecs_init,
    .cb_filter    = cb_ecs_filter,
    .cb_exit      = cb_ecs_exit,
    .config_map   = config_map,
    .flags        = 0
};
