/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <monkey/mk_core/mk_list.h>
#include <msgpack.h>
#include <stdlib.h>
#include <errno.h>

#include "aws.h"

static int get_ec2_token(struct flb_filter_aws *ctx);
static int get_metadata(struct flb_filter_aws *ctx, char *metadata_path,
                        flb_sds_t *metadata, size_t *metadata_len);
static int get_ec2_metadata(struct flb_filter_aws *ctx);
static int get_metadata_by_key(struct flb_filter_aws *ctx, char *metadata_path,
                               flb_sds_t *metadata, size_t *metadata_len, char *key);

static void expose_aws_meta(struct flb_filter_aws *ctx)
{
    struct flb_env *env;
    struct flb_config *config = ctx->ins->config;

    env = config->env;

    flb_env_set(env, "aws", "enabled");

    if (ctx->availability_zone_include) {
        flb_env_set(env,
                    "aws." FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY,
                    ctx->availability_zone);
    }

    if (ctx->instance_id_include) {
        flb_env_set(env,
                    "aws." FLB_FILTER_AWS_INSTANCE_ID_KEY,
                    ctx->instance_id);
    }

    if (ctx->instance_type_include) {
        flb_env_set(env,
                    "aws." FLB_FILTER_AWS_INSTANCE_TYPE_KEY,
                    ctx->instance_type);
    }

    if (ctx->private_ip_include) {
        flb_env_set(env,
                    "aws." FLB_FILTER_AWS_PRIVATE_IP_KEY,
                    ctx->private_ip);
    }

    if (ctx->vpc_id_include) {
        flb_env_set(env,
                    "aws." FLB_FILTER_AWS_VPC_ID_KEY,
                    ctx->vpc_id);
    }

    if (ctx->ami_id_include) {
        flb_env_set(env,
                    "aws." FLB_FILTER_AWS_AMI_ID_KEY,
                    ctx->ami_id);
    }

    if (ctx->account_id_include) {
        flb_env_set(env,
                    "aws." FLB_FILTER_AWS_ACCOUNT_ID_KEY,
                    ctx->account_id);
    }

    if (ctx->hostname_include) {
        flb_env_set(env,
                    "aws." FLB_FILTER_AWS_HOSTNAME_KEY,
                    ctx->hostname);
    }
}

static int cb_aws_init(struct flb_filter_instance *f_ins,
                       struct flb_config *config,
                       void *data)
{
    int use_v2;
    int ret;
    struct flb_filter_aws *ctx = NULL;
    const char *tmp = NULL;
    (void) data;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_filter_aws));
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

    use_v2 = FLB_TRUE;
    tmp = flb_filter_get_property("imds_version", f_ins);
    if (tmp != NULL) {
        if (strcasecmp(tmp, "v1") == 0) {
            use_v2 = FLB_FALSE;
        }
        else if (strcasecmp(tmp, "v2") != 0) {
            flb_plg_error(ctx->ins, "Invalid value %s for config option "
                          "'imds_version'. Valid values are 'v1' and 'v2'",
                          tmp);
            flb_free(ctx);
            return -1;
        }
    }

    /* v1 or v2 instance metadata */
    ctx->use_v2 = use_v2;

    ctx->metadata_retrieved = FLB_FALSE;

    ctx->ec2_upstream = flb_upstream_create(config,
                                            FLB_FILTER_AWS_IMDS_HOST,
                                            80,
                                            FLB_IO_TCP,
                                            NULL);
    if (!ctx->ec2_upstream) {
        flb_plg_error(ctx->ins, "connection initialization error");
        flb_free(ctx);
        return -1;
    }

    /* Remove async flag from upstream */
    ctx->ec2_upstream->flags &= ~(FLB_IO_ASYNC);

    /* Retrieve metadata */
    ret = get_ec2_metadata(ctx);
    if (ret < 0) {
        /*
         * If metadata fails, just print the error. Every flush will try to
         * retrieve it if needed.
         */
        flb_plg_error(ctx->ins, "Could not retrieve ec2 metadata from IMDS "
                      "on initialization");
    }
    else {
        expose_aws_meta(ctx);
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

/* Get an IMDSv2 token */
static int get_ec2_token(struct flb_filter_aws *ctx)
{
    int ret;
    size_t b_sent;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *client;

    u_conn = flb_upstream_conn_get(ctx->ec2_upstream);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "connection initialization error");
        return -1;
    }

    /* Compose HTTP Client request */
    client = flb_http_client(u_conn, FLB_HTTP_PUT,
                             FLB_FILTER_AWS_IMDS_V2_TOKEN_PATH,
                             NULL, 0, FLB_FILTER_AWS_IMDS_HOST,
                             80, NULL, 0);

    if (!client) {
        flb_plg_error(ctx->ins, "count not create http client");
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    flb_http_add_header(client, FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_LEN,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL,
                        FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL_LEN);

    /* Perform request */
    ret = flb_http_do(client, &b_sent);
    flb_plg_debug(ctx->ins, "IMDSv2 token request http_do=%i, HTTP Status: %i",
              ret, client->resp.status);

    if (ret != 0 || client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_plg_debug(ctx->ins, "IMDSv2 token response\n%s",
                          client->resp.payload);
        }
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    ctx->imds_v2_token = flb_sds_create_len(client->resp.payload,
                                            client->resp.payload_size);
    if (!ctx->imds_v2_token) {
        flb_errno();
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }
    ctx->imds_v2_token_len = client->resp.payload_size;

    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    return 0;
}

/* get the metadata by key if the result is a json object.
 * If key is NULL, just return the value it get.
 */
static int get_metadata_by_key(struct flb_filter_aws *ctx, char *metadata_path,
                               flb_sds_t *metadata, size_t *metadata_len,
                               char *key)
{
    int ret;
    size_t b_sent;
    flb_sds_t tmp;
    struct flb_http_client *client;
    struct flb_upstream_conn *u_conn;

    u_conn = flb_upstream_conn_get(ctx->ec2_upstream);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "connection initialization error");
        return -1;
    }

    /* Compose HTTP Client request */
    client = flb_http_client(u_conn,
                             FLB_HTTP_GET, metadata_path,
                             NULL, 0,
                             FLB_FILTER_AWS_IMDS_HOST, 80,
                             NULL, 0);

    if (!client) {
        flb_plg_error(ctx->ins, "count not create http client");
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    if (ctx->use_v2 == FLB_TRUE) {
        flb_http_add_header(client, FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER,
                            FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER_LEN,
                            ctx->imds_v2_token,
                            ctx->imds_v2_token_len);
        flb_plg_debug(ctx->ins, "Using IMDSv2");
    }
    else {
        flb_plg_debug(ctx->ins, "Using IMDSv1");
    }

    /* Perform request */
    ret = flb_http_do(client, &b_sent);
    flb_plg_debug(ctx->ins, "IMDS metadata request http_do=%i, HTTP Status: %i",
                  ret, client->resp.status);

    if (ret != 0 || client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_plg_debug(ctx->ins, "IMDS metadata request\n%s",
                          client->resp.payload);
        }
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    if (key != NULL) {
        /* get the value of the key from payload json string */
        tmp = flb_json_get_val(client->resp.payload,
                               client->resp.payload_size, key);
        if (!tmp) {
            tmp = flb_sds_create_len("NULL", 4);
            flb_plg_error(ctx->ins,
                         "%s is undefined in EC2 instance", key);
        }
    } else {
        tmp = flb_sds_create_len(client->resp.payload, client->resp.payload_size);
    }

    if (!tmp) {
        flb_errno();
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        return -1;
    }

    *metadata = tmp;
    *metadata_len = key == NULL ? client->resp.payload_size : strlen(tmp);

    flb_http_client_destroy(client);
    flb_upstream_conn_release(u_conn);
    return 0;
}

static int get_metadata(struct flb_filter_aws *ctx, char *metadata_path,
                        flb_sds_t *metadata, size_t *metadata_len)
{
    return get_metadata_by_key(ctx, metadata_path, metadata,
                               metadata_len, NULL);
}

/* get VPC metadata, it called IMDS twice.
 * First is for getting the Mac ID and combine into the path for VPC.
 * Second call is using the VPC path to get the VPC id
 */
static int get_vpc_metadata(struct flb_filter_aws *ctx)
{
    int ret;
    flb_sds_t mac_id = NULL;
    size_t len = 0;

    /* get EC2 instance Mac id first before getting VPC id */
    ret = get_metadata(ctx, FLB_FILTER_AWS_IMDS_MAC_PATH, &mac_id, &len);

    if (ret < 0) {
        flb_sds_destroy(mac_id);
        return -1;
    }

    /* the VPC full path should be like:
     *latest/meta-data/network/interfaces/macs/{mac_id}/vpc-id/"
     */
    flb_sds_t vpc_path = flb_sds_create_size(70);
    vpc_path = flb_sds_printf(&vpc_path, "%s/%s/%s/",
                              "/latest/meta-data/network/interfaces/macs",
                              mac_id, "vpc-id");
    ret = get_metadata(ctx, vpc_path, &ctx->vpc_id, &ctx->vpc_id_len);

    flb_sds_destroy(mac_id);
    flb_sds_destroy(vpc_path);

    return ret;
}

/*
 * Makes a call to IMDS to set get the values of all metadata fields.
 * It can be called repeatedly if some metadata calls initially do not succeed.
 */
static int get_ec2_metadata(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->use_v2 == FLB_TRUE && !ctx->imds_v2_token) {
        ret = get_ec2_token(ctx);

        if (ret < 0) {
            return -1;
        }
    }

    if (ctx->instance_id_include && !ctx->instance_id) {
        ret = get_metadata(ctx, FLB_FILTER_AWS_IMDS_INSTANCE_ID_PATH,
                           &ctx->instance_id, &ctx->instance_id_len);

        if (ret < 0) {
            return -1;
        }
        ctx->new_keys++;
    }

    if (ctx->availability_zone_include && !ctx->availability_zone) {
        ret = get_metadata(ctx, FLB_FILTER_AWS_IMDS_AZ_PATH,
                           &ctx->availability_zone,
                           &ctx->availability_zone_len);

        if (ret < 0) {
            return -1;
        }
        ctx->new_keys++;
    }

    if (ctx->instance_type_include && !ctx->instance_type) {
        ret = get_metadata(ctx, FLB_FILTER_AWS_IMDS_INSTANCE_TYPE_PATH,
                           &ctx->instance_type, &ctx->instance_type_len);

        if (ret < 0) {
            return -1;
        }
        ctx->new_keys++;
    }

    if (ctx->private_ip_include && !ctx->private_ip) {
        ret = get_metadata(ctx, FLB_FILTER_AWS_IMDS_PRIVATE_IP_PATH,
                           &ctx->private_ip, &ctx->private_ip_len);

        if (ret < 0) {
            return -1;
        }
        ctx->new_keys++;
    }

    if (ctx->vpc_id_include && !ctx->vpc_id) {
        ret = get_vpc_metadata(ctx);

        if (ret < 0) {
            return -1;
        }
        ctx->new_keys++;
    }

    if (ctx->ami_id_include && !ctx->ami_id) {
        ret = get_metadata(ctx, FLB_FILTER_AWS_IMDS_AMI_ID_PATH,
                           &ctx->ami_id, &ctx->ami_id_len);

        if (ret < 0) {
            return -1;
        }
        ctx->new_keys++;
    }

    if (ctx->account_id_include && !ctx->account_id) {
        ret = get_metadata_by_key(ctx, FLB_FILTER_AWS_IMDS_ACCOUNT_ID_PATH,
                                  &ctx->account_id, &ctx->account_id_len,
                                  "accountId");

        if (ret < 0) {
            return -1;
        }
        ctx->new_keys++;
    }

    if (ctx->hostname_include && !ctx->hostname) {
        ret = get_metadata(ctx, FLB_FILTER_AWS_IMDS_HOSTNAME_PATH,
                           &ctx->hostname, &ctx->hostname_len);

        if (ret < 0) {
            return -1;
        }
        ctx->new_keys++;
    }

    ctx->metadata_retrieved = FLB_TRUE;
    return 0;
}

static int cb_aws_filter(const void *data, size_t bytes,
                         const char *tag, int tag_len,
                         void **out_buf, size_t *out_size,
                         struct flb_filter_instance *f_ins,
                         struct flb_input_instance *i_ins,
                         void *context,
                         struct flb_config *config)
{
    struct flb_filter_aws *ctx = context;
    (void) f_ins;
    (void) i_ins;
    (void) config;
    size_t off = 0;
    int i = 0;
    int ret;
    struct flb_time tm;
    int total_records;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object_kv *kv;

    /* First check that the metadata has been retrieved */
    if (!ctx->metadata_retrieved) {
        ret = get_ec2_metadata(ctx);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Could not retrieve ec2 metadata "
                          "from IMDS");
            return FLB_FILTER_NOTOUCH;
        }
        expose_aws_meta(ctx);
    }
    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate over each item */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)
           == MSGPACK_UNPACK_SUCCESS) {
        /*
         * Each record is a msgpack array [timestamp, map] of the
         * timestamp and record map. We 'unpack' each record, and then re-pack
         * it with the new fields added.
         */

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* obj should now be the record map */
        if (obj->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* re-pack the array into a new buffer */
        msgpack_pack_array(&tmp_pck, 2);
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        /* new record map size is old size + the new keys we will add */
        total_records = obj->via.map.size + ctx->new_keys;
        msgpack_pack_map(&tmp_pck, total_records);

        /* iterate through the old record map and add it to the new buffer */
        kv = obj->via.map.ptr;
        for(i=0; i < obj->via.map.size; i++) {
            msgpack_pack_object(&tmp_pck, (kv+i)->key);
            msgpack_pack_object(&tmp_pck, (kv+i)->val);
        }

        /* append new keys */

        if (ctx->availability_zone_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY,
                                  FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->availability_zone_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->availability_zone,
                                  ctx->availability_zone_len);
        }

        if (ctx->instance_id_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_INSTANCE_ID_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_INSTANCE_ID_KEY,
                                  FLB_FILTER_AWS_INSTANCE_ID_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->instance_id_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->instance_id, ctx->instance_id_len);
        }

        if (ctx->instance_type_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_INSTANCE_TYPE_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_INSTANCE_TYPE_KEY,
                                  FLB_FILTER_AWS_INSTANCE_TYPE_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->instance_type_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->instance_type, ctx->instance_type_len);
        }

        if (ctx->private_ip_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_PRIVATE_IP_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_PRIVATE_IP_KEY,
                                  FLB_FILTER_AWS_PRIVATE_IP_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->private_ip_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->private_ip, ctx->private_ip_len);
        }

        if (ctx->vpc_id_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_VPC_ID_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_VPC_ID_KEY,
                                  FLB_FILTER_AWS_VPC_ID_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->vpc_id_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->vpc_id, ctx->vpc_id_len);
        }

        if (ctx->ami_id_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_AMI_ID_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_AMI_ID_KEY,
                                  FLB_FILTER_AWS_AMI_ID_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->ami_id_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->ami_id, ctx->ami_id_len);
        }

        if (ctx->account_id_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_ACCOUNT_ID_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_ACCOUNT_ID_KEY,
                                  FLB_FILTER_AWS_ACCOUNT_ID_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->account_id_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->account_id, ctx->account_id_len);
        }

        if (ctx->hostname_include) {
            msgpack_pack_str(&tmp_pck, FLB_FILTER_AWS_HOSTNAME_KEY_LEN);
            msgpack_pack_str_body(&tmp_pck,
                                  FLB_FILTER_AWS_HOSTNAME_KEY,
                                  FLB_FILTER_AWS_HOSTNAME_KEY_LEN);
            msgpack_pack_str(&tmp_pck, ctx->hostname_len);
            msgpack_pack_str_body(&tmp_pck,
                                  ctx->hostname, ctx->hostname_len);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf  = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
    return FLB_FILTER_MODIFIED;
}

static void flb_filter_aws_destroy(struct flb_filter_aws *ctx)
{
    if (ctx->ec2_upstream) {
        flb_upstream_destroy(ctx->ec2_upstream);
    }

    if (ctx->imds_v2_token) {
        flb_sds_destroy(ctx->imds_v2_token);
    }

    if (ctx->availability_zone) {
        flb_sds_destroy(ctx->availability_zone);
    }

    if (ctx->instance_id) {
        flb_sds_destroy(ctx->instance_id);
    }

    if (ctx->instance_type) {
        flb_sds_destroy(ctx->instance_type);
    }

    if (ctx->private_ip) {
        flb_sds_destroy(ctx->private_ip);
    }

    if (ctx->vpc_id) {
        flb_sds_destroy(ctx->vpc_id);
    }

    if (ctx->ami_id) {
        flb_sds_destroy(ctx->ami_id);
    }

    if (ctx->account_id) {
        flb_sds_destroy(ctx->account_id);
    }

    if (ctx->hostname) {
        flb_sds_destroy(ctx->hostname);
    }

    flb_free(ctx);
}

static int cb_aws_exit(void *data, struct flb_config *config)
{
    struct flb_filter_aws *ctx = data;

    if (ctx != NULL) {
        flb_filter_aws_destroy(ctx);
    }
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "imds_version", "v2",
     0, FLB_FALSE, 0,
     "Specifies which version of the EC2 instance metadata service"
     " will be used: 'v1' or 'v2'. 'v2' may not work"
     " if you run Fluent Bit in a container."
    },
    {
     FLB_CONFIG_MAP_BOOL, "az", "true",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, availability_zone_include),
     "Enable EC2 instance availability zone"
    },
    {
     FLB_CONFIG_MAP_BOOL, "ec2_instance_id", "true",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, instance_id_include),
     "Enable EC2 instance ID"
    },
    {
     FLB_CONFIG_MAP_BOOL, "ec2_instance_type", "false",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, instance_type_include),
     "Enable EC2 instance type"
    },
    {
     FLB_CONFIG_MAP_BOOL, "private_ip", "false",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, private_ip_include),
     "Enable EC2 instance private IP"
    },
    {
     FLB_CONFIG_MAP_BOOL, "vpc_id", "false",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, vpc_id_include),
     "Enable EC2 instance VPC ID"
    },
    {
     FLB_CONFIG_MAP_BOOL, "ami_id", "false",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, ami_id_include),
     "Enable EC2 instance Image ID"
    },
    {
     FLB_CONFIG_MAP_BOOL, "account_id", "false",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, account_id_include),
     "Enable EC2 instance Account ID"
    },
    {
     FLB_CONFIG_MAP_BOOL, "hostname", "false",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, hostname_include),
     "Enable EC2 instance hostname"
    },
    {0}
};

struct flb_filter_plugin filter_aws_plugin = {
    .name         = "aws",
    .description  = "Add AWS Metadata",
    .cb_init      = cb_aws_init,
    .cb_filter    = cb_aws_filter,
    .cb_exit      = cb_aws_exit,
    .config_map   = config_map,
    .flags        = 0
};
