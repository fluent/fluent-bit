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
#include <fluent-bit/aws/flb_aws_imds.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <monkey/mk_core/mk_list.h>
#include <msgpack.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "aws.h"

static int get_ec2_metadata(struct flb_filter_aws *ctx);

static void expose_aws_meta(struct flb_filter_aws *ctx)
{
    struct flb_env *env;
    struct flb_config *config = ctx->ins->config;

    env = config->env;

    flb_env_set(env, "aws", "enabled");

    if (ctx->group_az.done &&
            !ctx->group_az.exposed) {
        if (ctx->availability_zone_include) {
            flb_env_set(env,
                        "aws." FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY,
                        ctx->availability_zone);
        }
        ctx->group_az.exposed = FLB_TRUE;
    }

    if (ctx->group_instance_id.done &&
            !ctx->group_instance_id.exposed) {
        if (ctx->instance_id_include) {
            flb_env_set(env,
                        "aws." FLB_FILTER_AWS_INSTANCE_ID_KEY,
                        ctx->instance_id);
        }
        ctx->group_instance_id.exposed = FLB_TRUE;
    }

    if (ctx->group_instance_type.done &&
            !ctx->group_instance_type.exposed) {
        if (ctx->instance_type_include) {
            flb_env_set(env,
                        "aws." FLB_FILTER_AWS_INSTANCE_TYPE_KEY,
                        ctx->instance_type);
        }
        ctx->group_instance_type.exposed = FLB_TRUE;
    }

    if (ctx->group_private_ip.done &&
            !ctx->group_private_ip.exposed) {
        if (ctx->private_ip_include) {
            flb_env_set(env,
                        "aws." FLB_FILTER_AWS_PRIVATE_IP_KEY,
                        ctx->private_ip);
        }
        ctx->group_private_ip.exposed = FLB_TRUE;
    }

    if (ctx->group_vpc_id.done &&
            !ctx->group_vpc_id.exposed) {
        if (ctx->vpc_id_include) {
            flb_env_set(env,
                        "aws." FLB_FILTER_AWS_VPC_ID_KEY,
                        ctx->vpc_id);
        }
        ctx->group_vpc_id.exposed = FLB_TRUE;
    }

    if (ctx->group_ami_id.done &&
            !ctx->group_ami_id.exposed) {
        if (ctx->ami_id_include) {
            flb_env_set(env,
                        "aws." FLB_FILTER_AWS_AMI_ID_KEY,
                        ctx->ami_id);
        }
        ctx->group_ami_id.exposed = FLB_TRUE;
    }

    if (ctx->group_account_id.done &&
            !ctx->group_account_id.exposed) {
        if (ctx->account_id_include) {
            flb_env_set(env,
                        "aws." FLB_FILTER_AWS_ACCOUNT_ID_KEY,
                        ctx->account_id);
        }
        ctx->group_account_id.exposed = FLB_TRUE;
    }

    if (ctx->group_hostname.done &&
            !ctx->group_hostname.exposed) {
        if (ctx->hostname_include) {
            flb_env_set(env,
                        "aws." FLB_FILTER_AWS_HOSTNAME_KEY,
                        ctx->hostname);
        }
        ctx->group_hostname.exposed = FLB_TRUE;
    }

    /* TODO: expose aws ec2 tags in flb_env_set */
}

static int cb_aws_init(struct flb_filter_instance *f_ins,
                       struct flb_config *config,
                       void *data)
{
    int imds_version = FLB_AWS_IMDS_VERSION_2;
    int ret;
    struct flb_filter_aws *ctx = NULL;
    struct flb_filter_aws_init_options *options = data;
    const char *tmp = NULL;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_filter_aws));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->options = options;
    ctx->ins = f_ins;

    tmp = flb_filter_get_property("imds_version", f_ins);
    if (tmp != NULL) {
        if (strcasecmp(tmp, "v1") == 0) {
            imds_version = FLB_AWS_IMDS_VERSION_1;
        }
        else if (strcasecmp(tmp, "v2") != 0) {
            flb_plg_error(ctx->ins, "Invalid value %s for config option "
                          "'imds_version'. Valid values are 'v1' and 'v2'",
                          tmp);
            flb_free(ctx);
            return -1;
        }
    }

    struct flb_aws_client_generator *generator;
    if (options && options->client_generator) {
        generator = options->client_generator;
    } else {
        generator = flb_aws_client_generator();
    }
    ctx->aws_ec2_filter_client = generator->create();
    ctx->aws_ec2_filter_client->name = "ec2_imds_provider_client";
    ctx->aws_ec2_filter_client->has_auth = FLB_FALSE;
    ctx->aws_ec2_filter_client->provider = NULL;
    ctx->aws_ec2_filter_client->region = NULL;
    ctx->aws_ec2_filter_client->service = NULL;
    ctx->aws_ec2_filter_client->port = FLB_AWS_IMDS_PORT;
    ctx->aws_ec2_filter_client->flags = 0;
    ctx->aws_ec2_filter_client->proxy = NULL;

    struct flb_upstream *upstream;
    upstream = flb_upstream_create(config, FLB_AWS_IMDS_HOST, FLB_AWS_IMDS_PORT,
                                   FLB_IO_TCP, NULL);
    if (!upstream) {
        flb_plg_debug(ctx->ins, "unable to connect to EC2 IMDS");
        return -1;
    }

    /* IMDSv2 token request will timeout if hops = 1 and running within container */
    upstream->base.net.connect_timeout = FLB_AWS_IMDS_TIMEOUT;
    upstream->base.net.io_timeout = FLB_AWS_IMDS_TIMEOUT;
    upstream->base.net.keepalive = FLB_FALSE; /* On timeout, the connection is broken */
    ctx->aws_ec2_filter_client->upstream = upstream;
    flb_stream_disable_async_mode(&ctx->aws_ec2_filter_client->upstream->base);

    ctx->client_imds = flb_aws_imds_create(&flb_aws_imds_config_default,
                                           ctx->aws_ec2_filter_client);
    if (!ctx->client_imds) {
        flb_plg_error(ctx->ins, "failed to create aws client");
        flb_free(ctx);
        return -1;
    }
    ctx->client_imds->imds_version = imds_version;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_filter_config_map_set(f_ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(f_ins, "configuration error");
        flb_free(ctx);
        return -1;
    }

    /* Retrieve metadata */
    ret = get_ec2_metadata(ctx);
    if (ret < 0) {
        /* If the metadata fetch fails, the plugin continues to work. */
        /* Every flush will attempt to fetch ec2 metadata, if needed. */
        /* If the error is unrecoverable, it exits and does not retry. */
        /* e.g.: unrecoverable errors might be related to invalid configuration. */
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            flb_free(ctx);
            return -1;
        }
    }
    else {
        expose_aws_meta(ctx);
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}


/* Get VPC ID from the metadata server.
 * Initializes ctx->vpc_id and ctx->vpc_id_len.
 */
static int get_vpc_id(struct flb_filter_aws *ctx)
{
    ctx->vpc_id = flb_aws_imds_get_vpc_id(ctx->client_imds);
    if (ctx->vpc_id == NULL) {
        return -1;
    }
    ctx->vpc_id_len = flb_sds_len(ctx->vpc_id);
    return 0;
}

void flb_filter_aws_tags_destroy(struct flb_filter_aws *ctx)
{
    int i;
    if (!ctx) {
        return;
    }
    if (ctx->tag_keys) {
        for (i = 0; i < ctx->tags_count; i++) {
            if (ctx->tag_keys[i]) {
                flb_sds_destroy(ctx->tag_keys[i]);
            }
        }
        flb_free(ctx->tag_keys);
        ctx->tag_keys = NULL;
    }
    if (ctx->tag_values) {
        for (i = 0; i < ctx->tags_count; i++) {
            if (ctx->tag_values[i]) {
                flb_sds_destroy(ctx->tag_values[i]);
            }
        }
        flb_free(ctx->tag_values);
        ctx->tag_values = NULL;
    }
    if (ctx->tag_keys_len) {
        flb_free(ctx->tag_keys_len);
    }
    ctx->tag_keys_len = NULL;
    if (ctx->tag_values_len) {
        flb_free(ctx->tag_values_len);
    }
    ctx->tag_values_len = NULL;
    if (ctx->tag_is_enabled) {
        flb_free(ctx->tag_is_enabled);
    }
    ctx->tag_is_enabled = NULL;
    ctx->tags_count = 0;
}

/* Get EC2 instance tag keys from /latest/meta-data/tags/instance.
 * Initializes ctx->tags_count, ctx->tag_keys and ctx->tag_keys_len.
 *
 * In case EC2 metadata server doesn't return tags, either due to the fact that tags are
 * disabled in the metadata server or EC2 has no tags, function returns -2.
 */
static int get_ec2_tag_keys(struct flb_filter_aws *ctx)
{
    int ret;
    flb_sds_t tags_list = NULL;
    size_t len = 0;
    size_t tag_index = 0;
    size_t tag_start = 0;
    size_t tag_end = 0;
    flb_sds_t tag_key;
    flb_sds_t tmp;
    size_t tag_key_len;
    int i;

    /* get a list of tag keys from the meta data server */
    ret = flb_aws_imds_request(ctx->client_imds, FLB_AWS_IMDS_INSTANCE_TAG, &tags_list,
							   &len);
    if (ret < 0) {
        ctx->tags_count = 0;
        if (ret == -2) { /* if there are no tags, response status code is 404 */
            flb_plg_warn(ctx->ins, "EC2 instance metadata tag request returned 404. "
                                   "This likely indicates your instance has no tags "
                                   "or the EC2 tagging metadata API is not enabled");
            return -2;
        }
        flb_sds_destroy(tags_list);
        return -1;
    }

    /* if endpoint returned 200, normally at least 1 tag should be present */
    /* for the sake of correctness, let's check the edge case when response is empty */
    if (len == 0) {
        ctx->tags_count = 0;
        flb_sds_destroy(tags_list);
        return -1;
    }

    /* count number of tag keys and allocate memory for pointers and lengths */
    /* since get_metadata returned 0, we assume there is at least 1 tag */
    /* \n is separator, therefore number of items = number of \n + 1 */
    ctx->tags_count = 1;
    for (i = 0; i < len; i++) {
        if (tags_list[i] == '\n') {
            ctx->tags_count++;
        }
    }
    ctx->tag_keys = flb_calloc(ctx->tags_count, sizeof(flb_sds_t));
    if (!ctx->tag_keys) {
        flb_errno();
        flb_sds_destroy(tags_list);
        return -1;
    }
    ctx->tag_keys_len = flb_calloc(ctx->tags_count, sizeof(size_t));
    if (!ctx->tag_keys_len) {
        flb_errno();
        flb_sds_destroy(tags_list);
        return -1;
    }

    /* go over the response and initialize tag_keys values */
    /* code below finds two indices which define tag key and copies them to ctx */
    while (tag_end <= len) {
        /* replace \n with \0 to 'clearly' separate tag key strings */
        if (tags_list[tag_end] == '\n') {
            tags_list[tag_end] = '\0';
        }
        if ((tags_list[tag_end] == '\0' || tag_end == len) && (tag_start < tag_end)) {
            /* length of tag key characters is the difference between start and end */
            /* for instance, if tag name is 'Name\0...', the corresponding values are */
            /*   tag_start = 0, points to 'N' */
            /*   tag_end = 4, points to '\0' just after 'e' */
            /*   f.e.: 4 - 0 = 4, which is equal to len("Name") */
            tag_key_len = tag_end - tag_start;
            ctx->tag_keys_len[tag_index] = tag_key_len;

            /* allocate new memory for the tag key value */
            /* + 1, because we need one more character for \0 */
            tmp = flb_sds_create_size(tag_key_len + 1);
            if (!tmp) {
                flb_errno();
                flb_sds_destroy(tags_list);
                return -2;
            }
            tmp[tag_key_len] = '\0';
            ctx->tag_keys[tag_index] = tmp;

            /* tag_key points to the first character of tag key as char* */
            tag_key = tags_list + tag_start;
            memcpy(ctx->tag_keys[tag_index], tag_key, tag_key_len);

            tag_index++;
            tag_start = tag_end + 1;
        }
        tag_end++;
    }

    flb_sds_destroy(tags_list);

    return ret;
}

/* Get EC2 instance tag values from /latest/meta-data/tags/instance/{tag_key}.
 * Initializes ctx->tag_values and ctx->tag_values_len.
 */
static int get_ec2_tag_values(struct flb_filter_aws *ctx)
{
    int ret;
    size_t i;
    flb_sds_t tag_value = NULL;
    size_t tag_value_len = 0;
    size_t tag_value_path_len;
    flb_sds_t tag_value_path;
    flb_sds_t tmp;

    /* initialize array for the tag values */
    ctx->tag_values = flb_calloc(ctx->tags_count, sizeof(flb_sds_t));
    if (!ctx->tag_values) {
        flb_errno();
        return -1;
    }
    ctx->tag_values_len = flb_calloc(ctx->tags_count, sizeof(size_t));
    if (!ctx->tag_values_len) {
        flb_errno();
        return -1;
    }

    for (i = 0; i < ctx->tags_count; i++) {
        /* fetch tag value using path: /latest/meta-data/tags/instance/{tag_name} */
        tag_value_path_len = ctx->tag_keys_len[i] + 1 +
                             strlen(FLB_AWS_IMDS_INSTANCE_TAG);
        tag_value_path = flb_sds_create_size(tag_value_path_len + 1);
        if (!tag_value_path) {
            flb_errno();
            return -1;
        }
        tmp = flb_sds_printf(&tag_value_path, "%s/%s",
                             FLB_AWS_IMDS_INSTANCE_TAG,
                             ctx->tag_keys[i]);
        if (!tmp) {
            flb_errno();
            flb_sds_destroy(tag_value_path);
            return -1;
        }
        tag_value_path = tmp;

        ret = flb_aws_imds_request(ctx->client_imds, tag_value_path, &tag_value,
                                   &tag_value_len);
        if (ret < 0) {
            flb_sds_destroy(tag_value_path);
            if (ret == -2) {
                flb_plg_error(ctx->ins, "no value for tag %s", ctx->tag_keys[i]);
            } else {
                flb_plg_error(ctx->ins, "could not fetch value for tag %s",
                              ctx->tag_keys[i]);
            }
            return ret;
        }

        ctx->tag_values[i] = tag_value;
        ctx->tag_values_len[i] = tag_value_len;

        flb_sds_destroy(tag_value_path);
    }

    return 0;
}

static int tag_is_present_in_list(struct flb_filter_aws *ctx, flb_sds_t tag,
        flb_sds_t *tags, int tags_n)
{
    int i;
    for (i = 0; i < tags_n; i++) {
        if (strcmp(tag, tags[i]) == 0) {
            return FLB_TRUE;
        }
    }
    return FLB_FALSE;
}

static int tags_split(char *tags, flb_sds_t **tags_list, int *tags_list_n) {
    flb_sds_t token;
    int i;
    int n;
    n = 1;
    for (i = 0; i < strlen(tags); i++) {
        if (tags[i] == ',') {
            n++;
        }
    }

    *tags_list = flb_calloc(sizeof(flb_sds_t), n);
    if (*tags_list == NULL) {
        return -2;
    }

    token = strtok(tags, ",");
    i = 0;
    while (token != NULL) {
        (*tags_list)[i] = token;
        i++;
        token = strtok(NULL, ",");
    }

    *tags_list_n = n;

    return 0;
}

static int get_ec2_tag_enabled(struct flb_filter_aws *ctx)
{
    const char *tags_include;
    const char *tags_exclude;
    char *tags_copy;
    flb_sds_t *tags;
    int tags_n;
    int i;
    int tag_present;
    int result;

    /* if there are no tags, there is no need to evaluate which tag is enabled */
    if (ctx->tags_count == 0) {
        return 0;
    }


    /* allocate memory for 'tag_is_enabled' for all tags */
    ctx->tag_is_enabled = flb_calloc(ctx->tags_count, sizeof(int));
    if (!ctx->tag_is_enabled) {
        flb_plg_error(ctx->ins, "Failed to allocate memory for tag_is_enabled");
        return -1;
    }

    /* if tags_include and tags_exclude are not defined, set all tags as enabled */
    for (i = 0; i < ctx->tags_count; i++) {
        ctx->tag_is_enabled[i] = FLB_TRUE;
    }

    /* apply tags_included configuration */
    tags_include = flb_filter_get_property("tags_include", ctx->ins);
    if (tags_include) {
        /* copy const string in order to use strtok which modifes the string */
        tags_copy = flb_strdup(tags_include);
        if (!tags_copy) {
            return -1;
        }
        result = tags_split(tags_copy, &tags, &tags_n);
        if (result < 0) {
            free(tags_copy);
            return -1;
        }
        for (i = 0; i < ctx->tags_count; i++) {
            tag_present = tag_is_present_in_list(ctx, ctx->tag_keys[i], tags, tags_n);
            /* tag is enabled if present in included list */
            ctx->tag_is_enabled[i] = tag_present;
        }
        free(tags_copy);
        free(tags);
    }

    /* apply tags_excluded configuration, only if tags_included is not defined */
    tags_exclude = flb_filter_get_property("tags_exclude", ctx->ins);
    if (tags_include && tags_exclude) {
        flb_plg_error(ctx->ins, "configuration is invalid, both tags_include"
                " and tags_exclude are specified at the same time");
        return FLB_FILTER_AWS_CONFIGURATION_ERROR;
    }
    if (!tags_include && tags_exclude) {
        /* copy const string in order to use strtok which modifes the string */
        tags_copy = flb_strdup(tags_exclude);
        if (!tags_copy) {
            return -1;
        }
        result = tags_split(tags_copy, &tags, &tags_n);
        if (result < 0) {
            free(tags_copy);
            return -1;
        }
        for (i = 0; i < ctx->tags_count; i++) {
            tag_present = tag_is_present_in_list(ctx, ctx->tag_keys[i], tags, tags_n);
            if (tag_present == FLB_TRUE) {
                /* tag is excluded, so should be disabled */
                ctx->tag_is_enabled[i] = FLB_FALSE;
            } else {
                /* tag is not excluded, therefore should be enabled */
                ctx->tag_is_enabled[i] = FLB_TRUE;
            }
        }
        free(tags_copy);
        free(tags);
    }

    return 0;
}

static int get_ec2_tags(struct flb_filter_aws *ctx)
{
    int i;
    int ret;

    ctx->tags_fetched = FLB_FALSE;

    /* get_ec2_tags function might be called multiple times, so we need to always */
    /* free memory for tags in case of previous allocations */
    flb_filter_aws_tags_destroy(ctx);

    ret = get_ec2_tag_keys(ctx);
    if (ret < 0) {
        flb_filter_aws_tags_destroy(ctx);
        if (ret == -2) {
            /* -2 means there are no tags, */
            /* to avoid requesting ec2 tags repeatedly for each flush */
            /* it marks fetching tags as done */
            ctx->tags_fetched = FLB_TRUE;
            return 0;
        }
        return ret;
    }
    ret = get_ec2_tag_values(ctx);
    if (ret < 0) {
        flb_filter_aws_tags_destroy(ctx);
        return ret;
    }

    ret = get_ec2_tag_enabled(ctx);
    if (ret < 0) {
        flb_filter_aws_tags_destroy(ctx);
        return ret;
    }

    /* log tags debug information */
    for (i = 0; i < ctx->tags_count; i++) {
        flb_plg_debug(ctx->ins, "found tag %s which is included=%d",
                ctx->tag_keys[i], ctx->tag_is_enabled[i]);
    }

    ctx->tags_fetched = FLB_TRUE;
    return 0;
}

static int get_ec2_metadata_instance_id(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->instance_id_include && !ctx->instance_id) {
        ret = flb_aws_imds_request(ctx->client_imds, FLB_AWS_IMDS_INSTANCE_ID_PATH,
                                   &ctx->instance_id,
                                   &ctx->instance_id_len);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to get instance ID");
            return -1;
        }
    }

    return 0;
}

static int get_ec2_metadata_instance_type(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->instance_type_include && !ctx->instance_type) {
        ret = flb_aws_imds_request(ctx->client_imds, FLB_AWS_IMDS_INSTANCE_TYPE_PATH,
                           &ctx->instance_type, &ctx->instance_type_len);

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to get instance type");
            return -1;
        }
    }

    return 0;
}

static int get_ec2_metadata_private_ip(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->private_ip_include && !ctx->private_ip) {
        ret = flb_aws_imds_request(ctx->client_imds, FLB_AWS_IMDS_PRIVATE_IP_PATH,
                           &ctx->private_ip, &ctx->private_ip_len);

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to get instance private IP");
            return -1;
        }
    }

    return 0;
}

static int get_ec2_metadata_vpc_id(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->vpc_id_include && !ctx->vpc_id) {
        ret = get_vpc_id(ctx);

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to get instance VPC ID");
            return -1;
        }
    }

    return 0;
}

static int get_ec2_metadata_ami_id(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->ami_id_include && !ctx->ami_id) {
        ret = flb_aws_imds_request(ctx->client_imds, FLB_AWS_IMDS_AMI_ID_PATH,
                           &ctx->ami_id, &ctx->ami_id_len);

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to get AMI ID");
            return -1;
        }
    }

    return 0;
}

static int get_ec2_metadata_account_id(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->account_id_include && !ctx->account_id) {
        ret = flb_aws_imds_request_by_key(ctx->client_imds, FLB_AWS_IMDS_ACCOUNT_ID_PATH,
                                  &ctx->account_id, &ctx->account_id_len,
                                  "accountId");

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to get Account ID");
            return -1;
        }
    }


    return 0;
}

static int get_ec2_metadata_hostname(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->hostname_include && !ctx->hostname) {
        ret = flb_aws_imds_request(ctx->client_imds, FLB_AWS_IMDS_HOSTNAME_PATH,
                           &ctx->hostname, &ctx->hostname_len);

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to get Hostname");
            return -1;
        }
    }

    return 0;
}

static int get_ec2_metadata_az(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->availability_zone_include && !ctx->availability_zone) {
        ret = flb_aws_imds_request(ctx->client_imds, FLB_AWS_IMDS_AZ_PATH,
                           &ctx->availability_zone,
                           &ctx->availability_zone_len);

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to get instance AZ");
            return -1;
        }
    }

    return 0;
}


static int get_ec2_metadata_tags(struct flb_filter_aws *ctx)
{
    int ret;

    if (ctx->tags_enabled && !ctx->tags_fetched) {
        ret = get_ec2_tags(ctx);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to get instance EC2 Tags");
            return ret;
        }
    }

    return 0;
}

static int ec2_metadata_group_should_fetch(struct flb_filter_aws *ctx,
                                           struct flb_filter_aws_metadata_group *group)
{
    time_t now, required_interval, interval;

    required_interval = ctx->retry_required_interval;
    if (required_interval == 0) {
        return FLB_TRUE;
    }

    now = time(NULL);

    interval = now - group->last_fetch_attempt;

    if (group->last_fetch_attempt > 0 && 
        interval < required_interval) {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

static int get_ec2_metadata_group(struct flb_filter_aws *ctx,
                                  struct flb_filter_aws_metadata_group *group,
                                  int (*fetch_func)(struct flb_filter_aws *ctx))
{
    int ret;
    if (group->done) {
        return 0;
    }
    if (!ec2_metadata_group_should_fetch(ctx, group)) {
        return -1;
    }
    group->last_fetch_attempt = time(NULL);
    ret = fetch_func(ctx);
    if (ret == 0) {
        group->done = FLB_TRUE;
    }
    return ret;
}

/*
 * Fetches all metadata values, including tags, from IMDS.
 * Function handles retries as configured for each metadata group.
 *
 * Returns 0 on success, negative values on failures.
 * Returns FLB_FILTER_AWS_CONFIGURATION_ERROR in case of configuration error.
 */
static int get_ec2_metadata(struct flb_filter_aws *ctx)
{
    int ret;
    int metadata_fetched = FLB_TRUE;

    if (ctx->metadata_retrieved) {
        return 0;
    }

    ret = get_ec2_metadata_group(ctx, &ctx->group_instance_id,
                                 get_ec2_metadata_instance_id);
    if (ret < 0) {
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            return ret;
        }
        metadata_fetched = FLB_FALSE;
    }

    ret = get_ec2_metadata_group(ctx, &ctx->group_account_id,
                                 get_ec2_metadata_account_id);
    if (ret < 0) {
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            return ret;
        }
        metadata_fetched = FLB_FALSE;
    }

    ret = get_ec2_metadata_group(ctx, &ctx->group_instance_type,
                                 get_ec2_metadata_instance_type);
    if (ret < 0) {
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            return ret;
        }
        metadata_fetched = FLB_FALSE;
    }

    ret = get_ec2_metadata_group(ctx, &ctx->group_private_ip,
                                 get_ec2_metadata_private_ip);
    if (ret < 0) {
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            return ret;
        }
        metadata_fetched = FLB_FALSE;
    }

    ret = get_ec2_metadata_group(ctx, &ctx->group_vpc_id, get_ec2_metadata_vpc_id);
    if (ret < 0) {
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            return ret;
        }
        metadata_fetched = FLB_FALSE;
    }

    ret = get_ec2_metadata_group(ctx, &ctx->group_ami_id, get_ec2_metadata_ami_id);
    if (ret < 0) {
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            return ret;
        }
        metadata_fetched = FLB_FALSE;
    }

    ret = get_ec2_metadata_group(ctx, &ctx->group_hostname, get_ec2_metadata_hostname);
    if (ret < 0) {
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            return ret;
        }
        metadata_fetched = FLB_FALSE;
    }

    ret = get_ec2_metadata_group(ctx, &ctx->group_az, get_ec2_metadata_az);
    if (ret < 0) {
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            return ret;
        }
        metadata_fetched = FLB_FALSE;
    }

    ret = get_ec2_metadata_group(ctx, &ctx->group_tag, get_ec2_metadata_tags);
    if (ret < 0) {
        if (ret == FLB_FILTER_AWS_CONFIGURATION_ERROR) {
            return ret;
        }
        metadata_fetched = FLB_FALSE;
    }

    if (metadata_fetched == FLB_TRUE) {
        ctx->metadata_retrieved = FLB_TRUE;
    }

    if (ctx->enable_entity) {
        if (!ctx->account_id) {
            ret = flb_aws_imds_request_by_key(ctx->client_imds, FLB_AWS_IMDS_ACCOUNT_ID_PATH,
                                  &ctx->account_id, &ctx->account_id_len,
                                  "accountId");

            if (ret < 0) {
                flb_plg_error(ctx->ins, "Failed to get Account ID");
                return -1;
            }
        }

        if (!ctx->instance_id) {
            ret = flb_aws_imds_request(ctx->client_imds, FLB_AWS_IMDS_INSTANCE_ID_PATH,
                                       &ctx->instance_id,
                                       &ctx->instance_id_len);
            if (ret < 0) {
                flb_plg_error(ctx->ins, "Failed to get instance ID");
                return -1;
            }
        }
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
    int i = 0;
    int ret;
    msgpack_object  *obj;
    msgpack_object_kv *kv;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    /* First check that the metadata has been retrieved */
    if (!ctx->metadata_retrieved) {
        get_ec2_metadata(ctx); /* ignore the error */
        /* it assumes the error cannot be the configuration error, as it would fail */
        /* during the _init function; */
        /* even if get_ec2_metadata failed, it may have been able to fetch some groups */
        /* therefore we continue flushing the logs with what we've got */
        expose_aws_meta(ctx);
    }

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
                    &log_encoder,
                    &log_event.timestamp);
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
        if (ctx->availability_zone_include &&
            ctx->group_az.done &&
            ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->availability_zone,
                                               ctx->availability_zone_len));
        }

        if (ctx->instance_id_include &&
            ctx->group_instance_id.done &&
            ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_INSTANCE_ID_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->instance_id,
                                               ctx->instance_id_len));
        }

        if (ctx->instance_type_include &&
            ctx->group_instance_type.done &&
            ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_INSTANCE_TYPE_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->instance_type,
                                               ctx->instance_type_len));
        }

        if (ctx->private_ip_include &&
            ctx->group_private_ip.done &&
            ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_PRIVATE_IP_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->private_ip,
                                               ctx->private_ip_len));
        }

        if (ctx->vpc_id_include &&
            ctx->group_vpc_id.done &&
            ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_VPC_ID_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->vpc_id,
                                               ctx->vpc_id_len));
        }

        if (ctx->ami_id_include &&
            ctx->group_ami_id.done &&
            ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_AMI_ID_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->ami_id,
                                               ctx->ami_id_len));
        }

        if (ctx->account_id_include &&
            ctx->group_account_id.done &&
            ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_ACCOUNT_ID_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->account_id,
                                               ctx->account_id_len));
        }

        if (ctx->hostname_include &&
            ctx->group_hostname.done &&
            ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_HOSTNAME_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->hostname,
                                               ctx->hostname_len));
        }

        if (ctx->tags_enabled && ctx->tags_fetched) {
            for (i = 0;
                 i < ctx->tags_count &&
                 ret == FLB_EVENT_ENCODER_SUCCESS;
                 i++) {
                if (ctx->tag_is_enabled[i] == FLB_TRUE) {
                    ret = flb_log_event_encoder_append_body_values(
                            &log_encoder,
                            FLB_LOG_EVENT_STRING_VALUE(ctx->tag_keys[i],
                                                       ctx->tag_keys_len[i]),
                            FLB_LOG_EVENT_STRING_VALUE(ctx->tag_values[i],
                                                       ctx->tag_values_len[i]));
                }
            }
        }

        if (ctx->enable_entity &&
            ctx->instance_id &&
            ctx->account_id &&
            ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_ENTITY_INSTANCE_ID_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->instance_id,
                                               ctx->instance_id_len));
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(FLB_FILTER_AWS_ENTITY_ACCOUNT_ID_KEY),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->account_id,
                                               ctx->account_id_len));
        }


        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(&log_encoder);
        }
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

static void flb_filter_aws_destroy(struct flb_filter_aws *ctx)
{
    if (ctx->options == NULL) {
        /* non null options are only provided by unit tests and since */
        /* aws client mock must clean up the memory with some special behaviour */
        /* if options are NOT null (which means we are running unit tests), */
        /* we rely on unit tests to perform memory cleanup */
        if (ctx->aws_ec2_filter_client) {
            flb_aws_client_destroy(ctx->aws_ec2_filter_client);
        }
    }
    if (ctx->client_imds) {
        flb_aws_imds_destroy(ctx->client_imds);
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

    flb_filter_aws_tags_destroy(ctx);

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
    {
     FLB_CONFIG_MAP_BOOL, "tags_enabled", "false",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, tags_enabled),
     "Enable EC2 instance tags, "
     "injects all tags if tags_include and tags_exclude are empty"
    },
    {
     FLB_CONFIG_MAP_STR, "tags_include", "",
     0, FLB_FALSE, 0,
     "Defines list of specific EC2 tag keys to inject into the logs; "
     "tag keys must be separated by \",\" character; "
     "tags which are not present in this list will be ignored; "
     "e.g.: \"Name,tag1,tag2\""
    },
    {
     FLB_CONFIG_MAP_STR, "tags_exclude", "",
     0, FLB_FALSE, 0,
     "Defines list of specific EC2 tag keys not to inject into the logs; "
     "tag keys must be separated by \",\" character; "
     "if both tags_include and tags_exclude are specified, configuration is invalid"
     " and plugin fails"
    },
    {
     FLB_CONFIG_MAP_INT, "retry_interval_s", "300",
     0, FLB_TRUE, offsetof(struct flb_filter_aws, retry_required_interval),
     "Defines minimum duration between retries for fetching metadata groups"
    },
    {
    FLB_CONFIG_MAP_BOOL, "enable_entity", "false",
    0, FLB_TRUE, offsetof(struct flb_filter_aws, enable_entity),
    "Enable entity prefix for fields used for constructing entity."
    "This currently only affects instance ID"
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
