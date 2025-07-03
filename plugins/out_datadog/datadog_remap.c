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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>

#include "datadog.h"
#include "datadog_remap.h"

const char *ECS_ARN_PREFIX = "arn:aws:ecs:";
const char *ECS_CLUSTER_PREFIX = "cluster/";
const char *ECS_TASK_PREFIX = "task/";

static int dd_remap_append_kv_to_ddtags(const char *key,
                                        const char *val, size_t val_len, flb_sds_t *dd_tags_buf)
{
    flb_sds_t tmp;

    if (flb_sds_len(*dd_tags_buf) != 0) {
        tmp = flb_sds_cat(*dd_tags_buf, FLB_DATADOG_TAG_SEPERATOR, strlen(FLB_DATADOG_TAG_SEPERATOR));
        if (!tmp) {
            flb_errno();
            return -1;
        }
        *dd_tags_buf = tmp;
    }

    tmp = flb_sds_cat(*dd_tags_buf, key, strlen(key));
    if (!tmp) {
            flb_errno();
            return -1;
        }
    *dd_tags_buf = tmp;

    tmp = flb_sds_cat(*dd_tags_buf, ":", 1);
    if (!tmp) {
            flb_errno();
            return -1;
        }
    *dd_tags_buf = tmp;

    tmp = flb_sds_cat(*dd_tags_buf, val, val_len);
    if (!tmp) {
            flb_errno();
            return -1;
        }
    *dd_tags_buf = tmp;

    return 0;
}

/* default remapping: just move the key/val pair under dd_tags */
static int dd_remap_move_to_tags(const char *tag_name,
                                  msgpack_object attr_value, flb_sds_t *dd_tags_buf)
{
    return dd_remap_append_kv_to_ddtags(tag_name, attr_value.via.str.ptr,
                                        attr_value.via.str.size, dd_tags_buf);
}

/* remapping function for container_name */
static int dd_remap_container_name(const char *tag_name,
                                    msgpack_object attr_value, flb_sds_t *dd_tags_buf)
{
    /* remove the first / if present */
    unsigned int adjust;
    flb_sds_t buf = NULL;
    int ret;

    adjust = attr_value.via.str.ptr[0] == '/' ? 1 : 0;
    buf = flb_sds_create_len(attr_value.via.str.ptr + adjust,
                             attr_value.via.str.size - adjust);
    if (!buf) {
        flb_errno();
        return -1;
    }
    ret = dd_remap_append_kv_to_ddtags(tag_name, buf, strlen(buf), dd_tags_buf);
    flb_sds_destroy(buf);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

/* remapping function for ecs_cluster */
static int dd_remap_ecs_cluster(const char *tag_name,
                                 msgpack_object attr_value, flb_sds_t *dd_tags_buf)
{
    flb_sds_t buf = NULL;
    char *cluster_name;
    int ret;

    buf = flb_sds_create_len(attr_value.via.str.ptr, attr_value.via.str.size);
    if (!buf) {
        flb_errno();
        return -1;
    }
    cluster_name = strstr(buf, ECS_CLUSTER_PREFIX);

    if (cluster_name != NULL) {
        cluster_name += strlen(ECS_CLUSTER_PREFIX);
        ret = dd_remap_append_kv_to_ddtags(tag_name, cluster_name, strlen(cluster_name), dd_tags_buf);
        if (ret < 0) {
            flb_sds_destroy(buf);
            return -1;
        }
    }
    else {
        /*
         * here the input is invalid: not in form of "XXXXXXcluster/"cluster-name
         * we preverse the original value under tag "cluster_name".
         */
        ret = dd_remap_append_kv_to_ddtags(tag_name, buf, strlen(buf), dd_tags_buf);
        if (ret < 0) {
            flb_sds_destroy(buf);
            return -1;
        }
    }
    flb_sds_destroy(buf);
    return 0;
}

/* remapping function for ecs_task_definition */
static int dd_remap_ecs_task_definition(const char *tag_name,
                                         msgpack_object attr_value, flb_sds_t *dd_tags_buf)
{
    flb_sds_t buf = NULL;
    char *split;
    int ret;

    buf = flb_sds_create_len(attr_value.via.str.ptr, attr_value.via.str.size);
    if (!buf) {
        flb_errno();
        return -1;
    }
    split = strchr(buf, ':');

    if (split != NULL) {
        ret = dd_remap_append_kv_to_ddtags("task_family", buf, split-buf, dd_tags_buf);
        if (ret < 0) {
            flb_sds_destroy(buf);
            return -1;
        }
        ret = dd_remap_append_kv_to_ddtags("task_version", split+1, strlen(split+1), dd_tags_buf);
        if (ret < 0) {
            flb_sds_destroy(buf);
            return -1;
        }
    }
    else {
        /*
         * here the input is invalid: not in form of task_name:task_version
         * we preverse the original value under tag "ecs_task_definition".
         */
        ret = dd_remap_append_kv_to_ddtags(tag_name, buf, strlen(buf), dd_tags_buf);
        if (ret < 0) {
            flb_sds_destroy(buf);
            return -1;
        }
    }
    flb_sds_destroy(buf);
    return 0;
}

/* remapping function for ecs_task_arn */
static int dd_remap_ecs_task_arn(const char *tag_name,
                                  msgpack_object attr_value, flb_sds_t *dd_tags_buf)
{
    flb_sds_t buf;
    int ret;

    buf = flb_sds_create_len(attr_value.via.str.ptr, attr_value.via.str.size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    /*
     * Use the full task ARN for compatibility with Datadog products
     * that expect the complete ARN format
     */
    ret = dd_remap_append_kv_to_ddtags(tag_name, buf, strlen(buf), dd_tags_buf);
    flb_sds_destroy(buf);
    if (ret < 0) {
         return -1;
    }

    return 0;
}
/* remapping function for ecs_task_id */
static int dd_remap_ecs_task_id(const char *tag_name,
                                  msgpack_object attr_value, flb_sds_t *dd_tags_buf)
{
    flb_sds_t buf;
    char *remain;
    char *split;
    char *task_arn;
    int ret;

    buf = flb_sds_create_len(attr_value.via.str.ptr, attr_value.via.str.size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    /*
     * if the input is invalid, not in the form of "arn:aws:ecs:region:XXXX"
     * then we won't add the "region" in the dd_tags.
     */
    if ((strlen(buf) > strlen(ECS_ARN_PREFIX)) &&
        (strncmp(buf, ECS_ARN_PREFIX, strlen(ECS_ARN_PREFIX)) == 0)) {

        remain = buf + strlen(ECS_ARN_PREFIX);
        split = strchr(remain, ':');

        if (split != NULL) {
            ret = dd_remap_append_kv_to_ddtags("region", remain, split-remain, dd_tags_buf);
            if (ret < 0) {
                flb_sds_destroy(buf);
                return -1;
            }
        }
    }

    task_arn = strstr(buf, ECS_TASK_PREFIX);
    if (task_arn != NULL) {
        /* parse out the task_arn */
        task_arn += strlen(ECS_TASK_PREFIX);
        ret = dd_remap_append_kv_to_ddtags(tag_name, task_arn, strlen(task_arn), dd_tags_buf);
    }
    else {
        /*
         * if the input is invalid, not in the form of "XXXXXXXXtask/"task-arn
         * then we preverse the original value under tag "task_arn".
         */
        ret = dd_remap_append_kv_to_ddtags(tag_name, buf, strlen(buf), dd_tags_buf);
    }
    flb_sds_destroy(buf);
    if (ret < 0) {
         return -1;
    }

    return 0;
}
/*
 * Statically defines the set of remappings rules in the form of
 * 1) original attr name 2) remapped tag name 3) remapping functions
 * The remapping functions assume the input is valid, and will always
 * produce one or more tags to be added in dd_tags.
 */
const struct dd_attr_tag_remapping remapping[] = {
    {"container_id", "container_id", dd_remap_move_to_tags},
    {"container_name", "container_name", dd_remap_container_name},
    {"container_image", "container_image", dd_remap_move_to_tags},
    {"ecs_cluster", "cluster_name", dd_remap_ecs_cluster},
    {"ecs_task_definition", "ecs_task_definition", dd_remap_ecs_task_definition},
    {"ecs_task_arn", "task_arn", dd_remap_ecs_task_arn},
    {"ecs_task_arn", "task_id", dd_remap_ecs_task_id}
};

/*
 * Check against dd_attr_tag_remapping to see if a given attributes key/val
 * pair need remapping. The key has to match origin_attr_name, and the val
 * has to be of type string and non-empty.
 * return value is the index of the remapping rule in dd_attr_tag_remapping,
 * or -1 if no need to remap
 */
int dd_attr_need_remapping(const msgpack_object key, const msgpack_object val)
{
    int i;

    if ((val.type != MSGPACK_OBJECT_STR) || (val.via.str.size == 0)) {
        return -1;
    }

    for (i = 0; i < sizeof(remapping) / sizeof(struct dd_attr_tag_remapping); i++) {
        if ((key.via.str.size == strlen(remapping[i].origin_attr_name) &&
             memcmp(key.via.str.ptr,
                    remapping[i].origin_attr_name, key.via.str.size) == 0)) {
            return i;
        }
    }

    return -1;
}
