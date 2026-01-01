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

#ifndef FLB_FILTER_ECS_H
#define FLB_FILTER_ECS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>

#define FLB_ECS_FILTER_HOST                       "127.0.0.1"
#define FLB_ECS_FILTER_PORT                       "51678"
#define FLB_ECS_FILTER_CLUSTER_PATH               "/v1/metadata"
#define FLB_ECS_FILTER_TASK_PATH_FORMAT           "/v1/tasks?dockerid=%s"
#define FLB_ECS_FILTER_METADATA_RETRIES           "2"

/*
 * Kubernetes recommends not running more than 110 pods per node
 * In ECS, the number of tasks per instance will vary considerably
 * But this should be a very safe starting size for the table
 * Since we use the TTL hash table there is no max size. 
 */
#define FLB_ECS_FILTER_HASH_TABLE_SIZE 100


struct flb_ecs_metadata_key {
    flb_sds_t key;
    flb_sds_t template;
    struct flb_record_accessor *ra;

    struct mk_list _head;
};

struct flb_ecs_metadata_buffer {
    /* msgpack_sbuffer */
    char *buf;
    size_t size;

    /* unpacked object to use with flb_ra_translate */
    msgpack_unpacked unpacked;
    msgpack_object obj;
    int free_packer;

    /* the hash table only stores a pointer- we need the list to track and free these */
    struct mk_list _head;
    /* we clean up the memory for these once ecs_meta_cache_ttl has expired */
    time_t last_used_time;

    /* 
     * To remove from the hash table on TTL expiration, we need the ID 
     * While we use a TTL hash, it won't clean up the memory, so we have a separate routine for that
     * and it needs to ensure that the list and hash table has the same contents
     */
    flb_sds_t id;
};

struct flb_ecs_cluster_metadata {
    flb_sds_t cluster_name;
    flb_sds_t container_instance_arn;
    flb_sds_t container_instance_id;
    flb_sds_t ecs_agent_version;
};

/*
 * The ECS Agent task response gives us both task & container at the same time
 * We need a temporary structure to organize the task metadata
 * Before we create the final flb_ecs_metadata_buffer objects with all metadata
 * So this struct just stores tmp pointers to the deserialized msgpack
 */
struct flb_ecs_task_metadata {
    const char* task_arn;
    int task_arn_len;
    const char *task_id;
    int task_id_len;
    const char *task_def_family;
    int task_def_family_len;
    const char *task_def_version;
    int task_def_version_len;
};

struct flb_filter_ecs {
    /* upstream connection to ECS Agent */
    struct flb_upstream *ecs_upstream;

    /* Filter plugin instance reference */
    struct flb_filter_instance *ins;

    struct mk_list metadata_keys;
    int metadata_keys_len;

    flb_sds_t ecs_host;
    int ecs_port;

    int agent_endpoint_retries;

    /* 
     * This field is used when we build new container metadata objects
     */
    struct flb_ecs_cluster_metadata cluster_metadata;
    int has_cluster_metadata;
    /*
     * If looking up the container fails, we should still always be able to
     * attach cluster metadata. So we have a fallback metadata buffer for that.
     * For example, users may want to attach cluster name to Docker Daemon logs,
     * even though Docker is not an AWS ECS Task/container.
     */
    struct flb_ecs_metadata_buffer cluster_meta_buf;

    /* 
     * Maps 12 char container short ID to metadata buffer
     */
    struct flb_hash_table *container_hash_table;

    /*
     * The hash table only stores pointers, so we keep a list of meta objects
     * that need to be freed
     */
    struct mk_list metadata_buffers;

    /* 
     * Fluent Bit may pick up logs for containers that were not scheduled by ECS
     * These will lead to continuous error messages. Therefore, we store
     * a hash table of tags for which we could not get metadata so we can stop
     * retrying on them.
     */
    struct flb_hash_table *failed_metadata_request_tags;

    int ecs_meta_cache_ttl;
    char *ecs_tag_prefix;
    int ecs_tag_prefix_len;
    int cluster_metadata_only;
};

#endif
