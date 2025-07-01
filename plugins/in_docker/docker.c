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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_kv.h>

#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "docker.h"

static int cb_docker_collect(struct flb_input_instance *i_ins,
                             struct flb_config *config, void *in_context);

docker_info *in_docker_init_docker_info(char *id)
{
    int len;
    docker_info *docker;

    docker = flb_malloc(sizeof(docker_info));
    if (!docker) {
        flb_errno();
        return NULL;
    }

    len = strlen(id);
    docker->id = flb_malloc(sizeof(char)*(len + 1));
    if (!docker->id) {
        flb_errno();
        flb_free(docker);
        return NULL;
    }
    strcpy(docker->id, id);
    docker->id[len] = '\0';

    return docker;
}

static docker_snapshot *init_snapshot(char *id)
{
    int id_len;
    docker_snapshot *snapshot;

    snapshot = (docker_snapshot *) flb_malloc(sizeof(docker_snapshot));
    if (!snapshot) {
        flb_errno();
        return NULL;
    }

    id_len = strlen(id) + 1;
    snapshot->id = (char *) flb_malloc((id_len)*sizeof(char));
    if (!snapshot->id) {
        flb_errno();
        flb_free(snapshot);
        return NULL;
    }
    strcpy(snapshot->id, id);

    return snapshot;
}

static bool is_exists(struct mk_list *list, char *id)
{
    int id_len;
    char *cmp;
    docker_info *item;
    bool result = false;
    struct mk_list *head;

    if (!list || !id) {
        return result;
    }

    mk_list_foreach(head, list) {
        item = mk_list_entry(head, docker_info, _head);

        /* id could be of length 12 or 64 */
        id_len = strlen(item->id);
        cmp = flb_calloc(id_len + 1, sizeof(char));
        if (!cmp) {
            flb_errno();
            return NULL;
        }
        memcpy(cmp, id, id_len);
        if (strcmp(item->id, cmp) == 0) {
            result = true;
        }
        flb_free(cmp);
    }

    return result;
}

static void free_snapshots(struct mk_list *snaps);
/* Returns dockers CPU/Memory metrics. */
static struct mk_list *get_docker_stats(struct flb_docker *ctx, struct mk_list *dockers)
{
    docker_snapshot *snapshot;
    struct docker_info *docker;
    struct mk_list *head;
    struct mk_list *snapshots;

    if (!dockers) {
        return NULL;
    }

    snapshots = flb_malloc(sizeof(struct mk_list));
    if (!snapshots) {
        flb_errno();
        return NULL;
    }

    mk_list_init(snapshots);
    mk_list_foreach(head, dockers) {
        docker = mk_list_entry(head, docker_info, _head);
        snapshot = init_snapshot(docker->id);
        if (snapshot == NULL) {
            free_snapshots(snapshots);
            return NULL;
        }
        snapshot->name = ctx->cgroup_api.get_container_name(ctx, docker->id);
        if (snapshot->name == NULL) {
            free_snapshots(snapshots);
            flb_free(snapshot->id);
            flb_free(snapshot);
            return NULL;
        }
        snapshot->cpu = ctx->cgroup_api.get_cpu_snapshot(ctx, docker->id);
        if (snapshot->cpu == NULL) {
            free_snapshots(snapshots);
            flb_free(snapshot->name);
            flb_free(snapshot->id);
            flb_free(snapshot);
            return NULL;
        }
        snapshot->mem = ctx->cgroup_api.get_mem_snapshot(ctx, docker->id);
        if (snapshot->mem == NULL) {
            free_snapshots(snapshots);
            flb_free(snapshot->cpu);
            flb_free(snapshot->name);
            flb_free(snapshot->id);
            flb_free(snapshot);
            return NULL;
        }

        mk_list_add(&snapshot->_head, snapshots);
    }

    return snapshots;
}

/* Returns a list of docker ids from space delimited string. */
static struct mk_list *get_ids_from_str(char *space_delimited_str)
{
     struct mk_list *str_parts;
     struct mk_list *parts_head;
     struct mk_list *tmp;
     struct flb_split_entry *part;
     struct mk_list *dockers;
     docker_info *docker;

     dockers = flb_malloc(sizeof(struct mk_list));
     if (!dockers) {
        flb_errno();
        return NULL;
     }

     mk_list_init(dockers);
     str_parts = flb_utils_split(space_delimited_str, ' ', 256);
     mk_list_foreach_safe(parts_head, tmp, str_parts) {
         part = mk_list_entry(parts_head, struct flb_split_entry, _head);
         if (part->len == DOCKER_LONG_ID_LEN
             || part->len == DOCKER_SHORT_ID_LEN) {
             docker = in_docker_init_docker_info(part->value);
             mk_list_add(&docker->_head, dockers);
         }
     }

     flb_utils_split_free(str_parts);
     return dockers;
}

/* Initializes blacklist/whitelist.  */
static void init_filter_lists(struct flb_input_instance *f_ins,
                              struct flb_docker *ctx)
{
    struct mk_list *head;
    struct flb_kv *kv;

    ctx->whitelist = NULL;
    ctx->blacklist = NULL;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "include") == 0) {
            ctx->whitelist = get_ids_from_str(kv->val);
        }
        else if (strcasecmp(kv->key, "exclude") == 0) {
            ctx->blacklist = get_ids_from_str(kv->val);
        }
    }
}

/* Filters list of active dockers as per config. This returns a new list */
static struct mk_list *apply_filters(struct flb_docker *ctx,
                                     struct mk_list *dockers)
{
    struct mk_list *head;
    struct mk_list *tmp;
    docker_info *new;
    docker_info *docker;
    struct mk_list *filtered;

    if (ctx->whitelist == NULL && ctx->blacklist == NULL) {
        return dockers;
    }

    filtered = flb_malloc(sizeof(struct mk_list));
    if (!filtered) {
        flb_errno();
        return NULL;
    }

    mk_list_init(filtered);

    /* whitelist */
    mk_list_foreach_safe(head, tmp, dockers) {
        docker = mk_list_entry(head, docker_info, _head);
        if (ctx->whitelist == NULL) {
            new = in_docker_init_docker_info(docker->id);
            mk_list_add(&new->_head, filtered);
        }
        else {
            if (is_exists(ctx->whitelist, docker->id)) {
                new = in_docker_init_docker_info(docker->id);
                mk_list_add(&new->_head, filtered);
            }
        }
    }

    /* blacklist */
    if (ctx->blacklist != NULL) {
        mk_list_foreach_safe(head, tmp, filtered) {
            docker = mk_list_entry(head, docker_info, _head);
            if (is_exists(ctx->blacklist, docker->id)) {
                mk_list_del(&docker->_head);
                flb_free(docker->id);
                flb_free(docker);
            }
        }
    }

    return filtered;
}

/*
 * Calculate which cgroup version is used on host by checing existence of
 * cgroup.controllers file (if it exists, it is V2).
 */
static int get_cgroup_version(struct flb_docker *ctx)
{
    char path[SYSFS_FILE_PATH_SIZE];
    snprintf(path, sizeof(path), "%s/%s", ctx->sysfs_path, CGROUP_V2_PATH);
    return (access(path, F_OK) == 0) ? CGROUP_V2 : CGROUP_V1;
}

/* Init Docker input */
static int cb_docker_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_docker *ctx;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_docker));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    init_filter_lists(in, ctx);

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_free(ctx);
        flb_plg_error(in, "unable to load configuration.");
        return -1;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }

    /* Detect cgroups version v2 or v1 */
    if (get_cgroup_version(ctx) == CGROUP_V2) {
        flb_plg_info(ctx->ins, "Detected cgroups v2");
        in_docker_set_cgroup_api_v2(&ctx->cgroup_api);
        ctx->cgroup_version = CGROUP_V2;
    }
    else {
        flb_plg_info(ctx->ins, "Detected cgroups v1");
        in_docker_set_cgroup_api_v1(&ctx->cgroup_api);
        ctx->cgroup_version = CGROUP_V1;
    }

    /* Set our collector based on time, CPU usage every 1 second */
    ret = flb_input_set_collector_time(in,
                                       cb_docker_collect, ctx->interval_sec,
                                       ctx->interval_nsec, config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for Docker input plugin");
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);
        flb_free(ctx);
        return -1;
    }

    return ret;
}

/* Flush snapshot as a message for output. */
static void flush_snapshot(struct flb_docker *ctx,
                           struct flb_input_instance *i_ins,
                           docker_snapshot *snapshot)
{
    int result;

    if (!snapshot) {
        return;
    }

    result = flb_log_event_encoder_begin_record(&ctx->log_encoder);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_current_timestamp(
                    &ctx->log_encoder);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    /* Docker ID [12 chars] */
                    FLB_LOG_EVENT_CSTRING_VALUE("id"),
                    FLB_LOG_EVENT_STRING_VALUE(snapshot->id, DOCKER_SHORT_ID_LEN),

                    /* Docker Name */
                    FLB_LOG_EVENT_CSTRING_VALUE("name"),
                    FLB_LOG_EVENT_CSTRING_VALUE(snapshot->name),

                    /* CPU used [nanoseconds] */
                    FLB_LOG_EVENT_CSTRING_VALUE("cpu_used"),
                    FLB_LOG_EVENT_UINT32_VALUE(snapshot->cpu->used),

                    /* Memory used [bytes] */
                    FLB_LOG_EVENT_CSTRING_VALUE("mem_used"),
                    FLB_LOG_EVENT_UINT32_VALUE(snapshot->mem->used),

                    /* Memory limit [bytes] */
                    FLB_LOG_EVENT_CSTRING_VALUE("mem_limit"),
                    FLB_LOG_EVENT_UINT64_VALUE(snapshot->mem->limit));
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(&ctx->log_encoder);
    }

    flb_trace("[in_docker] ID %s CPU %lu MEMORY %ld", snapshot->id,
              snapshot->cpu->used, snapshot->mem->used);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(i_ins, NULL, 0,
                             ctx->log_encoder.output_buffer,
                             ctx->log_encoder.output_length);

    }
    else {
        flb_plg_error(i_ins, "Error encoding record : %d", result);
    }

    flb_log_event_encoder_reset(&ctx->log_encoder);
}

static void flush_snapshots(struct flb_docker *ctx,
                            struct flb_input_instance *i_ins,
                            struct mk_list *snapshots)
{
    struct mk_list *head;
    docker_snapshot *snapshot;

    mk_list_foreach(head, snapshots) {
        snapshot = mk_list_entry(head, docker_snapshot, _head);
        flush_snapshot(ctx, i_ins, snapshot);
    }
}

static void free_snapshots(struct mk_list *snaps)
{
    struct docker_snapshot *snap;
    struct mk_list *tmp;
    struct mk_list *head;

    if (snaps == NULL) {
        return;
    }

    mk_list_foreach_safe(head, tmp, snaps) {
        snap = mk_list_entry(head, docker_snapshot, _head);
        flb_free(snap->id);
        flb_free(snap->name);
        flb_free(snap->cpu);
        flb_free(snap->mem);
        flb_free(snap);
    }
    flb_free(snaps);
}

static void free_docker_list(struct mk_list *dockers)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct docker_info *docker;

    if (dockers == NULL) {
        return;
    }

    mk_list_foreach_safe(head, tmp, dockers) {
        docker = mk_list_entry(head, docker_info, _head);
        flb_free(docker->id);
        flb_free(docker);
    }
    flb_free(dockers);
}

/* Callback to gather Docker CPU/Memory usage. */
static int cb_docker_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    struct mk_list *active;
    struct mk_list *filtered;
    struct mk_list *snaps;
    struct flb_docker *ctx = in_context;
    (void) config;

    /* Get current active dockers. */
    active = ctx->cgroup_api.get_active_container_ids(ctx);

    filtered = apply_filters(ctx, active);
    if (!filtered) {
        free_docker_list(active);
        return 0;
    }

    /* Get Mem/CPU stats of dockers. */
    snaps = get_docker_stats(ctx, filtered);
    if (!snaps) {
        free_docker_list(active);
        if (active != filtered) {
            /* apply_filters can return the address of acive.
             * In that case, filtered is already freed.
             */
            free_docker_list(filtered);
        }
        return 0;
    }

    flush_snapshots(ctx, ins, snaps);

    free_snapshots(snaps);
    free_docker_list(active);

    if (ctx->whitelist != NULL || ctx->blacklist != NULL) {
        free_docker_list(filtered);
    }

    return 0;
}

static void cb_docker_pause(void *data, struct flb_config *config)
{
    struct flb_docker *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void cb_docker_resume(void *data, struct flb_config *config)
{
    struct flb_docker *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int cb_docker_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_docker *ctx = data;

    /* done */
    flb_log_event_encoder_destroy(&ctx->log_encoder);

    free_docker_list(ctx->whitelist);
    free_docker_list(ctx->blacklist);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_docker, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_docker, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    {
      FLB_CONFIG_MAP_STR, "include", NULL,
      0, FLB_FALSE, 0,
      "A space-separated list of containers to include"
    },
    {
      FLB_CONFIG_MAP_STR, "exclude", NULL,
      0, FLB_FALSE, 0,
      "A space-separated list of containers to exclude"
    },
    {
      FLB_CONFIG_MAP_STR, "path.sysfs", DEFAULT_SYSFS_PATH,
      0, FLB_TRUE, offsetof(struct flb_docker, sysfs_path),
      "sysfs mount point"
    },
    {
      FLB_CONFIG_MAP_STR, "path.containers", DEFAULT_CONTAINERS_PATH,
      0, FLB_TRUE, offsetof(struct flb_docker, containers_path),
      "containers directory"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_docker_plugin = {
    .name         = "docker",
    .description  = "Docker containers metrics",
    .cb_init      = cb_docker_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_docker_collect,
    .cb_flush_buf  = NULL,
    .cb_pause     = cb_docker_pause,
    .cb_resume    = cb_docker_resume,
    .cb_exit      = cb_docker_exit,
    .config_map   = config_map
};
