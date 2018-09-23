/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_stats.h>
#include <fluent-bit/flb_pack.h>

#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <msgpack.h>

#include "in_docker.h"

struct flb_input_plugin in_docker_plugin;

/* This method returns list of currently running docker ids. */
static docker_list* get_active_dockers()
{
    DIR *dp;
    struct dirent *ep;
    docker_list *list = NULL;
    char buffer[256][DOCKER_ID_LEN + 1];

    dp = opendir(DOCKER_CGROUP_CPU_DIR);
    int counter = 0;
    if (dp != NULL) {
        ep = readdir(dp);
        while(ep != NULL) {

            /* buffer limit */
            if (counter > 255)
                break;

            if (ep->d_type == OS_DIR_TYPE) {
                if (strcmp(ep->d_name, CURRENT_DIR) != 0
                    && strcmp(ep->d_name, PREV_DIR) != 0) {
                    strcpy(buffer[counter], ep->d_name);
                    counter++;
                }
            }
            ep = readdir(dp);
        }

        list = (docker_list *) flb_calloc(1, sizeof(docker_list));
        if (list != NULL) {
            list->count = counter;
            list->ids = (char **) flb_calloc(list->count, sizeof (char **));
            for (int i = 0; i < list->count; i++) {
                list->ids[i] = (char*) flb_calloc(list->count,
                                                  sizeof(char) * (DOCKER_ID_LEN + 1));
                strcpy(list->ids[i], buffer[i]);
            }
        } else
            perror("calloc");
    }

    return list;
}

/* This routine returns path to docker's cgroup CPU usage file. */
char* get_cpu_used_file(char *id)
{
    if (!id)
        return NULL;

    char *path = (char *) flb_calloc(105, sizeof(char));
    if (!path) {
        perror("calloc");
        return NULL;
    }
    strcat(path, DOCKER_CGROUP_CPU_DIR);
    strcat(path, "/");
    strcat(path, id);
    strcat(path, "/");
    strcat(path, DOCKER_CPU_USAGE_FILE);

    return path;
}

/* This routine returns path to docker's cgroup memory limit file. */
char* get_mem_limit_file(char *id)
{
    if (!id)
        return NULL;

    char *path = (char *) flb_calloc(105, sizeof(char));
    if (!path) {
        perror("calloc");
        return NULL;
    }
    strcat(path, DOCKER_CGROUP_MEM_DIR);
    strcat(path, "/");
    strcat(path, id);
    strcat(path, "/");
    strcat(path, DOCKER_MEM_LIMIT_FILE);

    return path;
}

/* This routine returns path to docker's cgroup memory used file. */
char* get_mem_used_file(char *id)
{
    if (!id)
        return NULL;

    char *path = (char *) flb_calloc(116, sizeof(char));
    if (!path) {
        perror("calloc");
        return NULL;
    }
    strcat(path, DOCKER_CGROUP_MEM_DIR);
    strcat(path, "/");
    strcat(path, id);
    strcat(path, "/");
    strcat(path, DOCKER_MEM_USAGE_FILE);

    return path;
}

/* Returns CPU metrics for docker id. */
cpu_snapshot* get_docker_cpu_snapshot(char *id)
{
    cpu_snapshot *snapshot = NULL;
    char *usage_file = get_cpu_used_file(id);
    long int cpu_used = -1;
    FILE *f;

    if (usage_file != NULL) {
        f = fopen(usage_file, "r");

        if (!f) {
            perror(usage_file);
            return NULL;
        }

        fscanf(f, "%ld", &cpu_used);

        snapshot = (cpu_snapshot *) flb_calloc(1, sizeof(cpu_snapshot));
        if (!snapshot) {
            perror("calloc");
            return NULL;
        }
        snapshot->used = cpu_used;

        fclose(f);
    }

    return snapshot;
}

/* Returns memory used by a docker in bytes. */
uint64_t get_docker_mem_used(char *id)
{
    char *usage_file = get_mem_used_file(id);
    uint64_t mem_used = 0;
    FILE *f;

    if (usage_file != NULL) {
        f = fopen(usage_file, "r");

        if (!f) {
            perror(usage_file);
            return 0;
        }

        fscanf(f, "%ld", &mem_used);

        fclose(f);
    }

    return mem_used;
}

/* Returns memory limit for a docker in bytes. */
uint64_t get_docker_mem_limit(char *id)
{
    char *limit_file = get_mem_limit_file(id);
    uint64_t mem_limit = 0;
    FILE *f;

    if (limit_file != NULL) {
        f = fopen(limit_file, "r");

        if (!f) {
            perror(limit_file);
            return 0;
        }

        fscanf(f, "%ld", &mem_limit);

        fclose(f);
    }

    return mem_limit;
}

/* Get memory snapshot for a docker id. */
mem_snapshot* get_docker_mem_snapshot(char *id)
{
    mem_snapshot *snapshot = NULL;
    snapshot = (mem_snapshot *) flb_calloc(1, sizeof(mem_snapshot));
    if (!snapshot) {
        perror("calloc");
        return NULL;
    }

    snapshot->used = get_docker_mem_used(id);
    snapshot->limit = get_docker_mem_limit(id);

    return snapshot;
}

/* Allocate space to snapshot list. */
snapshot_list* snapshots_init(int count)
{
    snapshot_list *snapshots = NULL;
    snapshots = (snapshot_list *) flb_calloc(1, sizeof (snapshot_list));
    if (!snapshots) {
        perror("calloc");
        return NULL;
    }
    snapshots->snapshots = (docker_snapshot **) flb_calloc(count,
                                                           sizeof(docker_snapshot **));
    if (!snapshots->snapshots) {
        perror("calloc");
        return NULL;
    }
    snapshots->count = count;

    return snapshots;
}

docker_snapshot* snapshot_init(char *id)
{
    docker_snapshot *snapshot = (docker_snapshot *) flb_calloc(1, sizeof(docker_snapshot));
    if (!snapshot) {
        perror("calloc");
        return NULL;
    }
    int id_len = strlen(id) + 1;
    snapshot->id = (char *) flb_calloc((id_len), sizeof(char));
    if (!snapshot->id) {
        perror("calloc");
        return NULL;
    }
    strcpy(snapshot->id, id);

    return snapshot;
}

/* Retuns dockers CPU/Memory metrics. */
static snapshot_list* get_docker_stats(docker_list *dockers)
{
    if (!dockers) {
        return NULL;
    }

    snapshot_list *snapshots = snapshots_init(dockers->count);
    if (!snapshots)
        return NULL;

    for (int i = 0; i < dockers->count; i++) {
        docker_snapshot *snapshot = snapshot_init(dockers->ids[i]);
        snapshot->cpu = get_docker_cpu_snapshot(dockers->ids[i]);
        snapshot->mem = get_docker_mem_snapshot(dockers->ids[i]);
        snapshots->snapshots[i] = snapshot;
    }

    return snapshots;
}

/* Init Docker input */
static int in_docker_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_docker_config *ctx;
    (void) data;
    char *pval = NULL;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_docker_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }
    ctx->i_ins = in;

    /* Collection time setting */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) > 0) {
        ctx->interval_sec = atoi(pval);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }
    ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time, CPU usage every 1 second */
    ret = flb_input_set_collector_time(in, 
                                       in_docker_collect, ctx->interval_sec,
                                       ctx->interval_nsec, config);
    if (ret == -1) {
        perror("[in_docker] Could not set collector for Docker input plugin");
        return -1;
    }
    ctx->coll_fd = ret;

    return ret;
}

/* Flush snapshot as a message for output. */
void flush_snapshot(struct flb_input_instance *i_ins,
    docker_snapshot *snapshot)
{
    if (!snapshot)
        return;

    /* Timestamp */
    msgpack_pack_array(&i_ins->mp_pck, 2);
    flb_pack_time_now(&i_ins->mp_pck);
    msgpack_pack_map(&i_ins->mp_pck, 4);

    /* Docker ID [15 chars] */
    msgpack_pack_str(&i_ins->mp_pck, 2);
    msgpack_pack_str_body(&i_ins->mp_pck, "id", 2);
    msgpack_pack_str(&i_ins->mp_pck, 15);
    msgpack_pack_str_body(&i_ins->mp_pck, snapshot->id, 15);

    /* CPU used [nanoseconds] */
    msgpack_pack_str(&i_ins->mp_pck, 8);
    msgpack_pack_str_body(&i_ins->mp_pck, "cpu_used", 8);
    msgpack_pack_unsigned_long(&i_ins->mp_pck, snapshot->cpu->used);

    /* Memory used [bytes] */
    msgpack_pack_str(&i_ins->mp_pck, 8);
    msgpack_pack_str_body(&i_ins->mp_pck, "mem_used", 8);
    msgpack_pack_unsigned_long(&i_ins->mp_pck, snapshot->mem->used);

    /* Memory limit [bytes] */
    msgpack_pack_str(&i_ins->mp_pck, 9);
    msgpack_pack_str_body(&i_ins->mp_pck, "mem_limit", 9);
    msgpack_pack_unsigned_int(&i_ins->mp_pck, snapshot->mem->limit);

    flb_trace("[in_docker] ID %s CPU %lu MEMORY", snapshot->id,
        snapshot->cpu->used, snapshot->mem->used);
}

/* Callback to gather Docker CPU/Memory usage. */
int in_docker_collect(struct flb_input_instance *i_ins,
                      struct flb_config *config, void *in_context)
{
    docker_list *list = NULL;
    struct snapshot_list *s;
    (void) config;

    /* Get current active dockers. */
    list = get_active_dockers ();
    if (!list || list->count == 0) {

        /* No need to check for snapshot if
           no docker(s) or engine running.*/
        return -1;
    }

    /* Get Mem/CPU stats of dockers. */
    s = get_docker_stats (list);
    if (!s)
        return 0;

    /* Mark the start of a 'buffer write' operation */
    flb_input_buf_write_start(i_ins);

    for (int i = 0; i < s->count; i++)
        flush_snapshot(i_ins, s->snapshots[i]);

    flb_input_buf_write_end(i_ins);
    flb_stats_update(in_docker_plugin.stats_fd, 0, 1);

    return s->count;
}

static void in_docker_pause(void *data, struct flb_config *config)
{
    struct flb_in_docker_config *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->i_ins);
}

static void in_docker_resume(void *data, struct flb_config *config)
{
    struct flb_in_docker_config *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->i_ins);
}

static int in_docker_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_docker_config *ctx = data;

    /* done */
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_docker_plugin = {
    .name         = "docker",
    .description  = "Dockers CPU/Memory metrics",
    .cb_init      = in_docker_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_docker_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_docker_pause,
    .cb_resume    = in_docker_resume,
    .cb_exit      = in_docker_exit
};