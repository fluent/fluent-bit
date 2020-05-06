/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_kv.h>

#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <msgpack.h>

#include "docker.h"

static int cb_docker_collect(struct flb_input_instance *i_ins,
                             struct flb_config *config, void *in_context);

static docker_info *init_docker_info(char *id)
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

static char *read_line(FILE *fin)
{
    char *buffer;
    char *tmp;
    int read_chars = 0;
    int bufsize = 1215;
    char *line;

    line = (char *) flb_calloc(bufsize, sizeof(char));
    if (!line) {
        flb_errno();
        return NULL;
    }

    buffer = line;

    while (fgets(buffer, bufsize - read_chars, fin)) {
        read_chars = strlen(line);

        if (line[read_chars - 1] == '\n') {
            line[read_chars - 1] = '\0';
            return line;
        }
        else {
            bufsize = 2 * bufsize;
            tmp = flb_realloc(line, bufsize);
            if (!tmp) {
                flb_errno();
                return NULL;
            }
            else {
                line = tmp;
                buffer = line + read_chars;
            }
        }
    }

    return NULL;
}

/* This method returns list of currently running docker ids. */
static struct mk_list *get_active_dockers()
{
    DIR *dp;
    struct dirent *ep;
    struct mk_list *list;

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    dp = opendir(DOCKER_CGROUP_CPU_DIR);
    if (dp != NULL) {
        ep = readdir(dp);

        while(ep != NULL) {
            if (ep->d_type == OS_DIR_TYPE) {
                if (strcmp(ep->d_name, CURRENT_DIR) != 0
                    && strcmp(ep->d_name, PREV_DIR) != 0
                    && strlen(ep->d_name) == DOCKER_LONG_ID_LEN) { /* precautionary check */

                    docker_info *docker = init_docker_info(ep->d_name);
                    mk_list_add(&docker->_head, list);
                }
            }
            ep = readdir(dp);
        }
        closedir(dp);
    }

    return list;
}

/* This routine returns path to docker's cgroup CPU usage file. */
static char *get_cpu_used_file(char *id)
{
    char *path;

    if (!id) {
        return NULL;
    }

    path = (char *) flb_calloc(105, sizeof(char));
    if (!path) {
        flb_errno();
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
static char *get_mem_limit_file(char *id)
{
    char *path;

    if (!id) {
        return NULL;
    }

    path = (char *) flb_calloc(116, sizeof(char));
    if (!path) {
        flb_errno();
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
static char *get_mem_used_file(char *id)
{
    char *path;

    if (!id) {
        return NULL;
    }

    path = (char *) flb_calloc(116, sizeof(char));
    if (!path) {
        flb_errno();
        return NULL;
    }
    strcat(path, DOCKER_CGROUP_MEM_DIR);
    strcat(path, "/");
    strcat(path, id);
    strcat(path, "/");
    strcat(path, DOCKER_MEM_USAGE_FILE);

    return path;
}

static char *get_config_file(char *id)
{
    char *path;

    if (!id) {
        return NULL;
    }

    path = (char *) flb_calloc(107, sizeof(char));
    if (!path) {
        flb_errno();
        return NULL;
    }
    strcat(path, DOCKER_LIB_ROOT);
    strcat(path, "/");
    strcat(path, id);
    strcat(path, "/");
    strcat(path, DOCKER_CONFIG_JSON);

    return path;
}

static char *extract_name(char *line, char *start)
{
    int skip = 9;
    int len = 0;
    char *name;
    char buff[256];
    char *curr;

    if (start != NULL) {
        curr = start + skip;
        while (*curr != '"') {
            buff[len++] = *curr;
            curr++;
        }

        if (len > 0) {
            name = (char *) flb_calloc(len + 1, sizeof(char));
            if (!name) {
                flb_errno();
                return NULL;
            }
            memcpy(name, buff, len);

            return name;
        }
    }

    return NULL;
}

static char *get_container_name(struct flb_docker *ctx, char *id)
{
    char *container_name = NULL;
    char *config_file;
    FILE *f = NULL;
    char *line;

    config_file = get_config_file(id);
    if (!config_file) {
        return NULL;
    }

    f = fopen(config_file, "r");
    if (!f) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot open %s", config_file);
        flb_free(config_file);
        return NULL;
    }

    while ((line = read_line(f))) {
        char *index = strstr(line, DOCKER_NAME_ARG);
        if (index != NULL) {
            container_name = extract_name(line, index);
            flb_free(line);
            break;
        }
        flb_free(line);
    }

    flb_free(config_file);
    fclose(f);

    return container_name;
}

/* Returns CPU metrics for docker id. */
static cpu_snapshot *get_docker_cpu_snapshot(struct flb_docker *ctx, char *id)
{
    int c;
    unsigned long cpu_used = 0;
    char *usage_file;
    cpu_snapshot *snapshot = NULL;
    FILE *f;

    usage_file = get_cpu_used_file(id);
    if (!usage_file) {
        return NULL;
    }

    f = fopen(usage_file, "r");
    if (!f) {
        flb_errno();
        flb_plg_error(ctx->ins, "error gathering CPU data from %s",
                      usage_file);
        flb_free(usage_file);
        return NULL;
    }

    c = fscanf(f, "%ld", &cpu_used);
    if (c != 1) {
        flb_plg_error(ctx->ins, "error scanning used CPU value from %s",
                      usage_file);
        flb_free(usage_file);
        fclose(f);
        return NULL;
    }

    snapshot = (cpu_snapshot *) flb_calloc(1, sizeof(cpu_snapshot));
    if (!snapshot) {
        flb_errno();
        fclose(f);
        flb_free(usage_file);
        return NULL;
    }

    snapshot->used = cpu_used;

    flb_free(usage_file);
    fclose(f);
    return snapshot;
}

/* Returns memory used by a docker in bytes. */
static uint64_t get_docker_mem_used(struct flb_docker *ctx, char *id)
{
    int c;
    char *usage_file = NULL;
    uint64_t mem_used = 0;
    FILE *f;

    usage_file = get_mem_used_file(id);
    if (!usage_file) {
        return 0;
    }

    f = fopen(usage_file, "r");
    if (!f) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot retrieve memory used from %s",
                      usage_file);
        flb_free(usage_file);
        return 0;
    }

    c = fscanf(f, "%ld", &mem_used);
    if (c != 1) {
        flb_plg_error(ctx->ins, "cannot scan memory usage value from %s",
                      usage_file);
        flb_free(usage_file);
        fclose(f);
        return 0;
    }

    flb_free(usage_file);
    fclose(f);

    return mem_used;
}

/* Returns memory limit for a docker in bytes. */
static uint64_t get_docker_mem_limit(char *id)
{
    char *limit_file = get_mem_limit_file(id);
    uint64_t mem_limit = 0;
    FILE *f;

    if (!limit_file) {
        return 0;      
    }

    f = fopen(limit_file, "r");
    if (!f) {
        flb_errno();
        flb_free(limit_file);
        return 0;
    }

    fscanf(f, "%ld", &mem_limit);
    flb_free(limit_file);
    fclose(f);

    return mem_limit;
}

/* Get memory snapshot for a docker id. */
static mem_snapshot *get_docker_mem_snapshot(struct flb_docker *ctx, char *id)
{
    mem_snapshot *snapshot = NULL;

    snapshot = (mem_snapshot *) flb_calloc(1, sizeof(mem_snapshot));
    if (!snapshot) {
        flb_errno();
        return NULL;
    }

    snapshot->used = get_docker_mem_used(ctx, id);
    snapshot->limit = get_docker_mem_limit(id);

    return snapshot;
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
        snapshot->name = get_container_name(ctx, docker->id);
        snapshot->cpu = get_docker_cpu_snapshot(ctx, docker->id);
        snapshot->mem = get_docker_mem_snapshot(ctx, docker->id);
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
             docker = init_docker_info(part->value);
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
            new = init_docker_info(docker->id);
            mk_list_add(&new->_head, filtered);
        }
        else {
            if (is_exists(ctx->whitelist, docker->id)) {
                new = init_docker_info(docker->id);
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

/* Init Docker input */
static int cb_docker_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_docker *ctx;
    const char *pval = NULL;
    (void) data;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_docker));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    /* Collection time setting */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) > 0) {
        ctx->interval_sec = atoi(pval);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }
    ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;

    init_filter_lists(in, ctx);

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time, CPU usage every 1 second */
    ret = flb_input_set_collector_time(in,
                                       cb_docker_collect, ctx->interval_sec,
                                       ctx->interval_nsec, config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for Docker input plugin");
        return -1;
    }
    ctx->coll_fd = ret;

    return ret;
}

/* Flush snapshot as a message for output. */
static void flush_snapshot(struct flb_input_instance *i_ins,
                           docker_snapshot *snapshot)
{
    int name_len;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    if (!snapshot) {
        return;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Timestamp */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, 5);

    /* Docker ID [12 chars] */
    msgpack_pack_str(&mp_pck, 2);
    msgpack_pack_str_body(&mp_pck, "id", 2);
    msgpack_pack_str(&mp_pck, DOCKER_SHORT_ID_LEN);
    msgpack_pack_str_body(&mp_pck, snapshot->id, DOCKER_SHORT_ID_LEN);

    /* Docker Name */
    if (snapshot->name != NULL) {
        name_len = strlen(snapshot->name);
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "name", 4);
        msgpack_pack_str(&mp_pck, name_len);
        msgpack_pack_str_body(&mp_pck, snapshot->name, name_len);
    }

    /* CPU used [nanoseconds] */
    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "cpu_used", 8);
    msgpack_pack_unsigned_long(&mp_pck, snapshot->cpu->used);

    /* Memory used [bytes] */
    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "mem_used", 8);
    msgpack_pack_unsigned_long(&mp_pck, snapshot->mem->used);

    /* Memory limit [bytes] */
    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "mem_limit", 9);
    msgpack_pack_unsigned_int(&mp_pck, snapshot->mem->limit);

    flb_trace("[in_docker] ID %s CPU %lu MEMORY %ld", snapshot->id,
              snapshot->cpu->used, snapshot->mem->used);

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);
}

static void flush_snapshots(struct flb_input_instance *i_ins,
                     struct mk_list *snapshots)
{
    struct mk_list *head;
    docker_snapshot *snapshot;

    mk_list_foreach(head, snapshots) {
        snapshot = mk_list_entry(head, docker_snapshot, _head);
        flush_snapshot(i_ins, snapshot);
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
    active = get_active_dockers();

    filtered = apply_filters(ctx, active);
    if (!filtered) {
        free_docker_list(active);
        return 0;
    }

    /* Get Mem/CPU stats of dockers. */
    snaps = get_docker_stats(ctx, filtered);
    if (!snaps) {
        free_docker_list(active);
        free_docker_list(filtered);
        return 0;
    }

    flush_snapshots(ins, snaps);

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
    free_docker_list(ctx->whitelist);
    free_docker_list(ctx->blacklist);
    flb_free(ctx);

    return 0;
}

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
    .cb_exit      = cb_docker_exit
};
