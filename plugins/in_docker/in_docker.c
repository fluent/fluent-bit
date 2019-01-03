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

static docker_info* init_docker_info(char *id)
{
    docker_info *docker = flb_malloc(sizeof(docker_info));
    docker->id = flb_malloc(sizeof(char)*(strlen(id) + 1));
    strcpy(docker->id, id);

    return docker;
}

static char* read_line(FILE *fin)
{
    char *buffer;
    char *tmp;
    int read_chars = 0;
    int bufsize = 1215;
    char *line = (char *) flb_calloc(bufsize, sizeof(char));

    if (!line) {
        return NULL;
    }

    buffer = line;

    while (fgets(buffer, bufsize - read_chars, fin)) {
        read_chars = strlen(line);

        if (line[read_chars - 1] == '\n') {
            line[read_chars - 1] = '\0';
            return line;
        } else {
            bufsize = 2 * bufsize;
            tmp = realloc(line, bufsize);
            if (tmp) {
                line = tmp;
                buffer = line + read_chars;
            } else {
                flb_free(line);
                return NULL;
            }
        }
    }
    return NULL;
}

/* This method returns list of currently running docker ids. */
static struct mk_list* get_active_dockers()
{
    DIR *dp;
    struct dirent *ep;
    struct mk_list *list = flb_malloc(sizeof(struct mk_list));
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
static char* get_cpu_used_file(char *id)
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
static char* get_mem_limit_file(char *id)
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
    strcat(path, DOCKER_MEM_LIMIT_FILE);

    return path;
}

/* This routine returns path to docker's cgroup memory used file. */
static char* get_mem_used_file(char *id)
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

static char* get_config_file(char *id)
{
    if (!id)
        return NULL;

    char *path = (char *) flb_calloc(107, sizeof(char));
    if (!path) {
        perror("calloc");
        return NULL;
    }
    strcat(path, DOCKER_LIB_ROOT);
    strcat(path, "/");
    strcat(path, id);
    strcat(path, "/");
    strcat(path, DOCKER_CONFIG_JSON);
    
    return path;
}

static char* extract_name(char *line, char *start)
{
    char buff[256];
    int skip = 9;
    int len = 0;
    
    if (start != NULL) {
        char *curr = start + skip;
        while (*curr != '"') {
            buff[len++] = *curr;
            curr++;
        }
        
        if (len > 0) {
            char *name = (char *) flb_calloc(len + 1, sizeof(char));
            memcpy(name, buff, len);
            
            return name;
        }
    }
    
    return NULL;
}

static char* get_container_name(char *id)
{
    char *container_name = NULL;
    char *config_file = get_config_file(id);
    FILE *f;
    char *line;

    if (config_file != NULL) {
        f = fopen(config_file, "r");

        if (!f) {
            perror(config_file);
            return NULL;
        }
        
        if (f) {
            while ((line = read_line(f))) {
                char *index = strstr(line, DOCKER_NAME_ARG);
                if (index != NULL) {
                    container_name = extract_name(line, index);
                    flb_free(line);
                    break;
                }
                flb_free(line);
            }
        }
    }

    flb_free(config_file);
    fclose(f);
    
    return container_name;
}

/* Returns CPU metrics for docker id. */
static cpu_snapshot* get_docker_cpu_snapshot(char *id)
{
    cpu_snapshot *snapshot = NULL;
    char *usage_file = get_cpu_used_file(id);
    unsigned long cpu_used = 0;
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

        flb_free(usage_file);
        fclose(f);
    }

    return snapshot;
}

/* Returns memory used by a docker in bytes. */
static uint64_t get_docker_mem_used(char *id)
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

        flb_free(usage_file);
        fclose(f);
    }

    return mem_used;
}

/* Returns memory limit for a docker in bytes. */
static uint64_t get_docker_mem_limit(char *id)
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

        flb_free(limit_file);
        fclose(f);
    }

    return mem_limit;
}

/* Get memory snapshot for a docker id. */
static mem_snapshot* get_docker_mem_snapshot(char *id)
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

static docker_snapshot* init_snapshot(char *id)
{
    docker_snapshot *snapshot = (docker_snapshot *) flb_malloc(sizeof(docker_snapshot));
    if (!snapshot) {
        perror("malloc");
        return NULL;
    }
    int id_len = strlen(id) + 1;
    snapshot->id = (char *) flb_malloc((id_len)*sizeof(char));
    if (!snapshot->id) {
        perror("malloc");
        return NULL;
    }
    strcpy(snapshot->id, id);

    return snapshot;
}

static bool is_exists(struct mk_list *list, char *id)
{
    bool result = false;
    if (!list || !id)
        return result;

    struct mk_list *head;
    docker_info *item;
    mk_list_foreach(head, list) {
        item = mk_list_entry(head, docker_info, _head);

        /* id could be of length 12 or 64 */
        int id_len = strlen(item->id);
        char *cmp = flb_calloc(id_len + 1, sizeof(char));
        memcpy(cmp, id, id_len);
        if (strcmp(item->id, cmp) == 0) {
            result = true;
        }
        flb_free(cmp);
    }

    return result;
}

/* Returns dockers CPU/Memory metrics. */
static struct mk_list* get_docker_stats(struct mk_list *dockers)
{
    if (!dockers) {
        return NULL;
    }

    struct docker_info *docker;
    struct mk_list *snapshots = flb_malloc(sizeof(struct mk_list));
    struct mk_list *head;

    mk_list_init(snapshots);
    mk_list_foreach(head, dockers) {
        docker = mk_list_entry(head, docker_info, _head);
        docker_snapshot *snapshot = init_snapshot(docker->id);
        snapshot->name = get_container_name(docker->id);
        snapshot->cpu = get_docker_cpu_snapshot(docker->id);
        snapshot->mem = get_docker_mem_snapshot(docker->id);
        mk_list_add(&snapshot->_head, snapshots);
    }

    return snapshots;
}

/* Returns a list of docker ids from space delimited string. */
static struct mk_list* get_ids_from_str(char *space_delimited_str)
{
     struct mk_list *str_parts;
     struct mk_list *parts_head;
     struct mk_list *tmp;
     struct flb_split_entry *part;
     struct mk_list *dockers = flb_malloc(sizeof(struct mk_list));

     mk_list_init(dockers);
     str_parts = flb_utils_split(space_delimited_str, ' ', 256);
     mk_list_foreach_safe(parts_head, tmp, str_parts) {
         part = mk_list_entry(parts_head, struct flb_split_entry, _head);
         if (part->len == DOCKER_LONG_ID_LEN
             || part->len == DOCKER_SHORT_ID_LEN) {
             docker_info *docker = init_docker_info(part->value);
             mk_list_add(&docker->_head, dockers);
         }
     }

     flb_utils_split_free(str_parts);
     return dockers;
}

/* Initializes blacklist/whitelist.  */
static void init_filter_lists(struct flb_input_instance *f_ins,
                              struct flb_in_docker_config *ctx)
{
    struct mk_list *head;
    struct flb_config_prop *prop;
    ctx->whitelist = NULL;
    ctx->blacklist = NULL;


    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        if (strcasecmp(prop->key, "include") == 0) {
            ctx->whitelist = get_ids_from_str(prop->val);
        }
        else if (strcasecmp(prop->key, "exclude") == 0) {
            ctx->blacklist = get_ids_from_str(prop->val);
        }
    }
}

/* Filters list of active dockers as per config.
   NOTE: This returns a new list. */
static struct mk_list* apply_filters(struct flb_in_docker_config *ctx,
                                     struct mk_list *dockers)
{
    if (ctx->whitelist == NULL
        && ctx->blacklist == NULL)
        return dockers;

    struct mk_list *filtered = flb_malloc(sizeof(struct mk_list));
    struct mk_list *head;
    struct mk_list *tmp;
    docker_info *docker;

    mk_list_init(filtered);

    /* whitelist */
    mk_list_foreach_safe(head, tmp, dockers) {
        docker = mk_list_entry(head, docker_info, _head);
        if (ctx->whitelist == NULL) {
            docker_info *new = init_docker_info(docker->id);
            mk_list_add(&new->_head, filtered);
        }
        else {
            if (is_exists(ctx->whitelist, docker->id)) {
                docker_info *new = init_docker_info(docker->id);
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

    init_filter_lists(in, ctx);

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
static void flush_snapshot(struct flb_input_instance *i_ins,
                           docker_snapshot *snapshot)
{
    if (!snapshot)
        return;

    /* Timestamp */
    msgpack_pack_array(&i_ins->mp_pck, 2);
    flb_pack_time_now(&i_ins->mp_pck);
    msgpack_pack_map(&i_ins->mp_pck, 5);

    /* Docker ID [12 chars] */
    msgpack_pack_str(&i_ins->mp_pck, 2);
    msgpack_pack_str_body(&i_ins->mp_pck, "id", 2);
    msgpack_pack_str(&i_ins->mp_pck, DOCKER_SHORT_ID_LEN);
    msgpack_pack_str_body(&i_ins->mp_pck, snapshot->id, DOCKER_SHORT_ID_LEN);
    
    /* Docker Name */
    if (snapshot->name != NULL) {
        int name_len = strlen(snapshot->name);
        msgpack_pack_str(&i_ins->mp_pck, 4);
        msgpack_pack_str_body(&i_ins->mp_pck, "name", 4);
        msgpack_pack_str(&i_ins->mp_pck, name_len);
        msgpack_pack_str_body(&i_ins->mp_pck, snapshot->name, name_len);
    }

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
        snapshot->cpu->used, *(snapshot->mem->used));
}

static void flush_snapshots(struct flb_input_instance *i_ins,
                     struct mk_list *snapshots)
{
    struct mk_list *head;
    docker_snapshot *snapshot;

    /* Mark the start of a 'buffer write' operation */
    flb_input_buf_write_start(i_ins);
    mk_list_foreach(head, snapshots) {
        snapshot = mk_list_entry(head, docker_snapshot, _head);
        flush_snapshot(i_ins, snapshot);
    }
    flb_input_buf_write_end(i_ins);
}

static void free_snapshots(struct mk_list *snaps)
{
    if (snaps == NULL)
        return;

    struct mk_list *head;
    struct docker_snapshot *snap;
    struct mk_list *tmp;
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
    if (dockers == NULL)
        return;

    struct mk_list *head;
    struct mk_list *tmp;
    struct docker_info *docker;
    mk_list_foreach_safe(head, tmp, dockers) {
        docker = mk_list_entry(head, docker_info, _head);
        flb_free(docker->id);
        flb_free(docker);
    }
    flb_free(dockers);
}

/* Callback to gather Docker CPU/Memory usage. */
int in_docker_collect(struct flb_input_instance *i_ins,
                      struct flb_config *config, void *in_context)
{
    struct mk_list *active;
    struct mk_list *filtered;
    struct mk_list *snaps;
    (void) config;
    struct flb_in_docker_config *ctx = in_context;

    /* Get current active dockers. */
    active = get_active_dockers();

    filtered = apply_filters(ctx, active);

    /* Get Mem/CPU stats of dockers. */
    snaps = get_docker_stats(filtered);
    if (!snaps)
        return 0;

    flush_snapshots(i_ins, snaps);

    flb_stats_update(in_docker_plugin.stats_fd, 0, 1);

    free_snapshots(snaps);
    free_docker_list(active);
    
    if (ctx->whitelist != NULL
        || ctx->blacklist != NULL)
        free_docker_list(filtered);

    return 0;
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
    free_docker_list(ctx->whitelist);
    free_docker_list(ctx->blacklist);
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_docker_plugin = {
    .name         = "docker",
    .description  = "Dockers metrics",
    .cb_init      = in_docker_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_docker_collect,
    .cb_flush_buf  = NULL,
    .cb_pause     = in_docker_pause,
    .cb_resume    = in_docker_resume,
    .cb_exit      = in_docker_exit
};