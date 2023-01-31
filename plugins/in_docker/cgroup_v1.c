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

#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input_plugin.h>

#include <dirent.h>
#include <string.h>
#include "docker.h"

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

    dp = opendir(DOCKER_CGROUP_V1_CPU_DIR);
    if (dp != NULL) {
        ep = readdir(dp);

        while(ep != NULL) {
            if (ep->d_type == OS_DIR_TYPE) {
                if (strcmp(ep->d_name, CURRENT_DIR) != 0
                    && strcmp(ep->d_name, PREV_DIR) != 0
                    && strlen(ep->d_name) == DOCKER_LONG_ID_LEN) { /* precautionary check */

                    docker_info *docker = in_docker_init_docker_info(ep->d_name);
                    mk_list_add(&docker->_head, list);
                }
            }
            ep = readdir(dp);
        }
        closedir(dp);
    }

    return list;
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

    flb_free(line);
    return NULL;
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

    strcat(path, DOCKER_CGROUP_V1_CPU_DIR);
    strcat(path, "/");
    strcat(path, id);
    strcat(path, "/");
    strcat(path, DOCKER_CGROUP_V1_CPU_USAGE_FILE);

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
    strcat(path, DOCKER_CGROUP_V1_MEM_DIR);
    strcat(path, "/");
    strcat(path, id);
    strcat(path, "/");
    strcat(path, DOCKER_CGROUP_V1_MEM_LIMIT_FILE);

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
    strcat(path, DOCKER_CGROUP_V1_MEM_DIR);
    strcat(path, "/");
    strcat(path, id);
    strcat(path, "/");
    strcat(path, DOCKER_CGROUP_V1_MEM_USAGE_FILE);

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

int in_docker_set_cgroup_api_v1(struct cgroup_api *api)
{
    api->cgroup_version = 1;
    api->get_active_docker_ids = get_active_dockers;
    api->get_container_name = get_container_name;
    api->get_cpu_snapshot = get_docker_cpu_snapshot;
    api->get_mem_snapshot = get_docker_mem_snapshot;

    return 0;
}
