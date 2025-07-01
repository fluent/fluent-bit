/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023 The Fluent Bit Authors
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
static struct mk_list *get_active_dockers(struct flb_docker *ctx)
{
    DIR *dp;
    struct dirent *ep;
    struct mk_list *list;
    docker_info *docker;
    char *p = NULL;
    char *container_id = NULL;
    char path[SYSFS_FILE_PATH_SIZE];

    path[0] = '\0';

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    snprintf(path, sizeof(path), "%s/%s", ctx->sysfs_path, DOCKER_CGROUP_V2_DOCKER_SERVICE_DIR);

    dp = opendir(path);
    if (dp != NULL) {
        ep = readdir(dp);

        while(ep != NULL) {
            if (ep->d_type == OS_DIR_TYPE) {
                if (strcmp(ep->d_name, CURRENT_DIR) != 0
                    && strcmp(ep->d_name, PREV_DIR) != 0
                    && strlen(ep->d_name) == DOCKER_CGROUP_V2_LONG_ID_LEN) { /* precautionary check */

                    p = strstr(ep->d_name, "-");
                    if (p == NULL) {
                        continue;
                    }
                    /* get rid of the prefix "-" and the suffix ".scope" */
                    container_id = strtok(p+1, ".");
                    if (container_id != NULL) {
                        docker = in_docker_init_docker_info(container_id);
                        mk_list_add(&docker->_head, list);
                    }

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
static char *get_cpu_used_file(struct flb_docker *ctx, char *id)
{
    char *path;
    int len = 0;

    if (!id) {
        return NULL;
    }

    len = flb_sds_len(ctx->sysfs_path);
    path = (char *) flb_calloc(101 + len, sizeof(char));
    if (!path) {
        flb_errno();
        return NULL;
    }

    strcat(path, ctx->sysfs_path);
    strcat(path, "/");
    strcat(path, DOCKER_CGROUP_V2_DOCKER_SERVICE_DIR);
    strcat(path, "/");
    strcat(path, "docker-");
    strcat(path, id);
    strcat(path, ".scope");
    strcat(path, "/");
    strcat(path, DOCKER_CGROUP_V2_CPU_USAGE_FILE);

    return path;
}

/* This routine returns path to docker's cgroup memory limit file. */
static char *get_mem_limit_file(struct flb_docker *ctx, char *id)
{
    char *path;
    int len = 0;

    if (!id) {
        return NULL;
    }

    len = flb_sds_len(ctx->sysfs_path);
    path = (char *) flb_calloc(108 + len, sizeof(char));
    if (!path) {
        flb_errno();
        return NULL;
    }
    strcat(path, ctx->sysfs_path);
    strcat(path, "/");
    strcat(path, DOCKER_CGROUP_V2_DOCKER_SERVICE_DIR);
    strcat(path, "/");
    strcat(path, "docker-");
    strcat(path, id);
    strcat(path, ".scope");
    strcat(path, "/");
    strcat(path, DOCKER_CGROUP_V2_MEM_MAX_FILE);

    return path;
}

/* This routine returns path to docker's cgroup memory used file. */
static char *get_mem_used_file(struct flb_docker *ctx, char *id)
{
    char *path;
    int len = 0;

    if (!id) {
        return NULL;
    }

    len = flb_sds_len(ctx->sysfs_path);
    path = (char *) flb_calloc(108 + len, sizeof(char));
    if (!path) {
        flb_errno();
        return NULL;
    }
    strcat(path, ctx->sysfs_path);
    strcat(path, "/");
    strcat(path, DOCKER_CGROUP_V2_DOCKER_SERVICE_DIR);
    strcat(path, "/");
    strcat(path, "docker-");
    strcat(path, id);
    strcat(path, ".scope");
    strcat(path, "/");
    strcat(path, DOCKER_CGROUP_V2_MEM_USAGE_FILE);

    return path;
}

static char *get_config_file(struct flb_docker *ctx, char *id)
{
    char *path;
    int len = 0;

    if (!id) {
        return NULL;
    }

    len = flb_sds_len(ctx->containers_path);
    path = (char *) flb_calloc(91 + len, sizeof(char));
    if (!path) {
        flb_errno();
        return NULL;
    }
    strcat(path, ctx->containers_path);
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

    config_file = get_config_file(ctx, id);
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
    char *line = NULL;

    usage_file = get_cpu_used_file(ctx, id);
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

    /* Read the content */
    while ((line = read_line(f))) {
        if (strncmp(line, DOCKER_CGROUP_V2_CPU_USAGE_KEY, 10) == 0) {
            c = sscanf(line, DOCKER_CGROUP_V2_CPU_USAGE_TEMPLATE, &cpu_used);
            if (c != 1) {
                flb_plg_error(ctx->ins, "error scanning used CPU value from %s with key = %s",
                              usage_file, DOCKER_CGROUP_V2_CPU_USAGE_KEY);
                flb_free(usage_file);
                flb_free(line);
                fclose(f);
                return NULL;
            }
            flb_free(line);

            break;
        }
        flb_free(line);
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

static uint64_t read_file_uint64(struct flb_docker *ctx, flb_sds_t path)
{
    int c;
    uint64_t value = UINT64_MAX;
    FILE *fp;

    fp = fopen(path, "r");
    if (!fp) {
        flb_errno();
        flb_plg_warn(ctx->ins, "Failed to read %s", path);
        return value;
    }

    c = fscanf(fp, "%lu", &value);
    fclose(fp);
    if (c != 1) {
        flb_plg_warn(ctx->ins, "Failed to read a number from %s", path);
        return value;
    }

    return value;
}

/* Returns memory used by a docker in bytes. */
static uint64_t get_docker_mem_used(struct flb_docker *ctx, char *id)
{
    char *usage_file = NULL;
    uint64_t mem_used = 0;

    usage_file = get_mem_used_file(ctx, id);
    if (!usage_file) {
        return 0;
    }

    mem_used = read_file_uint64(ctx, usage_file);
    flb_free(usage_file);

    return mem_used;
}

/* Returns memory limit for a docker in bytes. */
static uint64_t get_docker_mem_limit(struct flb_docker *ctx, char *id)
{
    int c;
    char *limit_file = get_mem_limit_file(ctx, id);
    uint64_t mem_limit;
    char *line = NULL;
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

    while ((line = read_line(f))) {
        if (strncmp(line, "max", 3) == 0) {
            mem_limit = UINT64_MAX;
        }
        else {
            c = sscanf(line, "%lu", &mem_limit);
            if (c != 1) {
                flb_plg_error(ctx->ins, "error scanning used mem_limit from %s",
                              limit_file);
                flb_free(line);
                flb_free(limit_file);
                fclose(f);
                return 0;
            }
        }
        flb_free(line);
    }

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
    snapshot->limit = get_docker_mem_limit(ctx, id);

    return snapshot;
}

int in_docker_set_cgroup_api_v2(struct cgroup_api *api)
{
    api->cgroup_version = 2;
    api->get_active_container_ids = get_active_dockers;
    api->get_container_name = get_container_name;
    api->get_cpu_snapshot = get_docker_cpu_snapshot;
    api->get_mem_snapshot = get_docker_mem_snapshot;

    return 0;
}
