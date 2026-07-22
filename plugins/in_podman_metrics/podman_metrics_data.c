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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_metrics_exporter.h>
#include <fluent-bit/flb_jsmn.h>

#include <monkey/mk_core/mk_list.h>

#include "podman_metrics_data.h"
#include "podman_metrics_config.h"

/*
 * Read uint64_t value from given path. If this function fails, it
 * returns UINT64_MAX, which will be later interpeted as invalid counter value
 * (it cannot return 0, because it is a valid value for counter
 */
uint64_t read_from_file(struct flb_in_metrics *ctx, flb_sds_t path)
{
    int c;
    uint64_t value = UINT64_MAX;
    FILE *fp;

    fp = fopen(path, "r");
    if (!fp) {
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

/*
 * Read uint64_t value from given path. Check for key: <VALUE> and return it. 
 * If this function fails, it
 * returns UINT64_MAX, which will be later interpeted as invalid counter value
 * (it cannot return 0, because it is a valid value for counter
 */
uint64_t read_key_value_from_file(struct flb_in_metrics *ctx, flb_sds_t path, flb_sds_t key)
{
    uint64_t value = UINT64_MAX;
    FILE *fp;
    flb_sds_t line  = NULL;
    flb_sds_t field = NULL;
    flb_sds_t line2 = NULL;
    size_t len = 0;
    ssize_t read = 0;
    int key_found = 0;

    fp = fopen(path, "r");
    if (!fp) {
        flb_plg_warn(ctx->ins, "Failed to read %s", path);
        return value;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        line2 = line;

        while( (field = strsep(&line2, " :")) != NULL ) {
            if( *field == '\0' ) {
                continue;
            }
            if (strcmp(field, key) == 0) {
                key_found = 1;
                continue;
            }
            if (key_found) {
                value = strtoull(field, NULL, 10);
                flb_plg_trace(ctx->ins, "Found key %s: %lu", key, value);
                fclose(fp);
                flb_free(line);
                flb_free(line2);
                return value;
            }
            
        }
        flb_free(line2);
    }
    flb_free(line);
    flb_plg_warn(ctx->ins, "%s not found in %s", key, path);
    fclose(fp);
    return value;
}

/*
 * Read uint64_t value from path previously picked from sysfs directory list.
 * If key is not NULL, it will be used to search a file instead of reading single value.
 */
uint64_t get_data_from_sysfs(struct flb_in_metrics *ctx, flb_sds_t dir, flb_sds_t name, flb_sds_t key)
{
    char path[SYSFS_FILE_PATH_SIZE];
    uint64_t data = UINT64_MAX;
    path[0]=0;

    if (dir == NULL) {
        return data;
    }

    snprintf(path, sizeof(path), "%s/%s", dir, name);

    if (key == NULL) {
        data = read_from_file(ctx, path);
    }
    else {
        data = read_key_value_from_file(ctx, path, key);
    }
    flb_plg_debug(ctx->ins, "%s: %lu", path, data);
    return data;
}

/*
 * Read all cgroups v2 io.stat counters in a single pass and store them in cnt.
 * io.stat lines look like:
 *   "8:0 rbytes=1024 wbytes=0 rios=2 wios=0 dbytes=0 dios=0"
 * The rbytes/wbytes/rios/wios fields are summed across all block devices. On a
 * missing or unreadable file (for example cgroups v1, where io.stat does not
 * exist) the four counters are set to UINT64_MAX so they are treated as invalid
 * and skipped, mirroring the other sysfs readers. An existing but empty io.stat
 * (no I/O yet) yields 0 for each counter.
 */
void read_io_stat(struct flb_in_metrics *ctx, flb_sds_t dir, flb_sds_t name, struct container *cnt)
{
    char path[SYSFS_FILE_PATH_SIZE];
    FILE *fp;
    char *line = NULL;
    char *pos;
    size_t len = 0;
    int i;
    struct {
        const char *key;
        size_t key_len;
        uint64_t *total;
    } fields[] = {
        { IO_STAT_KEY_READ_BYTES,  sizeof(IO_STAT_KEY_READ_BYTES) - 1,  &cnt->disk_read_bytes },
        { IO_STAT_KEY_WRITE_BYTES, sizeof(IO_STAT_KEY_WRITE_BYTES) - 1, &cnt->disk_write_bytes },
        { IO_STAT_KEY_READS,       sizeof(IO_STAT_KEY_READS) - 1,       &cnt->disk_reads },
        { IO_STAT_KEY_WRITES,      sizeof(IO_STAT_KEY_WRITES) - 1,      &cnt->disk_writes },
    };

    cnt->disk_read_bytes = UINT64_MAX;
    cnt->disk_write_bytes = UINT64_MAX;
    cnt->disk_reads = UINT64_MAX;
    cnt->disk_writes = UINT64_MAX;

    if (dir == NULL) {
        return;
    }

    snprintf(path, sizeof(path), "%s/%s", dir, name);

    fp = fopen(path, "r");
    if (!fp) {
        flb_plg_warn(ctx->ins, "Failed to read %s", path);
        return;
    }

    for (i = 0; i < 4; i++) {
        *fields[i].total = 0;
    }

    while (getline(&line, &len, fp) != -1) {
        for (i = 0; i < 4; i++) {
            pos = line;
            while ((pos = strstr(pos, fields[i].key)) != NULL) {
                pos += fields[i].key_len;
                *fields[i].total += strtoull(pos, NULL, 10);
            }
        }
    }
    flb_free(line);
    fclose(fp);

    flb_plg_debug(ctx->ins, "%s: rbytes=%lu wbytes=%lu rios=%lu wios=%lu", path,
                  cnt->disk_read_bytes, cnt->disk_write_bytes,
                  cnt->disk_reads, cnt->disk_writes);
}

/*
 * Check if container sysfs data is pressent in previously generated list of sysfs directories.
 * For cgroups v1, use subsystem (directory, for example memory) to search full path.
 */
int get_container_sysfs_subdirectory(struct flb_in_metrics *ctx, flb_sds_t id, flb_sds_t subsystem, flb_sds_t *path)
{
   struct sysfs_path *pth;
   struct mk_list *head;
   struct mk_list *tmp;

    mk_list_foreach_safe(head, tmp, &ctx->sysfs_items) {
        pth = mk_list_entry(head, struct sysfs_path, _head);
        if (strstr(pth->path, id) != 0) {
            if (subsystem != NULL && strstr(pth->path, subsystem) == 0) {
                continue;
            }
            *path = pth->path;
            flb_plg_trace(ctx->ins, "Found path for %s: %s", id, pth->path);
            return 0;
        }
    }
    *path = NULL;
    return -1;
}

/*
* Read data from /proc/ subsystem containing all data about network usage for pid (so, in this case,
* for container). These fields seem to be in constant positions, so check only specific fields in each
* row.
*/
int get_net_data_from_proc(struct flb_in_metrics *ctx, struct container *cnt, uint64_t pid) {
    char path[PROCFS_FILE_PATH_SIZE];
    char pid_buff[PID_BUFFER_SIZE];

    FILE * fp;
    flb_sds_t line  = NULL;
    flb_sds_t field = NULL;
    flb_sds_t line2 = NULL;

    size_t len = 0;
    ssize_t read = 0;
    int curr_line = 0;
    int curr_field = 0;

    struct net_iface *iface;

    path[0]=0;
    sprintf(pid_buff, "%" PRIu64, pid);
    snprintf(path, sizeof(path), "%s/%s/%s", ctx->procfs_path, pid_buff, PROC_NET_SUFFIX);

    fp = fopen(path, "r");
    if (fp == NULL) {
        flb_plg_warn(ctx->ins, "Failed to open %s", path);
        return -1;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        line2 = line;
        if (curr_line++ <= DEV_NET_IGNORE_LINES) {
            flb_plg_trace(ctx->ins, "Ignoring line %d in %s", curr_line, path);
            continue;
        }

        iface = flb_malloc(sizeof(struct net_iface));
        if (!iface) {
            flb_errno();
            return -1;
        }
        iface->name = NULL;
        iface->rx_bytes = UINT64_MAX;
        iface->rx_errors = UINT64_MAX;
        iface->tx_bytes = UINT64_MAX;
        iface->tx_errors = UINT64_MAX;


        while( (field = strsep(&line2, " ")) != NULL ) {
            if( *field == '\0' ) {
                continue;
            }
            switch (curr_field++)
            {
            case DEV_NET_NAME:
                /* Remove ':' from the end of name */
                iface->name = flb_sds_create_len(field, strlen(field)-1);
                flb_plg_trace(ctx->ins, "Reading name from %s: %s", path, iface->name);
                break;

            case DEV_NET_RX_BYTES:
                iface->rx_bytes = strtoull(field, NULL, 10);
                flb_plg_trace(ctx->ins, "Reading rx_bytes from %s: %lu", path, iface->rx_bytes);
                break;

            case DEV_NET_RX_ERRORS:
                iface->rx_errors = strtoull(field, NULL, 10);
                flb_plg_trace(ctx->ins, "Reading rx_errors from %s: %lu", path, iface->rx_errors);
                break;

            case DEV_NET_TX_BYTES:
                iface->tx_bytes = strtoull(field, NULL, 10);
                flb_plg_trace(ctx->ins, "Reading tx_bytes from %s: %lu", path, iface->tx_bytes);
                break;

            case DEV_NET_TX_ERRORS:
                iface->tx_errors = strtoull(field, NULL, 10);
                flb_plg_trace(ctx->ins, "Reading tx_errors from %s: %lu", path, iface->tx_errors);
                break;
            }
        }
        flb_free(line2);
        curr_field = 0;

        /* Ignore virtual interfaces connected to podman containers */
        if (name_starts_with(iface->name, VETH_INTERFACE) == 0) {
            flb_plg_trace(ctx->ins, "Ignoring virtual interface %s", iface->name);
            flb_sds_destroy(iface->name);
            flb_free(iface);
            continue;
        }
        mk_list_add(&iface->_head, &cnt->net_data);
    }

    flb_free(line);
    fclose(fp);
    return 0;
}

/*
 * Iterate over directories in sysfs system and collect all libpod-* directories
 */
int collect_sysfs_directories(struct flb_in_metrics *ctx, flb_sds_t name)
{
    char path[SYSFS_FILE_PATH_SIZE];
    path[0] = 0;
    DIR *dir;
    struct dirent *entry;
    struct sysfs_path *pth;

    if (!(dir = opendir(name))) {
        flb_plg_warn(ctx->ins, "Failed to open %s", name);
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, CURRENT_DIR) == 0 || strcmp(entry->d_name, PREV_DIR) == 0) {
                continue;
            }
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);

            if (name_starts_with(entry->d_name, SYSFS_CONTAINER_PREFIX) == 0 &&
                strcmp(entry->d_name, SYSFS_LIBPOD_PARENT) != 0 &&
                strstr(entry->d_name, SYSFS_CONMON) == 0) {
                pth = flb_malloc(sizeof(struct sysfs_path));
                if (!pth) {
                    flb_errno();
                    closedir(dir);
                    return -1;
                }
                pth->path = flb_sds_create(path);
                flb_plg_debug(ctx->ins, "Collected sysfs directory: %s", pth->path);
                mk_list_add(&pth->_head, &ctx->sysfs_items);
            }

            collect_sysfs_directories(ctx, path);
        }
    }
    closedir(dir);
    return 0;
}

/*
 * Iterate over previously created container list. For each entry, generate its
 * paths in sysfs system directory. From this path, grab data about container metrics
 * and put it this entry.
 * This function is used in cgroups v1 - meaning different directories for files.
 */
int fill_counters_with_sysfs_data_v1(struct flb_in_metrics *ctx)
{
    uint64_t pid;
    flb_sds_t mem_path;
    flb_sds_t cpu_path;
    flb_sds_t systemd_path;
    struct container *cnt;
    struct mk_list *head;
    struct mk_list *tmp;

    mk_list_foreach_safe(head, tmp, &ctx->items) {
        cnt = mk_list_entry(head, struct container, _head);

        get_container_sysfs_subdirectory(ctx, cnt->id, V1_SYSFS_MEMORY, &mem_path);
        get_container_sysfs_subdirectory(ctx, cnt->id, V1_SYSFS_CPU, &cpu_path);
        get_container_sysfs_subdirectory(ctx, cnt->id, V1_SYSFS_SYSTEMD, &systemd_path);

        cnt->memory_usage = get_data_from_sysfs(ctx, mem_path, V1_SYSFS_FILE_MEMORY, NULL);
        cnt->memory_max_usage = get_data_from_sysfs(ctx, mem_path, V1_SYSFS_FILE_MAX_MEMORY, NULL);
        cnt->rss = get_data_from_sysfs(ctx, mem_path, V1_SYSFS_FILE_MEMORY_STAT, STAT_KEY_RSS);
        cnt->memory_limit = get_data_from_sysfs(ctx, mem_path, V1_SYSFS_FILE_MEMORY_LIMIT, NULL);
        cnt->cpu_user = get_data_from_sysfs(ctx, cpu_path, V1_SYSFS_FILE_CPU_USER, NULL);
        cnt->cpu = get_data_from_sysfs(ctx, cpu_path, V1_SYSFS_FILE_CPU, NULL);
        pid = get_data_from_sysfs(ctx, systemd_path, V1_SYSFS_FILE_PIDS, NULL);
        if (pid && pid != UINT64_MAX) {
            get_net_data_from_proc(ctx, cnt, pid);
        }
        else {
            flb_plg_warn(ctx->ins, "Failed to collect PID for %s", cnt->name);
        }
    }
    return 0;
}

/*
 * Iterate over previously created container list. For each entry, generate its
 * path in sysfs system directory. From this path, grab data about container metrics
 * and put it this entry.
 * This function is used in cgroups v2 - meaning same directory for all files.
 */
int fill_counters_with_sysfs_data_v2(struct flb_in_metrics *ctx)
{
    uint64_t pid;
    flb_sds_t path;
    struct container *cnt;
    struct mk_list *head;
    struct mk_list *tmp;

    mk_list_foreach_safe(head, tmp, &ctx->items) {
        cnt = mk_list_entry(head, struct container, _head);

        get_container_sysfs_subdirectory(ctx, cnt->id, NULL, &path);

        cnt->memory_usage = get_data_from_sysfs(ctx, path, V2_SYSFS_FILE_MEMORY, NULL);
        cnt->memory_max_usage = get_data_from_sysfs(ctx, path, V2_SYSFS_FILE_MAX_MEMORY, NULL);
        cnt->rss = get_data_from_sysfs(ctx, path, V2_SYSFS_FILE_MEMORY_STAT, STAT_KEY_RSS);
        cnt->memory_limit = get_data_from_sysfs(ctx, path, V2_SYSFS_FILE_MEMORY_LIMIT, NULL);
        cnt->cpu_user = get_data_from_sysfs(ctx, path, V2_SYSFS_FILE_CPU_STAT, STAT_KEY_CPU_USER);
        cnt->cpu = get_data_from_sysfs(ctx, path, V2_SYSFS_FILE_CPU_STAT, STAT_KEY_CPU);
        read_io_stat(ctx, path, V2_SYSFS_FILE_IO_STAT, cnt);
        pid = get_data_from_sysfs(ctx, path, V2_SYSFS_FILE_PIDS, NULL);
        if (!pid || pid == UINT64_MAX) {
            pid = get_data_from_sysfs(ctx, path, V2_SYSFS_FILE_PIDS_ALT, NULL);
        }
        if (pid && pid != UINT64_MAX) {
            get_net_data_from_proc(ctx, cnt, pid);
        }
        else {
            flb_plg_warn(ctx->ins, "Failed to collect PID for %s", cnt->name);
        }
    }
    return 0;
}

/*
 * Check if flb_sds_t starts with given string
 */
int name_starts_with(flb_sds_t s, const char *str)
{
    size_t len = strlen(str);
    size_t flen = flb_sds_len(s);

    if (s == NULL || len > flen) {
        return -1;
    }

    return strncmp(s, str, len);
}

/* 
 * Calculate which cgroup version is used on host by checing existence of
 * cgroup.controllers file (if it exists, it is V2).
 */
int get_cgroup_version(struct flb_in_metrics *ctx)
{
    char path[SYSFS_FILE_PATH_SIZE];
    snprintf(path, sizeof(path), "%s/%s", ctx->sysfs_path, CGROUP_V2_PATH);
    return (access(path, F_OK) == 0) ? CGROUP_V2 : CGROUP_V1;
}
