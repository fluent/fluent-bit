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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>
#include <cfl/cfl_list.h>
#include <linux/limits.h>
#include <sys/statvfs.h>
#include <sys/statfs.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>
#include <float.h>

#define NE_ERROR_MOUNT_POINT_LIST_FETCH_SUCCESS            0
#define NE_ERROR_MOUNT_POINT_LIST_FETCH_GENERIC_ERROR     -1
#define NE_ERROR_MOUNT_POINT_LIST_FETCH_FILE_ACCESS_ERROR -2
#define NE_ERROR_MOUNT_POINT_LIST_FETCH_CORRUPTED_DATA    -3

static void unescape_character(cfl_sds_t input_buffer, char character)
{
    size_t needle_length;
    char   needle[8];
    char  *haystack;
    char  *match;

    needle_length = snprintf(needle, sizeof(needle), "\\0%02o", character);

    haystack = (char *) input_buffer;

    do {
        match = strstr(haystack, needle);

        if (match != NULL) {
            match[0] = character;

            memmove(&match[1],
                    &match[needle_length],
                    strlen(match) - needle_length + 1);
        }

        haystack = match;
    }
    while (match != NULL);
}

static cfl_sds_t greedy_read_file(char *path)
{
    char       read_buffer[1024];
    cfl_sds_t  temporary_buffer;
    FILE      *file_handle;
    size_t     read_size;
    cfl_sds_t  contents;

    file_handle = fopen(path, "rb");

    if (file_handle == NULL) {
        return NULL;
    }

    contents = cfl_sds_create_size(0);

    if (contents == NULL) {
        flb_errno();
        fclose(file_handle);

        return NULL;
    }

    do {
        read_size = fread(read_buffer,
                          1,
                          sizeof(read_buffer),
                          file_handle);

        if (read_size > 0) {
            temporary_buffer = cfl_sds_cat(contents, read_buffer, read_size);

            if (temporary_buffer == NULL) {
                cfl_sds_set_len(contents, 0);

                read_size = 0;
            }
            else {
                contents = temporary_buffer;
            }
        }
    }
    while (read_size > 0);

    fclose(file_handle);

    if (cfl_sds_len(contents) == 0) {
        cfl_sds_destroy(contents);

        contents = NULL;
    }

    return contents;
}

static int greedy_read_file_lines(char *path, struct mk_list *lines)
{
    cfl_sds_t contents;
    int       result;

    contents = greedy_read_file(path);

    if (contents == NULL) {
        return NE_ERROR_MOUNT_POINT_LIST_FETCH_FILE_ACCESS_ERROR;
    }

    mk_list_init(lines);

    result = flb_slist_split_string(lines, contents, '\n', -1);

    cfl_sds_destroy(contents);

    if (result == -1) {
        return NE_ERROR_MOUNT_POINT_LIST_FETCH_CORRUPTED_DATA;
    }

    return NE_ERROR_MOUNT_POINT_LIST_FETCH_SUCCESS;
}

static int filesystem_update(struct flb_ne *ctx,
                             char *mounts_file_path)
{
    struct statfs           mount_point_info;
    uint64_t                block_size;
    uint64_t                blocks;
    uint64_t                free_size;
    uint64_t                avail_size;
    uint64_t                size_bytes;
    uint64_t                avail_bytes;
    uint64_t                free_bytes;
    char                   *field_values[4];
    struct mk_list         *field_iterator;
    struct mk_list         *line_iterator;
    int                     readonly_flag;
    int                     field_index;
    int                     skip_flag;
    uint64_t                timestamp;
    char                   *labels[3];
    int                     result;
    struct mk_list          fields;
    struct mk_list          lines;
    struct flb_slist_entry *field;
    struct flb_slist_entry *line;

    result = greedy_read_file_lines(mounts_file_path, &lines);

    if (result != NE_ERROR_MOUNT_POINT_LIST_FETCH_SUCCESS) {
        return result;
    }

    mk_list_foreach(line_iterator, &lines) {
        line = mk_list_entry(line_iterator, struct flb_slist_entry, _head);

        mk_list_init(&fields);

        result = flb_slist_split_string(&fields, line->str, ' ', -1);
        if (result == -1) {
            continue;
        }

        field_index = 0;

        memset(field_values, 0, sizeof(field_values));

        mk_list_foreach(field_iterator, &fields) {
            field = mk_list_entry(field_iterator,
                                  struct flb_slist_entry,
                                  _head);

            if (field_index < 4) {
                field_values[field_index] = field->str;
            }
            else {
                break;
            }

            field_index++;
        }

        if (field_values[0] != NULL && /* device */
            field_values[1] != NULL && /* path */
            field_values[2] != NULL && /* fs type */
            field_values[3] != NULL) { /* options */
            skip_flag = flb_regex_match(ctx->fs_regex_skip_fs_types,
                                        (unsigned char *) field_values[2],
                                        strlen(field_values[2]));

            if (!skip_flag) {
                unescape_character(field_values[1], ' ');
                unescape_character(field_values[1], '\t');

                skip_flag = flb_regex_match(ctx->fs_regex_skip_mount,
                                            (unsigned char *) field_values[1],
                                            strlen(field_values[1]));

                if (!skip_flag) {
                    timestamp = cfl_time_now();

                    result = statfs(field_values[1], &mount_point_info);

                    if (result == 0) {
                        labels[0] = field_values[0];
                        labels[1] = field_values[2];
                        labels[2] = field_values[1];

                        readonly_flag = mount_point_info.f_flags & ST_RDONLY;
                        readonly_flag = (readonly_flag != 0);

                        block_size = (uint64_t) mount_point_info.f_bsize;
                        blocks     = (uint64_t) mount_point_info.f_blocks;
                        free_size  = (uint64_t) mount_point_info.f_bfree;
                        avail_size = (uint64_t) mount_point_info.f_bavail;
                        avail_bytes = block_size * avail_size;
                        size_bytes = block_size * blocks;
                        free_bytes = block_size * free_size;

                        cmt_gauge_set(ctx->fs_avail_bytes,
                                      timestamp,
                                      avail_bytes,
                                      3, labels);

                        /* We don't support device error couting yet */
                        cmt_gauge_set(ctx->fs_device_error,
                                      timestamp,
                                      0,
                                      3, labels);

                        cmt_gauge_set(ctx->fs_files,
                                      timestamp,
                                      (uint64_t) mount_point_info.f_files,
                                      3, labels);

                        cmt_gauge_set(ctx->fs_files_free,
                                      timestamp,
                                      (uint64_t) mount_point_info.f_ffree,
                                      3, labels);

                        cmt_gauge_set(ctx->fs_free_bytes,
                                      timestamp,
                                      free_bytes,
                                      3, labels);

                        cmt_gauge_set(ctx->fs_readonly,
                                      timestamp,
                                      readonly_flag,
                                      3, labels);

                        cmt_gauge_set(ctx->fs_size_bytes,
                                      timestamp,
                                      size_bytes,
                                      3, labels);
                    }
                }
            }
        }

        flb_slist_destroy(&fields);
    }

    flb_slist_destroy(&lines);

    return NE_ERROR_MOUNT_POINT_LIST_FETCH_SUCCESS;
}

static int ne_filesystem_init(struct flb_ne *ctx)
{
    ctx->fs_regex_skip_mount = flb_regex_create(ctx->fs_regex_ingore_mount_point_text);
    ctx->fs_regex_skip_fs_types = flb_regex_create(ctx->fs_regex_ingore_filesystem_type_text);

    ctx->fs_avail_bytes = cmt_gauge_create(ctx->cmt,
                                           "node",
                                           "filesystem",
                                           "avail_bytes",
                                           "Filesystem space available to " \
                                           "non-root users in bytes.",
                                           3, (char *[]) {"device",
                                                          "fstype",
                                                          "mountpoint"});

    if (ctx->fs_avail_bytes == NULL) {
        return -1;
    }

    ctx->fs_device_error = cmt_gauge_create(ctx->cmt,
                                            "node",
                                            "filesystem",
                                            "device_error",
                                            "Whether an error occurred while " \
                                            "getting statistics for the given " \
                                            "device.",
                                            3, (char *[]) {"device",
                                                           "fstype",
                                                           "mountpoint"});

    if (ctx->fs_device_error == NULL) {
        return -1;
    }

    ctx->fs_files = cmt_gauge_create(ctx->cmt,
                                     "node",
                                     "filesystem",
                                     "files",
                                     "Filesystem total file nodes.",
                                     3, (char *[]) {"device",
                                                    "fstype",
                                                    "mountpoint"});

    if (ctx->fs_files == NULL) {
        return -1;
    }

    ctx->fs_files_free = cmt_gauge_create(ctx->cmt,
                                          "node",
                                          "filesystem",
                                          "files_free",
                                          "Filesystem total free file nodes.",
                                          3, (char *[]) {"device",
                                                         "fstype",
                                                         "mountpoint"});

    if (ctx->fs_files_free == NULL) {
        return -1;
    }

    ctx->fs_free_bytes = cmt_gauge_create(ctx->cmt,
                                          "node",
                                          "filesystem",
                                          "free_bytes",
                                          "Filesystem free space in bytes.",
                                          3, (char *[]) {"device",
                                                         "fstype",
                                                         "mountpoint"});

    if (ctx->fs_free_bytes == NULL) {
        return -1;
    }

    ctx->fs_readonly = cmt_gauge_create(ctx->cmt,
                                        "node",
                                        "filesystem",
                                        "readonly",
                                        "Filesystem read-only status.",
                                        3, (char *[]) {"device",
                                                       "fstype",
                                                       "mountpoint"});

    if (ctx->fs_readonly == NULL) {
        return -1;
    }

    ctx->fs_size_bytes = cmt_gauge_create(ctx->cmt,
                                          "node",
                                          "filesystem",
                                          "size_bytes",
                                          "Filesystem size in bytes.",
                                          3, (char *[]) {"device",
                                                         "fstype",
                                                         "mountpoint"});

    if (ctx->fs_size_bytes == NULL) {
        return -1;
    }

    return 0;
}

static int ne_filesystem_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    int result;
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    result = filesystem_update(ctx, "/proc/1/mounts");

    if (result != NE_ERROR_MOUNT_POINT_LIST_FETCH_SUCCESS) {
        result = filesystem_update(ctx, "/proc/self/mounts");
    }

    return 0;
}

static int ne_filesystem_exit(struct flb_ne *ctx)
{
    if (ctx->fs_regex_skip_mount != NULL) {
        flb_regex_destroy(ctx->fs_regex_skip_mount);
    }

    if (ctx->fs_regex_skip_fs_types != NULL) {
        flb_regex_destroy(ctx->fs_regex_skip_fs_types);
    }

    return 0;
}

struct flb_ne_collector filesystem_collector = {
    .name = "filesystem",
    .cb_init = ne_filesystem_init,
    .cb_update = ne_filesystem_update,
    .cb_exit = ne_filesystem_exit
};
