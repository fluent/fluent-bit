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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_notification.h>
#include <fluent-bit/flb_input_blob.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#ifndef FLB_SYSTEM_WINDOWS
#include <glob.h>
#include <fnmatch.h>
#else
#define strtok_r strtok_s
#endif

#include <stdio.h>

#include "blob.h"
#include "blob_db.h"
#include "blob_file.h"

#include "win32_glob.c"

/* Define missing GLOB_TILDE if not exists */
#ifndef GLOB_TILDE
#define GLOB_TILDE    1<<2 /* use GNU Libc value */
#define UNSUP_TILDE   1

#ifndef FLB_SYSTEM_WINDOWS
/* we need these extra headers for path resolution */
#include <limits.h>
#include <sys/types.h>
#include <pwd.h>

static char *expand_tilde(const char *path)
{
    int len;
    char user[256];
    char *p = NULL;
    char *dir = NULL;
    char *tmp = NULL;
    struct passwd *uinfo = NULL;

    if (path[0] == '~') {
        p = strchr(path, '/');

        if (p) {
            /* check case '~/' */
            if ((p - path) == 1) {
                dir = getenv("HOME");
                if (!dir) {
                    return path;
                }
            }
            else {
                /*
                 * it refers to a different user: ~user/abc, first step grab
                 * the user name.
                 */
                len = (p - path) - 1;
                memcpy(user, path + 1, len);
                user[len] = '\0';

                /* use getpwnam() to resolve user information */
                uinfo = getpwnam(user);
                if (!uinfo) {
                    return path;
                }

                dir = uinfo->pw_dir;
            }
        }
        else {
            dir = getenv("HOME");
            if (!dir) {
                return path;
            }
        }

        if (p) {
            tmp = flb_malloc(PATH_MAX);
            if (!tmp) {
                flb_errno();
                return NULL;
            }
            snprintf(tmp, PATH_MAX - 1, "%s%s", dir, p);
        }
        else {
            dir = getenv("HOME");
            if (!dir) {
                return path;
            }

            tmp = flb_strdup(dir);
            if (!tmp) {
                return path;
            }
        }

        return tmp;
    }

    return path;
}
#else
static char* expand_tilde(const char* path)
{
    return NULL;
}
#endif
#endif

#ifndef FLB_SYSTEM_WINDOWS
static int is_directory(char *path, struct stat *fs_entry_metadata)
{
        return S_ISDIR(fs_entry_metadata->st_mode);
}
#endif

static inline int do_glob(const char *pattern,
                          int flags,
                          void *not_used,
                          glob_t *pglob)
{
    int ret;
    int new_flags;
    char *tmp = NULL;
    int tmp_needs_free = FLB_FALSE;
    (void) not_used;

    /* Save current values */
    new_flags = flags;

#if defined(UNSUP_TILDE) && !defined(FLB_SYSTEM_WINDOWS)
    if (flags & GLOB_TILDE) {
        /*
         * Some libc libraries like Musl do not support GLOB_TILDE for tilde
         * expansion. A workaround is to use wordexp(3) but looking at it
         * implementation in Musl it looks quite expensive:
         *
         *  http://git.musl-libc.org/cgit/musl/tree/src/misc/wordexp.c
         *
         * the workaround is to do our own tilde expansion in a temporary buffer.
         */

        /* Look for a tilde */
        tmp = expand_tilde(pattern);
        if (tmp != pattern) {
            /* the path was expanded */
            pattern = tmp;
            tmp_needs_free = FLB_TRUE;
        }

        /* remove unused flag */
        new_flags &= ~GLOB_TILDE;
    }
#endif

    /* invoke glob with new parameters */
    ret = glob(pattern, new_flags, NULL, pglob);

    /* remove temporary buffer, if allocated by expand_tilde above.
     * Note that this buffer is only used for libc implementations
     * that do not support the GLOB_TILDE flag, like musl. */
    if ((tmp != NULL) && (tmp_needs_free == FLB_TRUE)) {
        flb_free(tmp);
    }

    return ret;
}

#define MATCHING_METHOD_PRESENCE 0
#define MATCHING_METHOD_EXACT    1

static int apply_glob_pattern(flb_sds_t pattern, char *path) {
    int        matching_method;
    char      *strtok_context;
    cfl_sds_t  local_pattern;
    char      *filename_part;
    char      *pattern_part;
    char      *filename;
    int        result;
    size_t     index;

    if (pattern == NULL || pattern[0] == '\0') {
        return FLB_FALSE;
    }

    if (path == NULL || path[0] == '\0') {
        return FLB_FALSE;
    }

    filename = NULL;

#ifdef FLB_SYSTEM_WINDOWS
    filename = strrchr(path, '\\');
#endif

    if (filename == NULL) {
        filename = strrchr(path, '/');
    }

    if (filename != NULL) {
        filename = &filename[1];
    }
    else {
        filename = path;
    }

    if (filename[0] == '\0') {
        return FLB_FALSE;
    }

    local_pattern = cfl_sds_create(pattern);

    if (local_pattern == NULL) {
        return FLB_FALSE;
    }

    result = FLB_FALSE;

    if (strrchr(local_pattern, '*') != NULL) {
        index = 0;
        pattern_part = strtok_r(local_pattern, "*", &strtok_context);

        if (local_pattern[0] == '*') {
            matching_method = MATCHING_METHOD_PRESENCE;
        }
        else {
            matching_method = MATCHING_METHOD_EXACT;
        }

        filename_part = filename;


        while (pattern_part != NULL && filename_part != NULL) {
            if (matching_method == MATCHING_METHOD_PRESENCE) {
                filename_part = strstr(filename_part, pattern_part);
            }
            else {
                result = strncmp(filename_part, pattern_part, strlen(pattern_part));

                if (result != 0) {
                    filename_part = NULL;
                }

                matching_method = MATCHING_METHOD_PRESENCE;
            }

            if (filename_part != NULL) {
                filename_part = &filename_part[strlen(pattern_part)];
            }

            index++;
            pattern_part = strtok_r(NULL, "*", &strtok_context);
        }

        result = FLB_FALSE;

        if (pattern_part == NULL) {
            if (pattern[strlen(pattern) - 1] != '*') {
                if (filename_part != NULL) {
                    if (filename_part[0] == '\0') {
                        result = FLB_TRUE;
                    }
                }
            }
            else {
                if (filename_part != NULL) {
                    result = FLB_TRUE;
                }
            }
        }
        else {
            result = FLB_FALSE;
        }
    }
    else {
        result = strcmp(filename, local_pattern);

        if (result == 0) {
            result = FLB_TRUE;
        }
        else {
            result = FLB_FALSE;
        }
    }

    cfl_sds_destroy(local_pattern);

    return result;
}

/* This function recursively searches a directory tree using
 * a glob compatible pattern that implements the fluentd style
 * recursion wildcard **.
 *
 * Result values :
 *   - Negative values identify error conditions
 *   - Zero and positive values represent the match count
 *
 * Known issues :
 *   - This function is only able to handle one recursion
 *     wildcard in its pattern.
 *   - This function does not follow directory links
 *   - Pattern generation needs to be optimized to
 *     minimize garbage pattern generation
 */
static ssize_t recursive_file_search(struct blob_ctx *ctx,
                                     const char *path,
                                     const char *pattern)
{
    char       *recursive_search_token;
    int         recursive_search_flag;
    struct stat fs_entry_metadata;
    ssize_t     recursion_result;
    cfl_sds_t   local_pattern;
    glob_t      glob_context;
    ssize_t     match_count;
    cfl_sds_t   local_path;
    cfl_sds_t   sds_result;
    int         result;
    size_t      index;

    match_count = 0;

    memset(&glob_context, 0, sizeof(glob_t));

    if (path != NULL) {
        local_path = cfl_sds_create(path);
    }
    else {
        local_path = cfl_sds_create("");
    }

    if (local_path == NULL) {
        return -1;
    }

    if (pattern != NULL) {
        local_pattern = cfl_sds_create(pattern);
    }
    else {
        local_pattern = cfl_sds_create("");
    }

    if (local_pattern == NULL) {
        cfl_sds_destroy(local_path);

        return -2;
    }

    recursive_search_flag = FLB_TRUE;
    recursive_search_token = strstr(local_pattern, "/**/");

    if (recursive_search_token != NULL) {
        if (strstr(&recursive_search_token[4], "/**/") != NULL) {
            flb_plg_error(ctx->ins,
                          "a search path with multiple recursivity " \
                          "wildcards was provided which is not " \
                          "supported. \"%s\"", local_pattern);

            cfl_sds_destroy(local_pattern);
            cfl_sds_destroy(local_path);

            return -3;
        }

        recursive_search_token[0] = '\0';

        sds_result = cfl_sds_cat(local_path,
                                 local_pattern,
                                 strlen(local_pattern));

        if (sds_result == NULL) {
            cfl_sds_destroy(local_pattern);
            cfl_sds_destroy(local_path);

            return -4;
        }

        local_path = sds_result;

        memmove(local_pattern,
                &recursive_search_token[3],
                strlen(&recursive_search_token[3]) + 1);

        cfl_sds_len_set(local_pattern,
                        strlen(&recursive_search_token[3]));
    }
    else if (cfl_sds_len(local_pattern) == 0) {
        recursive_search_flag = FLB_FALSE;
    }
    else if (cfl_sds_len(local_path) == 0) {
        recursive_search_flag = FLB_FALSE;
    }

    memset(&glob_context, 0, sizeof(glob_t));

    /* Scan the given path */
    if (local_path[0] != '\0') {
        result = do_glob(local_path, GLOB_TILDE | GLOB_ERR, NULL, &glob_context);
    }
    else {
        result = do_glob(local_pattern, GLOB_TILDE | GLOB_ERR, NULL, &glob_context);
    }

    if (result != 0) {
        switch (result) {
        case GLOB_NOSPACE:
            flb_plg_error(ctx->ins, "no memory space available");

            cfl_sds_destroy(local_pattern);
            cfl_sds_destroy(local_path);

            return -5;
        case GLOB_ABORTED:
            cfl_sds_destroy(local_pattern);
            cfl_sds_destroy(local_path);

            return 0;
        case GLOB_NOMATCH:
            result = stat(local_path, &fs_entry_metadata);

            if (result == -1) {
                flb_plg_debug(ctx->ins, "cannot read info from: %s", local_path);
            }
            else {
                result = access(local_path, R_OK);
                if (result == -1 && errno == EACCES) {
                    flb_plg_error(ctx->ins, "NO read access for path: %s", local_path);
                }
                else {
                    flb_plg_debug(ctx->ins, "NO matches for path: %s", local_path);
                }
            }

            cfl_sds_destroy(local_pattern);
            cfl_sds_destroy(local_path);

            return 6;
        }
    }

    for (index = 0; index < glob_context.gl_pathc; index++) {
        result = stat(glob_context.gl_pathv[index], &fs_entry_metadata);

        if (result != 0) {
            flb_plg_debug(ctx->ins, "skip entry=%s", glob_context.gl_pathv[index]);

            continue;
        }

        if (is_directory(glob_context.gl_pathv[index],
                         &fs_entry_metadata)) {
            local_path[0] = '\0';

            cfl_sds_len_set(local_path, 0);

            sds_result = cfl_sds_printf(&local_path,
                                        "%s/*",
                                        glob_context.gl_pathv[index]);

            if (sds_result == NULL) {
                cfl_sds_destroy(local_pattern);
                cfl_sds_destroy(local_path);

                globfree(&glob_context);

                return -7;
            }

            recursion_result = recursive_file_search(ctx,
                                                     local_path,
                                                     local_pattern);

            if (recursion_result < 0) {
                cfl_sds_destroy(local_pattern);
                cfl_sds_destroy(local_path);

                globfree(&glob_context);

                return -8;
            }

            match_count += recursion_result;

            local_path[0] = '\0';

            cfl_sds_len_set(local_path, 0);

            sds_result = cfl_sds_printf(&local_path,
                                        "%s%s",
                                        glob_context.gl_pathv[index],
                                        local_pattern);

            if (sds_result == NULL) {
                cfl_sds_destroy(local_pattern);
                cfl_sds_destroy(local_path);

                globfree(&glob_context);

                return -9;
            }

            recursion_result = recursive_file_search(ctx,
                                                     local_path,
                                                     NULL);

            if (recursion_result < 0) {
                cfl_sds_destroy(local_pattern);
                cfl_sds_destroy(local_path);

                globfree(&glob_context);

                return -10;
            }

            match_count += recursion_result;
        }
        else if (recursive_search_flag == FLB_FALSE &&
                 (S_ISREG(fs_entry_metadata.st_mode) ||
                  S_ISLNK(fs_entry_metadata.st_mode))) {

            result = apply_glob_pattern(ctx->exclude_pattern,
                                        (char *) glob_context.gl_pathv[index]);

            if (result == FLB_FALSE) {
                result = blob_file_append(ctx,
                                        glob_context.gl_pathv[index],
                                        &fs_entry_metadata);

                if (result == 0) {
                    flb_plg_debug(ctx->ins,
                                "blob scan add: %s, inode %" PRIu64,
                                glob_context.gl_pathv[index],
                                (uint64_t) fs_entry_metadata.st_ino);
                }
                else {
                    /* Result codes :
                     *  0 - Success
                     * -1 - Generic failure
                     *  1 - The file was alrady present in our records
                     */
                    flb_plg_debug(ctx->ins,
                                "blob scan skip: %s",
                                glob_context.gl_pathv[index]);
                }

                match_count++;
            }
        }
    }

    globfree(&glob_context);

    cfl_sds_destroy(local_pattern);
    cfl_sds_destroy(local_path);

    return match_count;
}

static int cb_scan_path(struct flb_input_instance *ins,
                        struct flb_config *config, void *in_context)
{
    ssize_t          result;
    struct blob_ctx *ctx;;

    ctx = (struct blob_ctx *) in_context;

    flb_plg_debug(ctx->ins, "scanning path %s", ctx->path);

    result = recursive_file_search(ctx, NULL, ctx->path);

    if (result < 0) {
        flb_plg_trace(ctx->ins,
                      "path scanning returned error code : %zd",
                      result);
    }

    return 0;
}

/* Initialize plugin */
static int in_blob_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    int ret;
    struct blob_ctx *ctx;

    /* Allocate space for the configuration context */
    ctx = flb_calloc(1, sizeof(struct blob_ctx));
    if (!ctx) {
        return -1;
    }
    ctx->ins = ins;
    ctx->config = config;
    cfl_list_init(&ctx->files);

    /* laod the config map */
    ret = flb_input_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* associate the context with the instance */
    flb_input_set_context(ins, ctx);

    /* 'path' must be set */
    if (!ctx->path) {
        flb_plg_error(ins, "'path' configuration property is not set");
        flb_free(ctx);
        return -1;
    }

#ifdef FLB_HAVE_SQLDB
    if (ctx->database_file) {
        ctx->db = blob_db_open(ctx, ctx->database_file);
        if (!ctx->db) {
            return -1;
        }
    }
#endif

    ctx->upload_success_action = POST_UPLOAD_ACTION_NONE;

    if (ctx->upload_success_action_str != NULL) {
        if (strcasecmp(ctx->upload_success_action_str,
                       "delete") == 0) {
            ctx->upload_success_action = POST_UPLOAD_ACTION_DELETE;
        }
        else if (strcasecmp(ctx->upload_success_action_str,
                            "emit_log") == 0) {
            ctx->upload_success_action = POST_UPLOAD_ACTION_EMIT_LOG;
        }
        else if (strcasecmp(ctx->upload_success_action_str,
                            "add_suffix") == 0) {
            if (ctx->upload_success_suffix == NULL) {
                flb_plg_error(ins,
                              "'upload_success_suffix' configuration " \
                              "property is not set");
#ifdef FLB_HAVE_SQLDB
                if (ctx->db != NULL) {
                    blob_db_close(ctx);
                    ctx->db = NULL;
                }
#endif
                flb_free(ctx);

                return -1;
            }
            ctx->upload_success_action = POST_UPLOAD_ACTION_ADD_SUFFIX;
        }
    }

    ctx->upload_failure_action = POST_UPLOAD_ACTION_NONE;

    if (ctx->upload_failure_action_str != NULL) {
        if (strcasecmp(ctx->upload_failure_action_str,
                       "delete") == 0) {
            ctx->upload_failure_action = POST_UPLOAD_ACTION_DELETE;
        }
        else if (strcasecmp(ctx->upload_failure_action_str,
                            "emit_log") == 0) {
            ctx->upload_failure_action = POST_UPLOAD_ACTION_EMIT_LOG;
        }
        else if (strcasecmp(ctx->upload_failure_action_str,
                            "add_suffix") == 0) {
            if (ctx->upload_failure_suffix == NULL) {
                flb_plg_error(ins,
                              "'upload_failure_suffix' configuration " \
                              "property is not set");
#ifdef FLB_HAVE_SQLDB
                if (ctx->db != NULL) {
                    blob_db_close(ctx);
                    ctx->db = NULL;
                }
#endif
                flb_free(ctx);

                return -1;
            }
            ctx->upload_failure_action = POST_UPLOAD_ACTION_ADD_SUFFIX;
        }
    }

    /* create a collector to scan the path of files */
    ret = flb_input_set_collector_time(ins,
                                       cb_scan_path,
                                       ctx->scan_refresh_interval, 0,
                                       config);
    if (ret == -1) {
        flb_plg_error(ins, "could not create collector");
        return -1;
    }
    ctx->coll_fd = ret;

    /* initialize the encoder */
    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ctx->log_encoder == NULL) {
        flb_plg_error(ins, "could not initialize event encoder");
        return -1;
    }

    return 0;
}

/* Cleanup serial input */
static int in_blob_exit(void *in_context, struct flb_config *config)
{
    struct blob_ctx *ctx = in_context;

    if (!ctx) {
        return 0;
    }

    blob_db_close(ctx);
    blob_file_list_remove_all(ctx);
    flb_log_event_encoder_destroy(ctx->log_encoder);
    flb_free(ctx);

    return 0;
}


static int in_blob_notification(struct flb_input_instance *in_context,
                                struct flb_config *config,
                                void *untyped_notification)
{
    struct flb_blob_delivery_notification *notification;
    cfl_sds_t                              new_filename;
    cfl_sds_t                              sds_result;
    struct blob_ctx                       *context;
    int                                    result;

    context = (struct blob_ctx *) in_context;

    notification = (struct flb_blob_delivery_notification *) untyped_notification;

    if (notification->base.notification_type !=
        FLB_NOTIFICATION_TYPE_BLOB_DELIVERY) {
        flb_plg_error(context->ins,
                      "unexpected notification type received : %d",
                      notification->base.notification_type);

        return -1;
    }

    if (notification->success == FLB_TRUE) {
        switch (context->upload_success_action) {
        case POST_UPLOAD_ACTION_DELETE:
            result = unlink(notification->path);

            if (result == -1) {
                flb_errno();

                flb_plg_error(context->ins,
                              "successfully uploaded file \"%s\" could not be deleted",
                              notification->path);
            }

            break;

        case POST_UPLOAD_ACTION_EMIT_LOG:
            flb_log_event_encoder_begin_record(context->log_encoder);

            flb_log_event_encoder_set_current_timestamp(context->log_encoder);

            result = flb_log_event_encoder_append_metadata_values(
                        context->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("path"),
                        FLB_LOG_EVENT_CSTRING_VALUE(notification->path));

            if (result != FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_encoder_rollback_record(context->log_encoder);

                break;
            }

            result = flb_log_event_encoder_append_body_values(
                        context->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("message"),
                        FLB_LOG_EVENT_CSTRING_VALUE(context->upload_success_message));

            if (result != FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_encoder_rollback_record(context->log_encoder);

                break;
            }

            result = flb_log_event_encoder_commit_record(context->log_encoder);

            if (result != FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_encoder_rollback_record(context->log_encoder);

                break;
            }

            flb_input_log_append(context->ins, NULL, 0,
                                 context->log_encoder->output_buffer,
                                 context->log_encoder->output_length);

            flb_log_event_encoder_reset_record(context->log_encoder);

            break;

        case POST_UPLOAD_ACTION_ADD_SUFFIX:
            new_filename = cfl_sds_create(notification->path);

            if (new_filename == NULL) {
                flb_plg_error(context->ins,
                              "successfully uploaded file \"%s\" could not be renamed " \
                              "(new filename buffer allocation error)",
                              notification->path);

                break;
            }

            sds_result = cfl_sds_cat(new_filename,
                                     context->upload_success_suffix,
                                     strlen(context->upload_success_suffix));

            if (sds_result == NULL) {
                flb_plg_error(context->ins,
                              "successfully uploaded file \"%s\" could not be renamed " \
                              "(filename suffix concatentation error)",
                              notification->path);

                cfl_sds_destroy(new_filename);

                break;
            }

            new_filename = sds_result;

            result = rename(notification->path, new_filename);

            if (result == -1) {
                flb_errno();

                flb_plg_error(context->ins,
                              "successfully uploaded file \"%s\" could not be renamed " \
                              "(rename operation error)",
                              notification->path);
            }

            cfl_sds_destroy(new_filename);

            break;
        }
    }
    else if (notification->success == FLB_FALSE) {
        switch (context->upload_failure_action) {
        case POST_UPLOAD_ACTION_DELETE:
            result = unlink(notification->path);

            if (result == -1) {
                flb_errno();

                flb_plg_error(context->ins,
                              "failed to upload file \"%s\" could not be deleted",
                              notification->path);
            }

            break;

        case POST_UPLOAD_ACTION_EMIT_LOG:
            flb_log_event_encoder_begin_record(context->log_encoder);

            flb_log_event_encoder_set_current_timestamp(context->log_encoder);

            result = flb_log_event_encoder_append_metadata_values(
                        context->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("path"),
                        FLB_LOG_EVENT_CSTRING_VALUE(notification->path));

            if (result != FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_encoder_rollback_record(context->log_encoder);

                break;
            }

            result = flb_log_event_encoder_append_body_values(
                        context->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("message"),
                        FLB_LOG_EVENT_CSTRING_VALUE(context->upload_failure_message));

            if (result != FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_encoder_rollback_record(context->log_encoder);

                break;
            }

            result = flb_log_event_encoder_commit_record(context->log_encoder);

            if (result != FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_encoder_rollback_record(context->log_encoder);

                break;
            }

            flb_input_log_append(context->ins, NULL, 0,
                                 context->log_encoder->output_buffer,
                                 context->log_encoder->output_length);

            flb_log_event_encoder_reset_record(context->log_encoder);

            break;

        case POST_UPLOAD_ACTION_ADD_SUFFIX:
            new_filename = cfl_sds_create(notification->path);

            if (new_filename == NULL) {
                flb_plg_error(context->ins,
                              "failed to upload file \"%s\" could not be renamed " \
                              "(new filename buffer allocation error)",
                              notification->path);

                break;
            }

            sds_result = cfl_sds_cat(new_filename,
                                     context->upload_failure_suffix,
                                     strlen(context->upload_failure_suffix));

            if (sds_result == NULL) {
                flb_plg_error(context->ins,
                              "failed to upload file \"%s\" could not be renamed " \
                              "(filename suffix concatentation error)",
                              notification->path);

                cfl_sds_destroy(new_filename);

                break;
            }

            new_filename = sds_result;

            result = rename(notification->path, new_filename);

            if (result == -1) {
                flb_errno();

                flb_plg_error(context->ins,
                              "failed to upload file \"%s\" could not be renamed " \
                              "(rename operation error)",
                              notification->path);
            }

            cfl_sds_destroy(new_filename);

            break;
        }
    }

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "path", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, path),
     "Path to scan for blob/binary files"
    },

    {
     FLB_CONFIG_MAP_STR, "exclude_pattern", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, exclude_pattern),
     "Glob pattern to exclude files from being processed"
    },

#ifdef FLB_HAVE_SQLDB
    {
     FLB_CONFIG_MAP_STR, "database_file", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, database_file),
     "SQLite database file path to track processed files"
    },
#endif

    {
     FLB_CONFIG_MAP_TIME, "scan_refresh_interval", "2s",
     0, FLB_TRUE, offsetof(struct blob_ctx, scan_refresh_interval),
     "Set the interval time to scan for new files"
    },

    {
     FLB_CONFIG_MAP_STR, "upload_success_action", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, upload_success_action_str),
     "Action to perform after successful upload: \"delete\", \"emit_log\", or \"add_suffix\""
    },

    {
     FLB_CONFIG_MAP_STR, "upload_success_suffix", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, upload_success_suffix),
     "Suffix to append to filename when upload_success_action is \"add_suffix\""
    },

    {
     FLB_CONFIG_MAP_STR, "upload_success_message", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, upload_success_message),
     "Message to emit as log when upload_success_action is \"emit_log\""
    },

    {
     FLB_CONFIG_MAP_STR, "upload_failure_action", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, upload_failure_action_str),
     "Action to perform after failed upload: \"delete\", \"emit_log\", or \"add_suffix\""
    },

    {
     FLB_CONFIG_MAP_STR, "upload_failure_suffix", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, upload_failure_suffix),
     "Suffix to append to filename when upload_failure_action is \"add_suffix\""
    },

    {
     FLB_CONFIG_MAP_STR, "upload_failure_message", NULL,
     0, FLB_TRUE, offsetof(struct blob_ctx, upload_failure_message),
     "Message to emit as log when upload_failure_action is \"emit_log\""
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_blob_plugin = {
    .name            = "blob",
    .description     = "Blob (binary) files",
    .cb_init         = in_blob_init,
    .cb_pre_run      = NULL,
    .cb_collect      = NULL,
    .cb_flush_buf    = NULL,
    .cb_exit         = in_blob_exit,
    .cb_notification = in_blob_notification,
    .config_map      = config_map
};
