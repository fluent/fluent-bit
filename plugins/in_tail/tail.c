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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

#include "tail.h"
#include "tail_fs.h"
#include "tail_db.h"
#include "tail_file.h"
#include "tail_scan.h"
#include "tail_signal.h"
#include "tail_config.h"
#include "tail_dockermode.h"
#include "tail_multiline.h"

static inline int consume_byte(flb_pipefd_t fd)
{
    int ret;
    uint64_t val;

    /* We need to consume the byte */
    ret = flb_pipe_r(fd, (char *) &val, sizeof(val));
    if (ret <= 0) {
        flb_pipe_error();
        return -1;
    }

    return 0;
}

/* cb_collect callback */
static int in_tail_collect_pending(struct flb_input_instance *ins,
                                   struct flb_config *config, void *in_context)
{
    int ret;
    int active = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file;
    struct stat st;
    uint64_t pre;
    uint64_t total_processed = 0;

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        if (file->watch_fd == -1 ||
            (file->offset >= file->size)) {
            /* Gather current file size */
            ret = flb_tail_file_stat(file, &st);
            if (ret == -1) {
                flb_errno();
                flb_tail_file_remove(file);
                continue;
            }
            file->size = st.st_size;
            file->pending_bytes = (file->size - file->offset);
        }
        else {
            memset(&st, 0, sizeof(struct stat));
        }

        if (file->pending_bytes <= 0) {
            if(file->decompression_context == NULL ||
               file->decompression_context->input_buffer_length == 0) {
                continue;
            }
        }

        if (ctx->event_batch_size > 0 &&
            total_processed >= ctx->event_batch_size) {
            break;
        }

        /* get initial offset to calculate the number of processed bytes later */
        pre = file->offset;

        ret = flb_tail_file_chunk(file);

        /* Update the total number of bytes processed */
        if (file->offset > pre) {
            total_processed += (file->offset - pre);
        }

        switch (ret) {
        case FLB_TAIL_ERROR:
            /* Could not longer read the file */
            flb_tail_file_remove(file);
            break;
        case FLB_TAIL_OK:
        case FLB_TAIL_BUSY:
            /*
             * Adjust counter to verify if we need a further read(2) later.
             * For more details refer to tail_fs_inotify.c:96.
             */
            if (file->offset < file->size) {
                file->pending_bytes = (file->size - file->offset);
                active++;
            }
            else if(file->decompression_context != NULL &&
                    file->decompression_context->input_buffer_length > 0) {
                active++;
            }
            else {
                file->pending_bytes = 0;
            }

            break;
        }
    }

    /* If no more active files, consume pending signal so we don't get called again. */
    if (active == 0) {
        tail_consume_pending(ctx);
    }

    return 0;
}

/* cb_collect callback */
static int in_tail_collect_static(struct flb_input_instance *ins,
                                  struct flb_config *config, void *in_context)
{
    int ret;
    int active = 0;
    int pre_size;
    int pos_size;
    int alter_size = 0;
    int completed = FLB_FALSE;
    char s_size[32];
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file;
    uint64_t pre;
    uint64_t total_processed = 0;

    /* Do a data chunk collection for each file */
    mk_list_foreach_safe(head, tmp, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        /*
         * The list 'files_static' represents all the files that were discovered
         * on startup that already contains data: these are called 'static files'.
         *
         * When processing static files, we don't know what kind of content they
         * have and what kind of 'latency' might add to process all of them in
         * a row. Despite we always 'try' to do a full round and process a
         * fraction of them on every invocation of this function if we have a
         * huge number of files we will face latency and make the main pipeline
         * to degrade performance.
         *
         * In order to avoid this situation, we added a new option to the plugin
         * called 'static_batch_size' which basically defines how many bytes can
         * be processed on every invocation to process the static files.
         *
         * When the limit is reached, we just break the loop and as a side effect
         * we allow other events keep processing.
         */
        if (ctx->static_batch_size > 0 &&
            total_processed >= ctx->static_batch_size) {
            break;
        }

        /* get initial offset to calculate the number of processed bytes later */
        pre = file->stream_offset;

        /* Process the file */
        ret = flb_tail_file_chunk(file);

        /* Update the total number of bytes processed */
        if (file->stream_offset > pre) {
            total_processed += (file->stream_offset - pre);
        }

        switch (ret) {
        case FLB_TAIL_ERROR:
            /* Could not longer read the file */
            flb_plg_debug(ctx->ins, "inode=%"PRIu64" collect static ERROR",
                          file->inode);
            flb_tail_file_remove(file);
            break;
        case FLB_TAIL_OK:
        case FLB_TAIL_BUSY:
            active++;
            break;
        case FLB_TAIL_WAIT:
            if(file->decompression_context != NULL &&
               file->decompression_context->input_buffer_length > 0) {
                active++;

                break;
            }

            if (file->config->exit_on_eof) {
                flb_plg_info(ctx->ins, "inode=%"PRIu64" file=%s ended, stop",
                             file->inode, file->name);
                if (ctx->files_static_count == 1) {
#ifdef FLB_HAVE_PARSER
                    if (ctx->multiline) {
                        flb_tail_mult_flush(file, ctx);
                    }
#endif
                    flb_engine_exit(config);
                }
            }
            /* Promote file to 'events' type handler */
            flb_plg_debug(ctx->ins, "inode=%"PRIu64" file=%s promote to TAIL_EVENT",
                          file->inode, file->name);

            /*
             * When promoting a file from 'static' to 'event' mode, the promoter
             * will check if the file has been rotated while it was being
             * processed on this function, if so, it will try to check for the
             * following condition:
             *
             *   "discover a new possible file created due to rotation"
             *
             * If the condition above is met, a new file entry will be added to
             * the list that we are processing and a 'new signal' will be send
             * to the signal manager. But the signal manager will trigger the
             * message only if no pending messages exists (to avoid queue size
             * exhaustion).
             *
             * All good, but there is a corner case where if no 'active' files
             * exists, the signal will be read and this function will not be
             * called again and since the signal did not triggered the
             * message, the 'new file' enqueued by the nested function
             * might stay in stale mode (note that altering the length of this
             * list will not be reflected yet)
             *
             * To fix the corner case, we use a variable called 'alter_size'
             * that determinate if the size of the list keeps the same after
             * a rotation, so it means: a new file was added.
             *
             * We use 'alter_size' as a helper in the conditional below to know
             * when to stop processing the static list.
             */
            if (alter_size == 0) {
                pre_size = ctx->files_static_count;
            }
            ret = flb_tail_file_to_event(file);
            if (ret == -1) {
                flb_plg_debug(ctx->ins, "file=%s cannot promote, unregistering",
                              file->name);
                flb_tail_file_remove(file);
            }

            if (alter_size == 0) {
                pos_size = ctx->files_static_count;
                if (pre_size == pos_size) {
                    alter_size++;
                }
            }
            break;
        }
    }

    /*
     * If there are no more active static handlers, we consume the 'byte' that
     * triggered this event so this is not longer called again.
     */
    if (active == 0 && alter_size == 0) {
        consume_byte(ctx->ch_manager[0]);
        ctx->ch_reads++;
        completed = FLB_TRUE;
    }

    /* Debugging number of processed bytes */
    if (flb_log_check_level(ctx->ins->log_level, FLB_LOG_DEBUG)) {
        flb_utils_bytes_to_human_readable_size(total_processed,
                                               s_size, sizeof(s_size));
        if (completed) {
            flb_plg_debug(ctx->ins, "[static files] processed %s, done", s_size);
        }
        else {
            flb_plg_debug(ctx->ins, "[static files] processed %s", s_size);
        }
    }

    return 0;
}

static int in_tail_watcher_callback(struct flb_input_instance *ins,
                                    struct flb_config *config, void *context)
{
    int ret = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = context;
    struct flb_tail_file *file;
    (void) config;

    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (file->is_link == FLB_TRUE && ctx->keep_file_handle == FLB_TRUE) {
            ret = flb_tail_file_is_rotated(ctx, file);
            if (ret == FLB_FALSE) {
                continue;
            }

            /* The symbolic link name has been rotated */
            flb_tail_file_rotated(file);
        }
    }
    return ret;
}

int in_tail_collect_event(void *file, struct flb_config *config)
{
    int ret;
    struct stat st;
    struct flb_tail_file *f = file;

    ret = flb_tail_file_stat(f, &st);
    if (ret == -1) {
        flb_tail_file_remove(f);
        return 0;
    }

    ret = flb_tail_file_chunk(f);
    switch (ret) {
    case FLB_TAIL_ERROR:
        /* Could not longer read the file */
        flb_tail_file_remove(f);
        break;
    case FLB_TAIL_OK:
    case FLB_TAIL_WAIT:
        break;
    }

    return 0;
}

/* Initialize plugin */
static int in_tail_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_tail_config *ctx = NULL;

    /* Allocate space for the configuration */
    ctx = flb_tail_config_create(in, config);
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;

    /* Initialize file-system watcher */
    ret = flb_tail_fs_init(in, ctx, config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }

    /* Scan path */
    flb_tail_scan(ctx->path_list, ctx);

#ifdef FLB_HAVE_SQLDB
    /* Delete stale files that are not monitored from the database */
    ret = flb_tail_db_stale_file_delete(in, config, ctx);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
#endif

    if (ctx->read_newly_discovered_files_from_head) {
        /*
        * After the first scan (on start time), all new files discovered needs to be
        * read from head, so we switch the 'read_from_head' flag to true so any
        * other file discovered after a scan or a rotation are read from the
        * beginning.
        */
        ctx->read_from_head = FLB_TRUE;
    }

    /* Set plugin context */
    flb_input_set_context(in, ctx);

    /* Register an event collector */
    ret = flb_input_set_collector_event(in, in_tail_collect_static,
                                        ctx->ch_manager[0], config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_static = ret;

    /* Register re-scan: time managed by 'refresh_interval' property */
    ret = flb_input_set_collector_time(in, flb_tail_scan_callback,
                                       ctx->refresh_interval_sec,
                                       ctx->refresh_interval_nsec,
                                       config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_scan = ret;

    /* Register watcher, interval managed by 'watcher_interval' property */
    ret = flb_input_set_collector_time(in, in_tail_watcher_callback,
                                       ctx->watcher_interval, 0,
                                       config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_watcher = ret;

    /* Register callback to purge rotated files */
    ret = flb_input_set_collector_time(in, flb_tail_file_purge,
                                       ctx->rotate_wait, 0,
                                       config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_rotated = ret;

    /* Register callback to process pending bytes in promoted files */
    ret = flb_input_set_collector_event(in, in_tail_collect_pending,
                                        ctx->ch_pending[0], config);//1, 0, config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_pending = ret;


    if (ctx->multiline == FLB_TRUE && ctx->parser) {
        ctx->parser = NULL;
        flb_plg_warn(in, "on multiline mode 'Parser' is not allowed "
                     "(parser disabled)");
    }

    /* Register callback to process docker mode queued buffer */
    if (ctx->docker_mode == FLB_TRUE) {
        ret = flb_input_set_collector_time(in, flb_tail_dmode_pending_flush,
                                           ctx->docker_mode_flush, 0,
                                           config);
        if (ret == -1) {
            ctx->docker_mode = FLB_FALSE;
            flb_tail_config_destroy(ctx);
            return -1;
        }
        ctx->coll_fd_dmode_flush = ret;
    }

#ifdef FLB_HAVE_PARSER
    /* Register callback to process multiline queued buffer */
    if (ctx->multiline == FLB_TRUE) {
        ret = flb_input_set_collector_time(in, flb_tail_mult_pending_flush,
                                           ctx->multiline_flush, 0,
                                           config);
        if (ret == -1) {
            ctx->multiline = FLB_FALSE;
            flb_tail_config_destroy(ctx);
            return -1;
        }
        ctx->coll_fd_mult_flush = ret;
    }
#endif

    return 0;
}

/* Pre-run callback / before the event loop */
static int in_tail_pre_run(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_tail_config *ctx = in_context;
    (void) ins;

    return tail_signal_manager(ctx);
}

static int in_tail_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_tail_config *ctx = data;

    flb_tail_file_remove_all(ctx);
    flb_tail_fs_exit(ctx);
    flb_tail_config_destroy(ctx);

    return 0;
}

static void in_tail_pause(void *data, struct flb_config *config)
{
    struct flb_tail_config *ctx = data;

    /*
     * Pause general collectors:
     *
     * - static : static files lookup before promotion
     */
    flb_input_collector_pause(ctx->coll_fd_static, ctx->ins);
    flb_input_collector_pause(ctx->coll_fd_pending, ctx->ins);

    if (ctx->docker_mode == FLB_TRUE) {
        flb_input_collector_pause(ctx->coll_fd_dmode_flush, ctx->ins);
        if (config->is_ingestion_active == FLB_FALSE) {
            flb_plg_info(ctx->ins, "flushing pending docker mode data...");
            flb_tail_dmode_pending_flush_all(ctx);
        }
    }

    if (ctx->multiline == FLB_TRUE) {
        flb_input_collector_pause(ctx->coll_fd_mult_flush, ctx->ins);
        if (config->is_ingestion_active == FLB_FALSE) {
            flb_plg_info(ctx->ins, "flushing pending multiline data...");
            flb_tail_mult_pending_flush_all(ctx);
        }
    }

    /* Pause file system backend handlers */
    flb_tail_fs_pause(ctx);
}

static void in_tail_resume(void *data, struct flb_config *config)
{
    struct flb_tail_config *ctx = data;

    flb_input_collector_resume(ctx->coll_fd_static, ctx->ins);
    flb_input_collector_resume(ctx->coll_fd_pending, ctx->ins);

    if (ctx->docker_mode == FLB_TRUE) {
        flb_input_collector_resume(ctx->coll_fd_dmode_flush, ctx->ins);
    }

    if (ctx->multiline == FLB_TRUE) {
        flb_input_collector_resume(ctx->coll_fd_mult_flush, ctx->ins);
    }

    /* Pause file system backend handlers */
    flb_tail_fs_resume(ctx);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_CLIST, "path", NULL,
     0, FLB_TRUE, offsetof(struct flb_tail_config, path_list),
     "pattern specifying log files or multiple ones through "
     "the use of common wildcards."
    },
    {
     FLB_CONFIG_MAP_CLIST, "exclude_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_tail_config, exclude_list),
     "Set one or multiple shell patterns separated by commas to exclude "
     "files matching a certain criteria, e.g: 'exclude_path *.gz,*.zip'"
    },
    {
     FLB_CONFIG_MAP_STR, "key", "log",
     0, FLB_TRUE, offsetof(struct flb_tail_config, key),
     "when a message is unstructured (no parser applied), it's appended "
     "as a string under the key name log. This option allows to define an "
     "alternative name for that key."
    },
    {
     FLB_CONFIG_MAP_BOOL, "read_from_head", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_config, read_from_head),
     "For new discovered files on start (without a database offset/position), read the "
     "content from the head of the file, not tail."
    },
    {
     FLB_CONFIG_MAP_BOOL, "read_newly_discovered_files_from_head", "true",
     0, FLB_TRUE, offsetof(struct flb_tail_config, read_newly_discovered_files_from_head),
     "For new discovered files after start (without a database offset/position), read the "
     "content from the head of the file, not tail."
    },
    {
     FLB_CONFIG_MAP_STR, "refresh_interval", "60",
     0, FLB_FALSE, 0,
     "interval to refresh the list of watched files expressed in seconds."
    },
    {
     FLB_CONFIG_MAP_TIME, "watcher_interval", "2s",
     0, FLB_TRUE, offsetof(struct flb_tail_config, watcher_interval),
    },
    {
     FLB_CONFIG_MAP_TIME, "progress_check_interval", "2s",
     0, FLB_TRUE, offsetof(struct flb_tail_config, progress_check_interval),
    },
    {
     FLB_CONFIG_MAP_INT, "progress_check_interval_nsec", "0",
     0, FLB_TRUE, offsetof(struct flb_tail_config, progress_check_interval_nsec),
    },
    {
     FLB_CONFIG_MAP_STR, "fstat_interval", "250ms",
     0, FLB_FALSE, 0,
     "interval for fstat mode event polling. Controls how often files are checked "
     "for changes when using stat-based file watching (instead of inotify). "
     "Default is 250ms. Supports time suffixes: s, ms, us, ns."
    },
    {
     FLB_CONFIG_MAP_TIME, "rotate_wait", FLB_TAIL_ROTATE_WAIT,
     0, FLB_TRUE, offsetof(struct flb_tail_config, rotate_wait),
     "specify the number of extra time in seconds to monitor a file once is "
     "rotated in case some pending data is flushed."
    },
    {
     FLB_CONFIG_MAP_BOOL, "docker_mode", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_config, docker_mode),
     "If enabled, the plugin will recombine split Docker log lines before "
     "passing them to any parser as configured above. This mode cannot be "
     "used at the same time as Multiline."
    },
    {
     FLB_CONFIG_MAP_INT, "docker_mode_flush", "4",
     0, FLB_TRUE, offsetof(struct flb_tail_config, docker_mode_flush),
     "wait period time in seconds to flush queued unfinished split lines."

    },
#ifdef FLB_HAVE_REGEX
    {
     FLB_CONFIG_MAP_STR, "docker_mode_parser", NULL,
     0, FLB_FALSE, 0,
     "specify the parser name to fetch log first line for muliline log"
    },
#endif
    {
     FLB_CONFIG_MAP_STR, "path_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_tail_config, path_key),
     "set the 'key' name where the name of monitored file will be appended."
    },
    {
     FLB_CONFIG_MAP_STR, "offset_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_tail_config, offset_key),
     "set the 'key' name where the offset of monitored file will be appended."
    },
    {
     FLB_CONFIG_MAP_TIME, "ignore_older", "0",
     0, FLB_TRUE, offsetof(struct flb_tail_config, ignore_older),
     "ignore records older than 'ignore_older'. Supports m,h,d (minutes, "
     "hours, days) syntax. Default behavior is to read all records. Option "
     "only available when a Parser is specified and it can parse the time "
     "of a record."
    },
    {
     FLB_CONFIG_MAP_BOOL, "ignore_active_older_files", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_config, ignore_active_older_files),
     "ignore files that are older than the value set in ignore_older even "
     "if the file is being ingested."
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", FLB_TAIL_CHUNK,
     0, FLB_TRUE, offsetof(struct flb_tail_config, buf_chunk_size),
     "set the initial buffer size to read data from files. This value is "
     "used too to increase buffer size."
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", FLB_TAIL_CHUNK,
     0, FLB_TRUE, offsetof(struct flb_tail_config, buf_max_size),
     "set the limit of the buffer size per monitored file. When a buffer "
     "needs to be increased (e.g: very long lines), this value is used to "
     "restrict how much the memory buffer can grow. If reading a file exceed "
     "this limit, the file is removed from the monitored file list."
    },
    {
     FLB_CONFIG_MAP_SIZE, "static_batch_size", FLB_TAIL_STATIC_BATCH_SIZE,
     0, FLB_TRUE, offsetof(struct flb_tail_config, static_batch_size),
     "On start, Fluent Bit might process files which already contains data, "
     "these files are called 'static' files. The configuration property "
     "in question set's the maximum number of bytes to process per iteration "
     "for the static files monitored."
    },
    {
     FLB_CONFIG_MAP_SIZE, "event_batch_size", FLB_TAIL_EVENT_BATCH_SIZE,
     0, FLB_TRUE, offsetof(struct flb_tail_config, event_batch_size),
     "When Fluent Bit is processing files in event based mode the amount of"
     "data available for consumption could be too much and cause the input plugin "
     "to over extend and smother other plugins"
     "The configuration property sets the maximum number of bytes to process per iteration "
     "for the files monitored (in event mode)."
    },
    {
     FLB_CONFIG_MAP_BOOL, "skip_long_lines", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_config, skip_long_lines),
     "if a monitored file reach it buffer capacity due to a very long line "
     "(buffer_max_size), the default behavior is to stop monitoring that "
     "file. This option alter that behavior and instruct Fluent Bit to skip "
     "long lines and continue processing other lines that fits into the buffer."
    },
    {
     FLB_CONFIG_MAP_BOOL, "exit_on_eof", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_config, exit_on_eof),
     "exit Fluent Bit when reaching EOF on a monitored file."
    },

    {
     FLB_CONFIG_MAP_BOOL, "skip_empty_lines", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_config, skip_empty_lines),
     "Allows to skip empty lines."
    },
    {
     FLB_CONFIG_MAP_BOOL, "keep_file_handle", "true",
     0, FLB_TRUE, offsetof(struct flb_tail_config, keep_file_handle),
     "When set to false, the file handle will be reopened every time we read "
     "from the source tailed file and closed when done, to avoid keeping it open. "
     "Useful for SMB shares and network filesystems where keeping handles open "
     "can cause issues."
    },
    {
      FLB_CONFIG_MAP_BOOL, "truncate_long_lines", "false",
      0, FLB_TRUE, offsetof(struct flb_tail_config, truncate_long_lines),
      "Truncate overlong lines after input encoding to UTF-8"
    },
#ifdef __linux__
    {
     FLB_CONFIG_MAP_BOOL, "file_cache_advise", "true",
     0, FLB_TRUE, offsetof(struct flb_tail_config, file_cache_advise),
     "Use posix_fadvise for file access. Advise not to use kernel file cache."
    },
#endif
#ifdef FLB_HAVE_INOTIFY
    {
     FLB_CONFIG_MAP_BOOL, "inotify_watcher", "true",
     0, FLB_TRUE, offsetof(struct flb_tail_config, inotify_watcher),
     "set to false to use file stat watcher instead of inotify."
    },
#endif
#ifdef FLB_HAVE_REGEX
    {
     FLB_CONFIG_MAP_STR, "parser", NULL,
     0, FLB_FALSE, 0,
     "specify the parser name to process an unstructured message."
    },
    {
     FLB_CONFIG_MAP_STR, "tag_regex", NULL,
     0, FLB_FALSE, 0,
     "set a regex to extract fields from the file name and use them later to "
     "compose the Tag."
    },
#endif

#ifdef FLB_HAVE_SQLDB
    {
     FLB_CONFIG_MAP_STR, "db", NULL,
     0, FLB_FALSE, 0,
     "set a database file to keep track of monitored files and it offsets."
    },
    {
     FLB_CONFIG_MAP_STR, "db.sync", "normal",
     0, FLB_FALSE, 0,
     "set a database sync method. values: extra, full, normal and off."
    },
    {
     FLB_CONFIG_MAP_BOOL, "db.locking", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_config, db_locking),
     "set exclusive locking mode, increase performance but don't allow "
     "external connections to the database file."
    },
    {
     FLB_CONFIG_MAP_STR, "db.journal_mode", "WAL",
     0, FLB_TRUE, offsetof(struct flb_tail_config, db_journal_mode),
     "Option to provide WAL configuration for Work Ahead Logging mechanism (WAL). Enabling WAL "
     "provides higher performance. Note that WAL is not compatible with "
     "shared network file systems."
    },
    {
     FLB_CONFIG_MAP_BOOL, "db.compare_filename", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_config, compare_filename),
     "This option determines whether to check both the inode and the filename "
     "when retrieving file information from the db."
     "'true' verifies both the inode and filename, while 'false' checks only "
     "the inode (default)."
    },
#endif

    /* Multiline Options */
#ifdef FLB_HAVE_PARSER
    {
     FLB_CONFIG_MAP_BOOL, "multiline", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_config, multiline),
     "if enabled, the plugin will try to discover multiline messages and use "
     "the proper parsers to compose the outgoing messages. Note that when this "
     "option is enabled the Parser option is not used."
    },
    {
     FLB_CONFIG_MAP_TIME, "multiline_flush", FLB_TAIL_MULT_FLUSH,
     0, FLB_TRUE, offsetof(struct flb_tail_config, multiline_flush),
     "wait period time in seconds to process queued multiline messages."
    },
    {
     FLB_CONFIG_MAP_STR, "parser_firstline", NULL,
     0, FLB_FALSE, 0,
     "name of the parser that matches the beginning of a multiline message. "
     "Note that the regular expression defined in the parser must include a "
     "group name (named capture)."
    },
    {
     FLB_CONFIG_MAP_STR_PREFIX, "parser_", NULL,
     0, FLB_FALSE, 0,
     "optional extra parser to interpret and structure multiline entries. This "
     "option can be used to define multiple parsers, e.g: Parser_1 ab1, "
     "Parser_2 ab2, Parser_N abN."
    },

    /* Multiline Core Engine based API */
    {
     FLB_CONFIG_MAP_CLIST, "multiline.parser", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_tail_config, multiline_parsers),
     "specify one or multiple multiline parsers: docker, cri, go, java, etc."
    },
#endif

#ifdef FLB_HAVE_UNICODE_ENCODER
    {
     FLB_CONFIG_MAP_STR, "unicode.encoding", NULL,
     0, FLB_FALSE, 0,
     "specify the preferred input encoding for converting to UTF-8. "
     "Currently, UTF-16LE, UTF-16BE, auto are supported.",
    },
#endif
    {
     FLB_CONFIG_MAP_STR, "generic.encoding", NULL,
     0, FLB_FALSE, 0,
     "specify the preferred input encoding for converting to UTF-8. "
     "Currently, the following encodings are supported: "
     "ShiftJIS, UHC, GBK, GB18030, Big5, "
     "Win866, Win874, "
     "Win1250, Win1251, Win1252, Win2513, Win1254, Win1255, WIn1256",
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_tail_plugin = {
    .name         = "tail",
    .description  = "Tail files",
    .cb_init      = in_tail_init,
    .cb_pre_run   = in_tail_pre_run,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = in_tail_pause,
    .cb_resume    = in_tail_resume,
    .cb_exit      = in_tail_exit,
    .config_map   = config_map,
    .flags        = 0
};
