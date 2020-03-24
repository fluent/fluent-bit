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

static inline int consume_byte(int fd)
{
    int ret;
    uint64_t val;

    /* We need to consume the byte */
    ret = flb_pipe_r(fd, &val, sizeof(val));
    if (ret <= 0) {
        flb_errno();
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

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        /* Gather current file size */
        ret = fstat(file->fd, &st);
        if (ret == -1) {
            flb_errno();
            flb_tail_file_remove(file);
            continue;
        }
        file->size = st.st_size;
        file->pending_bytes = (file->size - file->offset);

        if (file->pending_bytes <= 0) {
            continue;
        }

        ret = flb_tail_file_chunk(file);
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
            if (file->offset < st.st_size) {
                file->pending_bytes = (st.st_size - file->offset);
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
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file;

    /* Do a data chunk collection for each file */
    mk_list_foreach_safe(head, tmp, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        ret = flb_tail_file_chunk(file);
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
            if (file->config->exit_on_eof) {
                flb_plg_info(ctx->ins, "inode=%"PRIu64" file=%s ended, stop",
                             file->inode, file->name);
                flb_engine_exit(config);
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
                pre_size = mk_list_size(&ctx->files_static);
            }
            ret = flb_tail_file_to_event(file);
            if (ret == -1) {
                flb_plg_debug(ctx->ins, "file=%s cannot promote, unregistering",
                              file->name);
                flb_tail_file_remove(file);
            }

            if (alter_size == 0) {
                pos_size = mk_list_size(&ctx->files_static);
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

#ifndef _MSC_VER
    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (file->is_link == FLB_TRUE) {
            ret = flb_tail_file_is_rotated(ctx, file);
            if (ret == FLB_FALSE) {
                continue;
            }

            /* The symbolic link name has been rotated */
            flb_tail_file_rotated(file);
        }
    }

#endif
    return ret;
}

int in_tail_collect_event(void *file, struct flb_config *config)
{
    int ret;
    struct stat st;
    struct flb_tail_file *f = file;

    ret = fstat(f->fd, &st);
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
    flb_tail_scan(ctx->path, ctx);
    flb_plg_trace(in, "scan path: %s", ctx->path);

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
    }

    if (ctx->multiline == FLB_TRUE) {
        flb_input_collector_pause(ctx->coll_fd_mult_flush, ctx->ins);
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
     FLB_CONFIG_MAP_STR, "path", NULL,
     0, FLB_TRUE, offsetof(struct flb_tail_config, path),
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
     FLB_CONFIG_MAP_STR, "refresh_interval", "60",
     0, FLB_FALSE, 0,
     "interval to refresh the list of watched files expressed in seconds."
    },
    {
     FLB_CONFIG_MAP_TIME, "watcher_interval", "2s",
     0, FLB_TRUE, offsetof(struct flb_tail_config, watcher_interval),
    },
    {
     FLB_CONFIG_MAP_INT, "rotate_wait", FLB_TAIL_ROTATE_WAIT,
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
     FLB_CONFIG_MAP_TIME, "ignore_older", "0",
     0, FLB_TRUE, offsetof(struct flb_tail_config, ignore_older),
     "ignore records older than 'ignore_older'. Supports m,h,d (minutes, "
     "hours, days) syntax. Default behavior is to read all records. Option "
     "only available when a Parser is specified and it can parse the time "
     "of a record."
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
     FLB_CONFIG_MAP_STR, "db.sync", "full",
     0, FLB_FALSE, 0,
     "set a database sync method. values: extra, full, normal and off."
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

#endif

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
