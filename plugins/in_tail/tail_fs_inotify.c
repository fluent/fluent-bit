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

#define _DEFAULT_SOURCE

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "tail_config.h"
#include "tail_file.h"
#include "tail_db.h"
#include "tail_signal.h"

#include <limits.h>
#include <fcntl.h>

#include <sys/ioctl.h>

static int debug_event_mask(struct flb_tail_config *ctx,
                            struct flb_tail_file *file,
                            uint32_t mask)
{
    flb_sds_t buf;
    int buf_size = 256;

    /* Only enter this function if debug mode is allowed */
    if (flb_log_check(FLB_LOG_DEBUG) == 0) {
        return 0;
    }

    if (file) {
        buf_size = file->name_len + 128;
    }
    
    if (buf_size < 256) {
        buf_size = 256;
    }

    /* Create buffer */
    buf = flb_sds_create_size(buf_size);
    if (!buf) {
        return -1;
    }

    /* Print info into sds */
    if (file) {
        flb_sds_printf(&buf, "inode=%"PRIu64", %s, events: ", file->inode, file->name);
    }
    else {
        flb_sds_printf(&buf, "events: ");
    }

    if (mask & IN_ATTRIB) {
        flb_sds_printf(&buf, "IN_ATTRIB ");
    }
    if (mask & IN_IGNORED) {
        flb_sds_printf(&buf, "IN_IGNORED ");
    }
    if (mask & IN_MODIFY) {
        flb_sds_printf(&buf, "IN_MODIFY ");
    }
    if (mask & IN_MOVE_SELF) {
        flb_sds_printf(&buf, "IN_MOVE_SELF ");
    }
    if (mask & IN_Q_OVERFLOW) {
        flb_sds_printf(&buf, "IN_Q_OVERFLOW ");
    }

    flb_plg_debug(ctx->ins, "%s", buf);
    flb_sds_destroy(buf);

    return 0;
}

static int tail_fs_add(struct flb_tail_file *file, int check_rotated)
{
    int flags;
    int watch_fd;
    char *name;
    struct flb_tail_config *ctx = file->config;

    /*
     * If there is no watcher associated, we only want to monitor events if
     * this file is rotated to somewhere. Note at this point we are polling
     * lines from the file and once we reach EOF (and a watch_fd exists),
     * we update the flags to receive notifications.
     */
    flags = IN_ATTRIB | IN_IGNORED | IN_MODIFY | IN_Q_OVERFLOW;

    if (check_rotated == FLB_TRUE) {
        flags |= IN_MOVE_SELF;
    }

    /*
     * Double check real name of the file associated to the inode:
     *
     * Inotify interface in the Kernel uses the inode number as a real reference
     * for the file we have opened. If for some reason the file we are pointing
     * out in file->name has been rotated and not been updated, we might not add
     * the watch to the real file we aim to.
     *
     * A case like this can generate the issue:
     *
     * 1. inode=1 : file a.log is being watched
     * 2. inode=1 : file a.log is rotated to a.log.1, but notification not
     *              delivered yet.
     * 3. inode=2 : new file 'a.log' is created
     * 4. inode=2 : the scan_path routine discover the new 'a.log' file
     * 5. inode=2 : add an inotify watcher for 'a.log'
     * 6. conflict: inotify_add_watch() receives the path 'a.log',
     */

    name = flb_tail_file_name(file);
    if (!name) {
        flb_plg_error(ctx->ins, "inode=%"PRIu64" cannot get real filename for inotify",
                      file->inode);
        return -1;
    }

    /* Register or update the flags */
    watch_fd = inotify_add_watch(ctx->fd_notify, name, flags);
    flb_free(name);

    if (watch_fd == -1) {
        flb_errno();
        if (errno == ENOSPC) {
            flb_plg_error(ctx->ins, "inotify: The user limit on the total "
                          "number of inotify watches was reached or the kernel "
                          "failed to allocate a needed resource (ENOSPC)");
        }
        return -1;
    }
    file->watch_fd = watch_fd;
    flb_plg_info(ctx->ins, "inotify_fs_add(): inode=%"PRIu64" watch_fd=%i name=%s",
                 file->inode, watch_fd, file->name);
    return 0;
}

static int flb_tail_fs_add_rotated(struct flb_tail_file *file)
{
    return tail_fs_add(file, FLB_FALSE);
}

static int tail_fs_event(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int ret;
    int64_t offset;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file = NULL;
    struct inotify_event ev;
    struct stat st;

    /* Read the event */
    ret = read(ctx->fd_notify, &ev, sizeof(struct inotify_event));
    if (ret < 1) {
        return -1;
    }

    /* Lookup watched file */
    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (file->watch_fd != ev.wd) {
            file = NULL;
            continue;
        }
        break;
    }

    if (!file) {
        return -1;
    }

    /* Debug event */
    debug_event_mask(ctx, file, ev.mask);

    if (ev.mask & IN_IGNORED) {
        flb_plg_debug(ctx->ins, "inode=%"PRIu64" watch_fd=%i IN_IGNORED",
                      file->inode, ev.wd);
        return -1;
    }

    /* Check file rotation (only if it has not been rotated before) */
    if (ev.mask & IN_MOVE_SELF && file->rotated == 0) {
        flb_plg_debug(ins, "inode=%"PRIu64" rotated IN_MOVE SELF '%s'",
                      file->inode, file->name);

        /* A rotated file must be re-registered */
        flb_tail_file_rotated(file);
        flb_tail_fs_remove(ctx, file);
        flb_tail_fs_add_rotated(file);
    }

    ret = fstat(file->fd, &st);
    if (ret == -1) {
        flb_plg_debug(ins, "inode=%"PRIu64" error stat(2) %s, removing",
                      file->inode, file->name);
        flb_tail_file_remove(file);
        return 0;
    }

    /* Check if the file was truncated */
    int64_t size_delta = st.st_size - file->size;
    if (size_delta != 0) {
        file->size = st.st_size;
    }

    file->pending_bytes = (st.st_size > file->offset) ? (st.st_size - file->offset) : 0;

    /* File was removed ? */
    if (ev.mask & IN_ATTRIB) {
        /* Check if the file have been deleted */
        if (st.st_nlink == 0) {
            flb_plg_debug(ins, "inode=%"PRIu64" file has been deleted: %s",
                          file->inode, file->name);

#ifdef FLB_HAVE_SQLDB
            if (ctx->db) {
                /* Remove file entry from the database */
                flb_tail_db_file_delete(file, ctx);
            }
#endif
            /* Remove file from the monitored list */
            flb_tail_file_remove(file);
            return 0;
        }
    }

    if (ev.mask & IN_MODIFY) {
        /*
         * The file was modified, check how many new bytes do
         * we have.
         */

        if (size_delta < 0) {
            offset = lseek(file->fd, 0, SEEK_SET);
            if (offset == -1) {
                flb_errno();
                return -1;
            }

            flb_plg_debug(ctx->ins, "tail_fs_event: inode=%"PRIu64" file truncated %s (diff: %"PRId64" bytes)",
                          file->inode, file->name, size_delta);
            file->offset = offset;
            file->buf_len = 0;

            /* Update offset in the database file */
#ifdef FLB_HAVE_SQLDB
            if (ctx->db) {
                flb_tail_db_file_offset(file, ctx);
            }
#endif
        }
    }

    /* Collect the data */
    ret = in_tail_collect_event(file, config);
    if (ret != FLB_TAIL_ERROR) {
        /*
         * Due to read buffer size capacity, there are some cases where the
         * read operation cannot consume all new data available on one
         * round; upon successfull read(2) some data can still remain.
         *
         * If that is the case, we set in the structure how
         * many bytes are available 'now', so then the further
         * routine that check pending bytes and then the inotified-file
         * can process them properly after an internal signal.
         *
         * The goal to defer this routine is to avoid a blocking
         * read(2) operation, that might kill performance. Just let's
         * wait a second and do a good job.
         */
        tail_signal_pending(ctx);
    }
    else {
        return ret;
    }

    return 0;
}

static int in_tail_progress_check_callback(struct flb_input_instance *ins,
                                           struct flb_config *config, void *context)
{
    int ret = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = context;
    struct flb_tail_file *file;
    int pending_data_detected;
    struct stat st;

    (void) config;

    pending_data_detected = FLB_FALSE;

    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        if (file->offset < file->size) {
            pending_data_detected = FLB_TRUE;

            continue;
        }

        ret = fstat(file->fd, &st);
        if (ret == -1) {
            flb_errno();
            flb_plg_error(ins, "fstat error");

            continue;
        }

        if (file->offset < st.st_size) {
            file->size = st.st_size;
            file->pending_bytes = (file->size - file->offset);

            pending_data_detected = FLB_TRUE;
        }
    }

    if (pending_data_detected) {
       tail_signal_pending(ctx);
    }

    return 0;
}

/* File System events based on Inotify(2). Linux >= 2.6.32 is suggested */
int flb_tail_fs_inotify_init(struct flb_input_instance *in,
                     struct flb_tail_config *ctx, struct flb_config *config)
{
    int fd;
    int ret;

    flb_plg_debug(ctx->ins, "flb_tail_fs_inotify_init() initializing inotify tail input");

    /* Create inotify instance */
    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd == -1) {
        flb_errno();
        return -1;
    }
    flb_plg_debug(ctx->ins, "inotify watch fd=%i", fd);
    ctx->fd_notify = fd;

    /* This backend use Fluent Bit event-loop to trigger notifications */
    ret = flb_input_set_collector_event(in, tail_fs_event,
                                        ctx->fd_notify, config);
    if (ret < 0) {
        close(fd);
        return -1;
    }
    ctx->coll_fd_fs1 = ret;

    /* Register callback to check current tail offsets */
    ret = flb_input_set_collector_time(in, in_tail_progress_check_callback,
                                       ctx->progress_check_interval,
                                       ctx->progress_check_interval_nsec,
                                       config);
    if (ret == -1) {
        flb_tail_config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd_progress_check = ret;

    return 0;
}

void flb_tail_fs_inotify_pause(struct flb_tail_config *ctx)
{
    flb_input_collector_pause(ctx->coll_fd_fs1, ctx->ins);
}

void flb_tail_fs_inotify_resume(struct flb_tail_config *ctx)
{
    flb_input_collector_resume(ctx->coll_fd_fs1, ctx->ins);
}

int flb_tail_fs_inotify_add(struct flb_tail_file *file)
{
    int ret;
    struct flb_tail_config *ctx = file->config;

    ret = tail_fs_add(file, FLB_TRUE);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "inode=%"PRIu64" cannot register file %s",
                      file->inode, file->name);
        return -1;
    }

    return 0;
}

int flb_tail_fs_inotify_remove(struct flb_tail_file *file)
{
    struct flb_tail_config *ctx = file->config;

    if (file->watch_fd == -1) {
        return 0;
    }

    flb_plg_info(ctx->ins, "inotify_fs_remove(): inode=%"PRIu64" watch_fd=%i",
             file->inode, file->watch_fd);

    inotify_rm_watch(file->config->fd_notify, file->watch_fd);
    file->watch_fd = -1;
    return 0;
}

int flb_tail_fs_inotify_exit(struct flb_tail_config *ctx)
{
    return close(ctx->fd_notify);
}
