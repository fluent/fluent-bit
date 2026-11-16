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
#include "tail_scan.h"
#include "tail_signal.h"

#include <limits.h>
#include <fcntl.h>

#include <sys/ioctl.h>

/* Maximum number of inotify events consumed per collector invocation */
#define FLB_TAIL_INOTIFY_EVENTS   256

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

/*
 * Watch descriptor table: resolving the file associated to an inotify event
 * must not depend on the number of monitored files, otherwise every event
 * pays a linear lookup.
 */
static inline struct mk_list *watch_table_bucket(struct flb_tail_config *ctx,
                                                 int watch_fd)
{
    return &ctx->watch_table[((uint32_t) watch_fd) &
                             (FLB_TAIL_WATCH_TABLE_SIZE - 1)];
}

static void watch_table_unset(struct flb_tail_file *file)
{
    if (file->watch_fd == -1) {
        return;
    }

    mk_list_del(&file->_watch_head);
    file->watch_fd = -1;
}

static void watch_table_set(struct flb_tail_config *ctx,
                            struct flb_tail_file *file, int watch_fd)
{
    if (file->watch_fd == watch_fd) {
        return;
    }

    watch_table_unset(file);
    file->watch_fd = watch_fd;
    mk_list_add(&file->_watch_head, watch_table_bucket(ctx, watch_fd));
}

static struct flb_tail_file *watch_table_get(struct flb_tail_config *ctx,
                                             int watch_fd)
{
    struct mk_list *head;
    struct flb_tail_file *file;

    mk_list_foreach(head, watch_table_bucket(ctx, watch_fd)) {
        file = mk_list_entry(head, struct flb_tail_file, _watch_head);
        if (file->watch_fd == watch_fd) {
            return file;
        }
    }

    return NULL;
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
    watch_table_set(ctx, file, watch_fd);
    flb_plg_info(ctx->ins, "inotify_fs_add(): inode=%"PRIu64" watch_fd=%i name=%s",
                 file->inode, watch_fd, file->name);
    return 0;
}

static int flb_tail_fs_add_rotated(struct flb_tail_file *file)
{
    return tail_fs_add(file, FLB_FALSE);
}

/*
 * Synchronize the state of a file with the file system. When 'check_rotated'
 * is disabled the (expensive) name based rotation lookup is skipped: this is
 * only meant for events that cannot be the result of a rotation, any other
 * caller must enable it.
 */
static int reconcile_file_state(struct flb_tail_config *ctx,
                                struct flb_tail_file *file,
                                const char *caller,
                                int check_rotated,
                                int *pending_data_detected)
{
    int ret;
    int64_t size_delta;
    struct stat st;

    if (pending_data_detected != NULL) {
        *pending_data_detected = FLB_FALSE;
    }

    ret = fstat(file->fd, &st);
    if (ret == -1) {
        flb_plg_debug(ctx->ins, "inode=%"PRIu64" error stat(2) %s, removing",
                      file->inode, file->name);
        flb_tail_file_remove(file);
        return -1;
    }

    size_delta = st.st_size - file->size;
    if (size_delta != 0) {
        file->size = st.st_size;
    }

    if (size_delta < 0 || st.st_size < file->offset ||
        flb_tail_file_offset_marker_matches(file) != FLB_TRUE) {
        ret = flb_tail_file_reset_on_truncate(file, size_delta, caller);
        if (ret == -1) {
            return -1;
        }
    }

    if (file->offset < st.st_size) {
        file->pending_bytes = (st.st_size - file->offset);
        if (pending_data_detected != NULL) {
            flb_tail_file_pending_add(file);
            *pending_data_detected = FLB_TRUE;
        }
    }
    else {
        file->pending_bytes = 0;
    }

    if (st.st_nlink == 0) {
        if (file->pending_bytes > 0) {
            return 0;
        }

        if (file->buf_len > 0) {
            return 0;
        }

        flb_plg_debug(ctx->ins, "inode=%"PRIu64" file has been deleted: %s",
                      file->inode, file->name);

#ifdef FLB_HAVE_SQLDB
        if (ctx->db) {
            flb_tail_db_file_delete(file, ctx);
        }
#endif
        flb_tail_file_remove(file);
        return -1;
    }

    ret = FLB_FALSE;
    if (check_rotated == FLB_TRUE) {
        ret = flb_tail_file_is_rotated(ctx, file);
    }

    if (ret == FLB_TRUE) {
        ret = flb_tail_file_rotated(file);
        if (ret == -1) {
            return -1;
        }

        ret = flb_tail_fs_remove(ctx, file);
        if (ret == -1) {
            return -1;
        }
    }
    else if (ret == -1) {
        return -1;
    }

    if (file->rotated != 0 && file->watch_fd == -1) {
        ret = flb_tail_fs_add_rotated(file);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

static int reconcile_all_files(struct flb_tail_config *ctx)
{
    int ret;
    int pending;
    int pending_data_detected;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_tail_file *file;

    pending_data_detected = FLB_FALSE;

    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        ret = reconcile_file_state(ctx, file, "inotify_reconcile",
                                   FLB_TRUE, &pending);
        if (ret == -1) {
            continue;
        }

        if (pending == FLB_TRUE) {
            pending_data_detected = FLB_TRUE;
        }
    }

    if (pending_data_detected == FLB_TRUE) {
        tail_signal_pending(ctx);
    }

    return pending_data_detected;
}

/*
 * Process the (coalesced) events reported for a file. Returns FLB_TRUE if the
 * file still has data waiting to be consumed by the 'pending' collector.
 */
static int tail_fs_event_file(struct flb_tail_config *ctx,
                              struct flb_config *config,
                              struct flb_tail_file *file, uint32_t mask)
{
    int ret;
    int check_rotated = FLB_FALSE;

    /* Debug event */
    debug_event_mask(ctx, file, mask);

    if ((mask & ~IN_IGNORED) == 0) {
        flb_plg_debug(ctx->ins, "inode=%"PRIu64" watch_fd=%i IN_IGNORED",
                      file->inode, file->watch_fd);
        return FLB_FALSE;
    }

    /*
     * A rotation renames the monitored inode, which is always reported as
     * IN_MOVE_SELF, IN_ATTRIB is delivered when the link count changes. A
     * plain IN_MODIFY cannot be a rotation so the name lookup is skipped,
     * the progress check timer covers any event that the kernel did not
     * deliver (e.g: network file systems).
     */
    if (mask & (IN_MOVE_SELF | IN_ATTRIB)) {
        check_rotated = FLB_TRUE;
    }

    ret = reconcile_file_state(ctx, file, "tail_fs_event", check_rotated, NULL);
    if (ret == -1) {
        return FLB_FALSE;
    }

    /* Collect the data */
    ret = in_tail_collect_event(file, config);
    if (ret == FLB_TAIL_ERROR) {
        /* the file is not longer valid, it was removed */
        return FLB_FALSE;
    }

    /*
     * Due to read buffer size capacity, there are some cases where the
     * read operation cannot consume all new data available on one
     * round; upon successfull read(2) some data can still remain.
     *
     * If that is the case, the file is registered in the 'pending' list so
     * the collector in charge of it can process the remaining bytes after
     * an internal signal, the goal to defer this routine is to avoid
     * monopolizing the event loop with a single file.
     */
    if (flb_tail_file_has_pending_data(file) == FLB_TRUE) {
        flb_tail_file_pending_add(file);
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int tail_fs_event(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int i;
    int count = 0;
    int overflow = FLB_FALSE;
    int pending = FLB_FALSE;
    ssize_t bytes;
    size_t off;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file;
    struct inotify_event ev;
    int watches[FLB_TAIL_INOTIFY_EVENTS];
    char buf[FLB_TAIL_INOTIFY_EVENTS * sizeof(struct inotify_event)];

    (void) ins;

    /*
     * Read as many events as possible in one shot: consuming a single event
     * per event loop iteration does not scale when many files are written
     * at the same time.
     */
    bytes = read(ctx->fd_notify, buf, sizeof(buf));
    if (bytes < (ssize_t) sizeof(struct inotify_event)) {
        return -1;
    }

    /*
     * First pass: coalesce the events per file. A busy file usually reports
     * several IN_MODIFY events between two reads, one reconciliation and one
     * read attempt are enough for all of them.
     */
    ctx->event_batch_id++;

    for (off = 0; off + sizeof(struct inotify_event) <= (size_t) bytes;
         off += sizeof(struct inotify_event) + ev.len) {
        memcpy(&ev, buf + off, sizeof(struct inotify_event));

        if (ev.mask & IN_Q_OVERFLOW) {
            overflow = FLB_TRUE;
            continue;
        }

        file = watch_table_get(ctx, ev.wd);
        if (!file) {
            continue;
        }

        if (file->event_batch_id == ctx->event_batch_id) {
            file->event_mask |= ev.mask;
            continue;
        }

        file->event_batch_id = ctx->event_batch_id;
        file->event_mask = ev.mask;
        watches[count++] = ev.wd;
    }

    /*
     * Second pass: process the files. A file can be removed while a previous
     * one is processed, so the reference is always resolved again through
     * its watch descriptor.
     */
    for (i = 0; i < count; i++) {
        file = watch_table_get(ctx, watches[i]);
        if (!file || file->event_batch_id != ctx->event_batch_id) {
            continue;
        }

        if (tail_fs_event_file(ctx, config, file,
                               file->event_mask) == FLB_TRUE) {
            pending = FLB_TRUE;
        }
    }

    if (pending == FLB_TRUE) {
        tail_signal_pending(ctx);
    }

    if (overflow == FLB_TRUE) {
        debug_event_mask(ctx, NULL, IN_Q_OVERFLOW);
        flb_plg_warn(ctx->ins, "inotify event queue overflow, reconciling files");

        reconcile_all_files(ctx);
        flb_tail_scan(ctx->path_list, ctx);
    }

    return 0;
}

static int in_tail_progress_check_callback(struct flb_input_instance *ins,
                                           struct flb_config *config, void *context)
{
    int ret = 0;
    int pending;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = context;
    struct flb_tail_file *file;
    int pending_data_detected;

    (void) config;
    (void) ins;

    pending_data_detected = FLB_FALSE;

    if (flb_input_buf_paused(ctx->ins) == FLB_TRUE) {
        return 0;
    }

    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        ret = reconcile_file_state(ctx, file, "in_tail_progress_check",
                                   FLB_TRUE, &pending);
        if (ret == -1) {
            continue;
        }

        if (pending == FLB_TRUE) {
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

    /*
     * Keep the collector ID so the recovery timer follows the inotify
     * collector through input pause and resume transitions.
     */
    ret = flb_input_set_collector_time(in, in_tail_progress_check_callback,
                                       ctx->progress_check_interval,
                                       ctx->progress_check_interval_nsec,
                                       config);
    if (ret == -1) {
        /* the caller is in charge of releasing the context */
        close(fd);
        ctx->fd_notify = -1;
        return -1;
    }
    ctx->coll_fd_progress_check = ret;

    return 0;
}

void flb_tail_fs_inotify_pause(struct flb_tail_config *ctx)
{
    flb_input_collector_pause(ctx->coll_fd_fs1, ctx->ins);
    flb_input_collector_pause(ctx->coll_fd_progress_check, ctx->ins);
}

void flb_tail_fs_inotify_resume(struct flb_tail_config *ctx)
{
    flb_input_collector_resume(ctx->coll_fd_fs1, ctx->ins);
    flb_input_collector_resume(ctx->coll_fd_progress_check, ctx->ins);
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
    watch_table_unset(file);
    return 0;
}

int flb_tail_fs_inotify_exit(struct flb_tail_config *ctx)
{
    return close(ctx->fd_notify);
}
