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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_input.h>
#include "winlog.h"

struct winlog_channel *winlog_open(const char *channel)
{
    struct winlog_channel *ch;

    ch = flb_calloc(1, sizeof(struct winlog_channel));
    if (!ch) {
        flb_errno();
        return NULL;
    }

    ch->name = flb_strdup(channel);
    if (!ch->name) {
        flb_errno();
        flb_free(ch);
        return NULL;
    }

    ch->h = OpenEventLogA(NULL, channel);
    if (!ch->h) {
        flb_error("[in_winlog] cannot open '%s' (%i)", channel, GetLastError());
        flb_free(ch->name);
        flb_free(ch);
        return NULL;
    }

    return ch;
}

void winlog_close(struct winlog_channel *ch)
{
    flb_free(ch->name);
    CloseEventLog(ch->h);
    flb_free(ch);
}

/*
 * This routine is called when Windows Event Log was cleared
 * while reading (e.g. running Clear-EventLog on PowerShell).
 *
 * In such a case, the only neat thing to do is to reopen the
 * channel and start reading from the beginning.
 */
int winlog_on_cleared(struct winlog_channel *ch)
{
    HANDLE h;

    h = OpenEventLogA(NULL, ch->name);
    if (!h) {
        flb_error("[in_winlog] cannot open '%s' (%i)", ch->name, GetLastError());
        return -1;
    }

    if (ch->h) {
        CloseEventLog(ch->h);
    }

    ch->h = h;
    ch->seek = 0;
    return 0;
}


/*
 * ReadEventLog() has a known bug that SEEK_READ fails when the log file
 * is too big.
 *
 * winlog_seek() is a workaround for the issue, which emulates seek
 * by reading the stream until it reaches the target record.
 *
 * https://support.microsoft.com/en-hk/help/177199/
 */
static int winlog_seek(struct winlog_channel *ch, char *buf,
                       unsigned int size, unsigned int *read)
{
    char *p;
    char *end;
    PEVENTLOGRECORD evt;

    ch->seek = 0;
    while (1) {
        if (winlog_read(ch, buf, size, read)) {
            return -1;
        }
        if (*read == 0) {
            flb_trace("[in_winlog] seek '%s' to EOF", ch->name);
            return 0;
        }

        p = buf;
        end = buf + *read;
        while (p < end) {
            evt = (PEVENTLOGRECORD) p;

            /* If the record is newer than the last record we've read,
             * stop immediately.
             */
            if (evt->TimeWritten > ch->time_written) {
                *read = (end - p);
                memmove(buf, p, *read);
                flb_trace("[in_winlog] seek '%s' to RecordNumber=%u (time)",
                          ch->name, evt->RecordNumber);
                return 0;
            }
            if (evt->TimeWritten == ch->time_written) {

               /* If the record was written at the same time, compare
                * the record number.
                *
                * Note! Since Windows would reset RecordNumber occasionally,
                * this comparison is not completely reliable.
                */
                if (evt->RecordNumber > ch->record_number) {
                    *read = (end - p);
                    memmove(buf, p, *read);
                    flb_trace("[in_winlog] seek '%s' to RecordNumber=%u",
                              ch->name, evt->RecordNumber);
                    return 0;
                }
            }
            p += evt->Length;
        }
    }
}

/*
 * Read from an open Windows Event Log channel.
 */
int winlog_read(struct winlog_channel *ch, char *buf, unsigned int size,
                unsigned int *read)
{
    unsigned int flags;
    unsigned int req;
    unsigned int err;

    if (ch->seek) {
        flags = EVENTLOG_SEEK_READ;
    } else {
        flags = EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ;
    }

    /*
     * Note: ReadEventLogW() ignores `ch->record_number` (dwRecordOffset)
     * if EVENTLOG_SEEK_READ is not set.
     */
    if (!ReadEventLogW(ch->h, flags, ch->record_number, buf, size, read, &req)) {
        switch (err = GetLastError()) {
            case ERROR_HANDLE_EOF:
                break;
            case ERROR_INVALID_PARAMETER:
                return winlog_seek(ch, buf, size, read);
            case ERROR_EVENTLOG_FILE_CHANGED:
                flb_info("[in_winlog] channel '%s' is cleared. reopen it.", ch->name);
                return winlog_on_cleared(ch);
            default:
                flb_error("[in_winlog] cannot read '%s' (%i)", ch->name, err);
                return -1;
        }
    }
    ch->seek = 0;
    return 0;
}

/*
 * Open multiple channels at once. The return value is a linked
 * list of window_channel objects.
 *
 * "channels" are comma-separated names like "Setup,Security".
 */
struct mk_list *winlog_open_all(const char *channels)
{
    char *tmp;
    char *channel;
    char *state;
    struct winlog_channel *ch;
    struct mk_list *list;

    tmp = flb_strdup(channels);
    if (!tmp) {
        flb_errno();
        return NULL;
    }

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        flb_free(tmp);
        return NULL;
    }
    mk_list_init(list);

    channel = strtok_s(tmp , ",", &state);
    while (channel) {
        ch = winlog_open(channel);
        if (!ch) {
            flb_free(tmp);
            winlog_close_all(list);
            return NULL;
        }
        mk_list_add(&ch->_head, list);
        channel = strtok_s(NULL, ",", &state);
    }
    flb_free(tmp);
    return list;
}

void winlog_close_all(struct mk_list *list)
{
    struct winlog_channel *ch;
    struct mk_list *head;
    struct mk_list *tmp;

    mk_list_foreach_safe(head, tmp, list) {
        ch = mk_list_entry(head, struct winlog_channel, _head);
        mk_list_del(&ch->_head);
        winlog_close(ch);
    }
    flb_free(list);
}

/*
 * Callback function for flb_sqldb_query().
 */
static int winlog_sqlite_callback(void *data, int argc, char **argv, char **cols)
{
    struct winlog_sqlite_record *p = data;

    p->name = argv[0];
    p->record_number = (unsigned int) strtoul(argv[1], NULL, 10);
    p->time_written = (unsigned int) strtoul(argv[2], NULL, 10);
    p->created = (unsigned int) strtoul(argv[3], NULL, 10);
    return 0;
}

/*
 * Load the read offset from SQLite DB.
 */
int winlog_sqlite_load(struct winlog_channel *ch, struct flb_sqldb *db)
{
    int ret;
    char query[1024];
    struct winlog_sqlite_record record = {0};

    snprintf(query, sizeof(query) - 1, SQL_GET_CHANNEL, ch->name);

    ret = flb_sqldb_query(db, query, winlog_sqlite_callback, &record);
    if (ret == FLB_ERROR) {
        return -1;
    }

    if (record.name) {
        ch->record_number = record.record_number;
        ch->time_written = record.time_written;
        ch->seek = 1;
    }
    return 0;
}

/*
 * Save the read offset into SQLite DB.
 */
int winlog_sqlite_save(struct winlog_channel *ch, struct flb_sqldb *db)
{
    int ret;
    char query[1024];

    snprintf(query, sizeof(query) - 1, SQL_UPDATE_CHANNEL,
             ch->name, ch->record_number, ch->time_written, time(NULL));

    ret = flb_sqldb_query(db, query, NULL, NULL);
    if (ret == FLB_ERROR) {
        return -1;
    }
    return 0;
}
