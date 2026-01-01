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

#ifndef FLB_WINLOG_H
#define FLB_WINLOG_H

struct winlog_config {
    unsigned int interval_sec;
    unsigned int interval_nsec;
    unsigned int bufsize;
    int string_inserts;
    int use_ansi;
    char *buf;
    struct mk_list *active_channel;
    struct flb_sqldb *db;
    flb_pipefd_t coll_fd;
    struct flb_input_instance *ins;
};

struct winlog_channel {
    HANDLE h;
    char *name;
    unsigned int record_number;
    unsigned int time_written;
    unsigned int seek;
    struct mk_list _head;
};

struct winlog_sqlite_record {
    char *name;
    unsigned int record_number;
    unsigned int time_written;
    unsigned int created;
};

/*
 * Open a Windows Event Log channel.
 */
struct winlog_channel *winlog_open(const char *channel);
void winlog_close(struct winlog_channel *ch);

/*
 * Read records from a channel.
 */
int winlog_read(struct winlog_channel *ch, char *buf, unsigned int size, unsigned int *read);

/*
 * A bulk API to handle multiple channels at once using mk_list.
 *
 * "channels" are comma-separated names like "Setup,Security".
 */
struct mk_list *winlog_open_all(const char *channels);
void winlog_close_all(struct mk_list *list);

void winlog_pack_event(msgpack_packer *mp_pck, PEVENTLOGRECORD evt,
                       struct winlog_channel *ch, struct winlog_config *ctx);

/*
 * Save the read offset to disk.
 */
int winlog_sqlite_load(struct winlog_channel *ch, struct flb_sqldb *db);
int winlog_sqlite_save(struct winlog_channel *ch, struct flb_sqldb *db);

/*
 * SQL templates
 */
#define SQL_CREATE_CHANNELS                                         \
    "CREATE TABLE IF NOT EXISTS in_winlog_channels ("               \
    "  name    TEXT PRIMARY KEY,"                                   \
    "  record_number INTEGER,"                                      \
    "  time_written INTEGER,"                                       \
    "  created INTEGER"                                             \
    ");"

#define SQL_GET_CHANNEL                                             \
    "SELECT name, record_number, time_written, created"             \
    " FROM in_winlog_channels WHERE name = '%s';"

/*
 * This uses UPCERT i.e. execute INSERT first and fall back to
 * UPDATE if the entry already exists. It saves the trouble of
 * doing an existence check manually.
 *
 * https://www.sqlite.org/lang_UPSERT.html
 */
#define SQL_UPDATE_CHANNEL                                          \
    "INSERT INTO in_winlog_channels"                                \
    "  (name, record_number, time_written, created)"                \
    "  VALUES ('%s', %u, %u, %llu)"                                   \
    "  ON CONFLICT(name) DO UPDATE"                                 \
    "  SET record_number = excluded.record_number,"                 \
    "      time_written = excluded.time_written"

#endif
