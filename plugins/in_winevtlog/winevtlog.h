/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_WINEVTLOG_H
#define FLB_WINEVTLOG_H

#include <winevt.h>
#include <fluent-bit/flb_log_event_encoder.h>

struct winevtlog_config {
    unsigned int interval_sec;
    unsigned int interval_nsec;
    unsigned int total_size_threshold;
    int string_inserts;
    int read_existing_events;
    int render_event_as_xml;
    int use_ansi;
    int ignore_missing_channels;

    struct mk_list *active_channel;
    struct flb_sqldb *db;
    flb_pipefd_t coll_fd;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

/* Some channels has very heavy contents for 10 events at same time.
 * For now, we specify simultaneous subscribe size to 5.
 */
#define SUBSCRIBE_ARRAY_SIZE 5

struct winevtlog_channel {
    EVT_HANDLE subscription;
    EVT_HANDLE bookmark;
    HANDLE signal_event;
    EVT_HANDLE events[SUBSCRIBE_ARRAY_SIZE];
    int count;

    char *name;
    unsigned int time_updated;
    unsigned int time_created;
    struct mk_list _head;
};

struct winevtlog_sqlite_record {
    char *name;
    char *bookmark_xml;
    unsigned int time_updated;
    unsigned int created;
};

/*
 * Open a Windows Event Log channel.
 */
struct winevtlog_channel *winevtlog_open(const char *channel);
void winevtlog_close(struct winevtlog_channel *ch);

/*
 * Read records from a channel.
 */
int winevtlog_read(struct winevtlog_channel *ch,
                   struct winevtlog_config *ctx, unsigned int *read);

/*
 * A bulk API to handle multiple channels at once using mk_list.
 *
 * "channels" are comma-separated names like "Setup,Security".
 */
struct mk_list *winevtlog_open_all(const char *channels, int read_exising_events, int ignore_missing_channels);
void winevtlog_close_all(struct mk_list *list);

void winevtlog_pack_xml_event(WCHAR *system_xml, WCHAR *message,
                              PEVT_VARIANT string_inserts, UINT count_inserts, struct winevtlog_channel *ch,
                              struct winevtlog_config *ctx);
void winevtlog_pack_event(PEVT_VARIANT system, WCHAR *message,
                          PEVT_VARIANT string_inserts, UINT count_inserts, struct winevtlog_channel *ch,
                          struct winevtlog_config *ctx);

/*
 * Save the read offset to disk.
 */
int winevtlog_sqlite_load(struct winevtlog_channel *ch, struct flb_sqldb *db);
int winevtlog_sqlite_save(struct winevtlog_channel *ch, struct flb_sqldb *db);

/*
 * SQL templates
 */
#define SQL_CREATE_CHANNELS                                         \
    "CREATE TABLE IF NOT EXISTS in_winevtlog_channels ("               \
    "  name    TEXT PRIMARY KEY,"                                   \
    "  bookmark_xml TEXT,"                                      \
    "  time_updated INTEGER,"                                      \
    "  created INTEGER"                                             \
    ");"

#define SQL_GET_CHANNEL                                             \
    "SELECT name, bookmark_xml, time_updated, created"             \
    " FROM in_winevtlog_channels WHERE name = '%s';"

/*
 * This uses UPCERT i.e. execute INSERT first and fall back to
 * UPDATE if the entry already exists. It saves the trouble of
 * doing an existence check manually.
 *
 * https://www.sqlite.org/lang_UPSERT.html
 */
#define SQL_UPDATE_CHANNEL                                          \
    "INSERT INTO in_winevtlog_channels"                                \
    "  (name, bookmark_xml, time_updated, created)"                \
    "  VALUES ('%s', \"%s\", %u, %llu)"                                   \
    "  ON CONFLICT(name) DO UPDATE"                                 \
    "  SET bookmark_xml = excluded.bookmark_xml,"      \
    "      time_updated = excluded.time_updated"      \

#endif
