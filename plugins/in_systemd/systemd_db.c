/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_sqldb.h>

#include "systemd_config.h"
#include "systemd_db.h"

struct query_status {
    int rows;
    char *cursor;
    time_t updated;
};

static int cb_cursor_check(void *data, int argc, char **argv, char **cols)
{
    struct query_status *qs = data;

    qs->cursor = flb_strdup(argv[0]);  /* cursor string */
    qs->updated = atoll(argv[1]);      /* timestamp     */
    qs->rows++;

    return 0;
}

struct flb_sqldb *flb_systemd_db_open(char *path, struct flb_input_instance *in,
                                      struct flb_config *config)
{
    int ret;
    struct flb_sqldb *db;

    /* Open/create the database */
    db = flb_sqldb_open(path, in->name, config);
    if (!db) {
        return NULL;
    }

    /* Create table schema if it don't exists */
    ret = flb_sqldb_query(db, SQL_CREATE_CURSOR, NULL, NULL);
    if (ret != FLB_OK) {
        flb_error("[in_systemd:db] could not create 'cursor' table");
        flb_sqldb_close(db);
        return NULL;
    }

    return db;
}

int flb_systemd_db_close(struct flb_sqldb *db)
{
    flb_sqldb_close(db);
    return 0;
}

int flb_systemd_db_set_cursor(struct flb_systemd_config *ctx, char *cursor)
{
    int ret;
    char query[PATH_MAX];
    struct query_status qs = {0};

    /* Check if the file exists */
    memset(&qs, '\0', sizeof(qs));
    ret = flb_sqldb_query(ctx->db,
                          SQL_GET_CURSOR, cb_cursor_check, &qs);

    if (qs.rows == 0) {
        /* Register the cursor */
        snprintf(query, sizeof(query) - 1,
                 SQL_INSERT_CURSOR,
                 cursor, time(NULL));
        ret = flb_sqldb_query(ctx->db,
                              query, NULL, NULL);
        if (ret == FLB_ERROR) {
            return -1;
        }
        return 0;
    }

    /* Register the cursor */
    flb_free(qs.cursor);
    snprintf(query, sizeof(query) - 1,
             SQL_UPDATE_CURSOR,
             cursor, time(NULL));
    ret = flb_sqldb_query(ctx->db,
                          query, NULL, NULL);
    if (ret == FLB_ERROR) {
        return -1;
    }
    return 0;
}

char *flb_systemd_db_get_cursor(struct flb_systemd_config *ctx)
{
    int ret;
    struct query_status qs = {0};

    memset(&qs, '\0', sizeof(qs));
    ret = flb_sqldb_query(ctx->db,
                          SQL_GET_CURSOR, cb_cursor_check, &qs);
    if (ret != FLB_OK) {
        return NULL;
    }

    if (qs.rows > 0) {
        /* cursor must be freed by the caller */
        return qs.cursor;
    }

    return NULL;
}
