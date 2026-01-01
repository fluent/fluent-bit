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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sqldb.h>

/*
 * Open or create a new database. Note that this function will always try to
 * use an open database and share it handler in as a new context.
 */
struct flb_sqldb *flb_sqldb_open(const char *path, const char *desc,
                                 struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct flb_sqldb *db_temp = NULL;
    struct flb_sqldb *db;
    sqlite3 *sdb = NULL;

    db = flb_calloc(1, sizeof(struct flb_sqldb));

    if (db == NULL) {
        flb_errno();

        return NULL;
    }

    db->parent = NULL;
    db->shared = FLB_FALSE;
    db->users  = 0;

    ret = flb_lock_init(&db->lock);

    if (ret != 0) {
        flb_free(db);

        return NULL;
    }

    /*
     * The database handler can be shared across different instances of
     * Fluent Bit. Before to open a new one, try to find a database that
     * is already open.
     */
    mk_list_foreach(head, &config->sqldb_list) {
        db_temp = mk_list_entry(head, struct flb_sqldb, _head);

        /* Only lookup for original database, not contexts already shared */
        if (db_temp->shared == FLB_TRUE) {
            continue;
        }

        if (strcmp(db_temp->path, path) == 0) {
            break;
        }
        db_temp = NULL;
    }

    /* Found a database that can be shared */
    if (db_temp) {
        /* Increase users counter */
        db_temp->users++;

        /* Setup the new context */
        db->handler = db_temp->handler;
        db->shared  = FLB_TRUE;
        db->parent  = db_temp;
    }
    else {
        ret = sqlite3_open(path, &sdb);

        if (ret) {
            flb_error("[sqldb] cannot open database %s", path);

            flb_lock_destroy(&db->lock);
            flb_free(db);

            return NULL;

        }
        db->handler = sdb;
    }

    db->path = flb_strdup(path);

    if (db->path == NULL) {
        flb_lock_destroy(&db->lock);
        sqlite3_close(sdb);
        flb_free(db);

        return NULL;
    }


    db->desc = flb_strdup(desc);

    if (db->desc == NULL) {
        flb_lock_destroy(&db->lock);
        flb_free(db->path);
        sqlite3_close(sdb);
        flb_free(db);

        return NULL;
    }

    mk_list_add(&db->_head, &config->sqldb_list);

    return db;
}

int flb_sqldb_close(struct flb_sqldb *db)
{
    struct flb_sqldb *parent;

    if (db->shared == FLB_TRUE) {
        parent = db->parent;
        parent->users--;
    }
    else {
        sqlite3_exec(db->handler, "COMMIT;", NULL, NULL, NULL);
        sqlite3_close(db->handler);
    }

    mk_list_del(&db->_head);
    flb_free(db->path);
    flb_free(db->desc);
    flb_lock_destroy(&db->lock);
    flb_free(db);

    return 0;
}

int flb_sqldb_query(struct flb_sqldb *db, const char *sql,
                    int (*callback) (void *, int, char **, char **),
                    void *data)
{
    int ret;
    char *err_msg = NULL;

    ret = sqlite3_exec(db->handler, sql, callback, data, &err_msg);
    if (ret != SQLITE_OK) {
        flb_error("[sqldb] error=%s", err_msg);
        sqlite3_free(err_msg);
        return FLB_ERROR;
    }

    return FLB_OK;
}

int64_t flb_sqldb_last_id(struct flb_sqldb *db)
{
    return sqlite3_last_insert_rowid(db->handler);
}

int flb_sqldb_lock(struct flb_sqldb *db)
{
    return flb_lock_acquire(&db->lock,
                            FLB_LOCK_INFINITE_RETRY_LIMIT,
                            FLB_LOCK_DEFAULT_RETRY_DELAY);
}

int flb_sqldb_unlock(struct flb_sqldb *db)
{
    return flb_lock_release(&db->lock,
                            FLB_LOCK_INFINITE_RETRY_LIMIT,
                            FLB_LOCK_DEFAULT_RETRY_DELAY);
}
