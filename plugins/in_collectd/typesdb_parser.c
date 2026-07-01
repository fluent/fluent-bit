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

/*
 * This file implements a collectd 5.x compatible parser for types.db(5).
 *
 * Note: it internally implements a finite state machine that consumes a
 * single char at once, and pushes parsed tokens via typesdb_* methods.
 */

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>

#include "typesdb.h"
#include "typesdb_parser.h"

#define TDB_INVALID   -1
#define TDB_INIT       0
#define TDB_LEFT       1
#define TDB_SEP        2
#define TDB_RIGHT      3
#define TDB_RIGHT_SEP  4
#define TDB_COMMENT    5

/* See collectd/src/daemon/types_list.c */
#define MAX_LINE_SIZE 4096

/*
 * tdb_* are state functions that take a single character as input.
 * They do some action based on the input and return the next state.
 */
static int tdb_init(char c, struct mk_list *tdb, char *buf)
{
    switch (c) {
        case '#':
            return TDB_COMMENT;
        case '\r':
        case '\n':
            return TDB_INIT;
        default:
            buf[0] = c;
            buf[1] = '\0';
            return TDB_LEFT;
    }
}

static int tdb_left(char c, struct mk_list *tdb, char *buf)
{
    int len;

    switch (c) {
        case ' ':
            if (typesdb_add_node(tdb, buf)) {
                return TDB_INVALID;
            }
            return TDB_SEP;
        case '\r':
        case '\n':
            return TDB_INVALID;
        default:
            len = strlen(buf);
            if (len >= MAX_LINE_SIZE - 1) {
                return TDB_INVALID;
            }
            buf[len] = c;
            buf[++len] = '\0';
            return TDB_LEFT;
    }
}

static int tdb_sep(char c, struct mk_list *tdb, char *buf)
{
    switch (c) {
        case ' ':
            return TDB_SEP;
        case '\r':
        case '\n':
            return TDB_INVALID;
        default:
            buf[0] = c;
            buf[1] = '\0';
            return TDB_RIGHT;
    }
}

static int tdb_right(char c, struct mk_list *tdb, char *buf)
{
    int len;
    struct typesdb_node *node = typesdb_last_node(tdb);

    switch (c) {
        case ' ':
        case ',':
            if (typesdb_add_field(node, buf)) {
                flb_error("[in_collectd] cannot add value '%s'", buf);
                return TDB_INVALID;
            }
            return TDB_RIGHT_SEP;
        case '\r':
        case '\n':
            if (typesdb_add_field(node, buf)) {
                flb_error("[in_collectd] cannot add value '%s'", buf);
                return TDB_INVALID;
            }
            return TDB_INIT;
        default:
            len = strlen(buf);
            if (len >= MAX_LINE_SIZE - 1) {
                flb_error("[in_collectd] line too long > %i", MAX_LINE_SIZE);
                return TDB_INVALID;
            }
            buf[len] = c;
            buf[++len] = '\0';
            return TDB_RIGHT;
    }
}

static int tdb_right_sep(char c,  struct mk_list *tdb, char *buf)
{
    switch (c) {
        case ' ':
        case ',':
            return TDB_RIGHT_SEP;
        case '\r':
        case '\n':
            return TDB_INIT;
        default:
            buf[0] = c;
            buf[1] = '\0';
            return TDB_RIGHT;
    }
}

static int tdb_comment(char c, struct mk_list *tdb, char *buf)
{
    switch (c) {
        case '\r':
        case '\n':
            return TDB_INIT;
        default:
            return TDB_COMMENT;
    }
}

/*
 * Entry point function
 */
int typesdb_parse(struct mk_list *tdb, int fp)
{
    char tmp[1024];
    char buf[MAX_LINE_SIZE];
    char c;
    int i;
    int bytes;
    int state = TDB_INIT;

    while (1) {
        bytes = read(fp, tmp, 1024);
        if (bytes < 0) {
            flb_errno();
            return bytes;
        }
        if (bytes == 0) {
            return 0;
        }
        for (i = 0; i < bytes; i++) {
            c = tmp[i];
            switch (state) {
                case TDB_INVALID:
                    return -1;
                case TDB_INIT:
                    state = tdb_init(c, tdb, buf);
                    break;
                case TDB_LEFT:
                    state = tdb_left(c, tdb, buf);
                    break;
                case TDB_SEP:
                    state = tdb_sep(c, tdb, buf);
                    break;
                case TDB_RIGHT:
                    state = tdb_right(c, tdb, buf);
                    break;
                case TDB_RIGHT_SEP:
                    state = tdb_right_sep(c, tdb, buf);
                    break;
                case TDB_COMMENT:
                    state = tdb_comment(c, tdb, buf);
                    break;
                default:
                    flb_error("[in_collectd] unknown state %i", state);
                    return -1;
            }
        }
    }
    return 0;
}
