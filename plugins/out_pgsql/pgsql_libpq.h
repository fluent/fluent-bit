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

#ifndef FLB_OUT_PGSQL_LIBPQ_H
#define FLB_OUT_PGSQL_LIBPQ_H

#include <libpq-fe.h>

struct flb_pgsql_libpq {
    void *handle;
    PGconn *(*PQsetdbLogin)(const char *, const char *, const char *, const char *,
                          const char *, const char *, const char *);
    ConnStatusType (*PQstatus)(const PGconn *);
    int (*PQconsumeInput)(PGconn *);
    PGresult *(*PQgetResult)(PGconn *);
    ExecStatusType (*PQresultStatus)(const PGresult *);
    char *(*PQerrorMessage)(const PGconn *);
    void (*PQclear)(PGresult *);
    void (*PQfinish)(PGconn *);
    int (*PQsetnonblocking)(PGconn *, int);
    int (*PQisBusy)(PGconn *);
    char *(*PQescapeIdentifier)(PGconn *, const char *, size_t);
    char *(*PQescapeLiteral)(PGconn *, const char *, size_t);
    void (*PQfreemem)(void *);
    PGresult *(*PQexec)(PGconn *, const char *);
    void (*PQreset)(PGconn *);
    int (*PQsendQuery)(PGconn *, const char *);
    int (*PQflush)(PGconn *);
};

struct flb_pgsql_config;
int pgsql_libpq_open(struct flb_pgsql_config *ctx, const char *path);
void pgsql_libpq_close(struct flb_pgsql_config *ctx);

#endif
