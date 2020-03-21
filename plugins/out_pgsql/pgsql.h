/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef FLB_OUT_PGSQL_H
#define FLB_OUT_PGSQL_H

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_time.h>

#include <libpq-fe.h>

#define FLB_PGSQL_HOST "127.0.0.1"
#define FLB_PGSQL_PORT 5432
#define FLB_PGSQL_DBNAME "fluentbit"
#define FLB_PGSQL_TABLE "fluentbit"
#define FLB_PGSQL_TIMESTAMP_KEY "date"

struct flb_pgsql_config {

    /* database */
    char *db_hostname;
    char db_port[8];
    const char *db_name;
    flb_sds_t db_table;

    /* auth */
    const char *db_user;
    const char *db_passwd;

    /* pgconn, params, etc */
    PGconn *conn;

    /* time key */
    flb_sds_t timestamp_key;
};

#endif
