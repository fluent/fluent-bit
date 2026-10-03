/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2020 The Fluent Bit Authors
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

#ifndef FLB_OUT_PGSQL_LOADLIB_H
#define FLB_OUT_PGSQL_LOADLIB_H

#include <fluent-bit/flb_output.h>

HMODULE pqDll;

typedef enum
{
    CONNECTION_OK,
    CONNECTION_BAD,
    /* Non-blocking mode only below here */

    /*
     * The existence of these should never be relied upon - they should only
     * be used for user feedback or similar purposes.
     */
    CONNECTION_STARTED,         /* Waiting for connection to be made.  */
    CONNECTION_MADE,            /* Connection OK; waiting to send.     */
    CONNECTION_AWAITING_RESPONSE,   /* Waiting for a response from the postmaster.        */
    CONNECTION_AUTH_OK,         /* Received authentication; waiting for backend startup. */
    CONNECTION_SETENV,          /* This state is no longer used. */
    CONNECTION_SSL_STARTUP,     /* Negotiating SSL. */
    CONNECTION_NEEDED,          /* Internal state: connect() needed */
    CONNECTION_CHECK_WRITABLE,  /* Checking if session is read-write. */
    CONNECTION_CONSUME,         /* Consuming any extra messages. */
    CONNECTION_GSS_STARTUP,     /* Negotiating GSSAPI. */
    CONNECTION_CHECK_TARGET,    /* Checking target server properties. */
    CONNECTION_CHECK_STANDBY    /* Checking if server is in standby mode. */
} ConnStatusType;

typedef enum
{
    PGRES_EMPTY_QUERY = 0,      /* empty query string was executed */
    PGRES_COMMAND_OK,           /* a query command that doesn't return anything was executed properly by the backend */
    PGRES_TUPLES_OK,            /* a query command that returns tuples was executed properly by the backend, PGresult contains the result tuples */
    PGRES_COPY_OUT,             /* Copy Out data transfer in progress */
    PGRES_COPY_IN,              /* Copy In data transfer in progress */
    PGRES_BAD_RESPONSE,         /* an unexpected response was recv'd from the backend */
    PGRES_NONFATAL_ERROR,       /* notice or warning message */
    PGRES_FATAL_ERROR,          /* query failed */
    PGRES_COPY_BOTH,            /* Copy In/Out data transfer in progress */
    PGRES_SINGLE_TUPLE,         /* single tuple from larger resultset */
    PGRES_PIPELINE_SYNC,        /* pipeline synchronization point */
    PGRES_PIPELINE_ABORTED      /* Command didn't run because of an abort
                                                                                                                        * earlier in a pipeline */
} ExecStatusType;

typedef struct pg_result PGresult;
typedef struct pg_conn PGconn;

// Declare all symbols loaded from pqlib.dll

typedef int (*PQconsumeInputP)(PGconn *);
PQconsumeInputP PQconsumeInput;

typedef ConnStatusType (*PQstatusP)(const PGconn *);
PQstatusP PQstatus;

typedef PGresult* (*PQgetResultP)(PGconn *);
PQgetResultP PQgetResult;

typedef ExecStatusType (*PQresultStatusP)(const PGresult *);
PQresultStatusP PQresultStatus;

typedef char* (*PQerrorMessageP)(const PGconn *);
PQerrorMessageP PQerrorMessage;

typedef void (*PQclearP)(PGresult*);
PQclearP PQclear;

typedef void (*PQfinishP)(PGconn*);
PQfinishP PQfinish;

typedef PGconn* (*PQsetdbLoginP)(const char*, const char*, const char*, const char*, const char*, const char*, const char*);
PQsetdbLoginP PQsetdbLogin;

typedef int (*PQsetnonblockingP)(PGconn*, int);
PQsetnonblockingP PQsetnonblocking;

typedef int (*PQisBusyP)(PGconn*);
PQisBusyP PQisBusy;

typedef char* (*PQescapeIdentifierP)(PGconn*, const char*, size_t);
PQescapeIdentifierP PQescapeIdentifier;

typedef void (*PQfreememP)(void*);
PQfreememP PQfreemem;

typedef PGresult* (*PQexecP)(PGconn*, const char*);
PQexecP PQexec;

typedef void (*PQresetP)(PGconn*);
PQresetP PQreset;

typedef char* (*PQescapeLiteralP)(PGconn*, const char*, size_t);
PQescapeLiteralP PQescapeLiteral;

typedef int (*PQsendQueryP)(PGconn*, const char*);
PQsendQueryP PQsendQuery;

typedef int (*PQflushP)(PGconn*);
PQflushP PQflush;

int loadPqDll(struct flb_output_instance* ins);
void freePqDll(void);

#endif
