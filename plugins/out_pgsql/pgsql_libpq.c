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
#ifndef FLB_SYSTEM_WINDOWS
#include <dlfcn.h>
#endif

#include "pgsql.h"

#ifdef FLB_SYSTEM_WINDOWS
#define FLB_PGSQL_LIBRARY "libpq.dll"
#define FLB_PGSQL_LOAD_FLAGS RTLD_LAZY
#elif defined(__APPLE__)
#define FLB_PGSQL_LIBRARY "libpq.5.dylib"
#define FLB_PGSQL_LOAD_FLAGS (RTLD_NOW | RTLD_LOCAL)
#else
#define FLB_PGSQL_LIBRARY "libpq.so.5"
#define FLB_PGSQL_LOAD_FLAGS (RTLD_NOW | RTLD_LOCAL)
#endif

/* Resolve every entry before any connection can use the library. */
#define PGSQL_LOAD_SYMBOL(name)                                                   \
    do {                                                                          \
        symbol = dlsym(ctx->pq.handle, #name);                                     \
        if (symbol == NULL) {                                                     \
            flb_plg_error(ctx->ins, "libpq '%s' is missing symbol %s: %s",          \
                          path, #name, dlerror());                                \
            pgsql_libpq_close(ctx);                                               \
            return -1;                                                            \
        }                                                                         \
        memcpy(&ctx->pq.name, &symbol, sizeof(ctx->pq.name));                       \
    } while (0)

int pgsql_libpq_open(struct flb_pgsql_config *ctx, const char *path)
{
    void *symbol;

    if (path == NULL) {
        path = FLB_PGSQL_LIBRARY;
    }
    if (path[0] == '\0') {
        flb_plg_error(ctx->ins, "libpq_path must not be empty");
        return -1;
    }

    ctx->pq.handle = dlopen(path, FLB_PGSQL_LOAD_FLAGS);
    if (ctx->pq.handle == NULL) {
        flb_plg_error(ctx->ins, "cannot load libpq '%s': %s", path, dlerror());
        return -1;
    }

    PGSQL_LOAD_SYMBOL(PQsetdbLogin);
    PGSQL_LOAD_SYMBOL(PQstatus);
    PGSQL_LOAD_SYMBOL(PQconsumeInput);
    PGSQL_LOAD_SYMBOL(PQgetResult);
    PGSQL_LOAD_SYMBOL(PQresultStatus);
    PGSQL_LOAD_SYMBOL(PQerrorMessage);
    PGSQL_LOAD_SYMBOL(PQclear);
    PGSQL_LOAD_SYMBOL(PQfinish);
    PGSQL_LOAD_SYMBOL(PQsetnonblocking);
    PGSQL_LOAD_SYMBOL(PQisBusy);
    PGSQL_LOAD_SYMBOL(PQescapeIdentifier);
    PGSQL_LOAD_SYMBOL(PQescapeLiteral);
    PGSQL_LOAD_SYMBOL(PQfreemem);
    PGSQL_LOAD_SYMBOL(PQexec);
    PGSQL_LOAD_SYMBOL(PQreset);
    PGSQL_LOAD_SYMBOL(PQsendQuery);
    PGSQL_LOAD_SYMBOL(PQflush);

    flb_plg_debug(ctx->ins, "loaded libpq '%s'", path);
    return 0;
}

void pgsql_libpq_close(struct flb_pgsql_config *ctx)
{
    if (ctx->pq.handle != NULL) {
        dlclose(ctx->pq.handle);
        memset(&ctx->pq, 0, sizeof(ctx->pq));
    }
}
