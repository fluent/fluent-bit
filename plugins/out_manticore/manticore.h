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

#ifndef FLB_OUT_MANTICORE_H
#define FLB_OUT_MANTICORE_H

#include <fluent-bit/flb_sds.h>

#include <stdint.h>

#define FLB_MANTICORE_DEFAULT_PORT 9308
#define FLB_MANTICORE_BULK_URI     "/bulk"
#define FLB_MANTICORE_BULK_IMPORT_URI "/bulk?bulk_import="

enum manticore_mode {
    MANTICORE_MODE_REGULAR,
    MANTICORE_MODE_SHARED
};

struct flb_out_manticore {
    char *table;
    char *action;
    const char *bulk_action;
    char *http_user;
    char *http_passwd;
    char *mode;
    enum manticore_mode mode_type;
    int shared_indexers;
    /*
     * Shared load state: workers only ever set these flags, atomically since
     * they flush in parallel, and cb_exit reads them after every worker has
     * stopped. A worker that has not seen a failure yet may send one more
     * request; the load is not committed either way.
     */
    uint64_t session_failed;
    uint64_t session_started;
    flb_sds_t bulk_uri;
    flb_sds_t join_uri; /* Shared: bulk_uri plus shared_join */
    size_t buffer_size;
    struct flb_upstream *u;
    struct flb_output_instance *ins;
    struct flb_config *config;
};

#endif
