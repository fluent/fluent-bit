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
 */

#ifndef FLB_SEARCH_BULK_H
#define FLB_SEARCH_BULK_H

#include <stddef.h>

#define FLB_SEARCH_BULK_COMPLETE  0
#define FLB_SEARCH_BULK_RETRY     1
#define FLB_SEARCH_BULK_INVALID  -1

#define FLB_SEARCH_BULK_ACK_CREATE_CONFLICTS  0
#define FLB_SEARCH_BULK_ACK_ALL_CONFLICTS     1

struct flb_search_bulk_retry {
    char *payload;
    size_t size;
    int records;
};

int flb_search_bulk_process_response(const char *response,
                                     size_t response_size,
                                     const char *payload,
                                     size_t payload_size,
                                     int acknowledge_all_conflicts,
                                     struct flb_search_bulk_retry **retry);
void flb_search_bulk_retry_destroy(void *data);

#endif
