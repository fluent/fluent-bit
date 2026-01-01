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

#ifndef FLB_CSV_H
#define FLB_CSV_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>

enum {
    FLB_CSV_SUCCESS = 0,
    FLB_CSV_ALLOC_FAILED = -1,
    FLB_CSV_INVALID_STATE = -2,
    FLB_CSV_EOF = -3,
};

typedef void (*flb_csv_field_parsed_callback)(void *data,
                                              const char *field,
                                              size_t field_len);

struct flb_csv_state {
    flb_csv_field_parsed_callback field_callback;
    flb_sds_t buffered_data;
    flb_sds_t escape_buffer;
    size_t offset;
    size_t start;
    size_t length;
    size_t field_count;
    int state;
    bool field_parsed;
    bool has_dquote;
    void *data;
};

void flb_csv_init(struct flb_csv_state *state,
                  flb_csv_field_parsed_callback field_callback,
                  void *data);

int flb_csv_parse_record(struct flb_csv_state *state,
                         char **bufptr,
                         size_t *buflen,
                         size_t *field_count);

void flb_csv_destroy(struct flb_csv_state *state);


#endif
