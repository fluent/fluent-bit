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

#ifndef FLB_ENCODING_H
#define FLB_ENCODING_H

#include <tutf8e.h>


#define FLB_ENCODING_SUCCESS      0
#define FLB_ENCODING_FAILURE     -1

struct flb_encoding {
    TUTF8encoder encoder;
    const char *invalid;
};

struct flb_encoding *flb_encoding_open(const char *encoding);

int flb_encoding_decode(struct flb_encoding *ec,
                        char *str, size_t slen,
                        char **result, size_t *result_len);

void flb_encoding_close(struct flb_encoding *ic);

#endif
