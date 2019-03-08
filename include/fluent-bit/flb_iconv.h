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

#ifndef FLB_ICONV_H
#define FLB_ICONV_H

#include <iconv.h>


#define FLB_ICONV_SUCCESS      0
#define FLB_ICONV_NOT_CHANGED  1
#define FLB_ICONV_FAILURE      -1

#define FLB_ICONV_ACCEPT_NOT_CHANGED  0x01

struct flb_iconv {
    iconv_t conv;
};

struct flb_iconv *flb_iconv_open(char *to, char *from);

int flb_iconv_execute(struct flb_iconv *ic,
                      char *str, size_t slen,
                      char **result, size_t *result_len,
                      unsigned int flags);

void flb_iconv_close(struct flb_iconv *ic);

#endif
