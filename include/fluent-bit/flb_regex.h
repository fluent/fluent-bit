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

#ifndef FLB_REGEX_H
#define FLB_REGEX_H

#include <fluent-bit/flb_compat.h>

#include <stdlib.h>
#include <stddef.h>

#include <onigmo.h>

struct flb_regex {
    unsigned char *pattern;
    OnigRegex regex;
};

struct flb_regex_search {
    int last_pos;
    OnigRegion *region;
    unsigned char *str;
    void (*cb_match) (unsigned char *,          /* name  */
                      unsigned char *, size_t,  /* value */
                      void *);                  /* caller data */
    void *data;
};

int flb_regex_init();
struct flb_regex *flb_regex_create(unsigned char *pattern);
ssize_t flb_regex_do(struct flb_regex *r, unsigned char *str, size_t slen,
                     struct flb_regex_search *result);
int flb_regex_parse(struct flb_regex *r, struct flb_regex_search *result,
                    void (*cb_match) (unsigned char *,          /* name  */
                                      unsigned char *, size_t,  /* value */
                                      void *),                  /* caller data */
                    void *data);
int flb_regex_destroy(struct flb_regex *r);
void flb_regex_exit();

#endif
