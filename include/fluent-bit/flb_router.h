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

#ifndef FLB_ROUTER_H
#define FLB_ROUTER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>

struct flb_router_path {
    struct flb_output_instance *ins;
    struct mk_list _head;
};

#ifdef FLB_HAVE_REGEX
#include <fluent-bit/flb_regex.h>
int flb_router_match(const char *tag, int tag_len,
                     const char *match, struct flb_regex *match_regex);
#else
int flb_router_match(const char *tag, int tag_len, const char *match);
#endif
int flb_router_io_set(struct flb_config *config);
void flb_router_exit(struct flb_config *config);

#endif
