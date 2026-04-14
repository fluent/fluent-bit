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

#ifndef FLB_IN_PROMETHEUS_TEXTFILE_H
#define FLB_IN_PROMETHEUS_TEXTFILE_H

#include <fluent-bit/flb_input_plugin.h>

struct prom_textfile {
    int coll_fd;                     /* collector id */
    uint64_t scrape_interval;        /* collection interval */
    struct mk_list *path_list;       /* list of paths */
    struct flb_input_instance *ins;  /* plugin instance */
};

#endif
