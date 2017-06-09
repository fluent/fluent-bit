/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#ifndef FLB_SYSTEMD_CONFIG_H
#define FLB_SYSTEMD_CONFIG_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>

#include <systemd/sd-journal.h>

#define FLB_SYSTEMD_UNIT     "_SYSTEMD_UNIT"
#define FLB_SYSTEMD_UNKNOWN  "unknown"
#define FLB_SYSTEND_ENTRIES  5000

/* Input configuration & context */
struct flb_systemd_config {
    /* Journal */
    int fd;          /* Journal file descriptor */
    sd_journal *j;   /* Journal context */

    /* Internal */
    int coll_fd_journal;
    int dynamic_tag;
    int max_entries;
    struct mk_list filters;
    struct flb_input_instance *i_ins;
};

struct flb_systemd_config *flb_systemd_config_create(struct flb_input_instance *i_ins,
                                                     struct flb_config *config);

int flb_systemd_config_destroy(struct flb_systemd_config *ctx);
#endif
