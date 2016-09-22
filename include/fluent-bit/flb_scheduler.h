/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#ifndef FLB_SCHEDULER_H
#define FLB_SCHEDULER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_output.h>

#define FLB_SCHED_CAP      2000
#define FLB_SCHED_BASE     5

struct flb_sched_request {
    struct mk_event event;
    int fd;
    time_t created;
    time_t timeout;
    void *data;
    struct mk_list _head;
};

int flb_sched_request_create(struct flb_config *config,
                             void *data, int tries);
int flb_sched_request_destroy(struct flb_config *config,
                              struct flb_sched_request *req);
int flb_sched_event_handler(struct flb_config *config, struct mk_event *event);
int flb_sched_exit(struct flb_config *config);

#endif
