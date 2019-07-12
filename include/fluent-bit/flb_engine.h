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

#ifndef FLB_ENGINE_H
#define FLB_ENGINE_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_bits.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>

/* Types of events handled by the Server engine */
#define FLB_ENGINE_EV_CORE          MK_EVENT_NOTIFICATION
#define FLB_ENGINE_EV_CUSTOM        MK_EVENT_CUSTOM
#define FLB_ENGINE_EV_THREAD        1024
#define FLB_ENGINE_EV_SCHED         2048
#define FLB_ENGINE_EV_SCHED_FRAME   (FLB_ENGINE_EV_SCHED + 4096)

/* Engine events: all engine events set the left 32 bits to '1' */
#define FLB_ENGINE_EV_STARTED   FLB_BITS_U64_SET(1, 1) /* Engine started    */
#define FLB_ENGINE_EV_FAILED    FLB_BITS_U64_SET(1, 2) /* Engine started    */
#define FLB_ENGINE_EV_STOP      FLB_BITS_U64_SET(1, 3) /* Requested to stop */
#define FLB_ENGINE_EV_SHUTDOWN  FLB_BITS_U64_SET(1, 4) /* Engine shutdown   */
#define FLB_ENGINE_EV_STATS     FLB_BITS_U64_SET(1, 5) /* Collect stats     */

/* Similar to engine events, but used as return values */
#define FLB_ENGINE_STARTED      FLB_BITS_U64_LOW(FLB_ENGINE_EV_STARTED)
#define FLB_ENGINE_FAILED       FLB_BITS_U64_LOW(FLB_ENGINE_EV_FAILED)
#define FLB_ENGINE_STOP         FLB_BITS_U64_LOW(FLB_ENGINE_EV_STOP)
#define FLB_ENGINE_SHUTDOWN     FLB_BITS_U64_LOW(FLB_ENGINE_EV_SHUTDOWN)
#define FLB_ENGINE_STATS        FLB_BITS_U64_LOW(FLB_ENGINE_EV_STATS)

/* Engine signals: Task, it only refer to the type */
#define FLB_ENGINE_TASK         2
#define FLB_ENGINE_IN_THREAD    3

int flb_engine_start(struct flb_config *config);
int flb_engine_failed(struct flb_config *config);
int flb_engine_flush(struct flb_config *config,
                     struct flb_input_plugin *in_force);
int flb_engine_exit(struct flb_config *config);
int flb_engine_shutdown(struct flb_config *config);
int flb_engine_destroy_tasks(struct mk_list *tasks);

#endif
