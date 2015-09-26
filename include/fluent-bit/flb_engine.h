/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>

/* Types of events handled by the Server engine */
#define FLB_ENGINE_EV_CORE      MK_EVENT_NOTIFICATION
#define FLB_ENGINE_EV_CUSTOM    MK_EVENT_CUSTOM
#define FLB_ENGINE_EV_THREAD    1024

/* Engine signals */
#define FLB_ENGINE_STARTED     0x00110aa0  /* Notify Fluent Bit started    */
#define FLB_ENGINE_STOP        0xdeadbeef  /* Requested to stop Fluent Bit */
#define FLB_ENGINE_SHUTDOWN    0xdead0000  /* Started shutdown phase       */
#define FLB_ENGINE_STATS       0xaabbccdd  /* Collect stats                */

int flb_engine_start(struct flb_config *config);
int flb_engine_flush(struct flb_config *config,
                     struct flb_input_plugin *in_force);
int flb_engine_shutdown(struct flb_config *config);

#endif
