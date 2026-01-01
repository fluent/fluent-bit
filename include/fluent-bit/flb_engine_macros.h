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

#ifndef FLB_ENGINE_MACROS_H
#define FLB_ENGINE_MACROS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_bits.h>

/* Types of events handled by the Server engine */
#define FLB_ENGINE_EV_CORE          MK_EVENT_NOTIFICATION
#define FLB_ENGINE_EV_CUSTOM        MK_EVENT_CUSTOM

#define FLB_ENGINE_EV_THREAD        (1 << 10)                          /*  1024 */
#define FLB_ENGINE_EV_SCHED         (1 << 11)                          /*  2048 */
#define FLB_ENGINE_EV_SCHED_FRAME   (FLB_ENGINE_EV_SCHED | (1 << 12))  /*  2048 | 4096 = 6144  */
#define FLB_ENGINE_EV_SCHED_CORO    (1 << 13)                          /*  8192 */

#define FLB_ENGINE_EV_INPUT         (1 << 14)                          /*  16384 */
#define FLB_ENGINE_EV_THREAD_INPUT  (1 << 15)                          /*  32768 */

#define FLB_ENGINE_EV_OUTPUT        (1 << 16)                          /*  65536 */
#define FLB_ENGINE_EV_THREAD_OUTPUT (1 << 17)                          /* 131072 */
#define FLB_ENGINE_EV_THREAD_ENGINE (1 << 18)                          /* 262144 */

#define FLB_ENGINE_EV_NOTIFICATION  (1 << 19)                          /* 524288 */

/* Engine events: all engine events set the left 32 bits to '1' */
#define FLB_ENGINE_EV_STARTED   FLB_BITS_U64_SET(1, 1) /* Engine started    */
#define FLB_ENGINE_EV_FAILED    FLB_BITS_U64_SET(1, 2) /* Engine started    */
#define FLB_ENGINE_EV_STOP      FLB_BITS_U64_SET(1, 3) /* Requested to stop */
#define FLB_ENGINE_EV_SHUTDOWN  FLB_BITS_U64_SET(1, 4) /* Engine shutdown   */

/* Similar to engine events, but used as return values */
#define FLB_ENGINE_STARTED      FLB_BITS_U64_LOW(FLB_ENGINE_EV_STARTED)
#define FLB_ENGINE_FAILED       FLB_BITS_U64_LOW(FLB_ENGINE_EV_FAILED)
#define FLB_ENGINE_STOP         FLB_BITS_U64_LOW(FLB_ENGINE_EV_STOP)
#define FLB_ENGINE_SHUTDOWN     FLB_BITS_U64_LOW(FLB_ENGINE_EV_SHUTDOWN)

/* Engine signals: Task, it only refer to the type */
#define FLB_ENGINE_TASK         2
#define FLB_ENGINE_IN_CORO      3

/* Engine priority queue configuration */
#define FLB_ENGINE_LOOP_MAX_ITER        10 /* Max events processed per round */

/* Engine event priorities: min value prioritized */
#define FLB_ENGINE_PRIORITY_DEFAULT     MK_EVENT_PRIORITY_DEFAULT
#define FLB_ENGINE_PRIORITY_COUNT       8
#define FLB_ENGINE_PRIORITY_TOP         0
#define FLB_ENGINE_PRIORITY_BOTTOM      (FLB_ENGINE_PRIORITY_COUNT - 1)
#define FLB_ENGINE_PRIORITY_NETWORK     1

#define FLB_ENGINE_PRIORITY_CB_SCHED    FLB_ENGINE_PRIORITY_TOP
#define FLB_ENGINE_PRIORITY_CB_TIMER    FLB_ENGINE_PRIORITY_TOP
#define FLB_ENGINE_PRIORITY_SHUTDOWN    FLB_ENGINE_PRIORITY_TOP
#define FLB_ENGINE_PRIORITY_FLUSH       (FLB_ENGINE_PRIORITY_NETWORK + 1)

#define FLB_ENGINE_PRIORITY_DNS         FLB_ENGINE_PRIORITY_NETWORK
#define FLB_ENGINE_PRIORITY_CONNECT     FLB_ENGINE_PRIORITY_NETWORK
#define FLB_ENGINE_PRIORITY_SEND_RECV   FLB_ENGINE_PRIORITY_NETWORK

#define FLB_ENGINE_PRIORITY_THREAD      FLB_ENGINE_PRIORITY_DEFAULT

#endif