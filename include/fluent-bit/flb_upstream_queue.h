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

#ifndef FLB_UPSTREAM_QUEUE_H
#define FLB_UPSTREAM_QUEUE_H

#include <fluent-bit/flb_info.h>

struct flb_upstream_queue {
    /*
     * This field is a linked-list-head for upstream connections that
     * are available for usage. When a connection is taken, it's moved to the
     * 'busy_queue' list.
     */
    struct mk_list av_queue;

    /*
     * Linked list head for upstream connections that are in use by some
     * plugin. When released, they are moved to the 'av_queue' list.
     */
    struct mk_list busy_queue;

    /*
     * Ready to destroy connections are linked here, mostly because they are
     * not yet destroyed but will be destroyed in a later step of the event loop
     * to avoid any race condition with a late event.
     */
    struct mk_list destroy_queue;
};

#endif
