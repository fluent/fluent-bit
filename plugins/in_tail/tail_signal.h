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

#ifndef FLB_TAIL_SIGNAL_H
#define FLB_TAIL_SIGNAL_H

#include "tail_config.h"
#include <unistd.h>

static inline int tail_signal_manager(struct flb_tail_config *ctx)
{
    int n;
    uint64_t val = 0xc001;

    /* Insert a dummy event into the channel manager */
    n = write(ctx->ch_manager[1], &val, sizeof(val));
    if (n == -1) {
        flb_errno();
        return -1;
    }

    return n;
}

static inline int tail_signal_pending(struct flb_tail_config *ctx)
{
    int n;
    uint64_t val = 0xc002;

    /* Insert a dummy event into the 'pending' channel */
    n = write(ctx->ch_pending[1], &val, sizeof(val));
    if (n == -1) {
        flb_errno();
        return -1;
    }

    return n;
}

#endif
