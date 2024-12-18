/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>

struct flb_router_path {
    struct flb_output_instance *ins;
    struct mk_list _head;
};

static inline int flb_router_match_type(int in_event_type,
                                        struct flb_output_instance *o_ins)
{
    if (in_event_type == FLB_INPUT_LOGS &&
        !(o_ins->event_type & FLB_OUTPUT_LOGS)) {
        return FLB_FALSE;
    }
    else if (in_event_type == FLB_INPUT_METRICS &&
             !(o_ins->event_type & FLB_OUTPUT_METRICS)) {
        return FLB_FALSE;
    }
    else if (in_event_type == FLB_INPUT_TRACES &&
             !(o_ins->event_type & FLB_OUTPUT_TRACES)) {
        return FLB_FALSE;
    }
    else if (in_event_type == FLB_INPUT_PROFILES &&
             !(o_ins->event_type & FLB_OUTPUT_PROFILES)) {
        return FLB_FALSE;
    }
    else if (in_event_type == FLB_INPUT_BLOBS &&
             !(o_ins->event_type & FLB_OUTPUT_BLOBS)) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int flb_router_connect(struct flb_input_instance *in,
                       struct flb_output_instance *out);
int flb_router_connect_direct(struct flb_input_instance *in,
                              struct flb_output_instance *out);

int flb_router_match(const char *tag, int tag_len,
                     const char *match, void *match_regex);
int flb_router_io_set(struct flb_config *config);
void flb_router_exit(struct flb_config *config);
#endif
