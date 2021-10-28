/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef FLB_OUT_COLLECTX
#define FLB_OUT_COLLECTX


#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>

// typedef int (*clx_callback_t)(const void *, const void *, size_t);

typedef struct ipc_msg_t {
    uint64_t data_size;
    char*    buffer_addr;
    char*    tag;
    int      status;  // -1 for retry, 0 for success, 1 for progressing
} ipc_msg_t;

struct flb_collectx {
    char*                       collector_sock_name;
    int                         fluent_aggr_sock_fd;

    void*                       fluent_aggr_provider;
    struct flb_output_instance *ins;  // pointer to the plugin info
                                      // ins->data can be used for user parameters
};


#endif  // FLB_OUT_COLLECTX
