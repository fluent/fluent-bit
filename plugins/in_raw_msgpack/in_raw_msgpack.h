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
 *
 *  Modified Work:
 *
 *  Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 *  This software product is a proprietary product of NVIDIA CORPORATION &
 *  AFFILIATES (the "Company") and all right, title, and interest in and to the
 *  software product, including all associated intellectual property rights, are
 *  and shall remain exclusively with the Company.
 *
 *  This software product is governed by the End User License Agreement
 *  provided with the software product.
 *
 */

#ifndef FLB_IN_RAW_MSGPACK_H
#define FLB_IN_RAW_MSGPACK_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>


typedef struct in_plugin_data_t {
    char * buffer_ptr;
    char * server_address;
} in_plugin_data_t;

typedef struct doorbell_msg_t {
    int   data_len;
    char* data_buf;
} doorbell_msg_t;

struct flb_raw_msgpack_config {
    // from 'stdin'
    // int  fd;
    int  coll_fd;
    // void* ptr;          // to point either to buffer or to shared memory

    int  buf_len;                     /* read buffer length    */
    char buf[8192 * 2];               /* read buffer: 16Kb max */
    struct flb_parser *parser;
    struct flb_pack_state pack_state;
    // ============

    char unix_sock_path[128];
    int sock_fd;
    // =================

    doorbell_msg_t msg;
    struct flb_input_instance *ins;
};

#endif  // FLB_IN_RAW_MSGPACK_H
