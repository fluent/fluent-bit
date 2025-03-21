/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MK_HTTP2_SETTINGS_H
#define MK_HTTP2_SETTINGS_H

struct mk_http2_settings {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
};


const struct mk_http2_settings MK_HTTP2_SETTINGS_DEFAULT =
    {
        .header_table_size      = 4096,
        .enable_push            = 1,
        .max_concurrent_streams = 64,
        .initial_window_size    = 65535,
        .max_frame_size         = 16384, /* 6.5.2 -> 2^14 */
        .max_header_list_size   = UINT32_MAX
    };

/*
 * Default settings of Monkey, we send this upon a new connection arrives
 * to the HTTP/2 handler.
 */
#define MK_HTTP2_SETTINGS_DEFAULT_FRAME                 \
    "\x00\x00\x0c"       /* frame length     */         \
    "\x04"               /* type=SETTINGS    */         \
    "\x00"               /* flags            */         \
    "\x00\x00\x00\x00"   /* stream ID        */         \
                                                        \
    /* SETTINGS_MAX_CONCURRENT_STREAMS  */              \
    "\x00\x03"                                          \
    "\x00\x00\x00\x40"   /* value=64    */              \
                                                        \
    /* SETTINGS_INITIAL_WINDOW_SIZE     */              \
    "\x00\x04"                                          \
    "\x00\x00\xff\xff"   /* value=65535 */

#define MK_HTTP2_SETTINGS_ACK_FRAME             \
    "\x00\x00\x00\x04\x01\x00\x00\x00\x00"

#define MK_HTTP2_SETTINGS_HEADER_TABLE_SIZE       0x1
#define MK_HTTP2_SETTINGS_ENABLE_PUSH             0x2
#define MK_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS  0x3
#define MK_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE     0x4
#define MK_HTTP2_SETTINGS_MAX_FRAME_SIZE          0x5
#define MK_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE    0x6

#endif
