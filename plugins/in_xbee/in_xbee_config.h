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

#ifndef FLB_IN_XBEE_CONFIG_H
#define FLB_IN_XBEE_CONFIG_H

#include <mk_core/mk_core.h>
#include <termios.h>
#include <msgpack.h>

#define FLB_XBEE_BUFFER_SIZE       128

struct flb_in_xbee_config {
    int fd;           /* Socket to destination/backend */

    char *file;
    char *bitrate;

    /* Tag: used to extend original tag */
    int  tag_len;              /* The real string length     */
    char tag[32];              /* Custom Tag for this input  */

    /* XBee setup */
    int  baudrate;
    char *device;
    int xbeeLogLevel;

    /* Active connection context */
    struct xbee_con *con;

    /* buffering */
    int buffer_len;

    /* MessagePack buffers */
    msgpack_packer  mp_pck;
    msgpack_sbuffer mp_sbuf;
    int buffer_id;
};


#endif
