/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Serial input plugin for Fluent Bit
 *  ==================================
 *  Copyright (C) 2015 Takeshi HASEGAWA
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

#ifndef FLB_IN_SERIAL_CONFIG_H
#define FLB_IN_SERIAL_CONFIG_H

#include <termios.h>
#include <msgpack.h>

struct flb_in_serial_config {
    int fd;           /* Socket to destination/backend */

    char *file;
    char *bitrate;

    struct termios tio;
    struct termios tio_orig;

    /* Tag: used to extend original tag */
    int  tag_len;              /* The real string length     */
    char tag[32];              /* Custom Tag for this input  */

    /* Line processing */
    int buffer_id;

    /* MessagePack buffers */
    msgpack_packer  mp_pck;
    msgpack_sbuffer mp_sbuf;
};

struct flb_in_serial_config *serial_config_read(struct flb_in_serial_config *config,
                                                struct mk_rconf *conf);
#endif
