/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Serial input plugin for Fluent Bit
 *  ==================================
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *  Copyright (C) 2015-2016 Takeshi HASEGAWA
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

#define FLB_SERIAL_FORMAT_NONE 0
#define FLB_SERIAL_FORMAT_JSON 1

#include <termios.h>
#include <msgpack.h>

#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>

struct flb_in_serial_config {
    int fd;           /* Socket to destination/backend */

    /* Buffer */
    int buf_len;
    char buf_data[8192];

    /* config */
    int min_bytes;
    flb_sds_t file;
    flb_sds_t bitrate;

    /* separator */
    int sep_len;
    flb_sds_t separator;

    /* Incoming format: JSON only for now */
    int format;
    flb_sds_t format_str;

    struct termios tio;
    struct termios tio_orig;

    /* Tag: used to extend original tag */
    int  tag_len;              /* The real string length     */
    char tag[32];              /* Custom Tag for this input  */

    /* Line processing */
    int buffer_id;

    /* Input instance reference */
    struct flb_input_instance *i_ins;
    struct flb_log_event_encoder *log_encoder;

    /*
     * If (format == FLB_SERIAL_FORMAT_JSON), we use this pack_state
     * to perform validation of the incomming JSON message.
     */
    struct flb_pack_state pack_state;
};

struct flb_in_serial_config *serial_config_read(struct flb_in_serial_config *config,
                                                struct flb_input_instance *i_ins);

#endif
