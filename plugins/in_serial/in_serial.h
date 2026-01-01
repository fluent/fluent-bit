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

#ifndef FLB_IN_SERIAL
#define FLB_IN_SERIAL

#include <stdint.h>

#define SERIAL_BUFFER_SIZE   256
#define IN_SERIAL_COLLECT_SEC  1
#define IN_SERIAL_COLLECT_NSEC 0

static inline speed_t flb_serial_speed(int br)
{
    switch (br) {
    case 0:      return B0;
    case 50:     return B50;
    case 75:     return B75;
    case 110:    return B110;
    case 134:    return B134;
    case 150:    return B150;
    case 200:    return B200;
    case 300:    return B300;
    case 600:    return B600;
    case 1200:   return B1200;
    case 1800:   return B1800;
    case 2400:   return B2400;
    case 4800:   return B4800;
    case 9600:   return B9600;
    case 19200:  return B19200;
    case 38400:  return B38400;
    case 57600:  return B57600;
    case 115200: return B115200;
    case 230400: return B230400;
    default:     return B9600;
    };

    return 0;
}

int in_serial_start();


extern struct flb_input_plugin in_serial_plugin;

#endif
