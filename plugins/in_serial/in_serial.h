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

#ifndef FLB_IN_SERIAL
#define FLB_IN_SERIAL

#include <stdint.h>

#define SERIAL_BUFFER_SIZE   256
#define IN_SERIAL_COLLECT_SEC  1
#define IN_SERIAL_COLLECT_NSEC 0

int in_serial_start();

extern struct flb_input_plugin in_serial_plugin;

#endif
