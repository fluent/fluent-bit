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

#ifndef FLB_IN_XBEE
#define FLB_IN_XBEE

#define FLB_XBEE_DEFAULT_DEVICE    "/dev/ttyUSB0"
#define FLB_XBEE_DEFAULT_BAUDRATE  9600

#define IN_XBEE_COLLECT_SEC    0
#define IN_XBEE_COLLECT_NSEC   1000

struct flb_in_xbee_config {
    int  baudrate;
    char *device;
};

extern struct flb_input_plugin in_xbee_plugin;

#endif
