/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>

#include <xbee.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <msgpack.h>

#include "in_xbee.h"
#include "in_xbee_config.h"

int in_xbee_conAddress2str(char *buf, int size, struct xbee_conAddress *addr) {
    int addr_len;
    int i;
    int len;
    char *src;

    if (size < 1)
        return -1;

    *buf = 0;

    if (addr->addr64_enabled) {
        addr_len = 8;
        src = (char*) &addr->addr64;
    } else if (addr->addr16_enabled) {
        addr_len = 1;
        src = (char*) &addr->addr16;
    } else {
        flb_error("xbee_conAddress has no address data?\n");
        return 0;
    }

   len = 0;
   for (i = 0; i < addr_len; i++) {
       snprintf(buf + len, size - len, "%2.2x", *(src + i));
       len += 2;
   }

   return 1;
}
