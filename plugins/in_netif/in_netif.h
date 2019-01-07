/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_IN_NETIF_H
#define FLB_IN_NETIF_H

#include <stdint.h>
#include <unistd.h>
#include <fluent-bit/flb_input.h>
#include <msgpack.h>

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0

#define FLB_IN_NETIF_NAME "in_netif"

struct entry_define
{
    char  *name;
    int   checked;
};

struct netif_entry {
    int   checked;

    char  *name;
    int   name_len;

    uint64_t prev;
    uint64_t now;
};

struct flb_in_netif_config {
    char *interface;
    int  interface_len;

    int  verbose;
    int  first_snapshot;   /* a feild to indicate whethor or not this is the first collect */

    struct netif_entry *entry;
    int entry_len;

    int map_num;
};

extern struct flb_input_plugin in_netif_plugin;

#endif /*FLB_IN_NETIF_H*/
