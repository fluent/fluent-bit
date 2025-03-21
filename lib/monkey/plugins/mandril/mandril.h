/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
 *  Copyright 2012, Sonny Karlsson
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

/* security.c */
#ifndef MK_SECURITY_H
#define MK_SECURITY_H

struct mk_secure_ip_t
{
    struct in_addr ip;

    /* if subnet is true, next fields are populated */
    int is_subnet;

    int network;
    int netmask;
    unsigned int hostmin;
    unsigned int hostmax;

    /* list head linker */
    struct mk_list _head;
};

struct mk_secure_url_t
{
    char *criteria;
    struct mk_list _head;
};

struct mk_secure_deny_hotlink_t
{
    char *criteria;
    struct mk_list _head;
};

struct mk_list mk_secure_ip;
struct mk_list mk_secure_url;
struct mk_list mk_secure_deny_hotlink;

#endif
