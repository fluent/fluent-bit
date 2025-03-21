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

#ifndef MK_RCONF_H
#define MK_RCONF_H

#include <limits.h>

#include "mk_list.h"
#include "mk_memory.h"

#define MK_RCONF_ON         "on"
#define MK_RCONF_OFF        "off"

#define MK_RCONF_STR        0
#define MK_RCONF_NUM        1
#define MK_RCONF_BOOL       2
#define MK_RCONF_LIST       3

/* default buffer size when reading a configuration line */
#define MK_RCONF_KV_SIZE    4096

struct mk_rconf_section
{
    char *name;

    struct mk_list entries;
    struct mk_list _head;
};

struct mk_rconf_entry
{
    char *key;
    char *val;

    struct mk_list _head;
};

struct mk_rconf_file
{
    char *path;
    struct mk_list _head;
};


struct mk_rconf
{
    int level;
    int created;
    char *file;
    char *root_path;

    /* included files */
    struct mk_list includes;

    /* meta instructions */
    struct mk_list metas;

    /* list of sections */
    struct mk_list sections;
};

void mk_rconf_free(struct mk_rconf *conf);
void mk_rconf_free_entries(struct mk_rconf_section *section);

struct mk_rconf *mk_rconf_open(const char *path);
struct mk_rconf *mk_rconf_create(const char *path);
struct mk_rconf_section *mk_rconf_section_add(struct mk_rconf *conf,
                                              char *name);
struct mk_rconf_section *mk_rconf_section_get(struct mk_rconf *conf,
                                              const char *name);
void *mk_rconf_section_get_key(struct mk_rconf_section *section,
                               char *key, int mode);
char *mk_rconf_meta_get(struct mk_rconf *conf, char *key);

#endif
