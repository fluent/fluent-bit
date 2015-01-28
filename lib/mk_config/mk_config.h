/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#ifndef MK_CONFIG_H
#define MK_CONFIG_H

#include <unistd.h>
#include <sys/types.h>

#include <mk_config/mk_list.h>

#define MK_FALSE   0
#define MK_TRUE    !MK_FALSE

#define MK_CONFIG_VAL_STR 0
#define MK_CONFIG_VAL_NUM 1
#define MK_CONFIG_VAL_BOOL 2
#define MK_CONFIG_VAL_LIST 3

#define MK_CONFIG_VAL_ON   "On"
#define MK_CONFIG_VAL_OFF  "Off"

/* Indented configuration */
struct mk_config
{
    int created;
    char *file;

    /* list of sections */
    struct mk_list sections;
};

struct mk_config_section
{
    char *name;

    struct mk_list entries;
    struct mk_list _head;
};

struct mk_config_entry
{
    char *key;
    char *val;

    struct mk_list _head;
};

/* Functions */
struct mk_server_config *mk_config_init();

/* config helpers */
void mk_config_error(const char *path, int line, const char *msg);

struct mk_config *mk_config_create(const char *path);
struct mk_config_section *mk_config_section_get(struct mk_config *conf,
                                                const char *section_name);
struct mk_config_section *mk_config_section_add(struct mk_config *conf,
                                                char *section_name);
void *mk_config_section_getval(struct mk_config_section *section, char *key, int mode);

void mk_config_free(struct mk_config *cnf);
void mk_config_free_all();
void mk_config_free_entries(struct mk_config_section *section);
int mk_config_get_bool(char *value);

#endif
