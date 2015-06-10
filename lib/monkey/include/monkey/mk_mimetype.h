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

#include <monkey/mk_core.h>

#ifndef MK_MIMETYPE_H
#define MK_MIMETYPE_H

#define MIMETYPE_DEFAULT_TYPE "text/plain\r\n"
#define MIMETYPE_DEFAULT_NAME "default"

struct mimetype
{
    char *name;
    mk_ptr_t type;
    mk_ptr_t header_type;
    struct mk_list _head;
    struct rb_node _rb_head;
};

/* Head for RBT */
struct mk_list mimetype_list;
struct rb_root mimetype_rb_head;

extern struct mimetype *mimetype_default;

int mk_mimetype_add(char *name, const char *type);
void mk_mimetype_read_config(void);
struct mimetype *mk_mimetype_find(mk_ptr_t * filename);
struct mimetype *mk_mimetype_lookup(char *name);
void mk_mimetype_free_all();

#endif
