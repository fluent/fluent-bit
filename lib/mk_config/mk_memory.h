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

#ifndef MK_MEM_H
#define MK_MEM_H

#include <stdio.h>

#include "mk_macros.h"

typedef struct {
    char *data;
    unsigned long len;
} mk_ptr_t;

void mk_mem_free(void *ptr);
void mk_mem_pointers_init(void);

/* mk_ptr_t_* */
mk_ptr_t mk_ptr_create(char *buf, long init, long end);
void mk_ptr_free(mk_ptr_t * p);
void mk_ptr_print(mk_ptr_t p);
char *mk_ptr_to_buf(mk_ptr_t p);
void mk_ptr_set(mk_ptr_t * p, char *data);

static inline void mk_ptr_reset(mk_ptr_t * p)
{
    p->data = NULL;
    p->len = 0;
}


#define mk_ptr_init(a) {a, sizeof(a) - 1}

#endif
