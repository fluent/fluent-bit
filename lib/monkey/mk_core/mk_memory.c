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

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <mk_core/mk_pthread.h>
#include <mk_core/mk_memory.h>
#include <mk_core/mk_macros.h>

mk_ptr_t mk_ptr_create(char *buf, long init, long end)
{
    mk_ptr_t p;

    p.data = buf + init;

    if (init != end) {
        p.len = (end - init);
    }
    else {
        p.len = 1;
    }

    return p;
}

void mk_ptr_free(mk_ptr_t * p)
{
    mk_mem_free(p->data);
    p->len = 0;
}

char *mk_ptr_to_buf(mk_ptr_t p)
{
    char *buf;

    buf = mk_mem_alloc(p.len + 1);
    if (!buf) return NULL;

    memcpy(buf, p.data, p.len);
    buf[p.len] = '\0';

    return (char *) buf;
}

void mk_ptr_print(mk_ptr_t p)
{
    unsigned int i;

    printf("\nDEBUG MK_POINTER: '");
    for (i = 0; i < p.len && p.data != NULL; i++) {
        printf("%c", p.data[i]);
    }
    printf("'");
    fflush(stdout);
}

void mk_ptr_set(mk_ptr_t *p, char *data)
{
    p->data = data;
    p->len = strlen(data);
}
