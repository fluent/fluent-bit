/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server (Duda I/O)
 *  -----------------------------
 *  Copyright 2017 Eduardo Silva <eduardo@monkey.io>
 *  Copyright 2014, Zeying Xie <swpdtz at gmail dot com>
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

#ifndef MK_THREAD_H
#define MK_THREAD_H

#include <mk_core/mk_pthread.h>
#include "mk_thread_channel.h"

#define MK_THREAD_DEAD       0
#define MK_THREAD_READY      1
#define MK_THREAD_RUNNING    2
#define MK_THREAD_SUSPEND    3

pthread_key_t mk_thread_scheduler;

typedef void (*mk_thread_func)(void *data);

struct mk_thread_scheduler *mk_thread_open();
void mk_thread_close(struct mk_thread_scheduler *sch);

int mk_thread_create(mk_thread_func func, void *data);
int mk_thread_status(int id);
void mk_thread_yield();
void mk_thread_resume(int id);
int mk_thread_running();

void mk_thread_add_channel(int id, struct mk_thread_channel *chan);

#endif
