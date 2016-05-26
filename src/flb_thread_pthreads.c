/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <pthread.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_thread_pthreads.h>

static void worker_init(void *data)
{
    struct flb_thread *th = data;
    struct flb_output_plugin *p;
    struct flb_output_instance *o_ins;

    o_ins = th->pth_cb.o_ins;
    p = o_ins->p;

    //flb_trace("[pthread flush]");
    p->cb_flush(th->pth_cb.buf,
                th->pth_cb.size,
                th->pth_cb.tag,
                th->pth_cb.tag_len,
                th->pth_cb.i_ins,
                th->pth_cb.o_ins->context,
                th->config);

    flb_thread_destroy(th);
    pthread_exit(0);
}


void flb_thread_resume(struct flb_thread *th)
{
    /* start the posix thread */
    mk_utils_worker_spawn(worker_init, th, &th->tid);
}
