/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include "fluent-bit/flb_pipe.h"
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_input_thread.h>
#include <fluent-bit/flb_log.h>
#include <mpack/mpack.h>


static void *worker(void *arg)
{
    struct flb_input_thread *it = arg;
    it->callback(it->write, it->data);
    fclose(it->write_file);
    return NULL;
}

int flb_input_thread_init(struct flb_input_thread *it, flb_input_thread_cb callback, void *data)
{
    flb_pipefd_t fd[2];
    int result;

    result = flb_pipe_create(fd);
    if (result) {
        flb_error("[input] failed to create pipe: %d", result);
        return -1;
    }

    it->read = fd[0];
    it->write = fd[1];
    it->data = data;
    it->callback = callback;
    it->bufpos = 0;
    it->write_file = fdopen(it->write, "ab");
    if (!it->write_file) {
        flb_errno();
        return -1;
    }

    it->exit = false;
    result = pthread_mutex_init(&it->mutex, NULL);
    if (result) {
        flb_error("[input] failed to initialize thread mutex: %d", result);
        return -1;
    }

    mpack_writer_init_stdfile(&it->writer, it->write_file, false);
    result = pthread_create(&it->thread, NULL, worker, it);
    if (result) {
        close(it->read);
        close(it->write);
        flb_error("[input] failed to create thread: %d", result);
        return -1;
    }

    return 0;
}

int flb_input_thread_collect(struct flb_input_instance *ins,
                             struct flb_config *config,
                             void *in_context)
{
    int object_count;
    size_t chunks_len;
    size_t remaining_bytes;
    struct flb_input_thread *it = in_context;

    int bytes_read = read(it->read,
                          it->buf + it->bufpos,
                          sizeof(it->buf) - it->bufpos);
    flb_plg_trace(ins, "input thread read() = %i", bytes_read);

    if (bytes_read == 0) {
        flb_plg_warn(ins, "end of file (read pipe closed by input thread)");
    }

    if (bytes_read <= 0) {
        flb_input_collector_pause(it->coll_fd, ins);
        flb_engine_exit(config);
        return -1;
    }
    it->bufpos += bytes_read;

    object_count = flb_mp_count_remaining(it->buf, it->bufpos, &remaining_bytes);
    if (!object_count) {
        // msgpack data is still not complete
        return 0;
    }

    chunks_len = it->bufpos - remaining_bytes;
    flb_input_chunk_append_raw(ins, NULL, 0, it->buf, chunks_len);
    memmove(it->buf, it->buf + chunks_len, remaining_bytes);
    it->bufpos = remaining_bytes;
    return 0;
}

int flb_input_thread_destroy(struct flb_input_thread *it, struct flb_input_instance *ins)
{
    int ret;
    flb_input_thread_exit(it, ins);
    ret = pthread_join(it->thread, NULL);
    mpack_writer_destroy(&it->writer);
    pthread_mutex_destroy(&it->mutex);
    return ret;
}

void flb_input_thread_exit(void *in_context, struct flb_input_instance *ins)
{
    struct flb_input_thread *it;

    if (!in_context) {
        flb_plg_warn(ins, "can't set exit flag, in_context not set");
        return;
    }

    it = in_context;
    pthread_mutex_lock(&it->mutex);
    it->exit = true;
    pthread_mutex_unlock(&it->mutex);
    flb_pipe_close(it->read);
}

bool flb_input_thread_exited(struct flb_input_thread *it)
{
    bool ret;
    pthread_mutex_lock(&it->mutex);
    ret = it->exit;
    pthread_mutex_unlock(&it->mutex);
    return ret;
}
