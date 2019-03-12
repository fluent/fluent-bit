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

 #include <fluent-bit/stream_processor/flb_sp.h>
 #include <fluent-bit/stream_processor/flb_sp_window.h>

int sp_populate_window(struct flb_sp_task *task, char *buf_data, size_t buf_size)
{
    switch (task->window.type) {
        case FLB_SP_WINDOW_DEFAULT:
            flb_free(task->window.buf_data);
            task->window.buf_size = 0;

            task->window.buf_data = flb_malloc(buf_size);
            if (!task) {
                flb_errno();
                return -1;
            }

            memcpy(task->window.buf_data, buf_data, buf_size);
            task->window.buf_size = buf_size;
            break;
        default:
            flb_error("[sp] error populating window for '%' : window tyoe unknown",
                      task->name);
            return -1;
    }
    return 0;
}
