/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_SP_SNAPSHOT_H
#define FLB_SP_SNAPSHOT_H

#define SNAPSHOT_PAGE_SIZE 1024

struct flb_sp_snapshot_page {
    int records;
    int start_pos;          /* Start position of the valid data */
    int end_pos;            /* End position of the valid data */
    char *snapshot_page;
    struct mk_list _head;
};

struct flb_sp_snapshot {
    int time_limit;
    int record_limit;
    int records;
    size_t size;
    struct mk_list pages;
};

int flb_sp_snapshot_update(struct flb_sp_task *task, const char *buf_data,
                           size_t buf_size, struct flb_time *tms);

int flb_sp_snapshot_flush(struct flb_sp *sp, struct flb_sp_task *task,
                          char **out_buf_data, size_t *out_buf_size);

void flb_sp_snapshot_destroy(struct flb_sp_snapshot *snapshot);

#endif
