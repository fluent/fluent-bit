/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_SP_H
#define FLB_SP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input.h>
#include <monkey/mk_core.h>

struct flb_sp_task {
    flb_sds_t name;          /* task name      */
    flb_sds_t query;         /* SQL text query */

    /*
     * if the command source is an existent stream (input plugin instance), we
     * map the instance address here to perform a fast lookup once the data
     * comes in.
     */
    void *source_instance;

    /*
     * If the command created a new stream, this field keeps a reference to
     * the initialized stream context.
     */
    void *stream;

    int aggr_keys;           /* do commands contains aggregated keys ? */
    struct flb_sp *sp;       /* parent context */
    struct flb_sp_cmd *cmd;  /* (SQL) commands */
    struct mk_list _head;    /* link to parent list flb_sp->tasks */
};

struct flb_sp {
    struct mk_list tasks;       /* processor tasks */
    struct flb_config *config;  /* reference to Fluent Bit context */
};

struct flb_sp *flb_sp_create(struct flb_config *config);
void flb_sp_destroy(struct flb_sp *sp);

int flb_sp_do(struct flb_sp *sp, struct flb_input_instance *in,
              char *tag, int tag_len,
              char *buf_data, size_t buf_size);
int flb_sp_test_do(struct flb_sp *sp, struct flb_sp_task *task,
                   char *buf_data, size_t buf_size,
                   char **out_data, size_t *out_size);

struct flb_sp_task *flb_sp_task_create(struct flb_sp *sp, char *name,
                                       char *query);
void flb_sp_task_destroy(struct flb_sp_task *task);

#endif
