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

#ifndef FLB_SP_H
#define FLB_SP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input.h>
#include <monkey/mk_core.h>
#include <rbtree.h>

/* Aggr num type */
#define FLB_SP_NUM_I64       0
#define FLB_SP_NUM_F64       1
#define FLB_SP_BOOLEAN       2
#define FLB_SP_STRING        3

struct aggr_num {
    int type;
    int ops;
    int64_t i64;
    double f64;
    bool boolean;
    flb_sds_t string;
};

struct aggr_node {
    int groupby_keys;
    int records;
    int nums_size;
    struct aggr_num *nums;
    struct aggr_num *groupby_nums;

    /* To keep track of the aggregation nodes */
    struct rb_tree_node _rb_head;
    struct mk_list _head;
};

struct flb_sp_window_data {
    char *buf_data;
    size_t buf_size;
    struct mk_list _head;
};

struct flb_sp_hopping_slot {
    struct rb_tree aggr_tree;
    struct mk_list aggr_list;
    int records;
    struct mk_list _head;
};

struct flb_sp_task_window {
    int type;

    int fd;
    struct mk_event event;
    struct mk_event event_hop;

    struct rb_tree aggr_tree;
    struct mk_list aggr_list;

    /* Hopping window parameters */
    /*
     * first hopping window. Timer event is set to window size for the first,
     * and will change to the advance_by time thereafter
     */
    bool first_hop;
    int fd_hop;
    int advance_by;
    struct mk_list hopping_slot;

    int records;

    struct mk_list data;
};

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

    struct flb_sp_task_window window; /* task window */
    struct mk_list _head;             /* link to parent list flb_sp->tasks */
};

struct flb_sp {
    struct mk_list tasks;        /* processor tasks */
    struct flb_config *config;   /* reference to Fluent Bit context */
};

struct flb_sp *flb_sp_create(struct flb_config *config);
void flb_sp_destroy(struct flb_sp *sp);

int flb_sp_do(struct flb_sp *sp, struct flb_input_instance *in,
              const char *tag, int tag_len,
              const char *buf_data, size_t buf_size);
int flb_sp_test_do(struct flb_sp *sp, struct flb_sp_task *task,
                   const char *tag, int tag_len,
                   const char *buf_data, size_t buf_size,
                   char **out_data, size_t *out_size);
int flb_sp_test_fd_event(int fd, struct flb_sp_task *task, char **out_data,
                         size_t *out_size);

struct flb_sp_task *flb_sp_task_create(struct flb_sp *sp, const char *name,
                                       const char *query);
int flb_sp_fd_event(int fd, struct flb_sp *sp);
void flb_sp_task_destroy(struct flb_sp_task *task);
void flb_sp_aggr_node_destroy(struct aggr_node *aggr_node);

#endif
