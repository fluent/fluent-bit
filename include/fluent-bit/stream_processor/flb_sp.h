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

#ifndef FLB_SP_H
#define FLB_SP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_input.h>
#include <monkey/mk_core.h>
#include <rbtree.h>

/* Aggregate num type */
#define FLB_SP_NUM_I64       0
#define FLB_SP_NUM_F64       1
#define FLB_SP_BOOLEAN       2
#define FLB_SP_STRING        3

struct sp_buffer {
    char* buffer;
    size_t size;
};

struct aggregate_num {
    int type;
    int ops;
    int64_t i64;
    double f64;
    bool boolean;
    flb_sds_t string;
};

struct aggregate_data {
    struct aggregate_num *nums;
    struct mk_list _head;
};

struct timeseries_forecast {
    struct aggregate_num *nums;
    struct mk_list _head;

    // future time to forecast
    double future_time;

    // time offset (the first time value captured)
    double offset;
    double latest_x;

    double sigma_x;
    double sigma_y;

    double sigma_xy;
    double sigma_x2;
};

struct aggregate_node {
    int groupby_keys;
    int records;
    int nums_size;
    struct aggregate_num *nums;
    struct aggregate_num *groupby_nums;

    /* Aggregate data */
    struct aggregate_data **aggregate_data;

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
    struct rb_tree aggregate_tree;
    struct mk_list aggregate_list;
    int records;
    struct mk_list _head;
};

struct flb_sp_task_window {
    int type;

    int fd;
    struct mk_event event;
    struct mk_event event_hop;

    struct rb_tree aggregate_tree;
    struct mk_list aggregate_list;

    /* Hopping window parameters */
    /*
     * first hopping window. Timer event is set to window size for the first,
     * and will change to the advance_by time thereafter
     */
    bool first_hop;
    int fd_hop;
    time_t advance_by;
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

    int aggregate_keys;      /* do commands contains aggregate keys? */
    struct flb_sp *sp;       /* parent context */
    struct flb_sp_cmd *cmd;  /* (SQL) commands */

    struct flb_sp_task_window window; /* task window */

    void *snapshot;          /* snapshot pages for SNAPSHOT sream type */

    struct mk_list _head;    /* link to parent list flb_sp->tasks */
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
int sp_process_data(const char *tag, int tag_len,
                    const char *buf_data, size_t buf_size,
                    char **out_buf, size_t *out_size,
                    struct flb_sp_task *task,
                    struct flb_sp *sp);
int sp_process_data_aggr(const char *buf_data, size_t buf_size,
                         const char *tag, int tag_len,
                         struct flb_sp_task *task,
                         struct flb_sp *sp, int convert_str_to_num);
void package_results(const char *tag, int tag_len,
                     char **out_buf, size_t *out_size,
                     struct flb_sp_task *task);
int sp_process_hopping_slot(const char *tag, int tag_len,
                            struct flb_sp_task *task);

int flb_sp_snapshot_create(struct flb_sp_task *task);
struct flb_sp_task *flb_sp_task_create(struct flb_sp *sp, const char *name,
                                       const char *query);
int flb_sp_fd_event(int fd, struct flb_sp *sp);
void flb_sp_task_destroy(struct flb_sp_task *task);
void groupby_nums_destroy(struct aggregate_num *groupby_nums, int size);
void flb_sp_aggregate_node_destroy(struct flb_sp_cmd *cmd,
                                   struct aggregate_node *aggregate_node);

#endif
