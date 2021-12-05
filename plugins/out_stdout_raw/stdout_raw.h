/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
 *
 *  Modified Work:
 *
 *  Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 *  This software product is a proprietary product of NVIDIA CORPORATION &
 *  AFFILIATES (the "Company") and all right, title, and interest in and to the
 *  software product, including all associated intellectual property rights, are
 *  and shall remain exclusively with the Company.
 *
 *  This software product is governed by the End User License Agreement
 *  provided with the software product.
 *
 */

#ifndef FLB_OUT_STDOUT_RAW
#define FLB_OUT_STDOUT_RAW


#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>

typedef char type_name_t[128];

typedef struct record_counters_t{
    int           num_types;
    type_name_t*  type_name;
    int*          num_records;
    int**         num_fields_per_record;
} record_counters_t;

struct record_counters_t* create_record_counters();
void destroy_record_counters(record_counters_t* rc);
void update_record_counters(record_counters_t* rc, msgpack_object o);
void print_record_counters(FILE* fd, record_counters_t* rc);

struct flb_stdout_raw {
    // to check in_raw_msgpack
    bool     use_bin_file_check;
    char*    check_dir;
    char     check_file_path[128];
    int      check_in_raw_msgpack_fd;
    char     fieds_counter_log_path[128];
    FILE*    log_fields_count_fd;
    unsigned total_num_received_records;

    struct record_counters_t * record_counters;
    FILE*    out_stream;
    uint64_t global_record_cnt;

    // to measure time
    bool     measure_speed;
    uint64_t bytes_milestone;
    uint64_t bytes_received;
    uint64_t ts_begin;
    uint64_t ts_end;

    int out_format;
    int json_date_format;
    flb_sds_t json_date_key;
    flb_sds_t date_key;
    struct flb_output_instance *ins;
};

#endif
