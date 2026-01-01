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
#ifndef FLB_IN_EXEC_WASI_H
#define FLB_IN_EXEC_WASI_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/wasm/flb_wasm.h>

#include <msgpack.h>

#define DEFAULT_BUF_SIZE      "4096"
#define DEFAULT_INTERVAL_SEC  "1"
#define DEFAULT_INTERVAL_NSEC "0"

#define DEFAULT_WASM_HEAP_SIZE  "8192"
#define DEFAULT_WASM_STACK_SIZE "8192"

struct flb_exec_wasi {
    flb_sds_t wasi_path;
    struct mk_list *accessible_dir_list; /* list of directories to be
                                          * accesible from WASM */
    flb_sds_t parser_name;
    struct flb_parser  *parser;
    char *buf;
    size_t buf_size;
    struct flb_input_instance *ins;
    struct flb_wasm *wasm;
    struct flb_wasm_config *wasm_conf;
    int oneshot;
    flb_pipefd_t ch_manager[2];
    int interval_sec;
    int interval_nsec;
    size_t wasm_heap_size;
    size_t wasm_stack_size;
    struct flb_log_event_encoder log_encoder;
    int coll_fd;
};

#endif /* FLB_IN_EXEC_WASI_H */
