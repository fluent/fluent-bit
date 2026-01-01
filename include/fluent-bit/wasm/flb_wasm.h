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

#ifndef FLB_WASM_H
#define FLB_WASM_H

#include "wasm_export.h"

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event.h>

#define FLB_WASM_DEFAULT_HEAP_SIZE  8192
#define FLB_WASM_DEFAULT_STACK_SIZE 8192

struct flb_wasm_config {
    size_t heap_size;
    size_t stack_size;
    int stdinfd;
    int stdoutfd;
    int stderrfd;
};

/* WASM Context */
struct flb_wasm {
    wasm_module_t module;
    wasm_module_inst_t module_inst;
    wasm_function_inst_t func;
    wasm_exec_env_t exec_env;
    uint32_t tag_buffer;
    uint32_t record_buffer;
    char *buffer;
    void *config;          /* Fluent Bit context      */
    struct mk_list _head;  /* Link to flb_config->wasm */
};

void flb_wasm_init(struct flb_config *config);
struct flb_wasm_config *flb_wasm_config_init(struct flb_config *config);
void flb_wasm_config_destroy(struct flb_wasm_config *wasm_config);
struct flb_wasm *flb_wasm_instantiate(struct flb_config *config, const char *wasm_path,
                                      struct mk_list *acessible_dir_list,
                                      struct flb_wasm_config *wasm_config);

char *flb_wasm_call_function_format_json(struct flb_wasm *fw, const char *function_name,
                                         const char* tag_data, size_t tag_len,
                                         struct flb_time t,
                                         const char* record_data, size_t record_len);

int flb_wasm_format_msgpack_mode(const char *tag, int tag_len,
                                 struct flb_log_event *log_event,
                                 void **out_buf, size_t *out_size);
char *flb_wasm_call_function_format_msgpack(struct flb_wasm *fw, const char *function_name,
                                            const char* tag_data, size_t tag_len,
                                            struct flb_time t,
                                            const char *records, size_t records_len);
int flb_wasm_call_wasi_main(struct flb_wasm *fw);
void flb_wasm_buffer_free(struct flb_wasm *fw);
void flb_wasm_destroy(struct flb_wasm *fw);
int flb_wasm_destroy_all(struct flb_config *ctx);

#endif
