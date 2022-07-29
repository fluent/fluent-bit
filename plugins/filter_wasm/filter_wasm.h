/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#ifndef FLB_FILTER_WASM_H
#define FLB_FILTER_WASM_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/wasm/flb_wasm.h>

#include <msgpack.h>

struct flb_filter_wasm {
    flb_sds_t wasm_path;
    struct mk_list *accessible_dir_list; /* list of directories to be
                                          * accesible from WASM */
    flb_sds_t wasm_function_name;
    struct flb_filter_instance *ins;
    struct flb_wasm *wasm;
};

#endif /* FLB_FILTER_WASM_H */
