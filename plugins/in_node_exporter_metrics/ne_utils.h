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

#ifndef FLB_NODE_EXPORTER_UTILS_H
#define FLB_NODE_EXPORTER_UTILS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_sds.h>
#include "ne.h"

int ne_utils_str_to_double(char *str, double *out_val);
int ne_utils_str_to_uint64(char *str, uint64_t *out_val);

int ne_utils_file_read_uint64(const char *mount,
                              const char *path,
                              const char *join_a, const char *join_b,
                              uint64_t *out_val);

int ne_utils_file_read_sds(const char *mount,
                           const char *path,
                           const char *join_a, 
			   const char *join_b, 
			   flb_sds_t *str);

int ne_utils_file_read_lines(const char *mount, const char *path, struct mk_list *list);
int ne_utils_path_scan(struct flb_ne *ctx, const char *mount, const char *path,
                       int expected, struct mk_list *list);
#endif
