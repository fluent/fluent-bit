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

#ifndef FLB_TAIL_SCAN_H
#define FLB_TAIL_SCAN_H

#include "tail_config.h"

int flb_tail_scan(struct mk_list *path, struct flb_tail_config *ctx);
int flb_tail_scan_callback(struct flb_input_instance *ins,
                           struct flb_config *config, void *context);

void flb_tail_scan_register_ignored_file_size(struct flb_tail_config *ctx, const char *path, size_t path_length, size_t size);
void flb_tail_scan_unregister_ignored_file_size(struct flb_tail_config *ctx, const char *path, size_t path_length);
ssize_t flb_tail_scan_fetch_ignored_file_size(struct flb_tail_config *ctx, const char *path, size_t path_length);

#endif
