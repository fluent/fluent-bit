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

#ifndef FLB_TAIL_FS_INOTIFY_H
#define FLB_TAIL_FS_INOTIFY_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>

#include "tail_config.h"
#include "tail_file_internal.h"

int flb_tail_fs_inotify_init(struct flb_input_instance *in,
                          struct flb_tail_config *ctx, struct flb_config *config);
int flb_tail_fs_inotify_add(struct flb_tail_file *file);
int flb_tail_fs_inotify_remove(struct flb_tail_file *file);
int flb_tail_fs_inotify_exit(struct flb_tail_config *ctx);
void flb_tail_fs_inotify_pause(struct flb_tail_config *ctx);
void flb_tail_fs_inotify_resume(struct flb_tail_config *ctx);

#endif
