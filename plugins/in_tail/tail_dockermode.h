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
 */

#ifndef FLB_TAIL_DOCKERMODE_H
#define FLB_TAIL_DOCKERMODE_H

#include "tail_file.h"
#define FLB_TAIL_DMODE_FLUSH 4

int flb_tail_dmode_create(struct flb_tail_config *ctx,
                          struct flb_input_instance *ins, struct flb_config *config);
int flb_tail_dmode_process_content(time_t now,
                                   char* line, size_t line_len,
                                   char **repl_line, size_t *repl_line_len,
                                   struct flb_tail_file *file,
                                   struct flb_tail_config *ctx,
                                   msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck);
void flb_tail_dmode_flush(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                          struct flb_tail_file *file, struct flb_tail_config *ctx);
int flb_tail_dmode_pending_flush(struct flb_input_instance *ins,
                                 struct flb_config *config, void *context);

#endif
