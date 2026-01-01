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

#ifndef FLB_TAIL_TAIL_MULT_H
#define FLB_TAIL_TAIL_MULT_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>

#include "tail_config.h"
#include "tail_file.h"

#define FLB_TAIL_MULT_NA    -1   /* not applicable as a multiline stream */
#define FLB_TAIL_MULT_DONE   0   /* finished a multiline stream */
#define FLB_TAIL_MULT_MORE   1   /* expect more lines to come   */
#define FLB_TAIL_MULT_FLUSH  "4"   /* max flush time for multiline: 4 seconds */

struct flb_tail_mult {
    struct flb_parser *parser;
    struct mk_list _head;
};

int flb_tail_mult_create(struct flb_tail_config *ctx,
                         struct flb_input_instance *ins,
                         struct flb_config *config);

int flb_tail_mult_destroy(struct flb_tail_config *ctx);

int flb_tail_mult_process_content(time_t now,
                                  char *buf, size_t len,
                                  struct flb_tail_file *file,
                                  struct flb_tail_config *ctx,
                                  size_t processed_bytes);
int flb_tail_mult_flush(struct flb_tail_file *file,
                        struct flb_tail_config *ctx);

int flb_tail_mult_pending_flush(struct flb_input_instance *ins,
                                struct flb_config *config, void *context);
int flb_tail_mult_pending_flush_all(struct flb_tail_config *ctx);

#endif
