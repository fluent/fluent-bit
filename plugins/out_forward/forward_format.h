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

#ifndef FLB_OUT_FORWARD_FORMAT_H
#define FLB_OUT_FORWARD_FORMAT_H

#include <fluent-bit/flb_output_plugin.h>
#include "forward.h"

void flb_forward_format_bin_to_hex(uint8_t *buf, size_t len, char *out);

int flb_forward_format_append_tag(struct flb_forward *ctx,
                                  struct flb_forward_config *fc,
                                  msgpack_packer *mp_pck,
                                  msgpack_object *map,
                                  const char *tag, int tag_len);

int flb_forward_format(struct flb_config *config,
                       struct flb_input_instance *ins,
                       void *ins_ctx,
                       void *flush_ctx,
                       int event_type,
                       const char *tag, int tag_len,
                       const void *data, size_t bytes,
                       void **out_buf, size_t *out_size);

int flb_forward_format_transcode(
        struct flb_forward *ctx, int format,
        char *input_buffer, size_t input_length,
        char **output_buffer, size_t *output_length);

#endif
