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

#ifndef FLB_INPUT_BLOB_H
#define FLB_INPUT_BLOB_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_notification.h>
#include <fluent-bit/flb_log_event_encoder.h>

struct flb_blob_delivery_notification {
    struct flb_notification base;
    cfl_sds_t path;
    int success;
};


struct flb_blob_file {
    cfl_sds_t path;
};

void flb_input_blob_delivery_notification_destroy(void *instance);

int flb_input_blob_file_get_info(msgpack_object map, cfl_sds_t *source,
                                 cfl_sds_t *file_path, size_t *size);
int flb_input_blob_file_register(struct flb_input_instance *ins,
                                 struct flb_log_event_encoder *encoder,
                                 const char *tag, size_t tag_len,
                                 char *file_path, size_t size);
#endif
