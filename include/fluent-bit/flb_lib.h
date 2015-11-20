/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
 *  Copyright (C) 2015 Treasure Data Inc.
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

#ifndef FLB_LIB_H
#define FLB_LIB_H

#include <fluent-bit/flb_config.h>

/* Library mode context data */
struct flb_lib_ctx {
    struct mk_event_loop *event_loop;
    struct mk_event *event_channel;
};

int flb_lib_init(struct flb_config *config, char *output);
int flb_lib_config_file(struct flb_config *config, char *path);
int flb_lib_push(struct flb_config *config, void *data, size_t len);
int flb_lib_start(struct flb_config *config);
int flb_lib_stop(struct flb_config *config);
void flb_lib_exit(struct flb_config *config);

#endif
