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

#ifndef FLB_FTS_TELEMETRY_H
#define FLB_FTS_TELEMETRY_H

#include "fts_proto.h"

extern const struct fts_signal_adapter fts_metrics_adapter;
extern const struct fts_signal_adapter fts_traces_adapter;

/* shared metrics and traces policy path */
int fts_register_telemetry_helpers(lua_State *l);
int fts_run_telemetry(lua_State *l);
int fts_telemetry_transform(struct flb_processor_instance *ins, char *buffer, size_t size,
                            char **output, size_t *output_size, const char *tag, int tag_len);

/* signal entry points */
int fts_process_metrics(struct flb_processor_instance *ins, struct cmt *input,
                        struct cmt **output, const char *tag, int tag_len);
int fts_process_traces(struct flb_processor_instance *ins, struct ctrace *input,
                       struct ctrace **output, const char *tag, int tag_len);

#endif
