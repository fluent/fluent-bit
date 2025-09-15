/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_ENGINE_H
#define FLB_ENGINE_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_thread_storage.h>

#define FLB_ENGINE_OUTPUT_EVENT_BATCH_SIZE 1

int flb_engine_start(struct flb_config *config);
int flb_engine_failed(struct flb_config *config);
int flb_engine_flush(struct flb_config *config,
                     struct flb_input_plugin *in_force);
int flb_engine_exit(struct flb_config *config);
int flb_engine_exit_status(struct flb_config *config, int status);
int flb_engine_shutdown(struct flb_config *config);
int flb_engine_destroy_tasks(struct mk_list *tasks);
void flb_engine_reschedule_retries(struct flb_config *config);
void flb_engine_stop_ingestion(struct flb_config *config);

/* Engine event loop */
void flb_engine_evl_init();
struct mk_event_loop *flb_engine_evl_get();
void flb_engine_evl_set(struct mk_event_loop *evl);

#endif
