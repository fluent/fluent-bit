/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#ifndef FLB_GPU_METRICS_AMD_H
#define FLB_GPU_METRICS_AMD_H

#include "gpu_metrics.h"

int amd_gpu_detect_cards(struct in_gpu_metrics *ctx);
int amd_gpu_collect_metrics(struct in_gpu_metrics *ctx, struct gpu_card *card);
int amd_gpu_read_utilization(struct in_gpu_metrics *ctx, int card_id, double *utilization);
int amd_gpu_read_memory_info(struct in_gpu_metrics *ctx, int card_id, uint64_t *used, uint64_t *total);

#endif
