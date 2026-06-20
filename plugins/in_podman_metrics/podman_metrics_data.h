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

#ifndef FLB_IN_PODMAN_METRICS_DATA_H
#define FLB_IN_PODMAN_METRICS_DATA_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_jsmn.h>

#include <dirent.h>
#include <monkey/mk_core/mk_list.h>

#include "podman_metrics_config.h"

int destroy_counter(struct flb_in_metrics *ctx, struct cmt_counter **c);
int destroy_gauge(struct flb_in_metrics *ctx, struct cmt_gauge **g);

uint64_t read_from_file(struct flb_in_metrics *ctx, flb_sds_t path);
uint64_t read_key_value_from_file(struct flb_in_metrics *ctx, flb_sds_t path, flb_sds_t key);
uint64_t get_data_from_sysfs(struct flb_in_metrics *ctx, flb_sds_t dir, flb_sds_t name, flb_sds_t key);

int get_container_sysfs_subdirectory(struct flb_in_metrics *ctx, flb_sds_t id, flb_sds_t subsystem, flb_sds_t *path);
int get_net_data_from_proc(struct flb_in_metrics *ctx, struct container *cnt, uint64_t pid);

int collect_sysfs_directories(struct flb_in_metrics *ctx, flb_sds_t name);
int fill_counters_with_sysfs_data_v1(struct flb_in_metrics *ctx);
int fill_counters_with_sysfs_data_v2(struct flb_in_metrics *ctx);

int name_starts_with(flb_sds_t s, const char *str);
int get_cgroup_version(struct flb_in_metrics *ctx);

#endif
