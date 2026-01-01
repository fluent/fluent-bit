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

#include <fluent-bit/flb_info.h>
#ifdef FLB_HAVE_METRICS

#ifndef FLB_METRICS_EXPORTER_H
#define FLB_METRICS_EXPORTER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_metrics.h>

struct flb_me {
    int fd;
    struct flb_config *config;
    struct mk_event event;
};

int flb_me_fd_event(int fd, struct flb_me *me);
struct flb_me *flb_me_create(struct flb_config *ctx);
int flb_me_destroy(struct flb_me *me);
struct cmt *flb_me_get_cmetrics(struct flb_config *ctx);

#endif
#endif /* FLB_HAVE_METRICS */
