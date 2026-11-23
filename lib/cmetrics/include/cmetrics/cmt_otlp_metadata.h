/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#ifndef CMT_OTLP_METADATA_H
#define CMT_OTLP_METADATA_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_map.h>
#include <mpack/mpack.h>

struct cfl_kvlist *cmt_otlp_metadata_clone(struct cfl_kvlist *source);
int cmt_otlp_metadata_pack(mpack_writer_t *writer, struct cmt *context);
int cmt_otlp_metadata_pack_external(mpack_writer_t *writer, struct cmt *context);
int cmt_otlp_metadata_restore(struct cmt *context);
int cmt_otlp_histogram_restore(struct cmt *context);
int cmt_otlp_capture_labels(struct cmt_map *map, struct cmt_metric *sample);
int cmt_otlp_attributes_match_labels(struct cmt_map *map, struct cmt_metric *sample);

#endif
