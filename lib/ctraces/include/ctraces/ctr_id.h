/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#ifndef CTR_ID_H
#define CTR_ID_H

#define CTR_ID_DEFAULT_SIZE     16
#define CTR_ID_OTEL_TRACE_SIZE  16
#define CTR_ID_OTEL_SPAN_SIZE    8

#define CTR_ID_TRACE_DEFAULT         "000000F1BI700000000000F1BI700000"
#define CTR_ID_SPAN_DEFAULT          "000000F1BI700000"

struct ctrace_id {
    cfl_sds_t buf;
};

struct ctrace_id *ctr_id_create_random(size_t size);
struct ctrace_id *ctr_id_create(void *buf, size_t len);
void ctr_id_destroy(struct ctrace_id *cid);
int ctr_id_set(struct ctrace_id *cid, void *buf, size_t len);
int ctr_id_cmp(struct ctrace_id *cid1, struct ctrace_id *cid2);
size_t ctr_id_get_len(struct ctrace_id *cid);
void *ctr_id_get_buf(struct ctrace_id *cid);
cfl_sds_t ctr_id_to_lower_base16(struct ctrace_id *cid);
struct ctrace_id *ctr_id_from_base16(cfl_sds_t id);

#endif
