/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_OUT_ES_BULK_H
#define FLB_OUT_ES_BULK_H

#include <inttypes.h>

#define ES_BULK_CHUNK      4096  /* Size of buffer chunks    */
#define ES_BULK_HEADER      128  /* ES Bulk API prefix line  */
#define ES_BULK_INDEX_FMT   "{\"index\":{\"_index\":\"%s\",\"_type\":\"%s\"}}\n"
#define ES_BULK_INDEX_FMT_ID "{\"index\":{\"_index\":\"%s\",\"_type\":\"%s\",\"_id\":\"%s\"}}\n"

struct es_bulk {
    char *ptr;
    uint32_t len;
    uint32_t size;
};

struct es_bulk *es_bulk_create();
int es_bulk_append(struct es_bulk *bulk, char *index, int i_len,
                   char *json, size_t j_len);
void es_bulk_destroy(struct es_bulk *bulk);

#endif
