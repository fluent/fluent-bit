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

#ifndef FLB_FTS_PROTO_H
#define FLB_FTS_PROTO_H

#include "fts.h"
#include <protobuf-c/protobuf-c.h>

struct fts_proto_budget {
    size_t used;
    size_t limit;
};

void *fts_proto_alloc(void *data, size_t size);
void fts_proto_free(void *data, void *ptr);
struct cfl_variant *fts_proto_read(const ProtobufCMessage *message,
                                  struct fts_proto_budget *budget, int depth);
ProtobufCMessage *fts_proto_build(const ProtobufCMessageDescriptor *descriptor,
                                  struct cfl_variant *value,
                                  struct fts_proto_budget *budget, int depth);

#endif
