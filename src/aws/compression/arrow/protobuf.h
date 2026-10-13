/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2026 The Fluent Bit Authors
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

#ifndef FLB_AWS_COMPRESSION_ARROW_PROTOBUF_H
#define FLB_AWS_COMPRESSION_ARROW_PROTOBUF_H

#include <fluent-bit/aws/flb_aws_compress.h>

#include <arrow/api.h>

#include <memory>

arrow::Status flb_aws_protobuf_records_to_arrow_table(
                    struct flb_aws_protobuf_schema *schema,
                    const struct flb_aws_protobuf_record *records,
                    size_t record_count,
                    std::shared_ptr<arrow::Table> *table);

#endif
