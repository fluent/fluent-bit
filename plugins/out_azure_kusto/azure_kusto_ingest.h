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

#ifndef FLB_OUT_AZURE_KUSTO_INGEST_H
#define FLB_OUT_AZURE_KUSTO_INGEST_H

#include "azure_kusto.h"
#include "azure_kusto_store.h"

int azure_kusto_queued_ingestion(struct flb_azure_kusto *ctx, flb_sds_t tag,
                                 size_t tag_len, flb_sds_t payload, size_t payload_size, struct azure_kusto_file *upload_file);

#endif