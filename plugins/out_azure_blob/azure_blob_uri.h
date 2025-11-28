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

#ifndef FLB_AZURE_BLOB_URI
#define FLB_AZURE_BLOB_URI

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>

#include "azure_blob.h"

flb_sds_t azb_uri_container(struct flb_azure_blob *ctx);
flb_sds_t azb_uri_ensure_or_create_container(struct flb_azure_blob *ctx);
flb_sds_t azb_uri_create_blob(struct flb_azure_blob *ctx,
							  const char *path_prefix,
							  char *tag);
flb_sds_t azb_uri_encode(const char *uri, size_t len);
flb_sds_t azb_uri_decode(const char *uri, size_t len);

#endif
