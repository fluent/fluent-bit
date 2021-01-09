/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef AZURE_BLOB_HTTP_H
#define AZURE_BLOB_HTTP_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include "azure_blob.h"

int azb_http_client_setup(struct flb_azure_blob *ctx, struct flb_http_client *c,
                          ssize_t content_length, int content_type,
                          int blob_type);

flb_sds_t azb_http_canonical_request(struct flb_azure_blob *ctx,
                                     struct flb_http_client *c,
                                     ssize_t content_length,
                                     int content_type);

#endif
