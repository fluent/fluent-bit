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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>

#include "azure_blob.h"
#include "azure_blob_conf.h"
#include "azure_blob_uri.h"

flb_sds_t azb_append_blob_uri(struct flb_azure_blob *ctx, char *tag)
{
    flb_sds_t uri;

    uri = azb_uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    if (ctx->path) {
        flb_sds_printf(&uri, "/%s/%s?comp=appendblock", ctx->path, tag);
    }
    else {
        flb_sds_printf(&uri, "/%s?comp=appendblock", tag);
    }

    return uri;
}
