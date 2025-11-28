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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>

#include "azure_blob.h"
#include "azure_blob_conf.h"
#include "azure_blob_uri.h"

flb_sds_t azb_append_blob_uri(struct flb_azure_blob *ctx,
                              const char *path_prefix,
                              char *tag)
{
    flb_sds_t uri;
    const char *effective_path;

    uri = azb_uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    effective_path = (path_prefix && path_prefix[0] != '\0') ? path_prefix : ctx->path;

    if (effective_path && effective_path[0] != '\0') {
        flb_sds_printf(&uri, "/%s/%s?comp=appendblock", effective_path, tag);
    }
    else {
        flb_sds_printf(&uri, "/%s?comp=appendblock", tag);
    }

    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        flb_sds_printf(&uri, "&%s", ctx->sas_token);
    }

    return uri;
}
