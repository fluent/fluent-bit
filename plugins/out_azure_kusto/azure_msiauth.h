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

 #ifndef FLB_AZURE_MSIAUTH_H
 #define FLB_AZURE_MSIAUTH_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/tls/flb_tls.h>

#define FLB_AZURE_IMDS_HOST "169.254.169.254"
#define FLB_AZURE_IMDS_HOST_LEN 15
#define FLB_AZURE_IMDS_PORT 80
#define FLB_AZURE_IMDS_TIMEOUT 1  /* 1 second */

#define FLB_AZURE_IMDS_TOKEN_URI "/metadata/identity/oauth2/token?api-version=2023-01-01&resource=https://api.kusto.windows.net""

#define FLB_AZURE_IMDS_HTTP_HEADER_METADATA "Metadata"

char *flb_azure_msiauth_token_get(struct flb_oauth2 *ctx);

#endif