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

#include <fluent-bit/flb_info.h>

/* MSI authorization URL template */
#define FLB_AZ_LI_MSIAUTH_URL_TEMPLATE \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01%s%s&resource=https://monitor.azure.com"

char *flb_azure_li_msiauth_token_get(struct flb_oauth2 *ctx);
int flb_azure_kusto_conf_destroy(struct flb_az_li *ctx);
