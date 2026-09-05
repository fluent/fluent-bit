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

#ifndef FLUENT_BIT_STACKDRIVER_EXTERNAL_ACCOUNT_H
#define FLUENT_BIT_STACKDRIVER_EXTERNAL_ACCOUNT_H

#include "stackdriver.h"

/*
 * Returns FLB_TRUE when ctx->creds describes an "external_account" credential
 * file (Workload Identity Federation).
 */
int stackdriver_external_account_is_configured(struct flb_stackdriver *ctx);

/*
 * Implements the Workload Identity Federation flow:
 *
 *   1. Read the subject token from credential_source.file
 *   2. POST it to the STS token URL to obtain a federated access token
 *   3. If service_account_impersonation_url is set, POST the federated
 *      token to the IAM Credentials generateAccessToken endpoint to obtain
 *      a Google service-account access token
 *
 * The resulting access_token / token_type / expires_at are stored in
 * ctx->o so that the existing get_google_token() machinery can use them.
 *
 * Returns 0 on success, -1 on failure.
 */
int stackdriver_external_account_read_token(struct flb_stackdriver *ctx);

#endif
