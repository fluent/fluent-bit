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

#ifndef FLUENT_BIT_GCE_METADATA_H
#define FLUENT_BIT_GCE_METADATA_H

#include "stackdriver.h"

/* Metadata server URL */
#define FLB_STD_METADATA_SERVER "http://metadata.google.internal"

/* Project ID metadata URI */
#define FLB_STD_METADATA_PROJECT_ID_URI "/computeMetadata/v1/project/project-id"

/* Zone metadata URI */
#define FLB_STD_METADATA_ZONE_URI "/computeMetadata/v1/instance/zone"

/* Instance ID metadata URI */
#define FLB_STD_METADATA_INSTANCE_ID_URI "/computeMetadata/v1/instance/id"

/* Service account metadata URI */
#define FLB_STD_METADATA_SERVICE_ACCOUNT_URI "/computeMetadata/v1/instance/service-accounts/"

/* Max size of token response from metadata server */
#define FLB_STD_METADATA_TOKEN_SIZE_MAX 14336

int gce_metadata_read_token(struct flb_stackdriver *ctx);
int gce_metadata_read_zone(struct flb_stackdriver *ctx);
int gce_metadata_read_project_id(struct flb_stackdriver *ctx);
int gce_metadata_read_instance_id(struct flb_stackdriver *ctx);

#endif //FLUENT_BIT_GCE_METADATA_H
