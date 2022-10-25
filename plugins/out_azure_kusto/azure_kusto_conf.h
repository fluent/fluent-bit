/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifndef FLB_OUT_AZURE_KUSTO_CONF_H
#define FLB_OUT_AZURE_KUSTO_CONF_H

#include "azure_kusto.h"

int azure_kusto_load_ingestion_resources(struct flb_azure_kusto *ctx,
                                         struct flb_config *config);
struct flb_azure_kusto *flb_azure_kusto_conf_create(struct flb_output_instance *ins,
                                                    struct flb_config *config);
int flb_azure_kusto_conf_destroy(struct flb_azure_kusto *ctx);

#endif
