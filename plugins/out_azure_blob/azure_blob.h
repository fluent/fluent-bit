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

#ifndef FLB_OUT_AZURE_BLOB_H
#define FLB_OUT_AZURE_BLOB_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_sds.h>

#define AZURE_BLOB_CT         "Content-Type"
#define AZURE_BLOB_CT_JSON    "application/json"
#define AZURE_ENDPOINT_PREFIX ".blob.core.windows.net"

struct flb_azure_blob {
    int auto_create_container;
    int emulator_mode;
    flb_sds_t account_name;
    flb_sds_t container_name;
    flb_sds_t shared_key;
    flb_sds_t endpoint;
    flb_sds_t path;
    flb_sds_t date_key;

    /*
     * Internal use
     */
    flb_sds_t real_endpoint;
    flb_sds_t base_uri;
    flb_sds_t shared_key_prefix;

    /* Shared key */
    unsigned char *decoded_sk;        /* decoded shared key */
    size_t decoded_sk_size;           /* size of decoded shared key */

    /* Upstream connection */
    struct flb_upstream *u;
    struct flb_output_instance *ins;
};

#endif
