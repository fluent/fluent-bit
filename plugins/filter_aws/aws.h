/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_FILTER_AWS_H
#define FLB_FILTER_AWS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>

#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER           "X-aws-ec2-metadata-token-ttl-seconds"
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_LEN       36

#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL       "21600"
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL_HEADER_VAL_LEN   5

#define FLB_FILTER_AWS_IMDS_V2_TOKEN_TTL                  21600

#define FLB_FILTER_AWS_IMDS_HOST                          "169.254.169.254"
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_PATH                 "/latest/api/token"

#define FLB_FILTER_AWS_IMDS_INSTANCE_ID_PATH              "/latest/meta-data/instance-id/"
#define FLB_FILTER_AWS_IMDS_AZ_PATH                       "/latest/meta-data/placement/availability-zone/"

#define FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER               "X-aws-ec2-metadata-token"
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER_LEN           24

#define FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY              "az"
#define FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY_LEN          2
#define FLB_FILTER_AWS_INSTANCE_ID_KEY                    "ec2_instance_id"
#define FLB_FILTER_AWS_INSTANCE_ID_KEY_LEN                15

struct flb_filter_aws {
    /* upstream connection to ec2 IMDS */
    struct flb_upstream *ec2_upstream;

    /*
     * IMDSv2 requires a token which must be present in metadata requests
     * This plugin does not refresh the token
     */
    flb_sds_t imds_v2_token;
    size_t imds_v2_token_len;

    /* Metadata fields
     * These are queried only once; ec2 metadata is assumed to be immutable
     */
    flb_sds_t availability_zone;
    size_t availability_zone_len;
    int availability_zone_include;

    flb_sds_t instance_id;
    size_t instance_id_len;
    int instance_id_include;

    /* number of new keys added by this plugin */
    int new_keys;

    int metadata_retrieved;

    /* Plugin can use EC2 metadata v1 or v2; default is v2 */
    int use_v2;

    /* Filter plugin instance reference */
    struct flb_filter_instance *ins;
};

#endif
