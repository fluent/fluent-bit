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
#define FLB_FILTER_AWS_IMDS_INSTANCE_TYPE_PATH            "/latest/meta-data/instance-type/"
#define FLB_FILTER_AWS_IMDS_PRIVATE_IP_PATH               "/latest/meta-data/local-ipv4/"
#define FLB_FILTER_AWS_IMDS_VPC_ID_PATH_PREFIX            "/latest/meta-data/network/interfaces/macs/"
#define FLB_FILTER_AWS_IMDS_AMI_ID_PATH                   "/latest/meta-data/ami-id/"
#define FLB_FILTER_AWS_IMDS_ACCOUNT_ID_PATH               "/latest/dynamic/instance-identity/document/"
#define FLB_FILTER_AWS_IMDS_HOSTNAME_PATH                 "/latest/meta-data/hostname/"
#define FLB_FILTER_AWS_IMDS_MAC_PATH                      "/latest/meta-data/mac/"

#define FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER               "X-aws-ec2-metadata-token"
#define FLB_FILTER_AWS_IMDS_V2_TOKEN_HEADER_LEN           24

#define FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY              "az"
#define FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY_LEN          2
#define FLB_FILTER_AWS_INSTANCE_ID_KEY                    "ec2_instance_id"
#define FLB_FILTER_AWS_INSTANCE_ID_KEY_LEN                15
#define FLB_FILTER_AWS_INSTANCE_TYPE_KEY                  "ec2_instance_type"
#define FLB_FILTER_AWS_INSTANCE_TYPE_KEY_LEN              17
#define FLB_FILTER_AWS_PRIVATE_IP_KEY                     "private_ip"
#define FLB_FILTER_AWS_PRIVATE_IP_KEY_LEN                 10
#define FLB_FILTER_AWS_VPC_ID_KEY                         "vpc_id"
#define FLB_FILTER_AWS_VPC_ID_KEY_LEN                     6
#define FLB_FILTER_AWS_AMI_ID_KEY                         "ami_id"
#define FLB_FILTER_AWS_AMI_ID_KEY_LEN                     6
#define FLB_FILTER_AWS_ACCOUNT_ID_KEY                     "account_id"
#define FLB_FILTER_AWS_ACCOUNT_ID_KEY_LEN                 10
#define FLB_FILTER_AWS_HOSTNAME_KEY                       "hostname"
#define FLB_FILTER_AWS_HOSTNAME_KEY_LEN                   8

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

    flb_sds_t instance_type;
    size_t instance_type_len;
    int instance_type_include;

    flb_sds_t private_ip;
    size_t private_ip_len;
    int private_ip_include;

    flb_sds_t vpc_id;
    size_t vpc_id_len;
    int vpc_id_include;

    flb_sds_t ami_id;
    size_t ami_id_len;
    int ami_id_include;

    flb_sds_t account_id;
    size_t account_id_len;
    int account_id_include;


    flb_sds_t hostname;
    size_t hostname_len;
    int hostname_include;

    /* number of new keys added by this plugin */
    int new_keys;

    int metadata_retrieved;

    /* Plugin can use EC2 metadata v1 or v2; default is v2 */
    int use_v2;

    /* Filter plugin instance reference */
    struct flb_filter_instance *ins;
};

#endif
