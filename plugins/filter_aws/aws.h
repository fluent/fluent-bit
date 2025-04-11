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

#ifndef FLB_FILTER_AWS_H
#define FLB_FILTER_AWS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>

#define FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY              "az"
#define FLB_FILTER_AWS_AVAILABILITY_ZONE_KEY_LEN          2
#define FLB_FILTER_AWS_INSTANCE_ID_KEY                    "ec2_instance_id"
#define FLB_FILTER_AWS_INSTANCE_ID_KEY_LEN                15
#define FLB_FILTER_AWS_ENTITY_INSTANCE_ID_KEY             "aws_entity_ec2_instance_id"
#define FLB_FILTER_AWS_ENTITY_INSTANCE_ID_KEY_LEN         26
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
#define FLB_FILTER_AWS_ENTITY_ACCOUNT_ID_KEY              "aws_entity_account_id"
#define FLB_FILTER_AWS_ENTITY_ACCOUNT_ID_KEY_LEN          21
#define FLB_FILTER_AWS_HOSTNAME_KEY                       "hostname"
#define FLB_FILTER_AWS_HOSTNAME_KEY_LEN                   8

/* defines returned value for cases when configuration is invalid and program should exit */
#define FLB_FILTER_AWS_CONFIGURATION_ERROR -100

struct flb_filter_aws_metadata_group {
    /* defines if fetch function for the information group was already done successfully
     * if set to FLB_FALSE after first attempt, then most likely another retry will be
     * required
     * done set to FLB_TRUE does not mean that information was retrieved, as it might
     * be disabled */
    int done;
    /* defines if information was already exposed in the filter for envs */
    int exposed;

    /* defines a timestamp of last execution of fetch method related to the group */
    /* unit: timestamp in seconds */
    time_t last_fetch_attempt;
};

struct flb_filter_aws {
    struct flb_filter_aws_init_options *options;

    /* upstream connection to ec2 IMDS */
    struct flb_aws_client *aws_ec2_filter_client;
    struct flb_aws_imds *client_imds;

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

    /* tags_* fields are related to exposing EC2 tags in log labels
     * tags_enabled defines if EC2 tags functionality is enabled */
    int tags_enabled;
    /*
    * Enable entity prefix appending. This appends
    * 'aws_entity' to relevant keys
    */
    int enable_entity;

    /* tags_fetched defines if tag keys and values were fetched successfully
     * and might be used to inject into msgpack */
    int tags_fetched;
    /* tags_count defines how many tags are available to use
     * it could be 0 if there are no tags defined or if metadata server has
     * disabled exposing tags functionality */
    size_t tags_count;
    /* tag_keys is an array of tag key strings */
    flb_sds_t *tag_keys;
    /* tag_keys_len is an array of lengths corresponding to tag_keys items */
    size_t *tag_keys_len;
    /* tag_values is an array of tag values strings */
    flb_sds_t *tag_values;
    /* tag_values_len is an array of lengths related to tag_values items */
    size_t *tag_values_len;
    /* tag_is_enabled is an array of bools which define if corresponding tag should be injected */
    /* e.g.: if tag_is_enabled[0] = FALSE, then filter aws should not inject first tag */
    int *tag_is_enabled;

    /* metadata group contains information for potential retries and
     * if group was already fetched successfully */
    struct flb_filter_aws_metadata_group group_az;
    struct flb_filter_aws_metadata_group group_instance_id;
    struct flb_filter_aws_metadata_group group_instance_type;
    struct flb_filter_aws_metadata_group group_private_ip;
    struct flb_filter_aws_metadata_group group_vpc_id;
    struct flb_filter_aws_metadata_group group_ami_id;
    struct flb_filter_aws_metadata_group group_account_id;
    struct flb_filter_aws_metadata_group group_hostname;
    struct flb_filter_aws_metadata_group group_tag;
    /* defines a minimal interval before consecutive retries */
    /* unit: seconds */
    time_t retry_required_interval;
    /* defines if all metadata groups were fetched successfully */
    int metadata_retrieved;

    /* Plugin can use EC2 metadata v1 or v2; default is v2 */
    int use_v2;

    /* Filter plugin instance reference */
    struct flb_filter_instance *ins;
};

struct flb_filter_aws_init_options {
    struct flb_aws_client_generator *client_generator;
};

#endif
