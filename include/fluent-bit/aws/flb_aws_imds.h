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

#ifndef FLB_AWS_IMDS
#define FLB_AWS_IMDS

#define FLB_AWS_IMDS_HOST "169.254.169.254"
#define FLB_AWS_IMDS_HOST_LEN 15
#define FLB_AWS_IMDS_PORT 80
#define FLB_AWS_IMDS_TIMEOUT 1  /* 1 second */

#define FLB_AWS_IMDS_VERSION_EVALUATE 0
#define FLB_AWS_IMDS_VERSION_1 1
#define FLB_AWS_IMDS_VERSION_2 2

/* The following metadata paths can be evaluated with flb_aws_imds_request
 * to retrieve specific metadata members */
#define FLB_AWS_IMDS_INSTANCE_ID_PATH      "/latest/meta-data/instance-id/"
#define FLB_AWS_IMDS_PARTITION_PATH        "/latest/meta-data/services/partition/"
#define FLB_AWS_IMDS_DOMAIN_PATH           "/latest/meta-data/services/domain/"
#define FLB_AWS_IMDS_REGION_PATH           "/latest/meta-data/placement/region/"
#define FLB_AWS_IMDS_AZ_PATH               "/latest/meta-data/placement/availability-zone/"
#define FLB_AWS_IMDS_AZ_ID_PATH            "/latest/meta-data/placement/availability-zone-id/"
#define FLB_AWS_IMDS_PLACEMENT_GROUP_PATH  "/latest/meta-data/placement/group-name/"
#define FLB_AWS_IMDS_PARTITION_NUMBER_PATH "/latest/meta-data/placement/partition-number/"
#define FLB_AWS_IMDS_HOST_ID_PATH          "/latest/meta-data/placement/host-id/"
#define FLB_AWS_IMDS_INSTANCE_TYPE_PATH    "/latest/meta-data/instance-type/"
#define FLB_AWS_IMDS_PRIVATE_IP_PATH       "/latest/meta-data/local-ipv4/"
#define FLB_AWS_IMDS_PUBLIC_IP_PATH        "/latest/meta-data/public-ipv4/"
#define FLB_AWS_IMDS_IPV6_PATH             "/latest/meta-data/ipv6/"
#define FLB_AWS_IMDS_VPC_ID_PATH_PREFIX    "/latest/meta-data/network/interfaces/macs/"
#define FLB_AWS_IMDS_AMI_ID_PATH           "/latest/meta-data/ami-id/"
#define FLB_AWS_IMDS_ACCOUNT_ID_PATH       "/latest/dynamic/instance-identity/document/"
#define FLB_AWS_IMDS_HOSTNAME_PATH         "/latest/meta-data/hostname/"
#define FLB_AWS_IMDS_MAC_PATH              "/latest/meta-data/mac/"
#define FLB_AWS_IMDS_INSTANCE_TAG          "/latest/meta-data/tags/instance"

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>

/* IMDS config values */
struct flb_aws_imds_config {
    int use_imds_version;  // FLB_AWS_IMDS_VERSION_EVALUATE for automatic detection
};

/* Default config values */
extern const struct flb_aws_imds_config flb_aws_imds_config_default;

/* Metadata service context struct */
struct flb_aws_imds {
    /* AWS Client to perform mockable requests to IMDS */
    struct flb_aws_client *ec2_imds_client;

    /* IMDSv2 requires a token which must be present in metadata requests */
    flb_sds_t imds_v2_token;
    size_t imds_v2_token_len;

    /*
     * Plugin can use EC2 metadata v1 or v2; default is FLB_AWS_IMDS_VERSION_EVALUATE
     * which is evaluated to FLB_AWS_IMDS_VERSION_1 or FLB_AWS_IMDS_VERSION_2 when
     * the IMDS is used.
     */
    int imds_version;
};

/*
 * Create IMDS context
 * Returns NULL on error
 * Note: Setting the FLB_IO_ASYNC flag is the job of the client.
 * Flag Set Example: flags &= ~(FLB_IO_ASYNC)
 */
struct flb_aws_imds *flb_aws_imds_create(const struct flb_aws_imds_config *imds_config,
                                         struct flb_aws_client *ec2_imds_client);

/*
 * Destroy IMDS context
 * The client is responsable for destroying
 * the "ec2_imds_client" struct.
 */
void flb_aws_imds_destroy(struct flb_aws_imds *ctx);

/*
 * Get IMDS metadata.
 * Sets flb_sds_t metadata string to the value found at IMDS' metadata_path.
 * Returns -1 on error, 0 on success.
 */
int flb_aws_imds_request(struct flb_aws_imds *ctx, const char *metadata_path,
                         flb_sds_t *metadata, size_t *metadata_len);

/*
 * Get IMDS metadata by key
 * Expects metadata to be in a json object format.
 * Sets flb_sds_t metadata string to the value associated with provided key.
 * Sets flb_sds_t metadata string to "NULL" if key not found.
 * Sets flb_sds_t metadata string to the full metadata value if key is NULL.
 * Returns -1 on error, 0 on success.
 */
int flb_aws_imds_request_by_key(struct flb_aws_imds *ctx, const char *metadata_path,
                                flb_sds_t *metadata, size_t *metadata_len, char *key);

/*
 * Get VPC id from EC2 IMDS. Requires multiple IMDS requests.
 * Returns sds string encoding vpc_id.
 * Note: Modified from AWS filter, not retested
 */
flb_sds_t flb_aws_imds_get_vpc_id(struct flb_aws_imds *ctx);

#endif
