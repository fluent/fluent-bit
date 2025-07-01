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

#ifndef FLB_AWS_MSK_IAM_H
#define FLB_AWS_MSK_IAM_H

#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>
#include <rdkafka.h>

struct flb_aws_msk_iam;

struct flb_msk_iam_cb {
    void *plugin_ctx;
    struct flb_aws_msk_iam *iam;
    char *broker_host;  /* Store the actual broker hostname */
};

/*
 * Register the oauthbearer refresh callback for MSK IAM authentication.
 * Returns context pointer on success or NULL on failure.
 */
struct flb_aws_msk_iam *flb_aws_msk_iam_register_oauth_cb(struct flb_config *config,
                                                          rd_kafka_conf_t *kconf,
                                                          const char *cluster_arn);
void flb_aws_msk_iam_destroy(struct flb_aws_msk_iam *ctx);

#endif
