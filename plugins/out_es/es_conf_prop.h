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

#ifndef FLB_OUT_ES_CONF_PROP_H
#define FLB_OUT_ES_CONF_PROP_H

#define FLB_ES_CONFIG_PROPERTY_INDEX                     "index"
#define FLB_ES_CONFIG_PROPERTY_TYPE                      "type"
#define FLB_ES_CONFIG_PROPERTY_SUPPRESS_TYPE_NAME        "suppress_type_name"
#define FLB_ES_CONFIG_PROPERTY_HTTP_USER                 "http_user"
#define FLB_ES_CONFIG_PROPERTY_HTTP_PASSWD               "http_passwd"
#define FLB_ES_CONFIG_PROPERTY_HTTP_API_KEY              "http_api_key"
#define FLB_ES_CONFIG_PROPERTY_COMPRESS                  "compress"
#define FLB_ES_CONFIG_PROPERTY_CLOUD_ID                  "cloud_id"
#define FLB_ES_CONFIG_PROPERTY_CLOUD_AUTH                "cloud_auth"

#ifdef FLB_HAVE_AWS
#define FLB_ES_CONFIG_PROPERTY_AWS_AUTH                  "aws_auth"
#define FLB_ES_CONFIG_PROPERTY_AWS_REGION                "aws_region"
#define FLB_ES_CONFIG_PROPERTY_AWS_STS_ENDPOINT          "aws_sts_endpoint"
#define FLB_ES_CONFIG_PROPERTY_AWS_ROLE_ARN              "aws_role_arn"
#define FLB_ES_CONFIG_PROPERTY_AWS_EXTERNAL_ID           "aws_external_id"
#define FLB_ES_CONFIG_PROPERTY_AWS_SERVICE_NAME          "aws_service_name"
#define FLB_ES_CONFIG_PROPERTY_AWS_PROFILE               "aws_profile"
#endif

#define FLB_ES_CONFIG_PROPERTY_LOGSTASH_FORMAT           "logstash_format"
#define FLB_ES_CONFIG_PROPERTY_LOGSTASH_PREFIX           "logstash_prefix"
#define FLB_ES_CONFIG_PROPERTY_LOGSTASH_PREFIX_SEPARATOR "logstash_prefix_separator"
#define FLB_ES_CONFIG_PROPERTY_LOGSTASH_PREFIX_KEY       "logstash_prefix_key"
#define FLB_ES_CONFIG_PROPERTY_LOGSTASH_DATEFORMAT       "logstash_dateformat"
#define FLB_ES_CONFIG_PROPERTY_TIME_KEY                  "time_key"
#define FLB_ES_CONFIG_PROPERTY_TIME_KEY_FORMAT           "time_key_format"
#define FLB_ES_CONFIG_PROPERTY_TIME_KEY_NANOS            "time_key_nanos"
#define FLB_ES_CONFIG_PROPERTY_INCLUDE_TAG_KEY           "include_tag_key"
#define FLB_ES_CONFIG_PROPERTY_TAG_KEY                   "tag_key"
#define FLB_ES_CONFIG_PROPERTY_BUFFER_SIZE               "buffer_size"
#define FLB_ES_CONFIG_PROPERTY_PATH                      "path"
#define FLB_ES_CONFIG_PROPERTY_PIPELINE                  "pipeline"
#define FLB_ES_CONFIG_PROPERTY_GENERATE_ID               "generate_id"
#define FLB_ES_CONFIG_PROPERTY_WRITE_OPERATION           "write_operation"
#define FLB_ES_CONFIG_PROPERTY_ID_KEY                    "id_key"
#define FLB_ES_CONFIG_PROPERTY_REPLACE_DOTS              "replace_dots"
#define FLB_ES_CONFIG_PROPERTY_CURRENT_TIME_INDEX        "current_time_index"
#define FLB_ES_CONFIG_PROPERTY_TRACE_OUTPUT              "trace_output"
#define FLB_ES_CONFIG_PROPERTY_TRACE_ERROR               "trace_error"
#define FLB_ES_CONFIG_PROPERTY_UPSTREAM                  "upstream"

#endif
