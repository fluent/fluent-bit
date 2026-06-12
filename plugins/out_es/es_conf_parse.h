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

#ifndef FLB_OUT_ES_CONF_PARSE_H
#define FLB_OUT_ES_CONF_PARSE_H

struct flb_config;
struct flb_elasticsearch;
struct flb_elasticsearch_config;

/*
 * flb_es_conf_set_cloud_credentials gets a cloud_auth
 * and sets the context's cloud_user and cloud_passwd.
 * Example:
 *   cloud_auth = elastic:ZXVyb3BxxxxxxZTA1Ng
 *   ---->
 *   cloud_user = elastic
 *   cloud_passwd = ZXVyb3BxxxxxxZTA1Ng
 */
int flb_es_conf_set_cloud_credentials(const char *cloud_auth,
                                      struct flb_elasticsearch_config *ec);

int flb_es_conf_set_cloud_auth(const char *cloud_auth, struct flb_elasticsearch *ctx);

#ifdef FLB_HAVE_AWS

int flb_es_set_aws_unsigned_headers(struct flb_elasticsearch_config *ec);

int flb_es_conf_set_aws_provider(const char *aws_external_id,
                                 const char *aws_role_arn,
                                 struct flb_elasticsearch_config *ec,
                                 struct flb_elasticsearch *ctx,
                                 struct flb_config *config);

#endif

#endif
