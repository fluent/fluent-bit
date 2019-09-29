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

#ifndef FLB_OUT_SYSLOG_H
#define FLB_OUT_SYSLOG_H

#define FLB_SYSLOG_UDP 0
#define FLB_SYSLOG_TCP 1
#define FLB_SYSLOG_TLS 2

#define FLB_SYSLOG_RFC3164 0
#define FLB_SYSLOG_RFC5424 1

struct out_syslog_config {
    flb_sockfd_t fd;
    struct flb_upstream *u;
    int mode;
    int format;
    int maxsize;
    flb_sds_t severity_key;
    flb_sds_t facility_key;
    flb_sds_t timestamp_key;
    flb_sds_t hostname_key;
    flb_sds_t appname_key;
    flb_sds_t procid_key;
    flb_sds_t msgid_key;
    int nsd;
    flb_sds_t *sd_key;
    flb_sds_t message_key;
};

struct out_syslog_config *out_syslog_config_create(struct flb_output_instance *ins,
                                                   struct flb_config *config);
void out_syslog_config_destroy (struct out_syslog_config *ctx);

#endif
