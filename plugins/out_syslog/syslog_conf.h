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

#ifndef FLB_OUT_SYSLOG_CONF_H
#define FLB_OUT_SYSLOG_CONF_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pipe.h>


#define FLB_SYSLOG_UDP 0
#define FLB_SYSLOG_TCP 1
#define FLB_SYSLOG_TLS 2

#define FLB_SYSLOG_RFC3164 0
#define FLB_SYSLOG_RFC5424 1

struct flb_syslog_sd_key {
    struct flb_record_accessor *ra_sd_key;
    flb_sds_t key_normalized;           /* normalized key name when using ra */

    struct mk_list _head;
};

struct flb_syslog {
    flb_sockfd_t fd;
    struct flb_upstream *u;
    flb_sds_t mode;
    flb_sds_t format;
    size_t maxsize;

    /* severity_key */
    flb_sds_t severity_key;
    struct flb_record_accessor *ra_severity_key;

    /* facility_key */
    flb_sds_t facility_key;
    struct flb_record_accessor *ra_facility_key;

    /* timestamp_key */
    flb_sds_t timestamp_key;

    /* hostname_key */
    flb_sds_t hostname_key;
    struct flb_record_accessor *ra_hostname_key;

    /* appname_key */
    flb_sds_t appname_key;
    struct flb_record_accessor *ra_appname_key;

    /* procid_key */
    flb_sds_t procid_key;
    struct flb_record_accessor *ra_procid_key;

    /* msgid_key */
    flb_sds_t msgid_key;
    struct flb_record_accessor *ra_msgid_key;

    /* sd_keys */
    struct mk_list *sd_keys;
    int allow_longer_sd_id;
    struct mk_list *ra_sd_keys;

    /* message_key */
    flb_sds_t message_key;
    struct flb_record_accessor *ra_message_key;

    /* Preset */
    int severity_preset;
    int facility_preset;
    flb_sds_t hostname_preset;
    flb_sds_t appname_preset;
    flb_sds_t procid_preset;
    flb_sds_t msgid_preset;

    /* Internal */
    int parsed_mode;
    int parsed_format;
    struct flb_output_instance *ins;
};

struct flb_syslog *flb_syslog_config_create(struct flb_output_instance *ins,
                                            struct flb_config *config);
void flb_syslog_config_destroy(struct flb_syslog *ctx);

#endif
