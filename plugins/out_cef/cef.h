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

#ifndef FLB_OUT_CEF_H
#define FLB_OUT_CEF_H

#define FLB_CEF_UDP 0
#define FLB_CEF_TCP 1
#define FLB_CEF_TLS 2

#define FLB_CEF_FMT_RAW 0
#define FLB_CEF_FMT_SYSLOG 1

enum cef_type {
    CEF_STR,
    CEF_INT,
    CEF_IPV4,
    CEF_IPV6,
    CEF_MAC,
    CEF_TIME,
    CEF_LONG,
    CEF_FLOAT
};

enum cef_ftype {
    CEF_SYSLOG_HOST,
    CEF_SYSLOG_FACILITY,
    CEF_SYSLOG_SEVERITY,
    CEF_HDR_DEV_VENDOR,
    CEF_HDR_DEV_PRODUCT,
    CEF_HDR_DEV_VERSION,
    CEF_HDR_DEV_EVENT_CID,
    CEF_HDR_SEVERITY,
    CEF_HDR_NAME,
    CEF_CUSTOM_IPV6,
    CEF_CUSTOM_FLOAT,
    CEF_CUSTOM_NUMBER,
    CEF_CUSTOM_STRING,
    CEF_CUSTOM_DATE,
    CEF_FLEX_DATE,
    CEF_FLEX_STRING,
    CEF_EXTENSION,
    CEF_CUSTOM_EXTENSION
};

struct cef_msg {
    int syslog_facility;
    int syslog_severity;
    flb_sds_t host;
    flb_sds_t dev_vendor;
    flb_sds_t dev_product;
    flb_sds_t dev_version;
    flb_sds_t dev_event_cid;
    flb_sds_t name;
    flb_sds_t severity;
    int ext_cnt;
    flb_sds_t ext;
};

#endif

