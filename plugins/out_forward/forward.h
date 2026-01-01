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

#ifndef FLB_OUT_FORWARD
#define FLB_OUT_FORWARD

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_pthread.h>
#include <cfl/cfl_list.h>

/*
 * Forward modes
 * =============
 */

/*
 * Message mode
 * ------------
 * https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1#message-modes
 */
#define MODE_MESSAGE               0

/*
 * Forward mode
 * ------------
 * https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1#forward-mode
 */
#define MODE_FORWARD               1

/*
 * Forward Compat: similar to MODE_FORWARD, but it sends the timestamps as unsigned
 * integers for compatibility with very old versions of Fluentd that don't have timestamps
 * with nanoseconds. This mode only applies for Logs.
 */
#define MODE_FORWARD_COMPAT        3

/* Compression options */
#define COMPRESS_NONE              0
#define COMPRESS_GZIP              1

/*
 * Configuration: we put this separate from the main
 * context so every Upstream Node can have it own configuration
 * reference and pass it smoothly to the required caller.
 *
 * On simple mode (no HA), the structure is referenced
 * by flb_forward->config. In HA mode the structure is referenced
 * by the Upstream node context as an opaque data type.
 */
struct flb_forward_config {
    int secured;              /* Using Secure Forward mode ?  */
    int compress;             /* Using compression ? */
    int time_as_integer;      /* Use backward compatible timestamp ? */
    int fluentd_compat;       /* Use Fluentd compatible payload for
                               * metrics and ctraces */

    /* add extra options to the Forward payload (advanced) */
    struct mk_list *extra_options;

    int fwd_retain_metadata;  /* Do not drop metadata in forward mode */

    /* config */
    flb_sds_t shared_key;        /* shared key                   */
    flb_sds_t self_hostname;     /* hostname used in certificate  */
    flb_sds_t tag;               /* Overwrite tag on forward */
    int empty_shared_key;        /* use an empty string as shared key */
    int require_ack_response;    /* Require acknowledge for "chunk" */
    int send_options;            /* send options in messages */
    flb_sds_t unix_path;         /* unix socket path */
    int       unix_fd;

    const char *username;
    const char *password;

    /* mbedTLS specifics */
    unsigned char shared_key_salt[16];

#ifdef FLB_HAVE_RECORD_ACCESSOR
    struct flb_record_accessor *ra_tag; /* Tag Record accessor */
    int ra_static;                      /* Is the record accessor static ? */
#endif
    int (*io_write)(struct flb_connection* conn, int fd, const void* data,
                        size_t len, size_t *out_len);
    int (*io_read)(struct flb_connection* conn, int fd, void* buf, size_t len);
    struct mk_list _head;     /* Link to list flb_forward->configs */
};

struct flb_forward_uds_connection {
    flb_sockfd_t    descriptor;
    struct cfl_list _head;     /* Link to list flb_forward->uds_connnection_list */
};

/* Plugin Context */
struct flb_forward {
    /* if HA mode is enabled */
    int ha_mode;              /* High Availability mode enabled ? */
    char *ha_upstream;        /* Upstream configuration file      */
    struct flb_upstream_ha *ha;

    struct cfl_list uds_connection_list;
    pthread_mutex_t uds_connection_list_mutex;

    /* Upstream handler and config context for single mode (no HA) */
    struct flb_upstream *u;
    struct mk_list configs;
    struct flb_output_instance *ins;
};

struct flb_forward_ping {
    const char *nonce;
    int nonce_len;
    const char *auth;
    int auth_len;
    int keepalive;
};

/* Flush callback context */
struct flb_forward_flush {
    struct flb_forward_config *fc;
    char checksum_hex[33];
};

struct flb_forward_config *flb_forward_target(struct flb_forward *ctx,
                                              struct flb_upstream_node **node);

#endif
