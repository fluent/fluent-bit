/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#ifdef FLB_HAVE_TLS
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#endif

struct flb_out_forward_config {
    int secured;              /* Using Secure Forward mode ?  */
    int time_as_integer;      /* Use backward compatible timestamp ? */

    /* config */
    int shared_key_len;       /* shared key length            */
    char *shared_key;         /* shared key                   */
    int self_hostname_len;    /* hostname length              */
    char *self_hostname;      /* hostname used in certificate */

    /* mbedTLS specifics */
#ifdef FLB_HAVE_TLS
    unsigned char shared_key_salt[16];
    mbedtls_entropy_context tls_entropy;
    mbedtls_ctr_drbg_context tls_ctr_drbg;
#endif

    /* Upstream handler */
    struct flb_upstream *u;
};

#endif
