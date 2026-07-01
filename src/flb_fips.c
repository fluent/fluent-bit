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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_fips.h>

#ifdef FLB_HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#endif

static void log_openssl_error(void)
{
#ifdef FLB_HAVE_OPENSSL
    char errbuf[256];
    unsigned long err;

    err = ERR_get_error();
    if (err != 0) {
        ERR_error_string_n(err, errbuf, sizeof(errbuf));
        flb_error("[fips] OpenSSL error: %s", errbuf);
    }
#endif
}

int flb_fips_init(struct flb_config *config)
{
    int ret;

    if (config == NULL) {
        return -1;
    }

    if (config->fips_mode != FLB_TRUE) {
        return 0;
    }

    if (config->fips_mode_active == FLB_TRUE) {
        return 0;
    }

#ifndef FLB_HAVE_OPENSSL
    flb_error("[fips] FIPS_Mode requires Fluent Bit to be built with OpenSSL");
    return -1;
#else
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    flb_error("[fips] FIPS_Mode requires OpenSSL 3.0 or later");
    return -1;
#else
    if (OSSL_PROVIDER_load(NULL, "base") == NULL) {
        flb_error("[fips] failed to load OpenSSL base provider");
        log_openssl_error();
        return -1;
    }

    if (OSSL_PROVIDER_load(NULL, "fips") == NULL) {
        flb_error("[fips] failed to load OpenSSL FIPS provider");
        log_openssl_error();
        return -1;
    }

    ret = EVP_default_properties_enable_fips(NULL, 1);
    if (ret != 1) {
        flb_error("[fips] failed to enable OpenSSL FIPS default properties");
        log_openssl_error();
        return -1;
    }

    ret = EVP_default_properties_is_fips_enabled(NULL);
    if (ret != 1) {
        flb_error("[fips] OpenSSL FIPS default properties are not enabled");
        return -1;
    }

    config->fips_mode_active = FLB_TRUE;
    flb_info("[fips] OpenSSL FIPS mode enabled");

    return 0;
#endif
#endif
}
