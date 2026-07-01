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
#include <fluent-bit/flb_pthread.h>

#ifdef FLB_HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#endif

#if defined(FLB_HAVE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#define FLB_FIPS_PROCESS_MODE_UNSET -1

static pthread_mutex_t fips_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static OSSL_PROVIDER *fips_provider;
static OSSL_PROVIDER *base_provider;
static int fips_process_mode = FLB_FIPS_PROCESS_MODE_UNSET;

static void log_openssl_errors(void)
{
    char errbuf[256];
    unsigned long err;

    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, errbuf, sizeof(errbuf));
        flb_error("[fips] OpenSSL error: %s", errbuf);
    }
}

static int fips_provider_is_active(void)
{
    EVP_MD *sha256;

    if (EVP_default_properties_is_fips_enabled(NULL) != 1) {
        return FLB_FALSE;
    }

    sha256 = EVP_MD_fetch(NULL, "SHA256", "fips=yes,provider=fips");
    if (sha256 == NULL) {
        return FLB_FALSE;
    }

    EVP_MD_free(sha256);

    return FLB_TRUE;
}
#endif

int flb_fips_init(struct flb_config *config)
{
#if defined(FLB_HAVE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    int ret;
    int properties_changed;
    OSSL_PROVIDER *new_fips_provider;
    OSSL_PROVIDER *new_base_provider;
#endif

    if (config == NULL) {
        return -1;
    }

#ifndef FLB_HAVE_OPENSSL
    if (config->fips_mode != FLB_TRUE) {
        return 0;
    }

    flb_error("[fips] security.fips_mode requires Fluent Bit to be built with OpenSSL");
    return -1;
#else
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (config->fips_mode != FLB_TRUE) {
        return 0;
    }

    flb_error("[fips] security.fips_mode requires OpenSSL 3.0 or later");
    return -1;
#else
    pthread_mutex_lock(&fips_init_mutex);

    properties_changed = FLB_FALSE;
    new_fips_provider = NULL;
    new_base_provider = NULL;

    if (fips_provider_is_active() == FLB_TRUE) {
        if (fips_process_mode == FLB_FALSE) {
            flb_error("[fips] OpenSSL FIPS mode changed after process initialization");
            pthread_mutex_unlock(&fips_init_mutex);
            return -1;
        }

        if (fips_provider == NULL || base_provider == NULL) {
            ERR_clear_error();
            new_fips_provider = OSSL_PROVIDER_try_load(NULL, "fips", 1);
            if (new_fips_provider == NULL) {
                flb_error("[fips] failed to retain the active OpenSSL FIPS provider");
                log_openssl_errors();
                goto error;
            }

            ERR_clear_error();
            new_base_provider = OSSL_PROVIDER_try_load(NULL, "base", 1);
            if (new_base_provider == NULL) {
                flb_error("[fips] failed to load OpenSSL base provider");
                log_openssl_errors();
                goto error;
            }

            fips_provider = new_fips_provider;
            base_provider = new_base_provider;
        }

        fips_process_mode = FLB_TRUE;
        config->fips_mode_active = FLB_TRUE;
        pthread_mutex_unlock(&fips_init_mutex);
        return 0;
    }

    if (EVP_default_properties_is_fips_enabled(NULL) == 1) {
        flb_error("[fips] OpenSSL FIPS properties are enabled without an active provider");
        pthread_mutex_unlock(&fips_init_mutex);
        return -1;
    }

    if (fips_process_mode == FLB_TRUE) {
        flb_error("[fips] OpenSSL FIPS mode changed after process initialization");
        pthread_mutex_unlock(&fips_init_mutex);
        return -1;
    }

    if (config->fips_mode != FLB_TRUE) {
        fips_process_mode = FLB_FALSE;
        config->fips_mode_active = FLB_FALSE;
        pthread_mutex_unlock(&fips_init_mutex);
        return 0;
    }

    if (fips_process_mode == FLB_FALSE) {
        flb_error("[fips] cannot enable FIPS mode after non-FIPS process initialization");
        pthread_mutex_unlock(&fips_init_mutex);
        return -1;
    }

    ERR_clear_error();
    new_fips_provider = OSSL_PROVIDER_try_load(NULL, "fips", 1);
    if (new_fips_provider == NULL) {
        flb_error("[fips] failed to load OpenSSL FIPS provider");
        log_openssl_errors();
        goto error;
    }

    ERR_clear_error();
    new_base_provider = OSSL_PROVIDER_try_load(NULL, "base", 1);
    if (new_base_provider == NULL) {
        flb_error("[fips] failed to load OpenSSL base provider");
        log_openssl_errors();
        goto error;
    }

    if (EVP_default_properties_is_fips_enabled(NULL) != 1) {
        ERR_clear_error();
        ret = EVP_default_properties_enable_fips(NULL, 1);
        if (ret != 1) {
            flb_error("[fips] failed to enable OpenSSL FIPS default properties");
            log_openssl_errors();
            goto error;
        }
        properties_changed = FLB_TRUE;
    }

    if (fips_provider_is_active() != FLB_TRUE) {
        flb_error("[fips] OpenSSL FIPS provider is not active");
        log_openssl_errors();
        goto error;
    }

    /* Keep the providers loaded because the default OpenSSL context is process-wide. */
    fips_provider = new_fips_provider;
    base_provider = new_base_provider;
    fips_process_mode = FLB_TRUE;
    config->fips_mode_active = FLB_TRUE;

    pthread_mutex_unlock(&fips_init_mutex);
    flb_info("[fips] OpenSSL FIPS mode enabled");

    return 0;

error:
    if (properties_changed == FLB_TRUE) {
        ret = EVP_default_properties_enable_fips(NULL, 0);
        if (ret != 1) {
            flb_error("[fips] failed to restore OpenSSL default properties");
            log_openssl_errors();
        }
    }
    if (new_base_provider != NULL) {
        OSSL_PROVIDER_unload(new_base_provider);
    }
    if (new_fips_provider != NULL) {
        OSSL_PROVIDER_unload(new_fips_provider);
    }

    pthread_mutex_unlock(&fips_init_mutex);
    return -1;
#endif
#endif
}
