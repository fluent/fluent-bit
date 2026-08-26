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

#include <string.h>
#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_crypto_constants.h>
#include <fluent-bit/flb_fips.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_hmac.h>
#ifdef FLB_TEST_FIPS_S3
#include <fluent-bit.h>
#endif

#if defined(FLB_HAVE_OPENSSL)
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/evp.h>
#include <openssl/provider.h>
#endif
#endif

#include "flb_tests_internal.h"

static int hash_payload(int hash_type, unsigned char *digest, size_t digest_size)
{
    const char *payload = "fips-provider-state";

    return flb_hash_simple(hash_type,
                           (unsigned char *) payload, strlen(payload),
                           digest, digest_size);
}

static void check_md5_available(void)
{
    int ret;
    struct flb_hmac hmac_context;
    unsigned char digest[32];
    const unsigned char key[] = "fips-test-key";

    ret = hash_payload(FLB_HASH_MD5, digest, sizeof(digest));
    TEST_CHECK(ret == FLB_CRYPTO_SUCCESS);

    ret = flb_hmac_init(&hmac_context, FLB_HASH_MD5,
                        (unsigned char *) key, sizeof(key) - 1);
    TEST_CHECK(ret == FLB_CRYPTO_SUCCESS);
    if (ret == FLB_CRYPTO_SUCCESS) {
        flb_hmac_cleanup(&hmac_context);
    }
}

static void check_fips_algorithms(void)
{
    int ret;
    struct flb_hash hash_context;
    struct flb_hmac hmac_context;
    unsigned char digest[32];
    const unsigned char key[] = "fips-test-key";

    ret = hash_payload(FLB_HASH_SHA256, digest, sizeof(digest));
    TEST_CHECK(ret == FLB_CRYPTO_SUCCESS);

    ret = flb_hash_init(&hash_context, FLB_HASH_MD5);
    TEST_CHECK(ret == FLB_CRYPTO_BACKEND_ERROR);
    TEST_CHECK(hash_context.backend_context == NULL);

    ret = flb_hmac_init(&hmac_context, FLB_HASH_MD5,
                        (unsigned char *) key, sizeof(key) - 1);
    TEST_CHECK(ret == FLB_CRYPTO_BACKEND_ERROR);
    TEST_CHECK(hmac_context.backend_context == NULL);
#if FLB_CRYPTO_OPENSSL_COMPAT_MODE >= 3
    TEST_CHECK(hmac_context.mac_algorithm == NULL);
#endif
}

#ifdef FLB_TEST_FIPS_S3
static void check_s3_content_md5_rejected(void)
{
    int ret;
    int input_id;
    int output_id;
    flb_ctx_t *ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    input_id = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(input_id >= 0);
    if (input_id < 0) {
        flb_destroy(ctx);
        return;
    }
    ret = flb_input_set(ctx, input_id, "tag", "fips.test", NULL);
    TEST_CHECK(ret == 0);

    output_id = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(output_id >= 0);
    if (output_id < 0) {
        flb_destroy(ctx);
        return;
    }

    ret = flb_output_set(ctx, output_id,
                         "match", "*",
                         "region", "us-east-1",
                         "bucket", "fips-test",
                         "send_content_md5", "true",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == -1);
    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}
#endif

#if defined(FLB_HAVE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
struct fips_test_provider_state {
    int base_loaded;
    int fips_loaded;
};

static int collect_provider_state(OSSL_PROVIDER *provider, void *data)
{
    const char *name;
    struct fips_test_provider_state *state;

    state = data;
    name = OSSL_PROVIDER_get0_name(provider);
    if (name == NULL) {
        return 1;
    }

    if (strcmp(name, "base") == 0) {
        state->base_loaded = FLB_TRUE;
    }
    else if (strcmp(name, "fips") == 0) {
        state->fips_loaded = FLB_TRUE;
    }

    return 1;
}
#endif

void test_fips_environment(void)
{
    int ret;
    struct flb_config config;
    struct flb_config second_config;
    const char *mode;
#if defined(FLB_HAVE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER *preenabled_provider;
    struct fips_test_provider_state provider_state;
#endif

    memset(&config, 0, sizeof(config));
    memset(&second_config, 0, sizeof(second_config));

    TEST_CHECK(flb_fips_init(NULL) == -1);

    mode = getenv("FLB_TEST_FIPS_MODE");
    if (mode == NULL || mode[0] == '\0') {
        config.fips_mode = FLB_FALSE;
        ret = flb_fips_init(&config);
        TEST_CHECK(ret == 0);

        if (config.fips_mode_active == FLB_TRUE) {
            check_fips_algorithms();
        }
        else {
            check_md5_available();
        }
        return;
    }

    if (strcmp(mode, "disabled") == 0) {
        config.fips_mode = FLB_FALSE;
        ret = flb_fips_init(&config);
        TEST_CHECK(ret == 0);
        TEST_CHECK(config.fips_mode_active == FLB_FALSE);

        check_md5_available();

        config.fips_mode = FLB_TRUE;
        ret = flb_fips_init(&config);
        TEST_CHECK(ret == -1);
        return;
    }

    if (strcmp(mode, "preenabled") == 0) {
#if defined(FLB_HAVE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
        preenabled_provider = OSSL_PROVIDER_load(NULL, "fips");
        TEST_CHECK(preenabled_provider != NULL);
        if (preenabled_provider == NULL) {
            return;
        }

        ret = EVP_default_properties_enable_fips(NULL, 1);
        TEST_CHECK(ret == 1);
        if (ret != 1) {
            OSSL_PROVIDER_unload(preenabled_provider);
            return;
        }

        config.fips_mode = FLB_FALSE;
        ret = flb_fips_init(&config);
        TEST_CHECK(ret == 0);
        TEST_CHECK(config.fips_mode_active == FLB_TRUE);
        if (ret != 0) {
            OSSL_PROVIDER_unload(preenabled_provider);
            return;
        }

        OSSL_PROVIDER_unload(preenabled_provider);

        memset(&provider_state, 0, sizeof(provider_state));
        ret = OSSL_PROVIDER_do_all(NULL, collect_provider_state, &provider_state);
        TEST_CHECK(ret == 1);
        TEST_CHECK(provider_state.fips_loaded == FLB_TRUE);
        TEST_CHECK(provider_state.base_loaded == FLB_TRUE);

        check_fips_algorithms();
#ifdef FLB_TEST_FIPS_S3
        check_s3_content_md5_rejected();
#endif
#else
        TEST_MSG("preenabled mode requires OpenSSL 3.0 or later");
        TEST_CHECK(0);
#endif
        return;
    }

    config.fips_mode = FLB_TRUE;
    ret = flb_fips_init(&config);

    if (strcmp(mode, "unavailable") == 0) {
        TEST_CHECK(ret == -1);
        TEST_CHECK(config.fips_mode_active == FLB_FALSE);

        config.fips_mode = FLB_FALSE;
        ret = flb_fips_init(&config);
        TEST_CHECK(ret == 0);

        check_md5_available();
        return;
    }

    if (strcmp(mode, "enabled") == 0) {
        TEST_CHECK(ret == 0);
        TEST_CHECK(config.fips_mode_active == FLB_TRUE);

        check_fips_algorithms();
#ifdef FLB_TEST_FIPS_S3
        check_s3_content_md5_rejected();
#endif

        second_config.fips_mode = FLB_FALSE;
        ret = flb_fips_init(&second_config);
        TEST_CHECK(ret == 0);
        TEST_CHECK(second_config.fips_mode_active == FLB_TRUE);
        return;
    }

    TEST_MSG("unknown FLB_TEST_FIPS_MODE value: %s", mode);
    TEST_CHECK(0);
}

TEST_LIST = {
    {"fips_environment", test_fips_environment},
    {0}
};
