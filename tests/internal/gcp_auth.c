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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_gcp_auth.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>

#include <monkey/mk_core.h>
#ifdef FLB_HAVE_HTTP_SERVER
#include <monkey/mk_lib.h>
#include <monkey/mk_http.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "flb_tests_internal.h"

#define DATA_DIR      FLB_TESTS_DATA_PATH "/data/gcp_auth/"
#define RUNTIME_DATA  FLB_TESTS_DATA_PATH "/../runtime/data/"
#define CREDS_VALID   RUNTIME_DATA "stackdriver/stackdriver-credentials.json"
#define CREDS_EXTRA   RUNTIME_DATA "gcs/gcs-credentials-extra-fields.json"
#define PRIVATE_KEY   RUNTIME_DATA "tls/private_key.pem"
#define NO_PRIVATE_KEY_FILE  DATA_DIR "missing_private_key.json"
#define NO_EMAIL_FILE        DATA_DIR "missing_client_email.json"
#define DUPLICATE_FILE       DATA_DIR "duplicate_keys.json"
#define TOKEN_EMPTY          DATA_DIR "identity_token_empty.txt"

#define ENV_ADC    "GOOGLE_APPLICATION_CREDENTIALS"
#define ENV_LEGACY "GOOGLE_SERVICE_CREDENTIALS"

#ifdef FLB_SYSTEM_WINDOWS
static int flb_test_setenv(const char *name, const char *value, int overwrite)
{
    if (overwrite == 0 && getenv(name) != NULL) {
        return 0;
    }

    return _putenv_s(name, value);
}

static int flb_test_unsetenv(const char *name)
{
    return _putenv_s(name, "");
}
#else
#define flb_test_setenv(name, value, overwrite) setenv(name, value, overwrite)
#define flb_test_unsetenv(name) unsetenv(name)
#endif

struct saved_env {
    char *adc;
    char *legacy;
};

static char *dup_env(const char *name)
{
    const char *val;

    val = getenv(name);
    if (!val) {
        return NULL;
    }

    return strdup(val);
}

static void set_env(const char *name, const char *val)
{
    if (!val) {
        flb_test_unsetenv(name);
        return;
    }
    flb_test_setenv(name, val, 1);
}

/* Saves the credential env vars and clears them for the test body */
static void env_save_and_clear(struct saved_env *s)
{
    s->adc = dup_env(ENV_ADC);
    s->legacy = dup_env(ENV_LEGACY);
    flb_test_unsetenv(ENV_ADC);
    flb_test_unsetenv(ENV_LEGACY);
}

static void env_restore(struct saved_env *s)
{
    set_env(ENV_ADC, s->adc);
    set_env(ENV_LEGACY, s->legacy);
    free(s->adc);
    free(s->legacy);
}

static void base_config(struct flb_gcp_auth_config *cfg, struct flb_config *config)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->config = config;
    cfg->scope = FLB_GCP_SCOPE_STORAGE_READ_WRITE;
    cfg->tls_verify = FLB_TRUE;
    cfg->tls_verify_hostname = FLB_TRUE;
}

static void federation_config(struct flb_gcp_auth_config *cfg,
                              struct flb_config *config)
{
    base_config(cfg, config);
    cfg->identity_federation = FLB_TRUE;
    cfg->project_number = "123456";
    cfg->pool_id = "my-pool";
    cfg->provider_id = "my-provider";
    cfg->identity_token_file = TOKEN_EMPTY;
}

static int write_text_file(const char *path, const char *content)
{
    FILE *fp;
    size_t expected;
    size_t written;

    fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }

    expected = strlen(content);
    written = fwrite(content, 1, expected, fp);
    fclose(fp);

    if (written != expected) {
        return -1;
    }

    return 0;
}

/* Invalid JSON is written at runtime: a checked-in invalid .json trips JSON linters */
static char *invalid_creds_file(void)
{
    char *path;

    path = flb_test_tmpdir_cat("/flb_gcp_auth_invalid_creds.json");
    TEST_CHECK(path != NULL);
    if (path) {
        TEST_CHECK(write_text_file(path, "{ this is not json\n") == 0);
    }
    return path;
}

/* ---- credentials_read ---- */

static int read_creds(const char *path, struct flb_gcp_credentials **out)
{
    int ret;
    struct flb_gcp_credentials *c;

    c = flb_calloc(1, sizeof(struct flb_gcp_credentials));
    if (!c) {
        return -2;
    }

    ret = flb_gcp_credentials_read(path, c);
    *out = c;
    return ret;
}

static void test_credentials_read_valid(void)
{
    int ret;
    struct flb_gcp_credentials *c = NULL;

    ret = read_creds(CREDS_VALID, &c);
    TEST_CHECK(ret == 0);
    TEST_CHECK(c != NULL);
    if (c && ret == 0) {
        TEST_CHECK(strcmp(c->type, "service_account") == 0);
        TEST_CHECK(strcmp(c->project_id, "fluent-bit") == 0);
        TEST_CHECK(strcmp(c->client_email,
                          "stackdriver@fluent-bit.iam.gserviceaccount.com") == 0);
        TEST_CHECK(strncmp(c->private_key, "-----BEGIN PRIVATE KEY-----\n", 28) == 0);
        TEST_CHECK(strcmp(c->client_id, "0123456789") == 0);
        TEST_CHECK(c->token_uri != NULL);
        TEST_CHECK(c->auth_uri != NULL);
    }
    flb_gcp_credentials_destroy(c);
}

static void test_credentials_read_extra_fields(void)
{
    int ret;
    struct flb_gcp_credentials *c = NULL;

    ret = read_creds(CREDS_EXTRA, &c);
    TEST_CHECK(ret == 0);
    if (c && ret == 0) {
        TEST_CHECK(strcmp(c->client_email,
                          "gcs@fluent-bit.iam.gserviceaccount.com") == 0);
    }
    flb_gcp_credentials_destroy(c);
}

static void test_credentials_read_missing_private_key(void)
{
    struct flb_gcp_credentials *c = NULL;

    TEST_CHECK(read_creds(NO_PRIVATE_KEY_FILE, &c) == -1);
    flb_gcp_credentials_destroy(c);
}

static void test_credentials_read_missing_client_email(void)
{
    struct flb_gcp_credentials *c = NULL;

    TEST_CHECK(read_creds(NO_EMAIL_FILE, &c) == -1);
    flb_gcp_credentials_destroy(c);
}

static void test_credentials_read_invalid_json(void)
{
    char *path;
    struct flb_gcp_credentials *c = NULL;

    path = invalid_creds_file();
    if (!path) {
        return;
    }
    TEST_CHECK(read_creds(path, &c) == -1);
    flb_gcp_credentials_destroy(c);
    remove(path);
    flb_free(path);
}

/* only top-level keys are credentials: nested objects must not override them */
static void test_credentials_read_nested_keys_ignored(void)
{
    char *path;
    struct flb_gcp_credentials *c = NULL;

    path = flb_test_tmpdir_cat("/flb_gcp_auth_nested_creds.json");
    TEST_CHECK(path != NULL);
    if (!path) {
        return;
    }
    TEST_CHECK(write_text_file(path,
                               "{\"type\":\"service_account\",\"client_email\":\"first@x\","
                               "\"private_key\":\"top-key\",\"client_email\":\"top@x\","
                               "\"extra\":{\"extra\":{\"client_email\":\"nested@x\","
                               "\"private_key\":\"zzz\",\"type\":\"nested\"}},"
                               "\"list\":[{\"client_email\":\"in-list@x\"}]}") == 0);

    TEST_CHECK(read_creds(path, &c) == 0);
    if (c) {
        TEST_CHECK(strcmp(c->client_email, "top@x") == 0);
        TEST_CHECK(strcmp(c->private_key, "top-key") == 0);
        TEST_CHECK(strcmp(c->type, "service_account") == 0);
    }
    flb_gcp_credentials_destroy(c);
    remove(path);
    flb_free(path);
}

static void test_credentials_read_nonexistent(void)
{
    struct flb_gcp_credentials *c = NULL;

    TEST_CHECK(read_creds(DATA_DIR "does-not-exist.json", &c) == -1);
    flb_gcp_credentials_destroy(c);
}

static void test_credentials_read_directory(void)
{
    struct flb_gcp_credentials *c = NULL;

    TEST_CHECK(read_creds(DATA_DIR, &c) == -1);
    flb_gcp_credentials_destroy(c);
}

static void test_credentials_read_duplicate_keys(void)
{
    int ret;
    struct flb_gcp_credentials *c = NULL;

    /* last value wins and nothing leaks */
    ret = read_creds(DUPLICATE_FILE, &c);
    TEST_CHECK(ret == 0);
    if (c && ret == 0) {
        TEST_CHECK(strcmp(c->client_email, "d@e.f") == 0);
    }
    flb_gcp_credentials_destroy(c);
}

static void test_credentials_destroy_null(void)
{
    flb_gcp_credentials_destroy(NULL);
    TEST_CHECK(1);
}

/* ---- jwt_encode ---- */

static void check_jwt_shape(const char *jwt)
{
    int dots = 0;
    const char *p;

    for (p = jwt; *p; p++) {
        if (*p == '.') {
            dots++;
        }
        else {
            TEST_CHECK(*p != '=' && *p != '+' && *p != '/');
        }
    }
    TEST_CHECK(dots == 2);
}

static void test_jwt_encode(void)
{
    int ret;
    char *key;
    char *jwt1 = NULL;
    char *jwt2 = NULL;
    char *jwt3 = NULL;
    size_t size1 = 0;
    size_t size2 = 0;
    size_t size3 = 0;

    key = mk_file_to_buffer(PRIVATE_KEY);
    TEST_CHECK(key != NULL);
    if (!key) {
        return;
    }

    ret = flb_gcp_jwt_encode("{\"sub\":\"fluent-bit\"}", key, &jwt1, &size1);
    TEST_CHECK(ret == 0);
    ret = flb_gcp_jwt_encode("{\"sub\":\"fluent-bit\"}", key, &jwt2, &size2);
    TEST_CHECK(ret == 0);
    ret = flb_gcp_jwt_encode("{\"sub\":\"other\"}", key, &jwt3, &size3);
    TEST_CHECK(ret == 0);

    if (jwt1 && jwt2 && jwt3) {
        TEST_CHECK(size1 == flb_sds_len(jwt1));
        check_jwt_shape(jwt1);
        /* RSA PKCS1 v1.5 is deterministic */
        TEST_CHECK(strcmp(jwt1, jwt2) == 0);
        TEST_CHECK(strcmp(jwt1, jwt3) != 0);
        /* header is {"alg": "RS256", "typ": "JWT"} */
        TEST_CHECK(strncmp(jwt1, "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.", 41) == 0);
    }

    if (jwt1) {
        flb_sds_destroy(jwt1);
    }
    if (jwt2) {
        flb_sds_destroy(jwt2);
    }
    if (jwt3) {
        flb_sds_destroy(jwt3);
    }
    flb_free(key);
}

static void test_jwt_encode_bad_key(void)
{
    int ret;
    char *jwt = NULL;
    size_t size = 0;

    ret = flb_gcp_jwt_encode("{}", "not a pem key", &jwt, &size);
    TEST_CHECK(ret == -1);
}

/* ---- utc_to_epoch ---- */

static void test_utc_to_epoch(void)
{
    TEST_CHECK(flb_gcp_utc_to_epoch(1970, 1, 1, 0, 0, 0) == 0);
    TEST_CHECK(flb_gcp_utc_to_epoch(2000, 2, 29, 12, 34, 56) == 951827696);
    TEST_CHECK(flb_gcp_utc_to_epoch(1969, 12, 31, 23, 59, 59) == -1);
    TEST_CHECK(flb_gcp_utc_to_epoch(1960, 1, 1, 0, 0, 0) == -315619200);
    if (sizeof(time_t) >= 8) {
        TEST_CHECK(flb_gcp_utc_to_epoch(2038, 1, 19, 3, 14, 8) == 2147483648LL);
    }
}

/* ---- create validation ---- */

static void test_create_null_and_missing_scope(void)
{
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct flb_gcp_auth *ctx;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();
    TEST_CHECK(config != NULL);

    TEST_CHECK(flb_gcp_auth_create(NULL) == NULL);

    base_config(&cfg, config);
    cfg.scope = NULL;
    TEST_CHECK(flb_gcp_auth_create(&cfg) == NULL);

    base_config(&cfg, config);
    cfg.scope = "";
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx == NULL);

    base_config(&cfg, NULL);
    TEST_CHECK(flb_gcp_auth_create(&cfg) == NULL);

    flb_config_exit(config);
    env_restore(&env);
}

static void test_create_federation_missing_fields(void)
{
    int i;
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();
    TEST_CHECK(config != NULL);

    for (i = 0; i < 4; i++) {
        federation_config(&cfg, config);
        switch (i) {
        case 0:
            cfg.project_number = NULL;
            break;
        case 1:
            cfg.pool_id = NULL;
            break;
        case 2:
            cfg.provider_id = NULL;
            break;
        case 3:
            cfg.identity_token_file = NULL;
            break;
        }
        TEST_CHECK(flb_gcp_auth_create(&cfg) == NULL);
        TEST_MSG("missing federation field index=%d was accepted", i);
    }

    flb_config_exit(config);
    env_restore(&env);
}

static void test_create_credentials_and_federation_conflict(void)
{
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();

    federation_config(&cfg, config);
    cfg.credentials_file = CREDS_VALID;
    TEST_CHECK(flb_gcp_auth_create(&cfg) == NULL);

    flb_config_exit(config);
    env_restore(&env);
}

static void test_create_with_credentials_file(void)
{
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct flb_gcp_auth *ctx;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();

    base_config(&cfg, config);
    cfg.credentials_file = CREDS_VALID;
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(flb_gcp_auth_uses_metadata_server(ctx) == FLB_FALSE);
        TEST_CHECK(flb_gcp_auth_uses_identity_federation(ctx) == FLB_FALSE);
        flb_gcp_auth_destroy(ctx);
    }

    /* invalid credentials file -> NULL, no leaks */
    base_config(&cfg, config);
    cfg.credentials_file = NO_PRIVATE_KEY_FILE;
    TEST_CHECK(flb_gcp_auth_create(&cfg) == NULL);

    flb_config_exit(config);
    env_restore(&env);
}

static void test_create_metadata_server_fallback(void)
{
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct flb_gcp_auth *ctx;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();

    base_config(&cfg, config);
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(flb_gcp_auth_uses_metadata_server(ctx) == FLB_TRUE);
        TEST_CHECK(flb_gcp_auth_uses_identity_federation(ctx) == FLB_FALSE);
        flb_gcp_auth_destroy(ctx);
    }

    /* custom metadata server */
    cfg.metadata_server = "http://127.0.0.1:1";
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(strcmp(ctx->metadata_server, "http://127.0.0.1:1") == 0);
        flb_gcp_auth_destroy(ctx);
    }

    flb_config_exit(config);
    env_restore(&env);
}

static void test_create_log_prefix(void)
{
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct flb_gcp_auth *ctx;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();

    /* named instance */
    base_config(&cfg, config);
    cfg.log_name = "gcs.0";
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(ctx->log_prefix != NULL);
        if (ctx->log_prefix) {
            TEST_CHECK(strcmp(ctx->log_prefix, "[gcp_auth:gcs.0]") == 0);
        }
        flb_gcp_auth_destroy(ctx);
    }

    /* no name */
    cfg.log_name = NULL;
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(ctx->log_prefix != NULL);
        if (ctx->log_prefix) {
            TEST_CHECK(strcmp(ctx->log_prefix, "[gcp_auth]") == 0);
        }
        flb_gcp_auth_destroy(ctx);
    }

    /* empty name */
    cfg.log_name = "";
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(ctx->log_prefix != NULL);
        if (ctx->log_prefix) {
            TEST_CHECK(strcmp(ctx->log_prefix, "[gcp_auth]") == 0);
        }
        flb_gcp_auth_destroy(ctx);
    }

    flb_config_exit(config);
    env_restore(&env);
}

static void test_create_env_credentials(void)
{
    char *invalid_path;
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct flb_gcp_auth *ctx;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();
    base_config(&cfg, config);

    /* application default credentials */
    flb_test_setenv(ENV_ADC, CREDS_VALID, 1);
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(flb_gcp_auth_uses_metadata_server(ctx) == FLB_FALSE);
        TEST_CHECK(strcmp(ctx->credentials_file, CREDS_VALID) == 0);
        flb_gcp_auth_destroy(ctx);
    }

    /* both set: GOOGLE_APPLICATION_CREDENTIALS wins */
    flb_test_setenv(ENV_LEGACY, DATA_DIR "does-not-exist.json", 1);
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(strcmp(ctx->credentials_file, CREDS_VALID) == 0);
        flb_gcp_auth_destroy(ctx);
    }

    /* legacy only */
    flb_test_unsetenv(ENV_ADC);
    flb_test_setenv(ENV_LEGACY, CREDS_EXTRA, 1);
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(strcmp(ctx->credentials_file, CREDS_EXTRA) == 0);
        flb_gcp_auth_destroy(ctx);
    }

    /* explicit credentials_file beats the environment */
    flb_test_setenv(ENV_ADC, DATA_DIR "does-not-exist.json", 1);
    cfg.credentials_file = CREDS_VALID;
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(strcmp(ctx->credentials_file, CREDS_VALID) == 0);
        flb_gcp_auth_destroy(ctx);
    }

    /* env var pointing to a broken file fails creation */
    cfg.credentials_file = NULL;
    invalid_path = invalid_creds_file();
    if (invalid_path) {
        flb_test_setenv(ENV_ADC, invalid_path, 1);
        TEST_CHECK(flb_gcp_auth_create(&cfg) == NULL);
        remove(invalid_path);
        flb_free(invalid_path);
    }

    /* federation ignores the environment */
    federation_config(&cfg, config);
    flb_test_setenv(ENV_ADC, DATA_DIR "does-not-exist.json", 1);
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(ctx->credentials == NULL);
        flb_gcp_auth_destroy(ctx);
    }

    flb_config_exit(config);
    env_restore(&env);
}

static void test_create_federation(void)
{
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct flb_gcp_auth *ctx;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();

    federation_config(&cfg, config);
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(flb_gcp_auth_uses_identity_federation(ctx) == FLB_TRUE);
        TEST_CHECK(flb_gcp_auth_uses_metadata_server(ctx) == FLB_FALSE);
        TEST_CHECK(strcmp(ctx->sts_audience,
                          "//iam.googleapis.com/projects/123456/locations/global/"
                          "workloadIdentityPools/my-pool/providers/my-provider") == 0);
        TEST_CHECK(ctx->sts_u != NULL);
        TEST_CHECK(ctx->iam_u == NULL);
        TEST_CHECK(strcmp(ctx->subject_token_type,
                          FLB_GCP_STS_SUBJECT_TOKEN_TYPE) == 0);
        flb_gcp_auth_destroy(ctx);
    }

    federation_config(&cfg, config);
    cfg.google_service_account = "sa@proj.iam.gserviceaccount.com";
    cfg.subject_token_type = "urn:custom";
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(ctx->iam_u != NULL);
        TEST_CHECK(strcmp(ctx->subject_token_type, "urn:custom") == 0);
        flb_gcp_auth_destroy(ctx);
    }

    flb_config_exit(config);
    env_restore(&env);
}

static void test_destroy_null_and_get_header_null(void)
{
    flb_gcp_auth_destroy(NULL);
    TEST_CHECK(flb_gcp_auth_get_header(NULL) == NULL);
    TEST_CHECK(flb_gcp_auth_uses_metadata_server(NULL) == FLB_FALSE);
    TEST_CHECK(flb_gcp_auth_uses_identity_federation(NULL) == FLB_FALSE);
}

/* ---- metadata path through the callback seam ---- */

struct fetch_mock {
    int calls;
    int ret;
    const char *response;
};

static int mock_fetch(void *data, flb_sds_t *payload)
{
    flb_sds_t tmp;
    struct fetch_mock *m = data;

    m->calls++;
    if (m->ret != 0) {
        return m->ret;
    }

    tmp = flb_sds_copy(*payload, m->response, strlen(m->response));
    if (!tmp) {
        return -1;
    }
    *payload = tmp;
    return 0;
}

static struct flb_gcp_auth *create_metadata_ctx(struct flb_config *config,
                                                struct fetch_mock *m)
{
    struct flb_gcp_auth_config cfg;

    base_config(&cfg, config);
    cfg.metadata_fetch = mock_fetch;
    cfg.metadata_fetch_data = m;
    return flb_gcp_auth_create(&cfg);
}

static void test_metadata_token_cached(void)
{
    flb_sds_t h1;
    flb_sds_t h2;
    struct flb_config *config;
    struct flb_gcp_auth *ctx;
    struct fetch_mock m = {0, 0,
        "{\"access_token\":\"metadata-token\",\"expires_in\":3600,"
        "\"token_type\":\"Bearer\"}"};
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();
    ctx = create_metadata_ctx(config, &m);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        h1 = flb_gcp_auth_get_header(ctx);
        TEST_CHECK(h1 != NULL);
        if (h1) {
            TEST_CHECK(strcmp(h1, "Bearer metadata-token") == 0);
            flb_sds_destroy(h1);
        }
        TEST_CHECK(m.calls == 1);

        h2 = flb_gcp_auth_get_header(ctx);
        TEST_CHECK(h2 != NULL);
        if (h2) {
            TEST_CHECK(strcmp(h2, "Bearer metadata-token") == 0);
            flb_sds_destroy(h2);
        }
        TEST_CHECK(m.calls == 1);
        flb_gcp_auth_destroy(ctx);
    }

    flb_config_exit(config);
    env_restore(&env);
}

static void test_metadata_token_invalid_response(void)
{
    struct flb_config *config;
    struct flb_gcp_auth *ctx;
    struct fetch_mock m = {0, 0, "{\"invalid\":true}"};
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();
    ctx = create_metadata_ctx(config, &m);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(flb_gcp_auth_get_header(ctx) == NULL);
        TEST_CHECK(m.calls == 1);
        /* failure is not cached: next call retries */
        TEST_CHECK(flb_gcp_auth_get_header(ctx) == NULL);
        TEST_CHECK(m.calls == 2);
        flb_gcp_auth_destroy(ctx);
    }

    flb_config_exit(config);
    env_restore(&env);
}

static void test_metadata_fetch_failure(void)
{
    struct flb_config *config;
    struct flb_gcp_auth *ctx;
    struct fetch_mock m = {0, -1, ""};
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();
    ctx = create_metadata_ctx(config, &m);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(flb_gcp_auth_get_header(ctx) == NULL);
        TEST_CHECK(m.calls == 1);
        flb_gcp_auth_destroy(ctx);
    }

    flb_config_exit(config);
    env_restore(&env);
}

/* ---- token invalidation ---- */

struct fetch_seq_mock {
    int calls;
};

static int mock_fetch_seq(void *data, flb_sds_t *payload)
{
    char tmp[128];
    flb_sds_t out;
    struct fetch_seq_mock *m = data;

    m->calls++;
    snprintf(tmp, sizeof(tmp) - 1,
             "{\"access_token\":\"token-%d\",\"expires_in\":3600,"
             "\"token_type\":\"Bearer\"}", m->calls);
    out = flb_sds_copy(*payload, tmp, strlen(tmp));
    if (!out) {
        return -1;
    }
    *payload = out;
    return 0;
}

static void test_invalidate_token_forces_refetch(void)
{
    flb_sds_t h;
    struct flb_config *config;
    struct flb_gcp_auth *ctx;
    struct flb_gcp_auth_config cfg;
    struct fetch_seq_mock m = {0};
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();
    base_config(&cfg, config);
    cfg.metadata_fetch = mock_fetch_seq;
    cfg.metadata_fetch_data = &m;
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);

    /* NULL-safe */
    flb_gcp_auth_invalidate_token(NULL);

    if (ctx) {
        h = flb_gcp_auth_get_header(ctx);
        TEST_CHECK(h != NULL && strcmp(h, "Bearer token-1") == 0);
        flb_sds_destroy(h);
        TEST_CHECK(m.calls == 1);

        h = flb_gcp_auth_get_header(ctx);
        TEST_CHECK(h != NULL && strcmp(h, "Bearer token-1") == 0);
        flb_sds_destroy(h);
        TEST_CHECK(m.calls == 1);

        flb_gcp_auth_invalidate_token(ctx);

        h = flb_gcp_auth_get_header(ctx);
        TEST_CHECK(h != NULL && strcmp(h, "Bearer token-2") == 0);
        flb_sds_destroy(h);
        TEST_CHECK(m.calls == 2);

        /* cached again after the refetch */
        h = flb_gcp_auth_get_header(ctx);
        TEST_CHECK(h != NULL && strcmp(h, "Bearer token-2") == 0);
        flb_sds_destroy(h);
        TEST_CHECK(m.calls == 2);

        flb_gcp_auth_destroy(ctx);
    }

    flb_config_exit(config);
    env_restore(&env);
}

/* ---- JWT claim ---- */

static void test_jwt_claim_scope(void)
{
    int ret;
    char buf[1024];
    char tiny[16];
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct flb_gcp_auth *ctx;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();

    base_config(&cfg, config);
    cfg.scope = FLB_GCP_SCOPE_STORAGE_READ_ONLY;
    cfg.credentials_file = CREDS_VALID;
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        ret = flb_gcp_auth_build_jwt_claim(ctx, 1000, buf, sizeof(buf));
        TEST_CHECK(ret == 0);
        TEST_CHECK(strstr(buf, "\"scope\": \"" FLB_GCP_SCOPE_STORAGE_READ_ONLY "\"")
                   != NULL);
        TEST_CHECK(strstr(buf, "\"iss\": \"stackdriver@fluent-bit.iam."
                          "gserviceaccount.com\"") != NULL);
        TEST_CHECK(strstr(buf, "\"aud\": \"" FLB_GCP_AUTH_URL "\"") != NULL);
        TEST_CHECK(strstr(buf, "\"iat\": 1000") != NULL);
        TEST_CHECK(strstr(buf, "\"exp\": 4000") != NULL);
        TEST_CHECK(strstr(buf, "read_write") == NULL);

        /* truncation is reported */
        ret = flb_gcp_auth_build_jwt_claim(ctx, 1000, tiny, sizeof(tiny));
        TEST_CHECK(ret == -1);
        flb_gcp_auth_destroy(ctx);
    }

    /* no claim for metadata-server contexts */
    base_config(&cfg, config);
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(flb_gcp_auth_build_jwt_claim(ctx, 1000, buf, sizeof(buf)) == -1);
        flb_gcp_auth_destroy(ctx);
    }

    flb_config_exit(config);
    env_restore(&env);
}

/* ---- federation helpers ---- */

static void test_read_identity_token(void)
{
    int ret;
    char *path;
    flb_sds_t tok = NULL;

    /* created at runtime: git normalizes CR/LF in checked-in fixtures */
    path = flb_test_tmpdir_cat("/flb_gcp_auth_token_trailing_ws.txt");
    TEST_CHECK(path != NULL);
    if (path) {
        ret = write_text_file(path, "token-value \t\r\n\r\n");
        TEST_CHECK(ret == 0);

        ret = flb_gcp_read_identity_token(path, &tok);
        TEST_CHECK(ret == 0);
        if (ret == 0) {
            TEST_CHECK(strcmp(tok, "token-value") == 0);
            flb_sds_destroy(tok);
        }

        remove(path);
        flb_free(path);
    }

    tok = NULL;
    TEST_CHECK(flb_gcp_read_identity_token(TOKEN_EMPTY, &tok) == -1);
    TEST_CHECK(tok == NULL);
    TEST_CHECK(flb_gcp_read_identity_token(DATA_DIR "does-not-exist.txt", &tok) == -1);
    TEST_CHECK(tok == NULL);
}

static void test_federation_expiry(void)
{
    time_t now = 1700000000;
    const char *sts = "{\"access_token\":\"x\",\"expires_in\":3600}";
    const char *sts_no_expiry = "{\"access_token\":\"x\"}";
    const char *sts_short = "{\"access_token\":\"x\",\"expires_in\":100}";
    const char *iam = "{\"accessToken\":\"y\",\"expireTime\":\"2035-01-01T00:00:00Z\"}";
    const char *iam_past = "{\"accessToken\":\"y\",\"expireTime\":\"2001-01-01T00:00:00Z\"}";

    TEST_CHECK(flb_gcp_federation_token_expiry(now, sts, strlen(sts), NULL, 0) ==
               now + 3600 - FLB_GCP_TOKEN_EXPIRY_SAFETY);
    TEST_CHECK(flb_gcp_federation_token_expiry(now, sts_no_expiry,
                                               strlen(sts_no_expiry), NULL, 0) ==
               now + FLB_GCP_TOKEN_REFRESH);
    TEST_CHECK(flb_gcp_federation_token_expiry(now, sts_short, strlen(sts_short),
                                               NULL, 0) == now + 1);

    /* IAM response wins over STS when impersonating */
    TEST_CHECK(flb_gcp_federation_token_expiry(now, sts, strlen(sts), iam,
                                               strlen(iam)) ==
               flb_gcp_utc_to_epoch(2035, 1, 1, 0, 0, 0) -
               FLB_GCP_TOKEN_EXPIRY_SAFETY);
    TEST_CHECK(flb_gcp_federation_token_expiry(now, sts, strlen(sts), iam_past,
                                               strlen(iam_past)) ==
               now + FLB_GCP_TOKEN_REFRESH);
    TEST_CHECK(flb_gcp_federation_token_expiry(now, NULL, 0, NULL, 0) ==
               now + FLB_GCP_TOKEN_REFRESH);
}

static void test_federation_expiry_exact_key_match(void)
{
    int i;
    size_t len;
    char big[2048];
    time_t now = 1700000000;
    time_t want = now + 3600 - FLB_GCP_TOKEN_EXPIRY_SAFETY;
    const char *cases[] = {
        "{\"expires_in_extra\":10,\"expires_in\":3600}",
        "{\"note\":\"expires_in\",\"expires_in\":3600}",
        "{\"nested\":{\"expires_in\":5},\"expires_in\":3600}",
        "{\"list\":[\"expires_in\",7],\"expires_in\":3600}",
        NULL
    };

    for (i = 0; cases[i]; i++) {
        TEST_CHECK(flb_gcp_federation_token_expiry(now, cases[i], strlen(cases[i]),
                                                   NULL, 0) == want);
        TEST_MSG("case %d: %s", i, cases[i]);
    }

    /* a key that only appears as a value or nested does not count */
    TEST_CHECK(flb_gcp_federation_token_expiry(now, "{\"a\":\"expires_in\"}", 21,
                                               NULL, 0) ==
               now + FLB_GCP_TOKEN_REFRESH);
    TEST_CHECK(flb_gcp_federation_token_expiry(now, "{\"n\":{\"expires_in\":5}}", 24,
                                               NULL, 0) ==
               now + FLB_GCP_TOKEN_REFRESH);

    /* more than 50 tokens before the key still works */
    len = snprintf(big, sizeof(big), "{");
    for (i = 0; i < 80; i++) {
        len += snprintf(big + len, sizeof(big) - len, "\"k%d\":\"v%d\",", i, i);
    }
    len += snprintf(big + len, sizeof(big) - len, "\"expires_in\":3600}");
    TEST_CHECK(flb_gcp_federation_token_expiry(now, big, len, NULL, 0) == want);

    /* not an object */
    TEST_CHECK(flb_gcp_federation_token_expiry(now, "[\"expires_in\",3600]", 20,
                                               NULL, 0) ==
               now + FLB_GCP_TOKEN_REFRESH);
}

#ifdef FLB_HAVE_HTTP_SERVER
/* ---- federation through a mock STS / IAM server ---- */

#define MOCK_HOST        "127.0.0.1"
#define MOCK_PORT        18932
#define MOCK_URL         "http://127.0.0.1:18932"
#define MOCK_TOKEN_SIZE  6000
#define MOCK_REQ_SIZE    16384

struct fed_mock {
    mk_ctx_t *mk;
    int vid;
    char sts_token[MOCK_TOKEN_SIZE + 1];
    char iam_token[MOCK_TOKEN_SIZE + 1];
    int sts_hits;
    int iam_hits;
    char sts_body[MOCK_REQ_SIZE];
    char iam_body[MOCK_REQ_SIZE];
    char iam_auth[MOCK_TOKEN_SIZE + 64];
};

static struct fed_mock fm;

static void mock_copy(char *dst, size_t dst_size, const char *src, size_t len)
{
    if (!src) {
        len = 0;
    }
    if (len >= dst_size) {
        len = dst_size - 1;
    }
    if (len > 0) {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
}

static void mock_reply(mk_request_t *request, int status, const char *body, size_t len)
{
    mk_http_status(request, status);
    mk_http_header(request, "Content-Type", 12, "application/json", 16);
    mk_http_send(request, (char *) body, len, NULL);
    mk_http_done(request);
}

static void cb_fed_mock(mk_request_t *request, void *data)
{
    char path[256];
    char *resp;
    size_t n;
    size_t cap = MOCK_TOKEN_SIZE + 128;
    struct mk_http_header *h;
    (void) data;

    mock_copy(path, sizeof(path), request->uri_processed.data, request->uri_processed.len);
    resp = flb_malloc(cap);
    if (!resp) {
        mock_reply(request, 500, "{}", 2);
        return;
    }

    if (strcmp(path, FLB_GCP_STS_TOKEN_ENDPOINT) == 0) {
        fm.sts_hits++;
        mock_copy(fm.sts_body, sizeof(fm.sts_body), request->data.data, request->data.len);
        n = snprintf(resp, cap, "{\"access_token\":\"%s\",\"token_type\":\"Bearer\","
                     "\"expires_in\":3600}", fm.sts_token);
        mock_reply(request, 200, resp, n);
    }
    else if (strstr(path, ":generateAccessToken") != NULL) {
        fm.iam_hits++;
        mock_copy(fm.iam_body, sizeof(fm.iam_body), request->data.data, request->data.len);
        h = mk_http_header_get(MK_HEADER_AUTHORIZATION, request, NULL, 0);
        mock_copy(fm.iam_auth, sizeof(fm.iam_auth), h ? h->val.data : NULL,
                  h ? h->val.len : 0);
        n = snprintf(resp, cap, "{\"accessToken\":\"%s\","
                     "\"expireTime\":\"2035-01-01T00:00:00Z\"}", fm.iam_token);
        mock_reply(request, 200, resp, n);
    }
    else {
        mock_reply(request, 404, "{}", 2);
    }
    flb_free(resp);
}

static void fed_mock_begin(void)
{
    char addr[64];

    memset(&fm, 0, sizeof(fm));
    memset(fm.sts_token, 'S', MOCK_TOKEN_SIZE);
    memset(fm.iam_token, 'I', MOCK_TOKEN_SIZE);

    fm.mk = mk_create();
    TEST_CHECK(fm.mk != NULL);
    snprintf(addr, sizeof(addr), "%s:%d", MOCK_HOST, MOCK_PORT);
    mk_config_set(fm.mk, "Listen", addr, NULL);
    fm.vid = mk_vhost_create(fm.mk, NULL);
    mk_vhost_set(fm.mk, fm.vid, "Name", "fake-sts", NULL);
    mk_vhost_handler(fm.mk, fm.vid, "/", cb_fed_mock, NULL);
    mk_start(fm.mk);
}

static void fed_mock_end(void)
{
    mk_stop(fm.mk);
    mk_destroy(fm.mk);
}

/* Token file created at runtime; returns an allocated path */
static char *fed_token_file(void)
{
    char *path;

    path = flb_test_tmpdir_cat("/flb_gcp_auth_fed_token.txt");
    TEST_CHECK(path != NULL);
    if (path) {
        TEST_CHECK(write_text_file(path, "subject-jwt\n") == 0);
    }
    return path;
}

/* Direct federation: the STS token is used as is, with the configured scope */
static void test_federation_direct_large_token(void)
{
    char *path;
    char expected[MOCK_TOKEN_SIZE + 16];
    flb_sds_t header;
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct flb_gcp_auth *ctx;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();
    path = fed_token_file();
    fed_mock_begin();

    federation_config(&cfg, config);
    cfg.scope = FLB_GCP_SCOPE_STORAGE_READ_ONLY;
    cfg.identity_token_file = path;
    cfg.sts_url = MOCK_URL;
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        header = flb_gcp_auth_get_header(ctx);
        TEST_CHECK(header != NULL);
        if (header) {
            snprintf(expected, sizeof(expected), "Bearer %s", fm.sts_token);
            TEST_CHECK(strcmp(header, expected) == 0);
            flb_sds_destroy(header);
        }
        TEST_CHECK(fm.sts_hits == 1);
        TEST_CHECK(fm.iam_hits == 0);
        TEST_CHECK(strstr(fm.sts_body, "\"audience\":\"//iam.googleapis.com/projects/"
                          "123456/locations/global/workloadIdentityPools/my-pool/"
                          "providers/my-provider\"") != NULL);
        TEST_CHECK(strstr(fm.sts_body, "\"subjectToken\":\"subject-jwt\"") != NULL);
        TEST_CHECK(strstr(fm.sts_body, "\"scope\":\"" FLB_GCP_SCOPE_STORAGE_READ_ONLY
                          "\"") != NULL);
        TEST_CHECK(strstr(fm.sts_body, FLB_GCP_STS_SCOPE) == NULL);
        flb_gcp_auth_destroy(ctx);
    }

    fed_mock_end();
    remove(path);
    flb_free(path);
    flb_config_exit(config);
    env_restore(&env);
}

/* Impersonation: cloud-platform for STS, the configured scope for generateAccessToken */
static void test_federation_impersonation_large_token(void)
{
    char *path;
    char expected[MOCK_TOKEN_SIZE + 16];
    flb_sds_t header;
    struct flb_config *config;
    struct flb_gcp_auth_config cfg;
    struct flb_gcp_auth *ctx;
    struct saved_env env;

    env_save_and_clear(&env);
    config = flb_config_init();
    path = fed_token_file();
    fed_mock_begin();

    federation_config(&cfg, config);
    cfg.scope = FLB_GCP_SCOPE_STORAGE_READ_ONLY;
    cfg.identity_token_file = path;
    cfg.google_service_account = "sa@proj.iam.gserviceaccount.com";
    cfg.sts_url = MOCK_URL;
    cfg.iam_url = MOCK_URL;
    ctx = flb_gcp_auth_create(&cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        header = flb_gcp_auth_get_header(ctx);
        TEST_CHECK(header != NULL);
        if (header) {
            snprintf(expected, sizeof(expected), "Bearer %s", fm.iam_token);
            TEST_CHECK(strcmp(header, expected) == 0);
            flb_sds_destroy(header);
        }
        TEST_CHECK(fm.sts_hits == 1);
        TEST_CHECK(fm.iam_hits == 1);
        TEST_CHECK(strstr(fm.sts_body, "\"scope\":\"" FLB_GCP_STS_SCOPE "\"") != NULL);
        snprintf(expected, sizeof(expected), "Bearer %s", fm.sts_token);
        TEST_CHECK(strcmp(fm.iam_auth, expected) == 0);
        TEST_CHECK(strstr(fm.iam_body, FLB_GCP_SCOPE_STORAGE_READ_ONLY) != NULL);
        TEST_CHECK(strstr(fm.iam_body, FLB_GCP_STS_SCOPE) == NULL);
        flb_gcp_auth_destroy(ctx);
    }

    fed_mock_end();
    remove(path);
    flb_free(path);
    flb_config_exit(config);
    env_restore(&env);
}
#endif /* FLB_HAVE_HTTP_SERVER */

TEST_LIST = {
    {"credentials_read_valid", test_credentials_read_valid},
    {"credentials_read_extra_fields", test_credentials_read_extra_fields},
    {"credentials_read_missing_private_key", test_credentials_read_missing_private_key},
    {"credentials_read_missing_client_email", test_credentials_read_missing_client_email},
    {"credentials_read_invalid_json", test_credentials_read_invalid_json},
    {"credentials_read_nested_keys_ignored", test_credentials_read_nested_keys_ignored},
    {"credentials_read_nonexistent", test_credentials_read_nonexistent},
    {"credentials_read_directory", test_credentials_read_directory},
    {"credentials_read_duplicate_keys", test_credentials_read_duplicate_keys},
    {"credentials_destroy_null", test_credentials_destroy_null},
    {"jwt_encode", test_jwt_encode},
    {"jwt_encode_bad_key", test_jwt_encode_bad_key},
    {"utc_to_epoch", test_utc_to_epoch},
    {"create_null_and_missing_scope", test_create_null_and_missing_scope},
    {"create_federation_missing_fields", test_create_federation_missing_fields},
    {"create_credentials_and_federation_conflict",
     test_create_credentials_and_federation_conflict},
    {"create_with_credentials_file", test_create_with_credentials_file},
    {"create_log_prefix", test_create_log_prefix},
    {"create_metadata_server_fallback", test_create_metadata_server_fallback},
    {"create_env_credentials", test_create_env_credentials},
    {"create_federation", test_create_federation},
    {"destroy_null_and_get_header_null", test_destroy_null_and_get_header_null},
    {"metadata_token_cached", test_metadata_token_cached},
    {"metadata_token_invalid_response", test_metadata_token_invalid_response},
    {"metadata_fetch_failure", test_metadata_fetch_failure},
    {"invalidate_token_forces_refetch", test_invalidate_token_forces_refetch},
    {"jwt_claim_scope", test_jwt_claim_scope},
    {"read_identity_token", test_read_identity_token},
    {"federation_expiry", test_federation_expiry},
    {"federation_expiry_exact_key_match", test_federation_expiry_exact_key_match},
#ifdef FLB_HAVE_HTTP_SERVER
    {"federation_direct_large_token", test_federation_direct_large_token},
    {"federation_impersonation_large_token", test_federation_impersonation_large_token},
#endif
    {NULL, NULL}
};
