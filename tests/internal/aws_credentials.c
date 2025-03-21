/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>

#include "flb_tests_internal.h"

#define ACCESS_KEY "akid"
#define SECRET_KEY "skid"
#define TOKEN      "token"

/* Credentials Environment Variables */
#define AWS_ACCESS_KEY_ID              "AWS_ACCESS_KEY_ID"
#define AWS_SECRET_ACCESS_KEY          "AWS_SECRET_ACCESS_KEY"
#define AWS_SESSION_TOKEN              "AWS_SESSION_TOKEN"


static void unsetenv_credentials()
{
    int ret;

    ret = unsetenv(AWS_ACCESS_KEY_ID);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = unsetenv(AWS_SECRET_ACCESS_KEY);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = unsetenv(AWS_SESSION_TOKEN);
    if (ret < 0) {
        flb_errno();
        return;
    }
}

/* test for the env provider */
static void test_environment_provider()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, ACCESS_KEY, 1);
    if (ret < 0) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, SECRET_KEY, 1);
    if (ret < 0) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    ret = setenv(AWS_SESSION_TOKEN, TOKEN, 1);
    if (ret < 0) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    provider = flb_aws_env_provider_create();
    if (!provider) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    unsetenv_credentials();

    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
}

/* token is not required */
static void test_environment_provider_no_token()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, ACCESS_KEY, 1);
    if (ret < 0) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, SECRET_KEY, 1);
    if (ret < 0) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    provider = flb_aws_env_provider_create();
    if (!provider) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(creds->session_token == NULL);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(creds->session_token == NULL);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    unsetenv_credentials();

    flb_aws_provider_destroy(provider);
        flb_config_exit(config);
}

/* access and secret key are required */
static void test_environment_provider_only_access()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    unsetenv_credentials();

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, ACCESS_KEY, 1);
    if (ret < 0) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    provider = flb_aws_env_provider_create();
    if (!provider) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    flb_aws_credentials_destroy(creds);

    /* refresh should return -1 (failure) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret < 0);

    unsetenv_credentials();

    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
}

/* test the env provider when no cred env vars are set */
static void test_environment_provider_unset()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    unsetenv_credentials();

    provider = flb_aws_env_provider_create();
    if (!provider) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* refresh should return -1 (failure) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret < 0);

    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
}

static void test_credential_expiration()
{
    struct tm tm = {0};
    /* one hour in the future */
    time_t exp_expected = time(NULL) + 3600;
    char time_stamp[50];
    time_t exp_actual;
    TEST_CHECK(gmtime_r(&exp_expected, &tm) != NULL);

    TEST_CHECK(strftime(time_stamp, 50, "%Y-%m-%dT%H:%M:%SZ", &tm) > 0);

    exp_actual = flb_aws_cred_expiration(time_stamp);

    TEST_CHECK(exp_actual == exp_expected);
}

static void test_standard_chain_provider()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, ACCESS_KEY, 1);
    if (ret < 0) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, SECRET_KEY, 1);
    if (ret < 0) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    ret = setenv(AWS_SESSION_TOKEN, TOKEN, 1);
    if (ret < 0) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    provider = flb_standard_chain_provider_create(config, NULL, "us-west-2",
                                                  "https://sts.us-west-2.amazonaws.com",
                                                  NULL,
                                                  flb_aws_client_generator(),
                                                  NULL);
    if (!provider) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    unsetenv_credentials();

    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
}

TEST_LIST = {
    { "test_credential_expiration" , test_credential_expiration},
    { "environment_credential_provider" , test_environment_provider},
    { "environment_provider_no_token" , test_environment_provider_no_token},
    { "environment_provider_only_access_key" ,
    test_environment_provider_only_access},
    { "environment_credential_provider_unset" ,
      test_environment_provider_unset},
    { "test_standard_chain_provider" , test_standard_chain_provider},
    { 0 }
};
