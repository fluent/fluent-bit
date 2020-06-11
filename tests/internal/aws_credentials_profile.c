/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>

#include "flb_tests_internal.h"

#define TEST_CREDENTIALS_FILE  FLB_TESTS_DATA_PATH "/data/aws_credentials/\
shared_credentials_file.ini"

#define TEST_CREDENTIALS_NODEFAULT  FLB_TESTS_DATA_PATH "/data/aws_credentials/\
shared_credentials_file_nodefault.ini"

/* these credentials look real but are not */
#define AKID_DEFAULT_PROFILE  "ASIASDMPIJWXJAXT3O3T"
#define SKID_DEFAULT_PROFILE  "EAUBpd/APPT4Nfi4DWY3gnt5TU/4T49laqS5zh8W"
#define TOKEN_DEFAULT_PROFILE "IQoJb3JpZ2luX2VjEOD//////////wEaCNVzLWVh\
c3QtMSJHMEUCIKCn7v/EDowMZvJnciSJbxA7rIV4p1K6pOUvcLHM+9EzNgIgeiYbfA47DGS\
qoEZS3yrRWGN8Fr4Q/bK7ANRgv09Hth8q1gEIWRABGgwxNDQ3MTg3MTE0NzAiDGSqzyXiic\
OZp63afiqzAUyWOljOn5HaIxRfpQ5pTf+o4roJ2KPlHn+XHEKJZKien4Ydm7zeVi7SbPLKo\
cjmjYJd31PrlbJ43C6AyrhmY57qaD7Zz4N3N0V6mekzvlAeARXsa4deflsbemqkp1WVsBLk\
O6qUuk+N04+MxIVXAxkW9RSPRTVjxeS2m5Yobygto58WLFE8gacRoNd4lCK4JUmEdiaxJEQ\
QO7leZ3v1XxQr6QBS8P/GmcJYcQTxlA6AFQxIMJKGwfAFOuMB2cEc8cF2Htiqf3LVGMk/6b\
YKkW7fHUtrnttp28jgWtbbLtFbX/zIdlqwm73Ryp7lI+xkM4XNIT+6ZKa4Xw0/Zw3xLzlk3\
jic6QWPAcffwR6kOunoTOWJzPskK/RZ4Cd+GyGarxG27Cz6xolAzAsDpdGQwV7kCCUPi6/V\
HjefwKEk9HjZfejC5WuCS173qFrU9kNb4IrYhnK+wmRzzJfgpWUwerdiJKBz95j1iW9rP1a\
8p1xLR3EXUMN3LIW0+gP8sFjg5iiqDkaS/tUXWZndM2QdJLcrxwAutFchc0nqJHYTijw="

#define AKID_NONDEFAULT_PROFILE "akid"
#define SKID_NONDEFAULT_PROFILE "skid"

#define AKID_NOSPACE_PROFILE  "akidnospace"
#define SKID_NOSPACE_PROFILE  "skidnospace"
#define TOKEN_NOSPACE_PROFILE "tokennospace"

#define AKID_WEIRDWHITESPACE_PROFILE "akidweird"
#define SKID_WEIRDWHITESPACE_PROFILE "skidweird"
#define TOKEN_WEIRDWHITESPACE_PROFILE "tokenweird///token=="

static int unset_profile_env()
{
    int ret;
    ret = unsetenv("AWS_SHARED_CREDENTIALS_FILE");
    if (ret < 0) {
        flb_errno();
        return -1;
    }
    ret = unsetenv("AWS_DEFAULT_PROFILE");
    if (ret < 0) {
        flb_errno();
        return -1;
    }
    ret = unsetenv("AWS_PROFILE");
    if (ret < 0) {
        flb_errno();
        return -1;
    }
    return 0;
}

static void test_profile_default()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials*creds;
    int ret;

    TEST_CHECK(unset_profile_env() == 0);

    /* set environment */
    ret = setenv("AWS_SHARED_CREDENTIALS_FILE", TEST_CREDENTIALS_FILE, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_profile_provider_create();
    if (!provider) {
        flb_errno();
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(AKID_DEFAULT_PROFILE, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SKID_DEFAULT_PROFILE, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_DEFAULT_PROFILE, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(AKID_DEFAULT_PROFILE, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SKID_DEFAULT_PROFILE, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_DEFAULT_PROFILE, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    flb_aws_provider_destroy(provider);

    TEST_CHECK(unset_profile_env() == 0);
}

static void test_profile_non_default()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials*creds;
    int ret;

    TEST_CHECK(unset_profile_env() == 0);

    /* set environment */
    ret = setenv("AWS_SHARED_CREDENTIALS_FILE", TEST_CREDENTIALS_FILE, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    ret = setenv("AWS_PROFILE", "nondefault", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_profile_provider_create();
    if (!provider) {
        flb_errno();
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(AKID_NONDEFAULT_PROFILE, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SKID_NONDEFAULT_PROFILE, creds->secret_access_key) == 0);
    TEST_CHECK(creds->session_token == NULL);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(AKID_NONDEFAULT_PROFILE, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SKID_NONDEFAULT_PROFILE, creds->secret_access_key) == 0);
    TEST_CHECK(creds->session_token == NULL);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    flb_aws_provider_destroy(provider);

    TEST_CHECK(unset_profile_env() == 0);
}

static void test_profile_no_space()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials*creds;
    int ret;

    TEST_CHECK(unset_profile_env() == 0);

    /* set environment */
    ret = setenv("AWS_SHARED_CREDENTIALS_FILE", TEST_CREDENTIALS_FILE, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    ret = setenv("AWS_DEFAULT_PROFILE", "nospace", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_profile_provider_create();
    if (!provider) {
        flb_errno();
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(AKID_NOSPACE_PROFILE, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SKID_NOSPACE_PROFILE, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_NOSPACE_PROFILE, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(AKID_NOSPACE_PROFILE, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SKID_NOSPACE_PROFILE, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_NOSPACE_PROFILE, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    flb_aws_provider_destroy(provider);

    TEST_CHECK(unset_profile_env() == 0);
}

static void test_profile_weird_whitespace()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials*creds;
    int ret;

    TEST_CHECK(unset_profile_env() == 0);

    /* set environment */
    ret = setenv("AWS_SHARED_CREDENTIALS_FILE", TEST_CREDENTIALS_FILE, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    ret = setenv("AWS_DEFAULT_PROFILE", "weirdwhitespace", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_profile_provider_create();
    if (!provider) {
        flb_errno();
        return;
    }

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(AKID_WEIRDWHITESPACE_PROFILE, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SKID_WEIRDWHITESPACE_PROFILE,
                      creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_WEIRDWHITESPACE_PROFILE, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(AKID_WEIRDWHITESPACE_PROFILE, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SKID_WEIRDWHITESPACE_PROFILE,
                      creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_WEIRDWHITESPACE_PROFILE, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    flb_aws_provider_destroy(provider);

    TEST_CHECK(unset_profile_env() == 0);
}

static void test_profile_missing()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials*creds;
    int ret;

    TEST_CHECK(unset_profile_env() == 0);

    /* set environment */
    ret = setenv("AWS_SHARED_CREDENTIALS_FILE", TEST_CREDENTIALS_FILE, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    ret = setenv("AWS_DEFAULT_PROFILE", "missing", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_profile_provider_create();
    if (!provider) {
        flb_errno();
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

    flb_aws_provider_destroy(provider);

    TEST_CHECK(unset_profile_env() == 0);
}

static void test_profile_nodefault()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials*creds;
    int ret;

    TEST_CHECK(unset_profile_env() == 0);

    /* set environment */
    ret = setenv("AWS_SHARED_CREDENTIALS_FILE", TEST_CREDENTIALS_NODEFAULT, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_profile_provider_create();
    if (!provider) {
        flb_errno();
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

    flb_aws_provider_destroy(provider);

    TEST_CHECK(unset_profile_env() == 0);
}

TEST_LIST = {
    { "test_profile_default" , test_profile_default},
    { "test_profile_non_default" , test_profile_non_default},
    { "test_profile_no_space" , test_profile_no_space},
    { "test_profile_weird_whitespace" , test_profile_weird_whitespace},
    { "test_profile_missing" , test_profile_missing},
    { "test_profile_nodefault" , test_profile_nodefault},
    { 0 }
};
