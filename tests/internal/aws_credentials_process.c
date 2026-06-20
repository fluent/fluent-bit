/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>

#include "aws_credentials_test_internal.h"

#define _TOSTRING(X) #X
#define TOSTRING(X) _TOSTRING(X)
#define TESTCASE_NAME() "aws_credentials_process.c:" TOSTRING(__LINE__)

#define MUST_SETENV(name, value) TEST_ASSERT(setenv(name, value, 1) == 0)
#define MUST_UNSETENV(name) TEST_ASSERT(unsetenv(name) == 0)

static int unset_process_env()
{
    int ret;

    ret = unset_profile_env();
    if (ret < 0) {
        return -1;
    }

    ret = unsetenv("_AWS_SECRET_ACCESS_KEY");
    if (ret < 0) {
        flb_errno();
        return -1;
    }

    ret = unsetenv("_AWS_SESSION_TOKEN");
    if (ret < 0) {
        flb_errno();
        return -1;
    }

    ret = unsetenv("_AWS_EXPIRATION");
    if (ret < 0) {
        flb_errno();
        return -1;
    }

    ret = unsetenv("_AWS_EXIT_CODE");
    if (ret < 0) {
        flb_errno();
        return -1;
    }

    return 0;
}

static void test_credential_process_default(void)
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials* creds;
    char* original_path = getenv("PATH");

    /* Print a newline so the test output starts on its own line. */
    fprintf(stderr, "\n");

    TEST_CHECK(unset_process_env() == 0);

    MUST_SETENV("AWS_CONFIG_FILE", AWS_TEST_DATA_PATH("shared_config.ini"));
    MUST_SETENV("PATH", AWS_TEST_DATA_PATH("credential_process"));

    provider = flb_profile_provider_create(NULL);
    TEST_ASSERT(provider != NULL);

    /* These environment variables are used by the test credential_process. */
    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key");
    MUST_SETENV("_AWS_SESSION_TOKEN", "aws_session_token");
    MUST_SETENV("_AWS_EXPIRATION", "+15 minutes");

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);

    TEST_CHECK(strcmp("default", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("aws_secret_access_key", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("aws_session_token", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    /* Repeated calls to get_credentials should return the cached credentials. */

    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key_2");
    MUST_SETENV("_AWS_SESSION_TOKEN", "aws_session_token_2");

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);

    TEST_CHECK(strcmp("default", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("aws_secret_access_key", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("aws_session_token", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    /* Calling refresh should fetch the new credentials. */

    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key_3");
    MUST_SETENV("_AWS_SESSION_TOKEN", "aws_session_token_3");

    TEST_ASSERT(provider->provider_vtable->refresh(provider) == 0);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);

    TEST_CHECK(strcmp("default", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("aws_secret_access_key_3", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("aws_session_token_3", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    flb_aws_provider_destroy(provider);
    provider = NULL;

    if (original_path) {
        MUST_SETENV("PATH", original_path);
    } else {
        MUST_UNSETENV("PATH");
    }
}

static void test_credential_process_no_expiration(void)
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials* creds;
    char* original_path = getenv("PATH");

    /* Print a newline so the test output starts on its own line. */
    fprintf(stderr, "\n");

    TEST_CHECK(unset_process_env() == 0);

    MUST_SETENV("AWS_CONFIG_FILE", AWS_TEST_DATA_PATH("shared_config.ini"));
    MUST_SETENV("AWS_PROFILE", "nondefault");
    MUST_SETENV("PATH", AWS_TEST_DATA_PATH("credential_process"));

    provider = flb_profile_provider_create(NULL);
    TEST_ASSERT(provider != NULL);

    /* These environment variables are used by the test credential_process. */
    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key");
    MUST_SETENV("_AWS_SESSION_TOKEN", "aws_session_token");

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);

    TEST_CHECK(strcmp("nondefault", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("aws_secret_access_key", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("aws_session_token", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    /* Repeated calls to get_credentials should return the cached credentials. */

    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key_2");
    MUST_SETENV("_AWS_SESSION_TOKEN", "aws_session_token_2");

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);

    TEST_CHECK(strcmp("nondefault", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("aws_secret_access_key", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("aws_session_token", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    /* Calling refresh should fetch the new credentials. */

    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key_3");
    MUST_SETENV("_AWS_SESSION_TOKEN", "aws_session_token_3");

    TEST_ASSERT(provider->provider_vtable->refresh(provider) == 0);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);

     TEST_CHECK(strcmp("nondefault", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("aws_secret_access_key_3", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("aws_session_token_3", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    flb_aws_provider_destroy(provider);
    provider = NULL;

    if (original_path) {
        MUST_SETENV("PATH", original_path);
    } else {
        MUST_UNSETENV("PATH");
    }
}

struct credential_process_expired_testcase {
    char* name;
    char* expiration;
};

struct credential_process_expired_testcase credential_process_expired_testcases[] = {
    /* Credentials that have already expired will be refreshed. */
    {
        .name = "expired",
        .expiration = "-5 minutes",
    },

    /* Credentials that expire within the next minute will be refreshed. */
    {
        .name = "expiring soon",
        .expiration = "+30 seconds",
    },
};

static void test_credential_process_expired_helper(char* expiration)
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials* creds;
    char* original_path = getenv("PATH");

    TEST_CHECK(unset_process_env() == 0);

    MUST_SETENV("AWS_CONFIG_FILE", AWS_TEST_DATA_PATH("shared_config.ini"));
    MUST_SETENV("AWS_PROFILE", "nondefault");
    MUST_SETENV("PATH", AWS_TEST_DATA_PATH("credential_process"));

    provider = flb_profile_provider_create(NULL);
    TEST_ASSERT(provider != NULL);

    /* These environment variable are used by the test credential_process. */
    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key");
    if (expiration) {
        MUST_SETENV("_AWS_EXPIRATION", expiration);
    }

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);

    TEST_CHECK(strcmp("nondefault", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("aws_secret_access_key", creds->secret_access_key) == 0);
    TEST_CHECK(creds->session_token == NULL);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    /* Repeated calls to get_credentials should fetch new credentials. */

    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key_2");

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);

    TEST_CHECK(strcmp("nondefault", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("aws_secret_access_key_2", creds->secret_access_key) == 0);
    TEST_CHECK(creds->session_token == NULL);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    flb_aws_provider_destroy(provider);
    provider = NULL;

    if (original_path) {
        MUST_SETENV("PATH", original_path);
    } else {
        MUST_UNSETENV("PATH");
    }
}

static void test_credential_process_expired(void)
{
    int i;
    int num_testcases = sizeof(credential_process_expired_testcases) /
                        sizeof(credential_process_expired_testcases[0]);
    struct credential_process_expired_testcase* current_testcase = NULL;

    /* Print a newline so the test output starts on its own line. */
    fprintf(stderr, "\n");

    for (i = 0; i < num_testcases; i++) {
        current_testcase = &credential_process_expired_testcases[i];
        TEST_CASE(current_testcase->name);
        test_credential_process_expired_helper(current_testcase->expiration);
    }
}

static void test_credential_process_failure(void)
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials* creds;
    char* original_path = getenv("PATH");

    /* Print a newline so the test output starts on its own line. */
    fprintf(stderr, "\n");

    TEST_CHECK(unset_process_env() == 0);

    MUST_SETENV("AWS_CONFIG_FILE", AWS_TEST_DATA_PATH("shared_config.ini"));
    MUST_SETENV("PATH", AWS_TEST_DATA_PATH("credential_process"));

    provider = flb_profile_provider_create(NULL);
    TEST_ASSERT(provider != NULL);

    /* These environment variables are used by the test credential_process. */
    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key");
    MUST_SETENV("_AWS_EXIT_CODE", "1");

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds == NULL);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    /* Repeated calls to get_credentials should try to fetch the credentials again. */

    MUST_SETENV("_AWS_SECRET_ACCESS_KEY", "aws_secret_access_key_2");
    MUST_UNSETENV("_AWS_EXIT_CODE");

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);

    TEST_CHECK(strcmp("default", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("aws_secret_access_key_2", creds->secret_access_key) == 0);

    flb_aws_credentials_destroy(creds);
    creds = NULL;

    flb_aws_provider_destroy(provider);
    provider = NULL;

    if (original_path) {
        MUST_SETENV("PATH", original_path);
    } else {
        MUST_UNSETENV("PATH");
    }
}

struct parse_credential_process_testcase {
    char* name;
    char* input;

    /*
     * NULL-terminated array of tokens that should be returned.
     * The choice of 10 here is completely arbitrary.
     * Since a char*[] cannot be NULL, we need a separate flag for the failure cases.
     */
    char* expected[10];
    int should_fail;
};

struct parse_credential_process_testcase parse_credential_process_testcases[] = {
    {
        .name = TESTCASE_NAME(),
        .input = "my-process",
        .expected = { "my-process", NULL },
    },
    {
        .name = TESTCASE_NAME(),
        .input = "   my-process ",
        .expected = { "my-process", NULL },
    },
    {
        .name = TESTCASE_NAME(),
        .input = "my-process arg1 arg2",
        .expected = { "my-process", "arg1", "arg2", NULL },
    },
    {
        .name = TESTCASE_NAME(),
        .input = " my-process   arg1    arg2 ",
        .expected = { "my-process", "arg1", "arg2", NULL },
    },
    {
        .name = TESTCASE_NAME(),
        .input = "my-process \"arg1 \" arg2 \"\"",
        .expected = { "my-process", "arg1 ", "arg2", "", NULL },
    },
    {
        .name = TESTCASE_NAME(),
        .input = "\"my process\"",
        .expected = { "my process", NULL },
    },
    {
        .name = TESTCASE_NAME(),
        .input = " \"my process\"    \" \" ",
        .expected = { "my process", " ", NULL },
    },
    {
        .name = TESTCASE_NAME(),
        .input = "",
        .expected = { NULL },
    },
    {
        .name = TESTCASE_NAME(),
        .input = "\"unterminated",
        .should_fail = FLB_TRUE,
    },
    {
        .name = TESTCASE_NAME(),
        .input = " \"unterminated ",
        .should_fail = FLB_TRUE,
    },
    {
        .name = TESTCASE_NAME(),
        .input = "abc\"def\"",
        .should_fail = FLB_TRUE,
    },
    {
        .name = TESTCASE_NAME(),
        .input = " abc\"def\" ",
        .should_fail = FLB_TRUE,
    },
    {
        .name = TESTCASE_NAME(),
        .input = "\"abc\"def",
        .should_fail = FLB_TRUE,
    },
    {
        .name = TESTCASE_NAME(),
        .input = " \"abc\"def ",
        .should_fail = FLB_TRUE,
    },
};

static void test_parse_credential_process_helper(char* input, char** expected)
{
    char* cpy = NULL;
    char** tokens = NULL;
    int i = 0;
    int input_len = strlen(input) + 1;

    /*
     * String literals are immutable, but parse_credential_process modifies its input.
     * To circumvent this, copy the literal into a mutable string.
     * Note: Because the return value of parse_credential_process will contain pointers
     * into this string, we cannot free the copy until we are done with the token array.
     */
    cpy = flb_malloc(input_len + 1);
    TEST_ASSERT(cpy != NULL);
    memcpy(cpy, input, input_len);

    tokens = parse_credential_process(cpy);

    if (expected) {
        TEST_ASSERT(tokens != NULL);
        for (i = 0; expected[i]; i++) {
            TEST_ASSERT_(tokens[i] != NULL, "expected='%s', got=(null)", expected[i]);
            TEST_CHECK_(strcmp(expected[i], tokens[i]) == 0, "expected='%s', got='%s'",
                        expected[i], tokens[i]);
        }
        TEST_ASSERT_(tokens[i] == NULL, "expected=(null), got='%s'", tokens[i]);
    }
    else {
        TEST_ASSERT(tokens == NULL);
    }

    flb_free(tokens);
    flb_free(cpy);
}

static void test_parse_credential_process(void)
{
    int i;
    int num_testcases = sizeof(parse_credential_process_testcases) /
                        sizeof(parse_credential_process_testcases[0]);
    struct parse_credential_process_testcase* current_testcase = NULL;
    char** expected = NULL;

    /* Print a newline so the test output starts on its own line. */
    fprintf(stderr, "\n");

    for (i = 0; i < num_testcases; i++) {
        current_testcase = &parse_credential_process_testcases[i];
        TEST_CASE(current_testcase->name);
        if (current_testcase->should_fail) {
            expected = NULL;
        }
        else {
            expected = current_testcase->expected;
        }
        test_parse_credential_process_helper(current_testcase->input, expected);
    }
}

TEST_LIST = {
    { "test_credential_process_default", test_credential_process_default },
    { "test_credential_process_no_expiration", test_credential_process_no_expiration },
    { "test_credential_process_expired", test_credential_process_expired },
    { "test_credential_process_failure", test_credential_process_failure },
    { "test_parse_credential_process", test_parse_credential_process },
    { 0 }
};
