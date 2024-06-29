/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>

#include <monkey/mk_core.h>
#include <string.h>
#include <unistd.h>

#include "flb_tests_internal.h"

#include "../include/aws_client_mock.h"
#include "../include/aws_client_mock.c"

#include "aws_credentials_test_internal.h"

#define HTTP_TOKEN_FILE AWS_TEST_DATA_PATH("http_token_file.txt")

#define HTTP_RESPONSE_MALFORMED  "{\n\
    \"AccessKeyId\": \"http_akid\",\n\
    \"partially-correct\": \"json\",\n\
    \"RoleArn\": \"TASK_ROLE_ARN\",\n\
    \"but incomplete\": \"and not terminated with a closing brace\",\n\
    \"Token\": \"http_token\""

/*
 * Setup test & Initialize test environment
 */
void setup_test(struct flb_aws_client_mock_request_chain *request_chain,
                struct flb_aws_provider **out_provider, struct flb_config **out_config) {
    struct flb_aws_provider *provider;
    struct flb_config *config;

    /* Initialize test environment */
    config = flb_config_init();
    TEST_ASSERT(config != NULL);

    flb_aws_client_mock_configure_generator(request_chain);

    /* Init provider */
    provider = flb_container_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider != NULL);

    *out_config = config;
    *out_provider = provider;
}

/* Test clean up */
void cleanup_test(struct flb_aws_provider *provider, struct flb_config *config) {
    flb_aws_client_mock_destroy_generator();
    if (provider != NULL) {
        ((struct flb_aws_provider_http *) (provider->implementation))->client = NULL;
        flb_aws_provider_destroy(provider);
        provider = NULL;
    }
    if (config != NULL) {
        flb_config_exit(config);
        config = NULL;
    }
}

/*
 * Unexpected/invalid HTTP response. The goal of this is not to test anything
 * that might happen in production, but rather to test the error handling
 * code for the providers. This helps ensure all code paths are tested and
 * the error handling code does not introduce memory leaks.
 */
static void test_http_provider_malformed_response()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/iam_credentials/pod1", 1);

    setup_test(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, HTTP_RESPONSE_MALFORMED),
            set(PAYLOAD_SIZE, strlen(HTTP_RESPONSE_MALFORMED))
        ),
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, HTTP_RESPONSE_MALFORMED),
            set(PAYLOAD_SIZE, strlen(HTTP_RESPONSE_MALFORMED))
        ),
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, HTTP_RESPONSE_MALFORMED),
            set(PAYLOAD_SIZE, strlen(HTTP_RESPONSE_MALFORMED))
        )
    ), &provider, &config);

    flb_time_msleep(1000);

    /* get_credentials will fail */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* refresh should return -1 (failure) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret < 0);

    /*
     * Request count should be 3:
     * - Each call to get_credentials and refresh invokes the client's
     * request method and returns a request failure.
     */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test(provider, config);
}

static void test_http_provider_ecs_case()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/iam_credentials/pod1", 1);

    setup_test(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEKSXXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEKSXXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEKSXXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),
            set(PAYLOAD_SIZE, 257)
        ),
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"YACCESSEKSXXX\",\n  \"SecretAccessKey\""
                " : \"YSECRETEKSXXXXXXXXXXXXXX\",\n  \"Token\" : \"YTOKENEKSXXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"), // Expires Year 3021
            set(PAYLOAD_SIZE, 257)
        )
    ), &provider, &config);

    flb_time_msleep(1000);

    /* Repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Retrieve from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    /* Retrieve refreshed credentials from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("YACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("YSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("YTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test(provider, config);
}

static void test_http_provider_eks_with_token()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/iam_credentials/pod1", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "password", 1);

    setup_test(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "password"),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEKSXXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEKSXXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEKSXXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),
            set(PAYLOAD_SIZE, 257)
        ),
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "password"),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"YACCESSEKSXXX\",\n  \"SecretAccessKey\""
                " : \"YSECRETEKSXXXXXXXXXXXXXX\",\n  \"Token\" : \"YTOKENEKSXXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),
            set(PAYLOAD_SIZE, 257)
        )
    ), &provider, &config);

    flb_time_msleep(1000);

    /* Repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Retrieve from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    /* Retrieve refreshed credentials from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("YACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("YSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("YTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test(provider, config);
}

static void test_http_provider_eks_with_token_file()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    /* 
     * tests validation of valid non-default local loopback IP
     * tests token file takes precedence over token variable
     */
    setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.7:80/iam_credentials/pod1", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "password", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", HTTP_TOKEN_FILE, 1);

    setup_test(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "this-is-a-fake-http-jwt"),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEKSXXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEKSXXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEKSXXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),
            set(PAYLOAD_SIZE, 257)
        ),
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "this-is-a-fake-http-jwt"),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"YACCESSEKSXXX\",\n  \"SecretAccessKey\""
                " : \"YSECRETEKSXXXXXXXXXXXXXX\",\n  \"Token\" : \"YTOKENEKSXXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),
            set(PAYLOAD_SIZE, 257)
        )
    ), &provider, &config);

    flb_time_msleep(1000);

    /* Repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Retrieve from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    /* Retrieve refreshed credentials from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("YACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("YSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("YTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test(provider, config);
}

static void test_http_provider_https_endpoint()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "https://customers-vpc-credential-vending-server/iam_credentials/pod1", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", HTTP_TOKEN_FILE, 1);

    setup_test(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "this-is-a-fake-http-jwt"),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEKSXXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEKSXXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEKSXXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),
            set(PAYLOAD_SIZE, 257)
        ),
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "this-is-a-fake-http-jwt"),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"YACCESSEKSXXX\",\n  \"SecretAccessKey\""
                " : \"YSECRETEKSXXXXXXXXXXXXXX\",\n  \"Token\" : \"YTOKENEKSXXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),
            set(PAYLOAD_SIZE, 257)
        )
    ), &provider, &config);

    flb_time_msleep(1000);

    /* Repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Retrieve from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    /* Retrieve refreshed credentials from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("YACCESSEKSXXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("YSECRETEKSXXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("YTOKENEKSXXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test(provider, config);
}

static void test_http_provider_server_failure()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_config *config;
    int ret;

    setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "https://customers-vpc-credential-vending-server/iam_credentials/pod1", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", HTTP_TOKEN_FILE, 1);

    setup_test(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "this-is-a-fake-http-jwt"),
            set(STATUS, 400),
            set(PAYLOAD, "{\"Message\": \"Invalid Authorization token\",\"Code\": \"ClientError\"}"),
            set(PAYLOAD_SIZE, 64)
        ),
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "this-is-a-fake-http-jwt"),
            set(STATUS, 500),
            set(PAYLOAD, "{\"Message\": \"Internal Server Error\",\"Code\": \"ServerError\"}"),
            set(PAYLOAD_SIZE, 58)
        )
    ), &provider, &config);

    flb_time_msleep(1000);

    /* Endpoint failure, no creds returnd */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds == NULL);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret != 0);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test(provider, config);
}

static void test_http_validator_invalid_auth_token()
{
    struct flb_aws_provider *provider;
    struct flb_config *config;

    setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.70.2:80/iam_credentials/pod1", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "password\\r\\n", 1);

    flb_aws_client_mock_configure_generator(NULL);

    config = flb_calloc(1, sizeof(struct flb_config));
    TEST_ASSERT(config != NULL);
    mk_list_init(&config->upstreams);

    /* provider creation will fail with error message indicating port was invalid */
    provider = flb_container_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider == NULL);

    flb_aws_client_mock_destroy_generator();
    flb_free(config);
}

static void test_http_validator_invalid_host()
{
    struct flb_aws_provider *provider;
    struct flb_config *config;

    setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://104.156.107.142:80/iam_credentials/pod1", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "password", 1);

    flb_aws_client_mock_configure_generator(NULL);

    config = flb_calloc(1, sizeof(struct flb_config));
    TEST_ASSERT(config != NULL);
    mk_list_init(&config->upstreams);

    /* provider creation will fail with error message indicating host was invalid */
    provider = flb_container_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider == NULL);

    flb_aws_client_mock_destroy_generator();
    flb_free(config);
}

static void test_http_validator_invalid_port()
{
    struct flb_aws_provider *provider;
    struct flb_config *config;

    setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.70.2:AA/iam_credentials/pod1", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "password", 1);

    flb_aws_client_mock_configure_generator(NULL);

    config = flb_calloc(1, sizeof(struct flb_config));
    TEST_ASSERT(config != NULL);
    mk_list_init(&config->upstreams);

    /* provider creation will fail with error message indicating port was invalid */
    provider = flb_container_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider == NULL);

    flb_aws_client_mock_destroy_generator();
    flb_free(config);
}

TEST_LIST = {
    { "test_http_provider_malformed_response" , test_http_provider_malformed_response},
    { "test_http_provider_ecs_case" , test_http_provider_ecs_case},
    { "test_http_provider_eks_with_token" , test_http_provider_eks_with_token},
    { "test_http_provider_eks_with_token_file" , test_http_provider_eks_with_token_file},
    { "test_http_provider_https_endpoint" , test_http_provider_https_endpoint},
    { "test_http_provider_server_failure" , test_http_provider_server_failure},
    { "test_http_validator_invalid_auth_token" , test_http_validator_invalid_auth_token},
    { "test_http_validator_invalid_host" , test_http_validator_invalid_host},
    { "test_http_validator_invalid_port" , test_http_validator_invalid_port},
    { 0 }
};
