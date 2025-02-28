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

#define ACCESS_KEY_HTTP "http_akid"
#define SECRET_KEY_HTTP "http_skid"
#define TOKEN_HTTP      "http_token"

#define HTTP_CREDENTIALS_RESPONSE "{\n\
    \"AccessKeyId\": \"http_akid\",\n\
    \"Expiration\": \"2025-10-24T23:00:23Z\",\n\
    \"RoleArn\": \"TASK_ROLE_ARN\",\n\
    \"SecretAccessKey\": \"http_skid\",\n\
    \"Token\": \"http_token\"\n\
}"

#define TEST_AUTHORIZATION_TOKEN_FILE AWS_TEST_DATA_PATH("container_authorization_token.txt")

/*
 * Unexpected/invalid HTTP response. The goal of this is not to test anything
 * that might happen in production, but rather to test the error handling
 * code for the providers. This helps ensure all code paths are tested and
 * the error handling code does not introduce memory leaks.
 */
#define HTTP_RESPONSE_MALFORMED  "{\n\
    \"AccessKeyId\": \"http_akid\",\n\
    \"partially-correct\": \"json\",\n\
    \"RoleArn\": \"TASK_ROLE_ARN\",\n\
    \"but incomplete\": \"and not terminated with a closing brace\",\n\
    \"Token\": \"http_token\""


/*
 * Global Variable that allows us to check the number of calls
 * made in each test
 */
int g_request_count;

struct flb_http_client *request_happy_case(struct flb_aws_client *aws_client,
                                           int method, const char *uri)
{
    struct flb_http_client *c = NULL;

    TEST_CHECK(method == FLB_HTTP_GET);

    TEST_CHECK(strstr(uri, "happy-case") != NULL);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 200;
    c->resp.payload = HTTP_CREDENTIALS_RESPONSE;
    c->resp.payload_size = strlen(HTTP_CREDENTIALS_RESPONSE);

    return c;
}

/* unexpected output test- see description for HTTP_RESPONSE_MALFORMED */
struct flb_http_client *request_malformed(struct flb_aws_client *aws_client,
                                          int method, const char *uri)
{
    struct flb_http_client *c = NULL;

    TEST_CHECK(method == FLB_HTTP_GET);

    TEST_CHECK(strstr(uri, "malformed") != NULL);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 200;
    c->resp.payload = HTTP_RESPONSE_MALFORMED;
    c->resp.payload_size = strlen(HTTP_RESPONSE_MALFORMED);

    return c;
}

struct flb_http_client *request_error_case(struct flb_aws_client *aws_client,
                                           int method, const char *uri)
{
    struct flb_http_client *c = NULL;

    TEST_CHECK(method == FLB_HTTP_GET);

    TEST_CHECK(strstr(uri, "error-case") != NULL);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 400;
    c->resp.payload = NULL;
    c->resp.payload_size = 0;

    return c;
}

/* test/mock version of the flb_aws_client request function */
struct flb_http_client *test_http_client_request(struct flb_aws_client *aws_client,
                                                 int method, const char *uri,
                                                 const char *body, size_t body_len,
                                                 struct flb_aws_header *dynamic_headers,
                                                 size_t dynamic_headers_len)
{
    g_request_count++;
    /*
     * route to the correct test case fn using the uri
     */
    if (strstr(uri, "happy-case") != NULL) {
        return request_happy_case(aws_client, method, uri);
    } else if (strstr(uri, "error-case") != NULL) {
        return request_error_case(aws_client, method, uri);
    } else if (strstr(uri, "malformed") != NULL) {
        return request_malformed(aws_client, method, uri);
    }

    /* uri should match one of the above conditions */
    flb_errno();
    return NULL;

}

/* Test/mock flb_aws_client */
static struct flb_aws_client_vtable test_vtable = {
    .request = test_http_client_request,
};

struct flb_aws_client *test_http_client_create()
{
    struct flb_aws_client *client = flb_calloc(1,
                                                sizeof(struct flb_aws_client));
    if (!client) {
        flb_errno();
        return NULL;
    }
    client->client_vtable = &test_vtable;
    return client;
}

/* Generator that returns clients with the test vtable */
static struct flb_aws_client_generator test_generator = {
    .create = test_http_client_create,
};

struct flb_aws_client_generator *generator_in_test()
{
    return &test_generator;
}

/* http and ecs providers */
static void test_http_provider()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;

    g_request_count = 0;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    provider = flb_http_provider_create(config, generator_in_test());

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
    TEST_CHECK(strcmp(ACCESS_KEY_HTTP, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY_HTTP, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_HTTP, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY_HTTP, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY_HTTP, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_HTTP, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    /*
     * Request count should be 2:
     * - One for the first call to get_credentials (2nd should hit cred cache)
     * - One for the call to refresh
     */
    TEST_CHECK(g_request_count == 2);

    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
}

static void test_http_provider_error_case()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;

    g_request_count = 0;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    provider = flb_http_provider_create(config, generator_in_test());
    if (!provider) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

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
    TEST_CHECK(g_request_count == 3);


    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
}

static void test_http_provider_malformed_response()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;

    g_request_count = 0;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    mk_list_init(&config->upstreams);

    provider = flb_http_provider_create(config, generator_in_test());

    if (!provider) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

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
    TEST_CHECK(g_request_count == 3);

    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
}

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
    provider = flb_http_provider_create(config, flb_aws_client_get_mock_generator());
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

    /* tests validation of valid non-default  local loopback IP */
    setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.7:80/iam_credentials/pod1", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", TEST_AUTHORIZATION_TOKEN_FILE, 1);

    setup_test(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "local-http-credential-server-authorization-token"),
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
            expect(HEADER, "Authorization", "local-http-credential-server-authorization-token"),
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
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", TEST_AUTHORIZATION_TOKEN_FILE, 1);

    setup_test(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "local-http-credential-server-authorization-token"),
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
            expect(HEADER, "Authorization", "local-http-credential-server-authorization-token"),
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
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", TEST_AUTHORIZATION_TOKEN_FILE, 1);

    setup_test(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "local-http-credential-server-authorization-token"),
            set(STATUS, 400),
            set(PAYLOAD, "{\"Message\": \"Invalid Authorization token\",\"Code\": \"ClientError\"}"),
            set(PAYLOAD_SIZE, 64)
        ),
        response(
            expect(URI, "/iam_credentials/pod1"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "Authorization", "local-http-credential-server-authorization-token"),
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
    provider = flb_http_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider == NULL);

    flb_aws_client_mock_destroy_generator();
    flb_free(config);
}

static void test_http_validator_invalid_port()
{
    struct flb_aws_provider *provider;
    struct flb_config *config;

    setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://104.156.107.142:AA/iam_credentials/pod1", 1);
    setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "password", 1);

    flb_aws_client_mock_configure_generator(NULL);

    config = flb_calloc(1, sizeof(struct flb_config));
    TEST_ASSERT(config != NULL);
    TEST_ASSERT(config != NULL);

    mk_list_init(&config->upstreams);

    /* provider creation will fail with error message indicating port was invalid */
    provider = flb_http_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider == NULL);

    flb_aws_client_mock_destroy_generator();
    flb_free(config);
}

TEST_LIST = {
    { "test_http_provider", test_http_provider},
    { "test_http_provider_error_case", test_http_provider_error_case},
    { "test_http_provider_malformed_response",test_http_provider_malformed_response},
    { "test_http_provider_ecs_case", test_http_provider_ecs_case},
    { "test_http_provider_eks_with_token", test_http_provider_eks_with_token},
    { "test_http_provider_eks_with_token_file", test_http_provider_eks_with_token_file},
    { "test_http_provider_https_endpoint", test_http_provider_https_endpoint},
    { "test_http_provider_server_failure", test_http_provider_server_failure},
    { "test_http_validator_invalid_host", test_http_validator_invalid_host},
    { "test_http_validator_invalid_port", test_http_validator_invalid_port},
    { 0 }
};
