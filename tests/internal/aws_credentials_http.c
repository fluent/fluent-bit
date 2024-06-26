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

#define ACCESS_KEY_HTTP "http_akid"
#define SECRET_KEY_HTTP "http_skid"
#define TOKEN_HTTP      "http_token"

#define TOKEN_FILE_ENV_VAR "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"
#define HTTP_TOKEN_FILE FLB_TESTS_DATA_PATH "/data/aws_credentials/\
http_token_file.txt"

#define HTTP_CREDENTIALS_RESPONSE "{\n\
    \"AccessKeyId\": \"http_akid\",\n\
    \"Expiration\": \"2025-10-24T23:00:23Z\",\n\
    \"RoleArn\": \"TASK_ROLE_ARN\",\n\
    \"SecretAccessKey\": \"http_skid\",\n\
    \"Token\": \"http_token\"\n\
}"

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

struct flb_http_client *request_auth_token_case(struct flb_aws_client *aws_client,
                                                int method, const char *uri,
                                                struct flb_aws_header *dynamic_headers,
                                                size_t dynamic_headers_len)
{
    struct flb_http_client *c = NULL;

    TEST_CHECK(method == FLB_HTTP_GET);

    TEST_CHECK(strstr(uri, "auth-token") != NULL);

    TEST_CHECK(dynamic_headers_len == 1);

    TEST_CHECK(strstr(dynamic_headers[0].key, "Authorization") != NULL);

    TEST_CHECK(strstr(dynamic_headers[0].val, "this-is-a-fake-http-jwt") != NULL);

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
    } else if (strstr(uri, "auth-token") != NULL) {
        return request_auth_token_case(aws_client, method, uri,
                                       dynamic_headers,
                                       dynamic_headers_len);
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

/* http and container providers */
static void test_http_provider()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;
    flb_sds_t endpoint;
    flb_sds_t path;

    g_request_count = 0;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    endpoint = flb_sds_create("http://127.0.0.1");
    if (!endpoint) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    path = flb_sds_create("/happy-case");
    if (!path) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    provider = flb_http_provider_create(config, endpoint, path, NULL,
                                 generator_in_test());

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

static void test_http_provider_auth_token()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;
    flb_sds_t endpoint;
    flb_sds_t path;
    flb_sds_t auth_token;

    g_request_count = 0;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    endpoint = flb_sds_create("http://127.0.0.1");
    if (!endpoint) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    path = flb_sds_create("/auth-token");
    if (!path) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    auth_token = flb_sds_create("this-is-a-fake-http-jwt");
    if (!auth_token) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    provider = flb_http_provider_create(config, endpoint, path, auth_token,
                                 generator_in_test());

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

static void test_local_http_provider()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;
    flb_sds_t endpoint;
    flb_sds_t auth_token;

    g_request_count = 0;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    endpoint = flb_sds_create("http://127.0.0.1/auth-token");
    if (!endpoint) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    /* tests that the token file takes precedence */
    auth_token = flb_sds_create("this-is-the-wrong-jwt");
    if (!auth_token) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    setenv(TOKEN_FILE_ENV_VAR, HTTP_TOKEN_FILE, 1);

    provider = flb_local_http_provider_create(config, endpoint, auth_token,
                                 generator_in_test());

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

    unsetenv(TOKEN_FILE_ENV_VAR);
    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
}

static void test_http_provider_error_case()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;
    flb_sds_t endpoint;
    flb_sds_t path;

    g_request_count = 0;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    endpoint = flb_sds_create("http://127.0.0.1");
    if (!endpoint) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    path = flb_sds_create("/error-case");
    if (!path) {
        flb_errno();
        flb_config_exit(config);
        return;    if (path) {
        flb_sds_destroy(path);
    }
    }

    provider = flb_http_provider_create(config, endpoint, path, NULL,
                                        generator_in_test());

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
    flb_sds_t endpoint;
    flb_sds_t path;

    g_request_count = 0;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    mk_list_init(&config->upstreams);

    endpoint = flb_sds_create("http://127.0.0.1");
    if (!endpoint) {
        flb_errno();
        flb_config_exit(config);
        return;
    }
    path = flb_sds_create("/malformed");
    if (!path) {
        flb_errno();
        flb_config_exit(config);
        return;
    }

    provider = flb_http_provider_create(config, endpoint, path, NULL,
                                 generator_in_test());

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

TEST_LIST = {
    { "test_http_provider" , test_http_provider},
    { "test_http_provider_auth_token" , test_http_provider_auth_token},
    { "test_local_http_provider" , test_local_http_provider},
    { "test_http_provider_error_case" , test_http_provider_error_case},
    { "test_http_provider_malformed_response" ,
    test_http_provider_malformed_response},
    { 0 }
};
