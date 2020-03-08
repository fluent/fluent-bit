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

#define ACCESS_KEY_EC2 "ec2_akid"
#define SECRET_KEY_EC2 "ec2_skid"
#define TOKEN_EC2      "ec2_token"

#define EC2_CREDENTIALS_RESPONSE "{\n\
    \"AccessKeyId\": \"ec2_akid\",\n\
    \"Expiration\": \"2014-10-24T23:00:23Z\",\n\
    \"RoleArn\": \"EC2_ROLE_ARN\",\n\
    \"SecretAccessKey\": \"ec2_skid\",\n\
    \"Token\": \"ec2_token\"\n\
}"

/*
 * Unexpected/invalid response. The goal of this is not to test anything
 * that might happen in production, but rather to test the error handling
 * code for the providers. This helps ensure all code paths are tested and
 * the error handling code does not introduce memory leaks.
 */
#define MALFORMED_RESPONSE "some complete garbage that is not expected"

#define EC2_TOKEN_RESPONSE     "AQAEAGB5i7Jq-RWC7OFZcjSs3Y5uxo06c5VB1vtYIOyVA=="
#define EC2_ROLE_NAME_RESPONSE "my-role-Ec2InstanceRole-1CBV45ZZHA1E5"

/*
 * Global variable to track number of http requests made.
 * This ensures credentials are being cached properly.
 */
int g_request_count;

struct flb_http_client * ec2_role_name_response(struct flb_aws_client *aws_client,
                                                int method, const char *uri,
                                                size_t dynamic_headers_len)
{
    struct flb_http_client *c = NULL;
    TEST_CHECK(method == FLB_HTTP_GET);

    TEST_CHECK(dynamic_headers_len == 0);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 200;
    c->resp.payload = EC2_ROLE_NAME_RESPONSE;
    c->resp.payload_size = strlen(EC2_ROLE_NAME_RESPONSE);

    return c;
}

struct flb_http_client *ec2_credentials_response(struct flb_aws_client *aws_client,
                                                 int method, const char *uri,
                                                 size_t dynamic_headers_len)
{
    struct flb_http_client *c = NULL;
    TEST_CHECK(method == FLB_HTTP_GET);

    TEST_CHECK(dynamic_headers_len == 0);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 200;
    c->resp.payload = EC2_CREDENTIALS_RESPONSE;
    c->resp.payload_size = strlen(EC2_CREDENTIALS_RESPONSE);

    return c;
}

/* test/mock version of the aws_http_client request function */
struct flb_http_client *test_http_client_request(struct flb_aws_client *aws_client,
                                                 int method, const char *uri,
                                                 const char *body, size_t body_len,
                                                 struct flb_aws_header *dynamic_headers,
                                                 size_t dynamic_headers_len)
{
    g_request_count++;
    /*
     * route to the correct response fn using the uri
     */
     if (strstr(uri, "latest/meta-data/iam/security-credentials/"
                            "my-role-Ec2InstanceRole-1CBV45ZZHA1E5") != NULL) {
         return ec2_credentials_response(aws_client, method, uri,
                                         dynamic_headers_len);
     }
     else if (strstr(uri, "latest/meta-data/iam/security-credentials") != NULL)
     {
         return ec2_role_name_response(aws_client, method, uri,
                                       dynamic_headers_len);
     }

    /* uri should match one of the above conditions */
    flb_errno();
    return NULL;

}

/* Test/mock aws_http_client */
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

/* test/mock version of the aws_http_client request function */
struct flb_http_client *malformed_http_client_request(struct flb_aws_client
                                                      *aws_client,
                                                      int method, const char *uri,
                                                      const char *body,
                                                      size_t body_len,
                                                      struct flb_aws_header
                                                      *dynamic_headers,
                                                      size_t dynamic_headers_len)
{
    struct flb_http_client *c = NULL;
    TEST_CHECK(method == FLB_HTTP_GET);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 200;
    c->resp.payload = MALFORMED_RESPONSE;
    c->resp.payload_size = strlen(MALFORMED_RESPONSE);

    return c;

}

/* Test/mock aws_http_client */
static struct flb_aws_client_vtable malformed_vtable = {
    .request = malformed_http_client_request,
};

struct flb_aws_client *malformed_http_client_create()
{
    struct flb_aws_client *client = flb_calloc(1, sizeof(struct flb_aws_client));
    if (!client) {
        flb_errno();
        return NULL;
    }
    client->client_vtable = &malformed_vtable;
    return client;
}

/* Generator that returns clients with the test vtable */
static struct flb_aws_client_generator malformed_generator = {
    .create = malformed_http_client_create,
};

struct flb_aws_client_generator *generator_malformed()
{
    return &malformed_generator;
}

/* Error case mock - uses a different client and generator than happy case */
struct flb_http_client *test_http_client_error_case(struct flb_aws_client
                                                    *aws_client,
                                                    int method, const char *uri,
                                                    const char *body,
                                                    size_t body_len,
                                                    struct flb_aws_header
                                                    *dynamic_headers,
                                                    size_t dynamic_headers_len)
{
    /* create an http client so that we can set the response */
    struct flb_http_client *c = NULL;
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 500;
    c->resp.payload = "error";
    c->resp.payload_size = 5;

    return c;

}

/* Test/mock aws_http_client */
static struct flb_aws_client_vtable error_case_vtable = {
    .request = test_http_client_error_case,
};

struct flb_aws_client *test_http_client_create_error_case()
{
    struct flb_aws_client *client = flb_calloc(1,
                                                sizeof(struct flb_aws_client));
    if (!client) {
        flb_errno();
        return NULL;
    }
    client->client_vtable = &error_case_vtable;
    return client;
}

/* Generator that returns clients with the test vtable */
static struct flb_aws_client_generator error_case_generator = {
    .create = test_http_client_create_error_case,
};

struct flb_aws_client_generator *generator_in_test_error_case()
{
    return &error_case_generator;
}

static void test_ec2_provider_v1()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;

    g_request_count = 0;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    provider = flb_ec2_provider_create(config, generator_in_test());

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
    TEST_CHECK(strcmp(ACCESS_KEY_EC2, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY_EC2, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_EC2, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(ACCESS_KEY_EC2, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(SECRET_KEY_EC2, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(TOKEN_EC2, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    /*
     * 2 requests are made with v1 for the first call to get_credentials.
     * The second call hits cache. The call to refresh leads to 2 more calls.
     *
     */
    TEST_CHECK(g_request_count == 4);

    flb_aws_provider_destroy(provider);
    flb_free(config);
}

static void test_ec2_provider_error_case()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    provider = flb_ec2_provider_create(config, generator_in_test_error_case());

    if (!provider) {
        flb_errno();
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

    flb_aws_provider_destroy(provider);
    flb_free(config);
}

/* unexpected output test- see description for MALFORMED_RESPONSE */
static void test_ec2_provider_malformed_case()
{
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;
    struct flb_config *config;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    provider = flb_ec2_provider_create(config, generator_malformed());

    if (!provider) {
        flb_errno();
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

    flb_aws_provider_destroy(provider);
    flb_free(config);
}

TEST_LIST = {
    { "test_ec2_provider_v1" , test_ec2_provider_v1},
    { "test_ec2_provider_error_case" , test_ec2_provider_error_case},
    { "test_ec2_provider_malformed_response" ,
    test_ec2_provider_malformed_case},
    { 0 }
};
