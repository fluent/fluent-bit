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

#define EKS_ACCESS_KEY "eks_akid"
#define EKS_SECRET_KEY "eks_skid"
#define EKS_TOKEN      "eks_token"

#define STS_ACCESS_KEY "sts_akid"
#define STS_SECRET_KEY "sts_skid"
#define STS_TOKEN      "sts_token"

/* standard environment variables */
#define AWS_ACCESS_KEY_ID              "AWS_ACCESS_KEY_ID"
#define AWS_SECRET_ACCESS_KEY          "AWS_SECRET_ACCESS_KEY"
#define AWS_SESSION_TOKEN              "AWS_SESSION_TOKEN"

#define TOKEN_FILE_ENV_VAR            "AWS_WEB_IDENTITY_TOKEN_FILE"
#define ROLE_ARN_ENV_VAR              "AWS_ROLE_ARN"
#define SESSION_NAME_ENV_VAR          "AWS_ROLE_SESSION_NAME"

#define WEB_TOKEN_FILE FLB_TESTS_DATA_PATH "/data/aws_credentials/\
web_identity_token_file.txt"

#define STS_RESPONSE_EKS  "<AssumeRoleWithWebIdentityResponse \
xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\n\
  <AssumeRoleWithWebIdentityResult>\n\
    <SubjectFromWebIdentityToken>amzn1.account.AF6RHO7KZU5XRVQJGXK6HB56KR2A\n\
</SubjectFromWebIdentityToken>\n\
    <Audience>client.5498841531868486423.1548@apps.example.com</Audience>\n\
    <AssumedRoleUser>\n\
      <Arn>arn:aws:sts::123456789012:assumed-role/WebIdentityRole/app1</Arn>\n\
      <AssumedRoleId>AROACLKWSDQRAOEXAMPLE:app1</AssumedRoleId>\n\
    </AssumedRoleUser>\n\
    <Credentials>\n\
      <SessionToken>eks_token</SessionToken>\n\
      <SecretAccessKey>eks_skid</SecretAccessKey>\n\
      <Expiration>2014-10-24T23:00:23Z</Expiration>\n\
      <AccessKeyId>eks_akid</AccessKeyId>\n\
    </Credentials>\n\
    <Provider>www.amazon.com</Provider>\n\
  </AssumeRoleWithWebIdentityResult>\n\
  <ResponseMetadata>\n\
    <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>\n\
  </ResponseMetadata>\n\
</AssumeRoleWithWebIdentityResponse>"

#define STS_RESPONSE_ASSUME_ROLE "<AssumeRoleResponse \
xmlns=\"https://sts.amazonaws.com/doc/\n\
2011-06-15/\">\n\
  <AssumeRoleResult>\n\
    <AssumedRoleUser>\n\
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/TestAR</Arn>\n\
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>\n\
    </AssumedRoleUser>\n\
    <Credentials>\n\
      <AccessKeyId>sts_akid</AccessKeyId>\n\
      <SecretAccessKey>sts_skid</SecretAccessKey>\n\
      <SessionToken>sts_token</SessionToken>\n\
      <Expiration>2019-11-09T13:34:41Z</Expiration>\n\
    </Credentials>\n\
    <PackedPolicySize>6</PackedPolicySize>\n\
  </AssumeRoleResult>\n\
  <ResponseMetadata>\n\
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>\n\
  </ResponseMetadata>\n\
</AssumeRoleResponse>"

/*
 * Unexpected/invalid STS response. The goal of this is not to test anything
 * that might happen in production, but rather to test the error handling
 * code for the providers. This helps ensure all code paths are tested and
 * the error handling code does not introduce memory leaks.
 */

#define STS_RESPONSE_MALFORMED "{\n\
    \"__type\": \"some unexpected response\",\n\
    \"this tests\": the error handling code\",\n\
\"This looks like JSON but is not valid.\"\n\
<Credentials><AccessKeyId>It also contains xml tags that a correct\n\
response would have</SecretAccessKey>"

/*
 * Global Variable that allows us to check the number of calls
 * made in each test
 */
int g_request_count;

/* Each test case has its own request function */

/* unexpected output test- see description for STS_RESPONSE_MALFORMED */
struct flb_http_client *request_unexpected_response(struct flb_aws_client
                                                    *aws_client, int method,
                                                    const char *uri)
{
    struct flb_http_client *c;
    TEST_CHECK(method == FLB_HTTP_GET);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 200;
    c->resp.payload = STS_RESPONSE_MALFORMED;
    c->resp.payload_size = strlen(STS_RESPONSE_MALFORMED);

    return c;
}
struct flb_http_client *request_eks_test1(struct flb_aws_client *aws_client,
                                          int method, const char *uri)
{
    struct flb_http_client *c;

    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRoleWithWebIdentity") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/test")
               != NULL);
    TEST_CHECK(strstr(uri, "WebIdentityToken=this-is-a-fake-jwt") != NULL);
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") != NULL);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 200;
    c->resp.payload = STS_RESPONSE_EKS;
    c->resp.payload_size = strlen(STS_RESPONSE_EKS);

    return c;
}

struct flb_http_client *request_eks_flb_sts_session_name(struct flb_aws_client
                                                         *aws_client,
                                                         int method,
                                                         const char *uri)
{
    struct flb_http_client *c;

    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRoleWithWebIdentity") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/"
                           "randomsession") != NULL);
    TEST_CHECK(strstr(uri, "WebIdentityToken=this-is-a-fake-jwt") != NULL);
    /* this test case has a random session name */
    TEST_CHECK(strstr(uri, "RoleSessionName=") != NULL);
    /* session name should not be the same as test 1 */
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") == NULL);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 200;
    c->resp.payload = STS_RESPONSE_EKS;
    c->resp.payload_size = strlen(STS_RESPONSE_EKS);

    return c;
}

struct flb_http_client *request_eks_api_error(struct flb_aws_client *aws_client,
                                              int method, const char *uri)
{
    struct flb_http_client *c;

    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRoleWithWebIdentity") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/apierror")
               != NULL);
    TEST_CHECK(strstr(uri, "WebIdentityToken=this-is-a-fake-jwt") != NULL);
    /* this test case has a random session name */
    TEST_CHECK(strstr(uri, "RoleSessionName=") != NULL);
    /* session name should not be the same as test 1 */
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") == NULL);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 500;
    c->resp.payload = NULL;
    c->resp.payload_size = 0;

    return c;
}

struct flb_http_client *request_sts_test1(struct flb_aws_client *aws_client,
                                          int method, const char *uri)
{
    struct flb_http_client *c;

    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRole") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/test")
               != NULL);
    TEST_CHECK(strstr(uri, "ExternalId=external_id") != NULL);
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") != NULL);

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    c->resp.status = 200;
    c->resp.payload = STS_RESPONSE_ASSUME_ROLE;
    c->resp.payload_size = strlen(STS_RESPONSE_ASSUME_ROLE);

    return c;
}

struct flb_http_client *request_sts_api_error(struct flb_aws_client *aws_client,
                                              int method, const char *uri)
{
    struct flb_http_client *c;

    TEST_CHECK(method == FLB_HTTP_GET);
    TEST_CHECK(strstr(uri, "Action=AssumeRole") != NULL);
    TEST_CHECK(strstr(uri, "RoleArn=arn:aws:iam::123456789012:role/apierror")
               != NULL);
    TEST_CHECK(strstr(uri, "ExternalId=external_id") != NULL);
    TEST_CHECK(strstr(uri, "RoleSessionName=session_name") != NULL);

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
                                                 struct flb_aws_header
                                                 *dynamic_headers,
                                                 size_t dynamic_headers_len)
{
    g_request_count++;
    if (strcmp(aws_client->name, "sts_client_eks_provider") == 0) {
        /*
         * route to the correct test case fn using the uri - the role
         * name is different in each test case.
         */
        if (strstr(uri, "test1") != NULL) {
            return request_eks_test1(aws_client, method, uri);
        } else if (strstr(uri, "randomsession") != NULL) {
            return request_eks_flb_sts_session_name(aws_client, method, uri);
        } else if (strstr(uri, "apierror") != NULL) {
            return request_eks_api_error(aws_client, method, uri);
        } else if (strstr(uri, "unexpected_api_response") != NULL) {
            return request_unexpected_response(aws_client, method, uri);
        }

        /* uri should match one of the above conditions */
        flb_errno();
        return NULL;
    } else if (strcmp(aws_client->name, "sts_client_assume_role_provider") == 0)
    {
        if (strstr(uri, "test1") != NULL) {
            return request_sts_test1(aws_client, method, uri);
        } else if (strstr(uri, "apierror") != NULL) {
            return request_sts_api_error(aws_client, method, uri);
        } else if (strstr(uri, "unexpected_api_response") != NULL) {
            return request_unexpected_response(aws_client, method, uri);
        }
        /* uri should match one of the above conditions */
        flb_errno();
        return NULL;
    }

    /* client name should match one of the above conditions */
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

static void unsetenv_eks()
{
    int ret;

    ret = unsetenv(TOKEN_FILE_ENV_VAR);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = unsetenv(ROLE_ARN_ENV_VAR);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = unsetenv(SESSION_NAME_ENV_VAR);
    if (ret < 0) {
        flb_errno();
        return;
    }
}

static void test_flb_sts_session_name()
{
    char *session_name = flb_sts_session_name();

    TEST_CHECK(strlen(session_name) == 32);

    flb_free(session_name);
}

static void test_sts_uri()
{
    flb_sds_t uri;

    uri = flb_sts_uri("AssumeRole", "myrole", "mysession",
                      "myexternalid", NULL);
    TEST_CHECK(strcmp(uri, "/?Version=2011-06-15&Action=AssumeRole"
                      "&RoleSessionName=mysession&RoleArn=myrole"
                      "&ExternalId=myexternalid") == 0);
    flb_sds_destroy(uri);
}

static void test_process_sts_response()
{
    struct flb_aws_credentials *creds;
    time_t expiration;

    creds = flb_parse_sts_resp(STS_RESPONSE_EKS, &expiration);

    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

}

static void test_eks_provider() {
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;

    g_request_count = 0;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    mk_list_init(&config->upstreams);

    /* set env vars */
    ret = setenv(ROLE_ARN_ENV_VAR, "arn:aws:iam::123456789012:role/test1", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(SESSION_NAME_ENV_VAR, "session_name", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(TOKEN_FILE_ENV_VAR, WEB_TOKEN_FILE, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_eks_provider_create(config, NULL, "us-west-2",
                                "https://sts.us-west-2.amazonaws.com",
                                NULL, generator_in_test());

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

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
    unsetenv_eks();
    flb_free(config);
}

static void test_eks_provider_random_session_name() {
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;

    g_request_count = 0;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    mk_list_init(&config->upstreams);

    /* set env vars - session name is not set */
    unsetenv_eks();
    ret = setenv(ROLE_ARN_ENV_VAR,
                 "arn:aws:iam::123456789012:role/randomsession", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(TOKEN_FILE_ENV_VAR, WEB_TOKEN_FILE, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_eks_provider_create(config, NULL, "us-west-2",
                                "https://sts.us-west-2.amazonaws.com",
                                NULL, generator_in_test());

    /* repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(EKS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(EKS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(EKS_TOKEN, creds->session_token) == 0);

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
    unsetenv_eks();
    flb_free(config);
}

/* unexpected output test- see description for STS_RESPONSE_MALFORMED */
static void test_eks_provider_unexpected_api_response() {
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;

    g_request_count = 0;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    mk_list_init(&config->upstreams);

    unsetenv_eks();
    ret = setenv(ROLE_ARN_ENV_VAR, "arn:aws:iam::123456789012:role/"
                 "unexpected_api_response", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(TOKEN_FILE_ENV_VAR, WEB_TOKEN_FILE, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_eks_provider_create(config, NULL, "us-west-2",
                                "https://sts.us-west-2.amazonaws.com",
                                NULL, generator_in_test());

    /* API will return an error - creds will be NULL */
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
    unsetenv_eks();
    flb_free(config);
}

static void test_eks_provider_api_error() {
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    int ret;

    g_request_count = 0;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    mk_list_init(&config->upstreams);

    unsetenv_eks();
    ret = setenv(ROLE_ARN_ENV_VAR, "arn:aws:iam::123456789012:role/apierror",
                 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(TOKEN_FILE_ENV_VAR, WEB_TOKEN_FILE, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    provider = flb_eks_provider_create(config, NULL, "us-west-2",
                                "https://sts.us-west-2.amazonaws.com",
                                NULL, generator_in_test());

    /* API will return an error - creds will be NULL */
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
    unsetenv_eks();
    flb_free(config);
}

static void test_sts_provider() {
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_provider *base_provider;
    struct flb_aws_credentials *creds;
    int ret;

    g_request_count = 0;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    mk_list_init(&config->upstreams);

    /* use the env provider as the base provider */
    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, "base_akid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, "base_skid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SESSION_TOKEN, "base_token", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    base_provider = flb_aws_env_provider_create();
    if (!base_provider) {
        flb_errno();
        return;
    }

    provider = flb_sts_provider_create(config, NULL, base_provider, "external_id",
                                       "arn:aws:iam::123456789012:role/test1",
                                       "session_name", "cn-north-1",
                                        "https://sts.us-west-2.amazonaws.com",
                                        NULL, generator_in_test());
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
    TEST_CHECK(strcmp(STS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(STS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(STS_TOKEN, creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    creds = provider->provider_vtable->get_credentials(provider);
    if (!creds) {
        flb_errno();
        return;
    }
    TEST_CHECK(strcmp(STS_ACCESS_KEY, creds->access_key_id) == 0);
    TEST_CHECK(strcmp(STS_SECRET_KEY, creds->secret_access_key) == 0);
    TEST_CHECK(strcmp(STS_TOKEN, creds->session_token) == 0);

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

    flb_aws_provider_destroy(base_provider);
    flb_aws_provider_destroy(provider);
    flb_free(config);
}

static void test_sts_provider_api_error() {
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_provider *base_provider;
    struct flb_aws_credentials *creds;
    int ret;

    g_request_count = 0;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    mk_list_init(&config->upstreams);

    /* use the env provider as the base provider */
    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, "base_akid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, "base_skid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SESSION_TOKEN, "base_token", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    base_provider = flb_aws_env_provider_create();
    if (!base_provider) {
        flb_errno();
        return;
    }

    provider = flb_sts_provider_create(config, NULL, base_provider, "external_id",
                                "arn:aws:iam::123456789012:role/apierror",
                                "session_name", "cn-north-1",
                                 "https://sts.us-west-2.amazonaws.com",
                                 NULL,
                                generator_in_test());
    if (!provider) {
        flb_errno();
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

    /*
     * Request count should be 3:
     * - Each call to get_credentials and refresh invokes the client's
     * request method and returns a request failure.
     */
     TEST_CHECK(g_request_count == 3);

    flb_aws_provider_destroy(base_provider);
    flb_aws_provider_destroy(provider);
    flb_free(config);
}

/* unexpected output test- see description for STS_RESPONSE_MALFORMED */
static void test_sts_provider_unexpected_api_response() {
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_provider *base_provider;
    struct flb_aws_credentials *creds;
    int ret;

    g_request_count = 0;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    mk_list_init(&config->upstreams);

    /* use the env provider as the base provider */
    /* set environment */
    ret = setenv(AWS_ACCESS_KEY_ID, "base_akid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, "base_skid", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SESSION_TOKEN, "base_token", 1);
    if (ret < 0) {
        flb_errno();
        return;
    }

    base_provider = flb_aws_env_provider_create();
    if (!base_provider) {
        flb_errno();
        return;
    }

    provider = flb_sts_provider_create(config, NULL, base_provider, "external_id",
                                       "arn:aws:iam::123456789012:role/"
                                       "unexpected_api_response",
                                       "session_name", "cn-north-1",
                                       "https://sts.us-west-2.amazonaws.com",
                                       NULL,
                                       generator_in_test());
    if (!provider) {
        flb_errno();
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

    /*
     * Request count should be 3:
     * - Each call to get_credentials and refresh invokes the client's
     * request method and returns a request failure.
     */
    TEST_CHECK(g_request_count == 3);

    flb_aws_provider_destroy(base_provider);
    flb_aws_provider_destroy(provider);
    flb_free(config);
}


TEST_LIST = {
    { "test_flb_sts_session_name" , test_flb_sts_session_name},
    { "test_sts_uri" , test_sts_uri},
    { "process_sts_response" , test_process_sts_response},
    { "eks_credential_provider" , test_eks_provider},
    { "eks_credential_provider_random_session_name" ,
      test_eks_provider_random_session_name},
    { "test_eks_provider_unexpected_api_response" ,
      test_eks_provider_unexpected_api_response},
    { "eks_credential_provider_api_error" , test_eks_provider_api_error},
    { "sts_credential_provider" , test_sts_provider},
    { "sts_credential_provider_api_error" , test_sts_provider_api_error},
    { "sts_credential_provider_unexpected_api_response" ,
    test_sts_provider_unexpected_api_response},
    { 0 }
};
