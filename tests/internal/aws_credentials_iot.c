/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * Hardcoding a copy of the IoT credential provider struct from
 * flb_aws_credentials_iot.c — update both if the layout changes.
 */
#include "../include/aws_client_mock.h"
#include "../include/aws_client_mock.c"

#include <fluent-bit.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_stream.h>
#include <fluent-bit/flb_upstream.h>

#include <monkey/mk_core.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "flb_tests_internal.h"

#include "aws_credentials_test_internal.h"

#define FLB_AWS_IOT_DEFAULT_REFRESH_INTERVAL_TEST 1800

#define IOT_TLS_CA   FLB_TESTS_DATA_PATH "data/tls/certificate.pem"
#define IOT_TLS_CERT FLB_TESTS_DATA_PATH "data/tls/certificate.pem"
#define IOT_TLS_KEY  FLB_TESTS_DATA_PATH "data/tls/private_key.pem"

#define IOT_JSON_WITH_EXP                                                      \
    "{\"credentials\":{\"accessKeyId\":\"ak\",\"secretAccessKey\":\"sk\","     \
    "\"sessionToken\":\"tok\",\"expiration\":\"3025-06-01T12:00:00Z\"}}"

#define IOT_JSON_NO_EXP                                                        \
    "{\"credentials\":{\"accessKeyId\":\"ak\",\"secretAccessKey\":\"sk\","     \
    "\"sessionToken\":\"tok\"}}"

#define IOT_JSON_BAD_EXP                                                       \
    "{\"credentials\":{\"accessKeyId\":\"ak\",\"secretAccessKey\":\"sk\","     \
    "\"expiration\":\"not-a-date\"}}"

struct flb_aws_provider_iot {
    struct flb_aws_credentials *creds;
    time_t next_refresh;

    struct flb_aws_client *client;

    char *key_file;
    char *cert_file;
    char *ca_cert_file;
    char *credentials_endpoint;
    char *thing_name;
    char *role_alias;

    struct flb_tls *tls;

    struct flb_aws_header thing_name_header;
};

static void iot_set_required_env(const char *endpoint)
{
    setenv(AWS_IOT_KEY_FILE, IOT_TLS_KEY, 1);
    setenv(AWS_IOT_CERT_FILE, IOT_TLS_CERT, 1);
    setenv(AWS_IOT_CA_CERT_FILE, IOT_TLS_CA, 1);
    setenv(AWS_IOT_CREDENTIALS_ENDPOINT, endpoint, 1);
    setenv(AWS_IOT_THING_NAME, "thing-1", 1);
    setenv(AWS_IOT_ROLE_ALIAS, "myrole", 1);
}

static void iot_unset_env(void)
{
    unsetenv(AWS_IOT_KEY_FILE);
    unsetenv(AWS_IOT_CERT_FILE);
    unsetenv(AWS_IOT_CA_CERT_FILE);
    unsetenv(AWS_IOT_CREDENTIALS_ENDPOINT);
    unsetenv(AWS_IOT_THING_NAME);
    unsetenv(AWS_IOT_ROLE_ALIAS);
}

static void test_iot_provider_happy_case(void)
{
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_aws_provider_iot *impl;
    time_t now;

    iot_set_required_env("https://example.com");

    flb_aws_client_mock_configure_generator(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/role-aliases/myrole/credentials"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, IOT_JSON_WITH_EXP),
            set(PAYLOAD_SIZE, sizeof(IOT_JSON_WITH_EXP) - 1)
        )
    ));

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    mk_list_init(&config->upstreams);

    provider = flb_iot_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider != NULL);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("ak", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("sk", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("tok", creds->session_token) == 0);
    flb_aws_credentials_destroy(creds);

    impl = (struct flb_aws_provider_iot *)provider->implementation;
    now = time(NULL);
    TEST_CHECK(impl->next_refresh > now + 86400);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    flb_aws_credentials_destroy(creds);

    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    flb_aws_client_mock_destroy_generator();
    impl->client = NULL;
    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
    iot_unset_env();
}

static void test_iot_provider_missing_expiration(void)
{
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_aws_provider_iot *impl;
    time_t now;
    time_t delta;

    iot_set_required_env("https://example.com");

    flb_aws_client_mock_configure_generator(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/role-aliases/myrole/credentials"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, IOT_JSON_NO_EXP),
            set(PAYLOAD_SIZE, sizeof(IOT_JSON_NO_EXP) - 1)
        )
    ));

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    mk_list_init(&config->upstreams);

    now = time(NULL);
    provider = flb_iot_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider != NULL);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    flb_aws_credentials_destroy(creds);

    impl = (struct flb_aws_provider_iot *)provider->implementation;
    delta = impl->next_refresh - now;
    TEST_CHECK(delta >= FLB_AWS_IOT_DEFAULT_REFRESH_INTERVAL_TEST - 3 &&
               delta <= FLB_AWS_IOT_DEFAULT_REFRESH_INTERVAL_TEST + 3);

    flb_aws_client_mock_destroy_generator();
    impl->client = NULL;
    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
    iot_unset_env();
}

static void test_iot_provider_invalid_expiration(void)
{
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_credentials *creds;
    struct flb_aws_provider_iot *impl;
    time_t now;
    time_t delta;

    iot_set_required_env("https://example.com");

    flb_aws_client_mock_configure_generator(FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/role-aliases/myrole/credentials"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, IOT_JSON_BAD_EXP),
            set(PAYLOAD_SIZE, sizeof(IOT_JSON_BAD_EXP) - 1)
        )
    ));

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    mk_list_init(&config->upstreams);

    now = time(NULL);
    provider = flb_iot_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider != NULL);

    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    flb_aws_credentials_destroy(creds);

    impl = (struct flb_aws_provider_iot *)provider->implementation;
    delta = impl->next_refresh - now;
    TEST_CHECK(delta >= FLB_AWS_IOT_DEFAULT_REFRESH_INTERVAL_TEST - 3 &&
               delta <= FLB_AWS_IOT_DEFAULT_REFRESH_INTERVAL_TEST + 3);

    flb_aws_client_mock_destroy_generator();
    impl->client = NULL;
    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
    iot_unset_env();
}

static void test_iot_provider_http_scheme_endpoint(void)
{
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_provider_iot *impl;

    iot_set_required_env("http://localhost:7777/");

    flb_aws_client_mock_configure_generator(NULL);

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    config->http_proxy = NULL;
    mk_list_init(&config->upstreams);

    provider = flb_iot_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider != NULL);

    impl = (struct flb_aws_provider_iot *)provider->implementation;
    TEST_CHECK(impl->tls == NULL);
    TEST_CHECK(flb_stream_get_flag_status(&impl->client->upstream->base,
                                          FLB_IO_TLS) == 0);
    TEST_CHECK(impl->client->upstream->tcp_port == 7777);

    flb_aws_client_mock_destroy_generator();
    impl->client = NULL;
    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
    iot_unset_env();
}

static void test_iot_provider_https_scheme_endpoint(void)
{
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_provider_iot *impl;

    iot_set_required_env("https://example.com");

    flb_aws_client_mock_configure_generator(NULL);

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    config->http_proxy = NULL;
    mk_list_init(&config->upstreams);

    provider = flb_iot_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider != NULL);

    impl = (struct flb_aws_provider_iot *)provider->implementation;
    TEST_CHECK(impl->tls != NULL);
    TEST_CHECK(flb_stream_get_flag_status(&impl->client->upstream->base,
                                          FLB_IO_TLS) != 0);
    TEST_CHECK(impl->client->upstream->tcp_port == 443);

    flb_aws_client_mock_destroy_generator();
    impl->client = NULL;
    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
    iot_unset_env();
}

static void test_iot_provider_no_scheme_endpoint(void)
{
    struct flb_config *config;
    struct flb_aws_provider *provider;
    struct flb_aws_provider_iot *impl;

    iot_set_required_env("example.com");

    flb_aws_client_mock_configure_generator(NULL);

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    config->http_proxy = NULL;
    mk_list_init(&config->upstreams);

    provider = flb_iot_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider != NULL);

    impl = (struct flb_aws_provider_iot *)provider->implementation;
    TEST_CHECK(strncmp(impl->credentials_endpoint, "https://", 8) == 0);
    TEST_CHECK(impl->tls != NULL);
    TEST_CHECK(impl->client->upstream->tcp_port == 443);

    flb_aws_client_mock_destroy_generator();
    impl->client = NULL;
    flb_aws_provider_destroy(provider);
    flb_config_exit(config);
    iot_unset_env();
}

static void test_iot_provider_unsupported_scheme(void)
{
    struct flb_config *config;
    struct flb_aws_provider *provider;

    iot_set_required_env("ftp://example.com:21/");

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    mk_list_init(&config->upstreams);

    provider = flb_iot_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_CHECK(provider == NULL);

    flb_config_exit(config);
    iot_unset_env();
}

TEST_LIST = {
    { "test_iot_provider_happy_case", test_iot_provider_happy_case },
    { "test_iot_provider_missing_expiration", test_iot_provider_missing_expiration },
    { "test_iot_provider_invalid_expiration", test_iot_provider_invalid_expiration },
    { "test_iot_provider_http_scheme_endpoint", test_iot_provider_http_scheme_endpoint },
    { "test_iot_provider_https_scheme_endpoint", test_iot_provider_https_scheme_endpoint },
    { "test_iot_provider_no_scheme_endpoint", test_iot_provider_no_scheme_endpoint },
    { "test_iot_provider_unsupported_scheme", test_iot_provider_unsupported_scheme },
    { 0 }
};
