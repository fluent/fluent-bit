/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "../include/aws_client_mock.h"
#include "../include/aws_client_mock.c"

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/aws/flb_aws_imds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_log.h>

#include <monkey/mk_core.h>
#include <string.h>
#include <unistd.h>

#include "flb_tests_internal.h"

/* Global variables for tests */
struct flb_aws_provider *provider;
struct flb_aws_credentials *creds;
struct flb_config *config;
struct flb_config *config_fluent;
int ret;

/*
 * Hardcoding a copy of the ec2 credential provider struct from flb_aws_credentials_ec2.c
 * Note: this will require a change if the other copy is changed.
 * A provider that obtains credentials from EC2 IMDS.
 */
struct flb_aws_provider_ec2 {
    struct flb_aws_credentials *creds;
    time_t next_refresh;

    /* upstream connection to IMDS */
    struct flb_aws_client *client;

    /* IMDS interface */
    struct flb_aws_imds *imds_interface;
};

/*
 * Setup test & Initialize test environment
 * Required for fluent bit debug logs
 * Note: Log level definitions do not work.
 * Example: config_fluent->verbose = FLB_LOG_OFF
 */
void setup_test(struct flb_aws_client_mock_request_chain *request_chain) {
    /* Initialize test environment */
    config_fluent = flb_config_init();

    flb_aws_client_mock_configure_generator(request_chain);

    /* Init provider */
    config = flb_calloc(1, sizeof(struct flb_config));
    TEST_ASSERT(config != NULL);
    mk_list_init(&config->upstreams);
    provider = flb_ec2_provider_create(config, flb_aws_client_get_mock_generator());
    TEST_ASSERT(provider != NULL);
}

/* Test clean up */
void cleanup_test() {
    flb_aws_client_mock_destroy_generator();
    if (provider != NULL) {
        ((struct flb_aws_provider_ec2 *) (provider->implementation))->client = NULL;
        flb_aws_provider_destroy(provider);
        provider = NULL;
    }
    if (config != NULL) {
        flb_free(config);
    }
    if (config_fluent != NULL) {
        flb_config_exit(config_fluent);
        config_fluent = NULL;
    }
}

/*
 * IMDSv2 -- Test Summary
 *  First call to get_credentials():
 *  -> 2 requests are made to obtain IMDSv2 token
 *  -> 2 requests are made to access credentials
 *  Second call to get_credentials() hits cache:
 *  -> 0 requests are made
 *  refresh():
 *  -> 2 requests are made to access credentials
 */
static void test_ec2_provider_v2()
{
    setup_test(FLB_AWS_CLIENT_MOCK(
        /* First call to get_credentials() */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 401)
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(PAYLOAD, "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(PAYLOAD_SIZE, 56)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),  /* Expires Year 3021 */
            set(PAYLOAD_SIZE, 257)
        ),

        /* Second call to get_credentials() hits cache */

        /* Refresh credentials (No token refesh) */
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name_New"),
            set(PAYLOAD_SIZE, 20)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name_New"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"YACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"YSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"YTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"), // Expires Year 3021
            set(PAYLOAD_SIZE, 257)
        )
    ));

    /* Repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Retrieve from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    /* Retrieve refreshed credentials from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("YACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("YSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("YTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test();
}

/*
 * IMDSv1 -- Fallback Test Summary
 *  First call to get_credentials():
 *  -> 1 requests is made to test for IMDSv2
 *  -> 2 requests are made to access credentials
 *  Second call to get_credentials() hits cache
 *  -> 0 requests are made
 *  refresh():
 *  -> 2 requests are made to access credentials
 */
static void test_ec2_provider_v1()
{
    setup_test(FLB_AWS_CLIENT_MOCK(
        /* First call to get_credentials() */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"),
            expect(HEADER_COUNT, 1),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),  /* Expires Year 3021 */
            set(PAYLOAD_SIZE, 257)
        ),

        /* Second call to get_credentials() hits cache */

        /* Refresh credentials (No token refesh) */
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name_New"),
            set(PAYLOAD_SIZE, 20)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name_New"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"YACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"YSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"YTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"), // Expires Year 3021
            set(PAYLOAD_SIZE, 257)
        )
    ));

    /* Repeated calls to get credentials should return the same set */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Retrieve from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    /* Retrieve refreshed credentials from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("YACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("YSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("YTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test();
}

/*
 * IMDSv1 -- IMDSv2 Timeout, Fallback Test Summary
 *  First call to get_credentials():
 *  -> 1 requests is made to test for IMDSv2 (IMDSv2)
 *  -> 1 request made to get token (Timeout failure)
 *  -> 1 request made to check IMDSv1 fallback (Failure - IMDSv1 not allowed)
 *
 * Second call to get_credentials():
 *  -> 1 requests is made to test for IMDSv2 (IMDSv2)
 *  -> 1 request made to get token (Timeout failure)
 *  -> 1 request made to check IMDSv1 fallback (Success)
 *  -> 2 requests are made to access credentials
 *  Second call to get_credentials() hits cache
 *  -> 0 requests are made
 *  refresh():
 *  -> 2 requests are made to access credentials
 */
static void test_ec2_provider_v1_v2_timeout()
{
    setup_test(FLB_AWS_CLIENT_MOCK(
        /* First call to get_credentials() */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"),
            expect(HEADER_COUNT, 1),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 401)
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            config(REPLACE, (struct flb_http_client *) NULL) /* Replicate timeout failure */
        ),
        response(
            expect(URI, "/"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 401) /* IMDSv1 not allowed */
        ),

        /* Second call to get_credentials() */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"),
            expect(HEADER_COUNT, 1),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 401)
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            config(REPLACE, (struct flb_http_client *) NULL) /* Replicate timeout failure */
        ),
        response(
            expect(URI, "/"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200) /* IMDSv1 is allowed */
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),  /* Expires Year 3021 */
            set(PAYLOAD_SIZE, 257)
        ),

        /* Second call to get_credentials() hits cache */

        /* Refresh credentials (No token refesh) */
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name_New"),
            set(PAYLOAD_SIZE, 20)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name_New"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER_COUNT, 0),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"YACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"YSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"YTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"), // Expires Year 3021
            set(PAYLOAD_SIZE, 257)
        )
    ));

    /* First call: IMDSv1 and IMDSv2 not accessible */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds == NULL);

    /*
     * Second call: IMDSv2 timeout, IMDSv1 accessible
     * Repeated calls to get credentials should return the same set
     */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Retrieve from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* refresh should return 0 (success) */
    ret = provider->provider_vtable->refresh(provider);
    TEST_CHECK(ret == 0);

    /* Retrieve refreshed credentials from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("YACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("YSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("YTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test();
}


/*
 * IMDS Version Detection Error -- Test Summary
 *  First call to get_credentials():
 *  -> 1 request made to test for IMDSv2 (Fails, 404)
 *  Second call to get_credentials():
 *  -> 1 request made to test for IMDSv2 (Fails, null http_client)
 *  Third call to get_credentials():
 *  -> 1 request made to test for IMDSv2 (Success)
 *  -> 1 request made to get token (Failure)
 *  Fourth call to get_credentials():
 *  -> 2 requests made to obtain IMDSv2 token (Success)
 *  -> 2 requests made to access credentials (Success)
 */
static void test_ec2_provider_version_detection_error()
{
    setup_test(FLB_AWS_CLIENT_MOCK(
        /* First call to get_credentials(): Version detection failure */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"),
            expect(HEADER_COUNT, 1),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 404) // IMDS not found (not likely to happen)
        ),

        /* Second call to get_credentials(): Version detection failure */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"),
            expect(METHOD, FLB_HTTP_GET),
            config(REPLACE, (struct flb_http_client *) NULL)
        ),

        /* Third call to get_credentials(): Version detection success */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 401)
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(PAYLOAD, "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(PAYLOAD_SIZE, 56)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),  /* Expires Year 3021 */
            set(PAYLOAD_SIZE, 257)
        )
    ));

    /* Version detection failure: Status 404 */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* Version detection failure: NULL response */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* Version detection success: IMDSv2 */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Retrieve from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test();
}

/*
 * IMDS Aquire Token Error -- Test Summary
 *  First call to get_credentials():
 *  -> 1 request made to test for IMDSv2 (Success)
 *  -> 1 request made to obtain IMDSv2 token (Fails) <-* Aquire token error
 *  -> 1 request made to check IMDSv1 fallback (Unauthorized)
 *  Second call to get_credentials():
 *  -> 1 request made to access instance name (Invalid token)
 *  -> 1 request made to obtain IMDSv2 token (Success)
 *  -> 1 request made to access instance name (Success)
 *  -> 1 request made to access credentials (Invalid token)
 *  -> 1 request made to obtain IMDSv2 token (Fails) <-* Aquire token error
 *  Third call to get_credentials():
 *  -> 1 request made to access instance name (Invalid token)
 *  -> 1 request made to obtain IMDSv2 token (Success)
 *  -> 1 request made to access instance name (Success)
 *  -> 1 request made to access credentials (Invalid token)
 *  -> 1 request made to obtain IMDSv2 token (Success)
 *  -> 1 request made to access credentials (Success, but credentials are expired as of Year 2000)
 *  Fourth call to get_credentials(): - hits expired cache
 *  -> 1 request made to access credentials (Invalid token)
 *  -> 1 request made to obtain IMDSv2 token (http_client is null) <-* Aquire token error
 *  Fifth call to get_credentials(): - hits expired cache
 *  -> 1 request made to access credentials (Invalid token)
 *  -> 1 request made to obtain IMDSv2 token (Success)
 *  -> 2 requests are made to access credentials
 */
static void test_ec2_provider_acquire_token_error()
{
    setup_test(FLB_AWS_CLIENT_MOCK(

        /*
         *  First call to get_credentials():
         *  -> 1 request made to test for IMDSv2 (Success)
         *  -> 1 request made to obtain IMDSv2 token (Fails) <-* Aquire token error
         *  -> 1 request made to check IMDSv1 fallback (Unauthorized)
         */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"), /* Why is this not invalid_token? */
            expect(HEADER_COUNT, 1),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 401) /* IMDSv2 */
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            config(REPLACE, NULL) /* HTTP Client is null */
        ),
        response(
            expect(URI, "/"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 401) /* IMDSv1 not allowed */
        ),

        /*
         *  Second call to get_credentials():
         *  -> 1 request made to test for IMDSv2 (Success)
         *  -> 1 request made to obtain IMDSv2 token (Success) <-* Bad token
         *  -> 1 request made to access instance name (Invalid token)
         *  -> 1 request made to obtain IMDSv2 token (Success)
         *  -> 1 request made to access instance name (Success)
         *  -> 1 request made to access credentials (Invalid token)
         *  -> 1 request made to obtain IMDSv2 token (Fails) <-* Aquire token error
         */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"), /* Why is this not invalid_token? */
            expect(HEADER_COUNT, 1),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 401) /* IMDSv2 */
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(PAYLOAD, "BAD_ANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(PAYLOAD_SIZE, 56)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "BAD_ANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="), /* Token failed to be set */
            set(STATUS, 401) /* Unauthorized, bad token */
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(PAYLOAD, "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(PAYLOAD_SIZE, 56)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 401) /* Unauthorized, bad token */
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 404), /* This should never actually happen */
            set(PAYLOAD, "Token not found"),
            set(PAYLOAD_SIZE, 15)
        ),

        /*
         *  Third call to get_credentials():
         *  -> 1 request made to access instance name (Invalid token)
         *  -> 1 request made to obtain IMDSv2 token (Success)
         *  -> 1 request made to access instance name (Success)
         *  -> 1 request made to access credentials (Invalid token)
         *  -> 1 request made to obtain IMDSv2 token (Success)
         *  -> 1 request made to access credentials (Success, but credentials are expired as of Year 2000)
         */
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="), /* Token failed to be set */
            set(STATUS, 401) /* Unauthorized, bad token */
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(PAYLOAD, "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(PAYLOAD_SIZE, 56)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 401) /* Unauthorized, bad token */
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(PAYLOAD, "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(PAYLOAD_SIZE, 56)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"2000-09-17T00:41:00Z\"\n}"),  /* Expires Year 2000 */
            set(PAYLOAD_SIZE, 257)
        ),

        /*
         *  Fourth call to get_credentials(): - hits expired cache
         *  -> 1 request made to access credentials (Invalid token)
         *  -> 1 request made to obtain IMDSv2 token (http_client is null) <-* Aquire token error
         */
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 401) /* Unauthorized, bad token */
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            config(REPLACE, NULL) /* HTTP Client is null */
        ),

        /*
         *  Fifth call to get_credentials(): - hits expired cache
         *  -> 1 request made to access credentials (Invalid token)
         *  -> 1 request made to obtain IMDSv2 token (Success)
         *  -> 2 requests are made to access credentials
         */
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 401) /* Unauthorized, bad token */
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(PAYLOAD, "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(PAYLOAD_SIZE, 56)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"YACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"YSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"YTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),  /* Expires Year 3021 */
            set(PAYLOAD_SIZE, 257)
        )
    ));

    /* 1. Aquire token error */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* 2. Aquire token error */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* 3. Aquire token success */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* 4. Aquire token error */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds); /* Remains unchanged */

    /* 5. Aquire token success */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("YACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("YSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("YTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test();
}

/*
 * IMDS Metadata Request Failure -- Test Summary
 *  First call to get_credentials():
 *  -> 2 requests are made to obtain IMDSv2 token
 *  -> 1 request is made to access instance name (fails, null client)
 *  Second call to get_credentials(): -- token cached
 *  -> 1 request is made to access instance name (success)
 *  -> 1 request is made to access credentials (fails, 404)
 *  Third call to get_credentials(): -- token cached
 *  -> 1 request is made to access instance name
 *  -> 1 request is made to access credentials (fails, garbage fuzz input)
 *  Fourth call to get_credentials(): -- token cached
 *  -> 1 request is made to access instance name
 *  -> 1 request is made to access credentials (success)
 */
static void test_ec2_provider_metadata_request_error()
{
    setup_test(FLB_AWS_CLIENT_MOCK(
        /* First call to get_credentials() */
        response(
            expect(URI, "/"),
            expect(HEADER, "X-aws-ec2-metadata-token", "INVALID"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 401)
        ),
        response(
            expect(URI, "/latest/api/token"),
            expect(HEADER, "X-aws-ec2-metadata-token-ttl-seconds", "21600"),  /* 6 hours */
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(PAYLOAD, "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(PAYLOAD_SIZE, 56)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            config(REPLACE, NULL)
        ),

        /* Second call to get_credentials() */
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 404),
            set(PAYLOAD, "IMDS server not found"), /* This should never happen */
            set(PAYLOAD_SIZE, 21)
        ),

        /* Third call to get_credentials() */
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, ("{tsJ@&K+Xo9?'a,uxb)=/iZg\"M4B\\&,qb"
                        "Y\\%%niHubN^I[#arpu9|A':W!JZ@?frM|\""
                        "?aVK<WS3ziAp:\"d=VD(Mu<Bl(e6I?G.3"
                        "rI!f5OxfmkJ)ePc\\5@dGIA!q${iVCF3*"
                        "#y6z<5Nal\\Wmp!0gpeoG!#iY[H&@350v"
                        "$!)i4?6!&}uQ]3%%b25I._H{!.4{42T ,"
                        "b{f\\jpAQ\"j>~<L%%<;k4uh5d+;\\%%soDl<F"
                        "+\\j|WvhX+V)Xb)&tF&'Gj:2Q8@/m3Y46"
                        "79HrM2^1sg11b94kP$)x-*A)ueiR=&L\""
                        "-Hd&sN[M[#BS;ZVIn#j7Lj{E`7 c:%%bK")),  /* Random text fuzz */
            set(PAYLOAD_SIZE, 328)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "My_Instance_Name"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/iam/security-credentials/My_Instance_Name"),
            expect(METHOD, FLB_HTTP_GET),
            expect(HEADER, "X-aws-ec2-metadata-token", "AQAAANjUxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_Q=="),
            set(STATUS, 200),
            set(PAYLOAD, "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2021-09-16T18:29:09Z\",\n"
                "  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"XACCESSEC2XXX\",\n  \"SecretAccessKey\""
                " : \"XSECRETEC2XXXXXXXXXXXXXX\",\n  \"Token\" : \"XTOKENEC2XXXXXXXXXXXXXXX==\",\n"
                "  \"Expiration\" : \"3021-09-17T00:41:00Z\"\n}"),  /* Expires Year 3021 */
            set(PAYLOAD_SIZE, 257)
        )
    ));

    /* First call to get_credentials() */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* Second call to get_credentials() */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* Third call to get_credentials() */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_CHECK(creds == NULL);

    /* Fourth call to get_credentials() */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Retrieve from cache */
    creds = provider->provider_vtable->get_credentials(provider);
    TEST_ASSERT(creds != NULL);
    TEST_CHECK(strcmp("XACCESSEC2XXX", creds->access_key_id) == 0);
    TEST_CHECK(strcmp("XSECRETEC2XXXXXXXXXXXXXX", creds->secret_access_key) == 0);
    TEST_CHECK(strcmp("XTOKENEC2XXXXXXXXXXXXXXX==", creds->session_token) == 0);

    flb_aws_credentials_destroy(creds);

    /* Check we have exhausted our response list */
    TEST_CHECK(flb_aws_client_mock_generator_count_unused_requests() == 0);

    cleanup_test();
}

/* IMDS specific testing */

/*
 * IMDS Creation and Destruction -- Test Summary
 *  First call to flb_aws_imds_create (fail)
 *  -> upstream not set
 *  Second call to flb_aws_imds_create (fail)
 *  -> upstream set
 *  -> upstream tcp not equal to IMDS (random text)
 *  Third call to flb_aws_imds_create (fail)
 *  -> upstream set
 *  -> upstream tcp not equal to IMDS (one fewer character)
 *  Fourth call to flb_aws_imds_create (fail)
 *  -> upstream set
 *  -> upstream tcp not equal to IMDS (one extra character)
 *  Fifth call to flb_aws_imds_create (fail)
 *  -> upstream set
 *  -> upstream tcp equal to IMDS address
 *  -> upstream port not equal to IMDS port (number 0)
 *  Sixth call to flb_aws_imds_create (success)
 *  -> upstream set
 *  -> upstream tcp equal to IMDS address
 *  -> upstream port equal to IMDS port (80)
 *  First call to flb_aws_imds_destroy (success)
 */
static void test_ec2_imds_create_and_destroy()
{
    /* Full test setup not needed */
    /* Initialize test environment */
    config_fluent = flb_config_init();

    struct flb_aws_imds_config i_config = flb_aws_imds_config_default;
    struct flb_aws_client a_client = { 0 };
    struct flb_aws_imds* imds;

    struct flb_upstream u_stream = { 0 };

    /* First call to flb_aws_imds_create */
    imds = flb_aws_imds_create(&i_config, &a_client);
    TEST_CHECK(imds == NULL);

    /* Second call to flb_aws_imds_create */
    a_client.upstream = &u_stream;
    u_stream.tcp_host = "Invalid host";
    imds = flb_aws_imds_create(&i_config, &a_client);
    TEST_CHECK(imds == NULL);

    /* Third call to flb_aws_imds_create */
    u_stream.tcp_host = "169.254.169.254ExtraInvalid";
    imds = flb_aws_imds_create(&i_config, &a_client);
    TEST_CHECK(imds == NULL);

    /* Fourth call to flb_aws_imds_create */
    u_stream.tcp_host = "169.254.169.254";
    u_stream.tcp_port = 0xBAD;
    imds = flb_aws_imds_create(&i_config, &a_client);
    TEST_CHECK(imds == NULL);

    /* Fifth call to flb_aws_imds_create */
    u_stream.tcp_host = "169.254.169.254";
    u_stream.tcp_port = 80;
    imds = flb_aws_imds_create(&i_config, &a_client);
    TEST_CHECK(imds != NULL);

    /* Destruction */
    flb_aws_imds_destroy(imds);

    flb_config_exit(config_fluent);
}

TEST_LIST = {
    { "test_ec2_provider_v2" , test_ec2_provider_v2},
    { "test_ec2_provider_v1" , test_ec2_provider_v1},
    { "test_ec2_provider_v1_v2_timeout" , test_ec2_provider_v1_v2_timeout},
    { "test_ec2_provider_version_detection_error" , test_ec2_provider_version_detection_error},
    { "test_ec2_provider_acquire_token_error" , test_ec2_provider_acquire_token_error},
    { "test_ec2_provider_metadata_request_error" , test_ec2_provider_metadata_request_error},
    { "test_ec2_imds_create_and_destroy" , test_ec2_imds_create_and_destroy},
    { 0 }
};
