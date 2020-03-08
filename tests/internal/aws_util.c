/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_mem.h>

#include "flb_tests_internal.h"

static void test_flb_aws_error()
{
    flb_sds_t error_type;
    char *api_response =  "{\"__type\":\"IncompleteSignatureException\","
                          "\"message\": \"Credential must have exactly 5 "
                          "slash-delimited elements, e.g. keyid/date/region/"
                          "service/term, got '<Credential>'\"}";
    char *garbage = "garbage"; /* something that can't be parsed */

    error_type = flb_aws_error(api_response, strlen(api_response));

    TEST_CHECK(strcmp("IncompleteSignatureException", error_type) == 0);

    flb_sds_destroy(error_type);

    error_type = flb_aws_error(garbage, strlen(garbage));

    TEST_CHECK(error_type == NULL);

    flb_sds_destroy(error_type);
}

static void test_flb_aws_endpoint()
{
    char *endpoint;

    endpoint = flb_aws_endpoint("cloudwatch", "ap-south-1");

    TEST_CHECK(strcmp("cloudwatch.ap-south-1.amazonaws.com",
                      endpoint) == 0);
    flb_free(endpoint);

    /* China regions have a different TLD */
    endpoint = flb_aws_endpoint("cloudwatch", "cn-north-1");

    TEST_CHECK(strcmp("cloudwatch.cn-north-1.amazonaws.com.cn",
                      endpoint) == 0);
    flb_free(endpoint);

}

TEST_LIST = {
    { "parse_api_error" , test_flb_aws_error},
    { "flb_aws_endpoint" , test_flb_aws_endpoint},
    { 0 }
};
