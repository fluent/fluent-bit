/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "aws_client_mock.h"

#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_http_client.h>

/* Vtable mocked methods */
static struct flb_http_client *flb_aws_client_mock_vtable_request(
    struct flb_aws_client *aws_client, int method, const char *uri, const char *body,
    size_t body_len, struct flb_aws_header *dynamic_headers, size_t dynamic_headers_len);

/* Protected structs */

/* flb_aws_client_mock pointer returned by mock_generator */
static struct flb_aws_client_mock *flb_aws_client_mock_instance = NULL;

/* Generator that returns clients with the test vtable */
static struct flb_aws_client_generator mock_generator = {
    .create = flb_aws_client_create_mock,
};

/* Test/mock flb_aws_client vtable */
static struct flb_aws_client_vtable mock_client_vtable = {
    .request = flb_aws_client_mock_vtable_request,
};

/*
 * Configure generator
 * Note: Automatically creates mock and wires to generator
 *       Destroys any existing mock in generator
 */
void flb_aws_client_mock_configure_generator(
    struct flb_aws_client_mock_request_chain *request_chain)
{
    flb_aws_client_mock_destroy_generator();
    flb_aws_client_mock_instance = flb_aws_client_mock_create(request_chain);
}

/*
 * Clean up generator's memory
 * Cleanup should be called on exiting generator
 */
void flb_aws_client_mock_destroy_generator()
{
    if (flb_aws_client_mock_instance != NULL) {
        flb_aws_client_mock_destroy(flb_aws_client_mock_instance);
    }
}

/* Create Mock of flb_aws_client */
struct flb_aws_client_mock *flb_aws_client_mock_create(
    struct flb_aws_client_mock_request_chain *request_chain)
{
    struct flb_aws_client_mock *mock = flb_calloc(1, sizeof(struct flb_aws_client_mock));

    /* Create a surrogate aws_client and copy to mock client */
    struct flb_aws_client *surrogate_aws_client = flb_aws_client_generator()->create();
    mock->super = *surrogate_aws_client;
    mock->surrogate = surrogate_aws_client;
    memset(mock->surrogate, 0, sizeof(struct flb_aws_client));

    /* Switch vtable to mock vtable */
    mock->super.client_vtable = &mock_client_vtable;
    mock->request_chain = request_chain;
    mock->next_request_index = 0;
    return mock;
}

/* Destroy flb_aws_client_mock */
void flb_aws_client_mock_destroy(struct flb_aws_client_mock *mock)
{
    /* Remove from generator registry if stored */
    if (flb_aws_client_mock_instance == mock) {
        flb_aws_client_mock_instance = NULL;
    }

    /* Resurrect surrogate, and destroy flb_aws_client */
    *mock->surrogate = mock->super;
    flb_aws_client_destroy(mock->surrogate);

    /* Destroy mock flb_aws_client */
    flb_free(mock);
}

/* Return a Mocked flb_aws_client, ready for injection */
struct flb_aws_client *flb_aws_client_mock_context(struct flb_aws_client_mock *mock)
{
    return (struct flb_aws_client *)mock;
}

/* Get the number of unused requests */
int flb_aws_client_mock_count_unused_requests(struct flb_aws_client_mock *mock)
{
    return mock->request_chain->length - mock->next_request_index;
}

/* Set flb_aws_client_mock_instance used in mock generator */
void flb_aws_client_mock_set_generator_instance(struct flb_aws_client_mock *mock)
{
    flb_aws_client_mock_instance = mock;
}

/* Set flb_aws_client_mock_instance used in mock generator */
struct flb_aws_client_mock *flb_aws_client_mock_get_generator_instance(
    struct flb_aws_client_mock *mock)
{
    return flb_aws_client_mock_instance = mock;
}

/* Get generator used in mock */
struct flb_aws_client_generator *flb_aws_client_get_mock_generator()
{
    return &mock_generator;
}

/* Get the number of unused requests */
int flb_aws_client_mock_generator_count_unused_requests()
{
    TEST_ASSERT(flb_aws_client_mock_instance != 0);
    return flb_aws_client_mock_count_unused_requests(flb_aws_client_mock_instance);
}

/* Return the mock instance */
struct flb_aws_client *flb_aws_client_create_mock()
{
    TEST_CHECK(flb_aws_client_mock_instance != NULL);
    TEST_MSG(
        "[aws_mock_client] Must initialize flb_aws_client_mock_instance before calling "
        "flb_aws_client_create_mock()");
    TEST_MSG(
        "[aws_mock_client] This ouccurs when the generator is called, before tests are "
        "initialized.");

    return flb_aws_client_mock_context(flb_aws_client_mock_instance);
}

/* Mock request used by flb_aws_client mock */
static struct flb_http_client *flb_aws_client_mock_vtable_request(
    struct flb_aws_client *aws_client, int method, const char *uri, const char *body,
    size_t body_len, struct flb_aws_header *dynamic_headers, size_t dynamic_headers_len)
{
    int h;
    int i;
    int ret;

    /* Get access to mock */
    struct flb_aws_client_mock *mock = (struct flb_aws_client_mock *)aws_client;

    /* Check that a response is left in the chain */
    ret = TEST_CHECK(mock->next_request_index < mock->request_chain->length);
    if (!ret) {
        TEST_MSG(
            "[flb_aws_client_mock] %d mock responses provided. Attempting to call %d "
            "times. Aborting.",
            (int)mock->request_chain->length, (int)mock->next_request_index + 1);
        return NULL;
    }
    struct flb_aws_client_mock_response *response =
        &(mock->request_chain->responses[mock->next_request_index]);
    struct flb_http_client *c = NULL;

    /* create an http client so that we can set the response */
    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&c->headers);

    /* Response configuration */
    for (i = 0; i < response->length; ++i) {
        struct flb_aws_client_mock_response_config *response_config =
            &(response->config_parameters[i]);
        void *val1 = response_config->config_value;
        void *val2 = response_config->config_value_2;

        /* Expectations */
        if (response_config->config_parameter == FLB_AWS_CLIENT_MOCK_EXPECT_HEADER) {
            int header_found = FLB_FALSE;
            /* Search for header in request */
            for (h = 0; h < dynamic_headers_len; ++h) {
                ret = strncmp(dynamic_headers[h].key, (char *)val1,
                              dynamic_headers[h].key_len);
                if (ret == 0) {
                    /* Check header value */
                    ret = strncmp(dynamic_headers[h].val, (char *)val2,
                                  dynamic_headers[h].val_len + 1);
                    TEST_CHECK(ret == 0);
                    TEST_MSG("[aws_mock_client] Expected Header: (%s: %s)", (char *)val1,
                             (char *)val2);
                    TEST_MSG("[aws_mock_client] Received Header: (%s: %s)", (char *)val1,
                             dynamic_headers[h].val);

                    header_found = FLB_TRUE;
                }
            }
            TEST_CHECK(header_found);
            TEST_MSG("[aws_mock_client] Expected Header: (%s: %s)", (char *)val1,
                     (char *)val2);
            TEST_MSG("[aws_mock_client] Header not received");
        }
        else if (response_config->config_parameter == FLB_AWS_CLIENT_MOCK_EXPECT_METHOD) {
            char *flb_http_methods[] = {
                "FLB_HTTP_GET",  "FLB_HTTP_POST",    "FLB_HTTP_PUT",
                "FLB_HTTP_HEAD", "FLB_HTTP_CONNECT", "FLB_HTTP_PATCH",
            };

            /*
             * Check method is what is expected
             * Typecast config value from void * -> int
             */
            TEST_CHECK(method == (int)(uintptr_t)val1);
            TEST_MSG("[aws_mock_client] Expected HTTP Method: %s",
                     flb_http_methods[(int)(uintptr_t)val1]);
            TEST_MSG("[aws_mock_client] Received HTTP Method: %s",
                     flb_http_methods[method]);
        }
        else if (response_config->config_parameter ==
                 FLB_AWS_CLIENT_MOCK_EXPECT_HEADER_COUNT) {
            TEST_CHECK(dynamic_headers_len == (int)(uintptr_t)val1);
            TEST_MSG("[aws_mock_client] Expected %d Headers", (int)(uintptr_t)val1);
            TEST_MSG("[aws_mock_client] Received %d Headers",
                     (int)(uintptr_t)dynamic_headers_len);
        }
        else if (response_config->config_parameter == FLB_AWS_CLIENT_MOCK_EXPECT_URI) {
            ret = strncmp(uri, (char *)val1, strlen((char *)val1) + 1);
            TEST_CHECK(ret == 0);
            TEST_MSG("[aws_mock_client] Expected URI: %s", (char *)val1);
            TEST_MSG("[aws_mock_client] Received URI: %s", uri);
        }

        /* Replace response client */
        else if (response_config->config_parameter ==
                 FLB_AWS_CLIENT_MOCK_CONFIG_REPLACE) {
            flb_http_client_destroy(c);
            c = (struct flb_http_client *)val1;
        }

        /*
        * Response setters
        * Set client fields using XMacro definitions
        */
#define EXPAND_CLIENT_RESPONSE_PARAMETER(lower, UPPER, type)                           \
        else if (response_config->config_parameter == FLB_AWS_CLIENT_MOCK_SET_##UPPER) \
        {                                                                              \
            c->resp.lower = CONVERT_##type((char *)val1);                              \
        }
#include "aws_client_mock_client_resp.def"
#undef EXPAND_CLIENT_RESPONSE_PARAMETER
    }

    /* Increment request */
    ++mock->next_request_index;

    return c;
};
