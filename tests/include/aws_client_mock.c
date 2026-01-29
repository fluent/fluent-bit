/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * AWS Client Mock Implementation
 *
 * NOTE: This .c file is directly included in test files (not compiled separately).
 *       Each test is built as a standalone executable, avoiding symbol conflicts.
 *       DO NOT compile multiple tests using this mock into a single executable
 *       without refactoring to a test library or using static functions.
 */

#define TEST_NO_MAIN
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
 * Note: This is safe to call even if the mock was already freed by S3 plugin cleanup
 */
void flb_aws_client_mock_destroy_generator()
{
    struct flb_aws_client_mock *mock = flb_aws_client_mock_instance;

    /* Clear instance first to prevent double-free scenarios */
    flb_aws_client_mock_instance = NULL;

    if (mock != NULL) {
        flb_aws_client_mock_destroy(mock);
    }
}

/*
 * Clear generator instance without freeing
 * Use this after flb_destroy() when the S3 plugin has already freed the mock client
 * This prevents use-after-free when configure_generator is called again
 */
void flb_aws_client_mock_clear_generator_instance()
{
    flb_aws_client_mock_instance = NULL;
}

/* Create Mock of flb_aws_client */
struct flb_aws_client_mock *flb_aws_client_mock_create(
    struct flb_aws_client_mock_request_chain *request_chain)
{
    struct flb_aws_client_mock *mock = flb_calloc(1, sizeof(struct flb_aws_client_mock));
    if (!mock) {
        return NULL;
    }

    /* Create a surrogate aws_client and copy to mock client */
    struct flb_aws_client *surrogate_aws_client = flb_aws_client_generator()->create();
    if (!surrogate_aws_client) {
        flb_free(mock);
        return NULL;
    }
    mock->super = *surrogate_aws_client;
    mock->surrogate = surrogate_aws_client;
    memset(mock->surrogate, 0, sizeof(struct flb_aws_client));

    /* Switch vtable to mock vtable */
    mock->super.client_vtable = &mock_client_vtable;

    /* Initialize shared state */
    mock->shared = flb_calloc(1, sizeof(struct flb_aws_client_mock_shared_state));
    if (!mock->shared) {
        flb_aws_client_destroy(mock->surrogate);
        flb_free(mock);
        return NULL;
    }
    mock->shared->request_chain = request_chain;
    mock->shared->next_request_index = 0;
    pthread_mutex_init(&mock->shared->lock, NULL);
    mock->owns_shared = 1;

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
    if (mock->surrogate) {
        *mock->surrogate = mock->super;
        flb_aws_client_destroy(mock->surrogate);
    }

    /* Destroy shared state if owned */
    if (mock->owns_shared && mock->shared) {
        pthread_mutex_destroy(&mock->shared->lock);
        flb_free(mock->shared);
    }

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
    int count;
    pthread_mutex_lock(&mock->shared->lock);
    count = mock->shared->request_chain->length - mock->shared->next_request_index;
    pthread_mutex_unlock(&mock->shared->lock);
    return count;
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

    /* Create a new mock instance that shares state with the primary instance */
    struct flb_aws_client_mock *new_mock = flb_calloc(1, sizeof(struct flb_aws_client_mock));
    if (!new_mock) {
        return NULL;
    }

    /* Create a fresh surrogate for this instance */
    struct flb_aws_client *surrogate = flb_aws_client_generator()->create();
    if (surrogate == NULL) {
        flb_free(new_mock);
        return NULL;
    }
    new_mock->super = *surrogate;
    new_mock->surrogate = surrogate;
    memset(new_mock->surrogate, 0, sizeof(struct flb_aws_client));

    /* Setup mock vtable */
    new_mock->super.client_vtable = &mock_client_vtable;

    /* Share state with primary instance */
    new_mock->shared = flb_aws_client_mock_instance->shared;
    new_mock->owns_shared = 0;

    return flb_aws_client_mock_context(new_mock);
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
    struct flb_aws_client_mock_response *response;

    /* Lock shared state */
    pthread_mutex_lock(&mock->shared->lock);

    /* Check that a response is left in the chain */
    ret = TEST_CHECK(mock->shared->next_request_index < mock->shared->request_chain->length);
    if (!ret) {
        TEST_MSG(
            "[flb_aws_client_mock] %d mock responses provided. Attempting to call %d "
            "times. Aborting.",
            (int)mock->shared->request_chain->length, (int)mock->shared->next_request_index + 1);
        pthread_mutex_unlock(&mock->shared->lock);
        return NULL;
    }
    response = &(mock->shared->request_chain->responses[mock->shared->next_request_index]);
    
    /* Increment request index atomically */
    mock->shared->next_request_index++;
    
    /* We can release the lock now as we have the response pointer (read-only) */
    pthread_mutex_unlock(&mock->shared->lock);

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
        else if (response_config->config_parameter == FLB_AWS_CLIENT_MOCK_EXPECT_HEADER_EXISTS) {
            int header_found = FLB_FALSE;
            /* Search for header key in request */
            for (h = 0; h < dynamic_headers_len; ++h) {
                ret = strncmp(dynamic_headers[h].key, (char *)val1,
                              dynamic_headers[h].key_len);
                if (ret == 0) {
                    header_found = FLB_TRUE;
                    break;
                }
            }
            TEST_CHECK(header_found);
            TEST_MSG("[aws_mock_client] Expected Header Key to exist: %s", (char *)val1);
            if (!header_found) {
                TEST_MSG("[aws_mock_client] Header key not found in request");
            }
        }
        else if (response_config->config_parameter == FLB_AWS_CLIENT_MOCK_EXPECT_METHOD) {
            char *flb_http_methods[] = {
                "FLB_HTTP_GET",  "FLB_HTTP_POST",    "FLB_HTTP_PUT",
                "FLB_HTTP_HEAD", "FLB_HTTP_CONNECT", "FLB_HTTP_PATCH",
                "FLB_HTTP_DELETE",
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
         * Special handling for DATA field - must be dynamically allocated
         * because flb_http_client_destroy() will call flb_free(c->resp.data)
         */
        else if (response_config->config_parameter == FLB_AWS_CLIENT_MOCK_SET_DATA) {
            if (val1 != NULL) {
                /* Get data size from response config or use strlen */
                size_t data_len = 0;
                int j;
                for (j = 0; j < response->length; ++j) {
                    if (response->config_parameters[j].config_parameter ==
                        FLB_AWS_CLIENT_MOCK_SET_DATA_SIZE) {
                        data_len = (size_t)(uintptr_t)response->config_parameters[j].config_value;
                        break;
                    }
                    if (response->config_parameters[j].config_parameter ==
                        FLB_AWS_CLIENT_MOCK_SET_DATA_LEN) {
                        data_len = (size_t)(uintptr_t)response->config_parameters[j].config_value;
                        break;
                    }
                }
                if (data_len == 0) {
                    data_len = strlen((char *)val1);
                }
                /* Allocate and copy data so flb_http_client_destroy can free it */
                c->resp.data = flb_malloc(data_len + 1);
                if (c->resp.data) {
                    memcpy(c->resp.data, val1, data_len);
                    c->resp.data[data_len] = '\0';
                    c->resp.data_len = data_len;
                    c->resp.data_size = data_len + 1;
                }
                else {
                    TEST_MSG("[aws_mock_client] Failed to allocate memory for response data");
                    flb_http_client_destroy(c);
                    return NULL;
                }
            }
        }

        /*
        * Response setters
        * Set client fields using XMacro definitions
        * Note: DATA field is handled specially above
        */
#define EXPAND_CLIENT_RESPONSE_PARAMETER(lower, UPPER, type)                           \
        else if (response_config->config_parameter == FLB_AWS_CLIENT_MOCK_SET_##UPPER  \
                 && response_config->config_parameter != FLB_AWS_CLIENT_MOCK_SET_DATA) \
        {                                                                              \
            c->resp.lower = CONVERT_##type((char *)val1);                              \
        }
#include "aws_client_mock_client_resp.def"
#undef EXPAND_CLIENT_RESPONSE_PARAMETER
    }

    return c;
};
