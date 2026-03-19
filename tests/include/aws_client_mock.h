/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * AWS Client Mock
 *
 * Usage: #include both .h and .c files in test files
 * Limitation: Do not compile multiple tests into one executable (duplicate symbols)
 * Thread safety: Not safe for concurrent tests (uses static variables)
 */

/*
 * FLB_AWS_CLIENT_MOCK() definition
 * The following macro FLB_AWS_CLIENT_MOCK() translates a request definition
 * into a c compound literal, which constructs a mock request chain
 * at the block scope.

 * The following translation might ouccur:

    FLB_AWS_CLIENT_MOCK(
        response(
            expect("token", "aws_token")
            expect("time", "123456")
            set(STATUS, 200),
        ),
        response(
            set(STATUS, 200),
        )
    )

 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 * *~~~> Translates to ~~~>*
 * *vvvvvvvvvvvvvvvvvvvvvvv*

    &(struct flb_aws_client_mock_request_chain){
        2,
        ((struct flb_aws_client_mock_response[]) { // Mock request chain
            {
                3,
                (struct flb_aws_client_mock_response_config[]){
                    ((struct flb_aws_client_mock_response_config) { // Response
 configuration FLB_AWS_CLIENT_MOCK_EXPECT_HEADER, (void *) "token", (void *) "aws_token"
                    }),
                    ((struct flb_aws_client_mock_response_config)
                        { FLB_AWS_CLIENT_MOCK_EXPECT_HEADER,
                            (void *) "time",
                            (void *) "123456"
                        }
                    )
                    ((struct flb_aws_client_mock_response_config) { // Response
 configuration FLB_AWS_CLIENT_MOCK_SET_STATUS, (void *) 200, (void *) 0
                    }),
                }
            },
            {
                1,
                &(struct flb_aws_client_mock_response_config) {
                    FLB_AWS_CLIENT_MOCK_SET_STATUS,
                    (void *) 200,
                    (void *) 0
                }
            }
        })
    }
*/

#ifndef AWS_CLIENT_MOCK_H
#define AWS_CLIENT_MOCK_H

/* Variadic Argument Counter, Counts up to 64 variadic args */
#define FLB_AWS_CLIENT_MOCK_COUNT64(...)                                                 \
    _FLB_AWS_CLIENT_MOCK_COUNT64(dummy, ##__VA_ARGS__, 63, 62, 61, 60, 59, 58, 57, 56,   \
                                 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, \
                                 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, \
                                 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, \
                                 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define _FLB_AWS_CLIENT_MOCK_COUNT64(                                                    \
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, \
    x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35, \
    x36, x37, x38, x39, x40, x41, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x52, \
    x53, x54, x55, x56, x57, x58, x59, x60, x61, x62, x63, count, ...)                   \
    count

#define FLB_AWS_CLIENT_MOCK_EVAL(...) __VA_ARGS__
#define FLB_AWS_CLIENT_MOCK_EMPTY()
#define FLB_AWS_CLIENT_MOCK_DIFER(...) \
    FLB_AWS_CLIENT_MOCK_EVAL FLB_AWS_CLIENT_MOCK_EMPTY()(__VA_ARGS__)

/* Make block-scope addressable compound-literal request chain */
#define FLB_AWS_CLIENT_MOCK(...)                                          \
    FLB_AWS_CLIENT_MOCK_EVAL(&(struct flb_aws_client_mock_request_chain){ \
        FLB_AWS_CLIENT_MOCK_COUNT64(__VA_ARGS__),                         \
        (struct flb_aws_client_mock_response[]){__VA_ARGS__}})

#define FLB_AWS_CLIENT_MOCK_RESPONSE(...)                  \
    {                                                      \
        FLB_AWS_CLIENT_MOCK_COUNT64(__VA_ARGS__),          \
            (struct flb_aws_client_mock_response_config[]) \
        {                                                  \
            __VA_ARGS__                                    \
        }                                                  \
    }

#define FLB_AWS_CLIENT_MOCK_VFUNC___(name, n) name##n
#define FLB_AWS_CLIENT_MOCK_VFUNC(name, n) FLB_AWS_CLIENT_MOCK_VFUNC___(name, n)

#define FLB_AWS_CLIENT_MOCK_STAGE_CONFIG(mode, parameter, value, ...) \
    ((struct flb_aws_client_mock_response_config){                    \
        FLB_AWS_CLIENT_MOCK_##mode##parameter, (void *)value,         \
        FLB_AWS_CLIENT_MOCK_VFUNC(                                    \
            FLB_AWS_CLIENT_MOCK_STAGE_CONFIG_OPTIONAL_VALUES_,        \
            FLB_AWS_CLIENT_MOCK_COUNT64(__VA_ARGS__))(__VA_ARGS__)})

#define FLB_AWS_CLIENT_MOCK_STAGE_CONFIG_OPTIONAL_VALUES_1(value) (void *)value
#define FLB_AWS_CLIENT_MOCK_STAGE_CONFIG_OPTIONAL_VALUES_0() (void *)0

// DIFER() allows for correct arg count
#define response(...) FLB_AWS_CLIENT_MOCK_DIFER(FLB_AWS_CLIENT_MOCK_RESPONSE(__VA_ARGS__))
#define expect(...) \
    FLB_AWS_CLIENT_MOCK_DIFER(FLB_AWS_CLIENT_MOCK_STAGE_CONFIG(EXPECT_, __VA_ARGS__))
#define config(...) \
    FLB_AWS_CLIENT_MOCK_DIFER(FLB_AWS_CLIENT_MOCK_STAGE_CONFIG(CONFIG_, __VA_ARGS__))
#define set(...) \
    FLB_AWS_CLIENT_MOCK_DIFER(FLB_AWS_CLIENT_MOCK_STAGE_CONFIG(SET_, __VA_ARGS__))

/* Includes */
#include <fluent-bit/flb_aws_util.h>

#include "../lib/acutest/acutest.h"
#include <pthread.h>

/* Enum */
enum flb_aws_client_mock_response_config_parameter {
    FLB_AWS_CLIENT_MOCK_EXPECT_METHOD,  // int: FLB_HTTP_<method> where method = { "GET",
                                        // "POST", "PUT", "HEAD", "CONNECT", "PATCH" }
    FLB_AWS_CLIENT_MOCK_EXPECT_HEADER,  // (string, string): (header key, header value)
    FLB_AWS_CLIENT_MOCK_EXPECT_HEADER_EXISTS,  // string: header key (checks if header exists)
    FLB_AWS_CLIENT_MOCK_EXPECT_HEADER_COUNT,  // int: header count
    FLB_AWS_CLIENT_MOCK_EXPECT_URI,           // string: uri
    FLB_AWS_CLIENT_MOCK_CONFIG_REPLACE,  // flb_http_client ptr. Client can be null if
                                         // needed
// Define all client fields using XMacro definitions
#define EXPAND_CLIENT_RESPONSE_PARAMETER(x, UPPER, y) FLB_AWS_CLIENT_MOCK_SET_##UPPER,
#include "aws_client_mock_client_resp.def"
#undef EXPAND_CLIENT_RESPONSE_PARAMETER
};

/* Structs */
struct flb_aws_client_mock_response_config {
    enum flb_aws_client_mock_response_config_parameter config_parameter;
    void *config_value;  // Most configuration must be passed in string format.
    void *config_value_2;
};

struct flb_aws_client_mock_response {
    size_t length;
    struct flb_aws_client_mock_response_config *config_parameters;
};

struct flb_aws_client_mock_request_chain {
    size_t length;
    struct flb_aws_client_mock_response *responses;
};

struct flb_aws_client_mock_shared_state {
    struct flb_aws_client_mock_request_chain *request_chain;
    size_t next_request_index;
    pthread_mutex_t lock;
};

struct flb_aws_client_mock {
    /* This member must come first in the struct's memory layout
     * so that this struct can mock flb_aws_client context */
    struct flb_aws_client super;
    struct flb_aws_client *surrogate;

    /* Additional data members added to mock */
    struct flb_aws_client_mock_shared_state *shared;
    int owns_shared; /* Flag to indicate if this instance owns the shared state memory */
};

/* Declarations */

/*
 * Configure mock generator to be returned by flb_aws_client_get_mock_generator()
 * Generator is injected into credential providers and returns a mocked
 * flb_aws_client instance.
 *
 * Note: Automatically creates mock and wires to generator
 *       Destroys any existing mock in generator
 */
void flb_aws_client_mock_configure_generator(
    struct flb_aws_client_mock_request_chain *request_chain);

/*
 * Clean up generator memory
 * Note: Cleanup should be called at the end of each test
 */
void flb_aws_client_mock_destroy_generator();

/*
 * Clear generator instance without freeing
 * Use this after flb_destroy() when the S3 plugin has already freed the mock client
 * This prevents use-after-free when configure_generator is called again
 */
void flb_aws_client_mock_clear_generator_instance();

/* Create Mock of flb_aws_client */
struct flb_aws_client_mock *flb_aws_client_mock_create(
    struct flb_aws_client_mock_request_chain *request_chain);

/*
 * Destroy flb_aws_client_mock
 * Note: flb_aws_client_destroy must not be used prior to flb_aws_client_mock_destroy.
 */
void flb_aws_client_mock_destroy(struct flb_aws_client_mock *mock);

/* Get the number of unused requests */
int flb_aws_client_mock_count_unused_requests(struct flb_aws_client_mock *mock);

/* Return a Mocked flb_aws_client, ready for injection */
struct flb_aws_client *flb_aws_client_mock_context(struct flb_aws_client_mock *mock);

/* Generator Methods */
/* Get/set flb_aws_client_mock_instance used by mock generator */
void flb_aws_client_mock_set_generator_instance(struct flb_aws_client_mock *mock);
struct flb_aws_client_mock *flb_aws_client_mock_get_generator_instance(
    struct flb_aws_client_mock *mock);

int flb_aws_client_mock_generator_count_unused_requests();

/* Substitute Methods */
/* Get generator used in mock */
struct flb_aws_client_generator *flb_aws_client_get_mock_generator();

/* Return the mock instance */
struct flb_aws_client *flb_aws_client_create_mock();

#endif /* AWS_CLIENT_MOCK_H */