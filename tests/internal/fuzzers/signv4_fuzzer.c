#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <monkey/mk_core.h>
#include <unistd.h>
#include <fluent-bit/flb_sds.h>
#include "flb_fuzz_header.h"

#define AWS_ACCESS_KEY_ID              "AWS_ACCESS_KEY_ID"
#define AWS_SECRET_ACCESS_KEY          "AWS_SECRET_ACCESS_KEY"
#define AWS_SESSION_TOKEN              "AWS_SESSION_TOKEN"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 59) {
        return 0;
    }

    /* Set flb_malloc_mod to be fuzzer-data dependent */
    flb_malloc_p = 0;
    flb_malloc_mod = *(int*)data;
    data += 4;
    size -= 4;

    /* Avoid division by zero for modulo operations */
    if (flb_malloc_mod == 0) {
        flb_malloc_mod = 1;
    }

    char s3_mode = data[0];
    MOVE_INPUT(1)
    int method = (int)data[0];

    /* Prepare a general null-terminated string */
    char *uri             = get_null_terminated(50, &data, &size);
    char *null_terminated = get_null_terminated(size, &data, &size);

    /* Now begin the core work of the fuzzer */
    struct flb_config *config;
    struct mk_list *tests;
    struct flb_aws_provider *provider;
    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_free(uri);
        flb_free(null_terminated);
        return 0;
    }
    mk_list_init(&config->upstreams);
    provider = flb_aws_env_provider_create();

    /* Create the necessary http context */
    struct flb_upstream *http_u;
    struct flb_connection *http_u_conn = NULL;
    struct flb_http_client *http_c;
    struct flb_config *http_config;

    http_config = flb_config_init();
    if (http_config == NULL) {
        flb_aws_provider_destroy(provider);
        flb_free(uri);
        flb_free(null_terminated);
        flb_free(config);
        return 0;
    }

    http_u = flb_upstream_create(http_config, "127.0.0.1", 8001, 0, NULL);
    if (http_u != NULL) {
        http_u_conn = flb_calloc(1, sizeof(struct flb_connection));
        if (http_u_conn != NULL) {
            http_u_conn->upstream = http_u;

            http_c = flb_http_client(http_u_conn, method, uri,
                         null_terminated, size, "127.0.0.1", 8001, NULL, 0);
            if (http_c) {
                /* Call into the main target flb_signv4_do*/
                time_t t = 1440938160;
                char *region = "us-east-1";
                char *access_key = "AKIDEXAMPLE";
                char *service = "service";
                char *secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
                int ret = setenv(AWS_ACCESS_KEY_ID, access_key, 1);
                if (ret >= 0) {
                    ret = setenv(AWS_SECRET_ACCESS_KEY, secret_key, 1);
                    if (ret >= 0) {
                        flb_sds_t signature = flb_signv4_do(http_c, FLB_TRUE, FLB_FALSE,
                                    t, region, service, s3_mode, NULL, provider);
                        if (signature) {
                          flb_sds_destroy(signature);
                        }
                    }
                }
                flb_http_client_destroy(http_c);
            }
        }
        flb_upstream_destroy(http_u);
    }

    /* Cleanup */
    flb_config_exit(http_config);
    flb_aws_provider_destroy(provider);
    flb_free(config);

    flb_free(null_terminated);
    flb_free(http_u_conn);
    flb_free(uri);

    return 0;
}
