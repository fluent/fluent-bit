#include <fluent-bit.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_stream.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include "flb_tests_runtime.h"
#include <stdlib.h>
#include <unistd.h>

void test_instance_principal_auth()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    setenv("FLB_OCI_PLUGIN_UNDER_TEST", "1", 1);
    setenv("TEST_IMDS_SUCCESS", "1", 1);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    TEST_MSG("failed to create flb context");

    if (!ctx) {
        return;
    }

    flb_service_set(ctx, "flush", "1", "grace", "1", "log_level", "debug",
                    NULL);

    in_ffd = flb_input(ctx, "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_MSG("failed to create input instance");

    if (in_ffd < 0) {
        flb_destroy(ctx);
        return;
    }

    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, "oracle_log_analytics", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_MSG("failed to create output instance");

    if (out_ffd < 0) {
        flb_destroy(ctx);
        return;
    }

    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "auth_type", "instance_principal",
                   "namespace", "test_namespace",
                   "oci_la_log_group_id", "test_log_group",
                   "oci_la_log_source_name", "test_source",
                   "tls", "on", "tls.verify", "off", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    TEST_MSG("flb_start failed ret -> %d..", ret);

    if (ret == 0) {
        TEST_MSG("plugin initialized successfully");
        flb_stop(ctx);
    }

    flb_destroy(ctx);

    unsetenv("TEST_IMDS_SUCCESS");
}

void test_imds_failure()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    setenv("FLB_OCI_PLUGIN_UNDER_TEST", "1", 1);
    setenv("TEST_IMDS_FAILURE", "1", 1);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx, "flush", "1", "grace", "1", "log_level", "debug",
                    NULL);

    in_ffd = flb_input(ctx, "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, "oracle_log_analytics", NULL);
    TEST_CHECK(out_ffd >= 0);

    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "auth_type", "instance_principal",
                   "namespace", "test_namespace",
                   "oci_la_log_group_id", "test_log_group",
                   "oci_la_log_source_name", "test_source", NULL);

    ret = flb_start(ctx);

    TEST_CHECK(ret != 0);

    flb_destroy(ctx);

    unsetenv("FLB_OCI_PLUGIN_UNDER_TEST");
    unsetenv("TEST_IMDS_FAILURE");
}

void test_config_file_auth()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    char config_content[] =
        "[DEFAULT]\n"
        "user=ocid1.user.oc1..test\n"
        "fingerprint=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\n"
        "tenancy=ocid1.tenancy.oc1..test\n"
        "region=us-ashburn-1\n" "key_file=/tmp/test_key.pem\n";

    char key_content[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"
        "vGZlGJpmn65+A4xHXWUId1eJsCMFtgKhXFMSp6/8RkLcYMrFoAWKpILYdSrvJ0R6\n"
        "6u+zR1EpqQvk8TDrNMVzfv/jDPPG2BHYkp7RWE7pWQv8vZGnU6p3SJGvTwKdgnjG\n"
        "jNvCsXI8Dx7ePLxLZhX0Vg8bqXFfVVN3FlWKVfPy4jLQfQhWVx7dL1EfJL2YiEXI\n"
        "1Oj2DQKLVxPHHcNRVJKXhUHJ2F6PVYqMfAJ9bJnTHhOGZfYWO7pQQQv2eFaInp6s\n"
        "6LfDZ/P9l5T7PiNJvWNGnJZpVQqEXdqTxXrCMQIDAQABAoIBABPHBWJ1BwpJVxjJ\n"
        "DvVF6qMvHdFXdFyxJkYmGMxXl7xLdEXLzEKfvAh4Mm4XnL5tVEUWr/5uOVqPNgQm\n"
        "9E3SpJdoFUk4V8hCdLr1WkdWpHLiIzH7M3LXyLzWhFrLx1nC7tFGfOZWLCmE1SLM\n"
        "Yv2FvqcqAVEkpNjbYB8pLQVQZzNqvqqvFuUGW7jHLQsXnvVFLxHjD6YIqPZHsKYY\n"
        "VLPSZvSx2VHWOPbBKvM6fqLwQJfJWqjJGH7sBCuQGGKzpb3Jqhqb/5WdY4LTQKCQ\n"
        "bXPcGqHhGvKFCMELXCcLdqmQNflQZOTpZLVmHQMGJQYRY2gOkJCRs0UQVR0gVkDX\n"
        "6l6EoAECgYEA9aAZxLlnJBjFPwQT8UkFvzAZJfPBHCkNBwLmxL/WGLQPMmLcYZkD\n"
        "jGOGsLFNjNuDhAQQVjMFoME0mKNpFJGKqLcNcKYUQKdvHqTrqCOxLQpCEbvJ3qYB\n"
        "dYNFLFzpfMqCiL7kQjRLzZIH3k5K9Dg8+JKNn5VX8g9LMXr7clKJgfECgYEA1Bk4\n"
        "qsHjMjPMVdmVCEiCpGPBVy7j6dFWbFJT3WqdLMqz7mLvL3spLLWZKDvKFdAhFIKb\n"
        "AkWVQBKpUQKxtCBfJXCX3KKqfMxXKCNm7QH7hFXpKvVKLKuXphCW/6Y+qU8JUHyO\n"
        "Y5rn6eMmfzOTRJGp2C2hMKqKHw6pEJmdC5K0pLkCgYAZXPBJGhSNY3x3TIzQMvvF\n"
        "jjEZRLHnmCBJqS4J1vqJLJqXqfnHSFwZBEChFLLgXLFKjJGqNGQbV3NkwZWQXkOT\n"
        "Zy3FQhPLvVMKOKvWHW8bLQS7FQVDCJQ2TIJ0OPQhAjTJLQEFJ5WEK0LmJqEDTHXP\n"
        "HK6LgqLEcaV2xvlYKgYbQQKBgF7eG3LWxKmfH0NbQXZ5UFVQW3VCXOQ4LBBb3y0w\n"
        "VnvGqLMV5GJVP2gHxPFQM4T0eW8xLXNM5LYH3xqvLGGmvx3YGqGDh+FDHqtI9pCC\n"
        "qPoLLBZ4pLfBGJfaVFHJQBLJNHNgCLz7LLQ5YYhQYjCWGKcuNvEzNiDvKMQePLjL\n"
        "EoHpAoGBAK3pHYfhwCJRGNVJbKO6BjfLQr8JDXKdqzaGmKKN2eVdNGqLFjFuFl6N\n"
        "fVHxq3RKFfgwGYkZ8pCNLHK7lO8Q9i2BO7qE1bDZFqRMJgC6EqhHLVEHDYVYGDrO\n"
        "VDLq3cL2MQKmVPrmWCFKLJSXiKGmqYZmVXC7FqfJJrKqLdFQCZNf\n"
        "-----END RSA PRIVATE KEY-----\n";

    FILE *config_file = fopen("/tmp/test_oci_config", "w");
    TEST_CHECK(config_file != NULL);
    if (config_file) {
        fwrite(config_content, 1, strlen(config_content), config_file);
        fclose(config_file);
    }

    FILE *key_file = fopen("/tmp/test_key.pem", "w");
    TEST_CHECK(key_file != NULL);
    if (key_file) {
        fwrite(key_content, 1, strlen(key_content), key_file);
        fclose(key_file);
    }

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx, "flush", "1", "grace", "1", "log_level", "debug",
                    NULL);

    in_ffd = flb_input(ctx, "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, "oracle_log_analytics", NULL);
    TEST_CHECK(out_ffd >= 0);

    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "auth_type", "config_file",
                   "config_file_location", "/tmp/test_oci_config",
                   "namespace", "test_namespace",
                   "oci_la_log_group_id", "test_log_group",
                   "oci_la_log_source_name", "test_source",
                   "tls", "on", "tls.verify", "off", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    if (ret == 0) {
        flb_stop(ctx);
    }

    flb_destroy(ctx);

    unlink("/tmp/test_oci_config");
    unlink("/tmp/test_key.pem");
}

TEST_LIST = {
    {"test_instance_principal_auth", test_instance_principal_auth},
    {"test_imds_failure", test_imds_failure},
    {"test_config_file_auth", test_config_file_auth},
    {0}
};
