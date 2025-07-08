/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_config.h>
#include "flb_tests_internal.h"


void test_upstream_with_proxy() {
    struct flb_config *config;
    struct flb_upstream *upstream1, *upstream2;
    
    /* Create a config with proxy settings */
    config = flb_config_init();
    if (!config) {
        TEST_CHECK(0);
        return;
    }
    
    /* Set proxy configuration */
    config->http_proxy = flb_strdup("http://proxy.example.com:8080");
    
    /* Test regular upstream creation - should use proxy */
    upstream1 = flb_upstream_create(config, "destination.com", 443, 0, NULL);
    TEST_CHECK(upstream1 != NULL);
    if (!upstream1) {
        flb_free(config->http_proxy);
        flb_config_exit(config);
        return;
    }
    
    /* Test bypass proxy upstream creation - should skip proxy */
    upstream2 = flb_upstream_create_bypass_proxy(config, "destination.com", 443, 0, NULL);
    TEST_CHECK(upstream2 != NULL);
    if (!upstream2) {
        flb_upstream_destroy(upstream1);
        flb_free(config->http_proxy);
        flb_config_exit(config);
        return;
    }
    
    /* VERIFY ACTUAL PROXY BEHAVIOR */
    /* upstream1 should connect to proxy, with destination as proxied target */
    TEST_CHECK(upstream1->tcp_host != NULL);
    TEST_CHECK(strcmp(upstream1->tcp_host, "proxy.example.com") == 0);
    TEST_CHECK(upstream1->tcp_port == 8080);
    TEST_CHECK(upstream1->proxied_host != NULL);
    TEST_CHECK(strcmp(upstream1->proxied_host, "destination.com") == 0);
    TEST_CHECK(upstream1->proxied_port == 443);
    
    /* upstream2 should connect directly to destination, no proxy */
    TEST_CHECK(upstream2->tcp_host != NULL);
    TEST_CHECK(strcmp(upstream2->tcp_host, "destination.com") == 0);
    TEST_CHECK(upstream2->tcp_port == 443);
    TEST_CHECK(upstream2->proxied_host == NULL);  /* No proxying! */
    
    /* Cleanup */
    flb_upstream_destroy(upstream1);
    flb_upstream_destroy(upstream2);
    
    flb_free(config->http_proxy);
    flb_config_exit(config);
}

TEST_LIST = {
    { "upstream_with_proxy", test_upstream_with_proxy },
    { 0 }
};
