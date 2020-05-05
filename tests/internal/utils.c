/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>

#include "flb_tests_internal.h"


struct url_check {
    int ret;
    char *url;     /* full URL          */
    char *prot;    /* expected protocol */
    char *host;    /* expected host     */
    char *port;    /* expected port     */
    char *uri;     /* expected uri      */
};

struct url_check url_checks[] = {
    {0, "https://fluentbit.io/something",
     "https", "fluentbit.io", "443", "/something"},
    {0, "http://fluentbit.io/something",
     "http", "fluentbit.io", "80", "/something"},
    {0, "https://fluentbit.io", "https", "fluentbit.io", "443", "/"},
    {0, "https://fluentbit.io:1234/something",
    "https", "fluentbit.io", "1234", "/something"},
    {0, "https://fluentbit.io:1234", "https", "fluentbit.io", "1234", "/"},
    {0, "https://fluentbit.io:1234/", "https", "fluentbit.io", "1234", "/"},
    {0, "https://fluentbit.io:1234/v", "https", "fluentbit.io", "1234", "/v"},
    {-1, "://", NULL, NULL, NULL, NULL},
};

void test_url_split()
{
    int i;
    int ret;
    int size;
    char *protocol;
    char *host;
    char *port;
    char *uri;
    struct url_check *u;

    size = sizeof(url_checks) / sizeof(struct url_check);
    for (i = 0; i < size; i ++) {
        u = &url_checks[i];

        protocol = NULL;
        host = NULL;
        port = NULL;
        uri = NULL;

        ret = flb_utils_url_split(u->url, &protocol, &host, &port, &uri);
        TEST_CHECK(ret == u->ret);
        if (ret == -1) {
            continue;
        }

        /* protocol */
        if (u->prot) {
            TEST_CHECK(protocol != NULL);

            ret = strcmp(u->prot, protocol);
            TEST_CHECK(ret == 0);
        }
        else {
            TEST_CHECK(protocol == NULL);
        }

        /* host */
        if (u->host) {
            TEST_CHECK(host != NULL);
            ret = strcmp(u->host, host);
            TEST_CHECK(ret == 0);
        }
        else {
            TEST_CHECK(host == NULL);
        }

        /* port */
        if (u->port) {
            TEST_CHECK(port != NULL);
            ret = strcmp(u->port, port);
            TEST_CHECK(ret == 0);
        }
        else {
            TEST_CHECK(port == NULL);
        }

        /* uri */
        if (u->uri) {
            TEST_CHECK(uri != NULL);
            ret = strcmp(u->uri, uri);
            TEST_CHECK(ret == 0);
        }
        else {
            TEST_CHECK(uri == NULL);
        }

        if (protocol) {
            flb_free(protocol);
        }
        if (host) {
            flb_free(host);
        }
        if (port) {
            flb_free(port);
        }
        if (uri) {
            flb_free(uri);
        }
    }
}

void test_write_str()
{
    char buf[10];
    int size = sizeof(buf);
    int off;
    int ret;

    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "a", 1);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(memcmp(buf, "a", off) == 0);

    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "\n", 1);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(memcmp(buf, "\\n", off) == 0);

    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "\xe3\x81\x82", 3);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(memcmp(buf, "\\u3042", off) == 0);

    // Truncated bytes
    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "\xe3\x81\x82\xe3", 1);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(memcmp(buf, "\\u3042", off) == 0);

    // Error: buffer too small
    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "aaaaaaaaaaa", 11);
    TEST_CHECK(ret == FLB_FALSE);
}

TEST_LIST = {
    /* JSON maps iteration */
    { "url_split", test_url_split },
    { "write_str", test_write_str },
    { 0 }
};
