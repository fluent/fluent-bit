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

struct write_str_case {
    char *input;
    int input_len;
    char *output;
    int ret;
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

/* test case loop for flb_utils_write_str */
static void write_str_test_cases_w_buf_size(struct write_str_case *cases, int buf_size);
static void write_str_test_cases(struct write_str_case *cases) {
    write_str_test_cases_w_buf_size(cases, 100);
}

/* test case loop for flb_utils_write_str */
static void write_str_test_cases_w_buf_size(struct write_str_case *cases, int buf_size) {
    char *buf = flb_calloc(buf_size + 1, sizeof(char));
    int size = buf_size + 1;
    int off;
    int ret;

    struct write_str_case *tcase = cases;
    while (!(tcase->input == 0 && tcase->output == 0)) {
        memset(buf, 0, size);
        off = 0;
        ret = flb_utils_write_str(buf, &off, buf_size, tcase->input, tcase->input_len);

        if(!TEST_CHECK(ret == tcase->ret)) {
            TEST_MSG("Input string: %s", tcase->input);
            TEST_MSG("| Expected return value: %s", (tcase->ret == FLB_TRUE) ? "FLB_TRUE"
            : "FLB_FALSE");
            TEST_MSG("| Produced return value: %s", (ret == FLB_TRUE) ? "FLB_TRUE"
            : "FLB_FALSE");
        }
        if(!TEST_CHECK(memcmp(buf, tcase->output, off) == 0)) {
            TEST_MSG("Input string: %s", tcase->input);
            TEST_MSG("| Expected output: %s", tcase->output);
            TEST_MSG("| Produced output: %s", buf);
        }
        if (!TEST_CHECK(strlen(buf) == strlen(tcase->output))) {
            TEST_MSG("Input string: %s", tcase->input);
            TEST_MSG("| Expected length: %zu", strlen(tcase->output));
            TEST_MSG("| Produced length: %zu", strlen(buf));
            TEST_MSG("| Expected output: %s", tcase->output);
            TEST_MSG("| Produced output: %s", buf);
        }
        if (!TEST_CHECK(buf[size-1] == 0)) {
            TEST_MSG("Out buffer overwrite detected '%c'", buf[size-1]);
        }

        ++tcase;
    }

    flb_free(buf);
}

void test_write_str()
{
    char buf[10];
    char japanese_a[4] = {0xe3, 0x81, 0x82};
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
    TEST_CHECK(memcmp(buf, japanese_a, off) == 0);

    // Truncated bytes
    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "\xe3\x81\x82\xe3", 1);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(memcmp(buf, japanese_a, off) == 0);

    // Error: buffer too small
    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "aaaaaaaaaaa", 11);
    TEST_CHECK(ret == FLB_FALSE);
}

void test_write_str_invalid_trailing_bytes()
{
    struct write_str_case cases[] = {
        /* Invalid unicode (one bad trailing bytes) */
        {
            "\xe3\x81\x01""abc", 6,  /* note that 0x01 is an invalid byte */
            "\xee\x83\xa3" /* e3 fragment */ /* replace invalid unicode */
            "\xee\x82\x81" /* 81 fragment */
            "\\u0001abc",
            FLB_TRUE
        },
        /*
         * Invalid unicode (two bad trailing bytes)
         */
        {
            "\xe3\x01\x01""abc", 6,
            "\xee\x83\xa3" /* e3 fragment */
            "\\u0001\\u0001abc",
            FLB_TRUE
        },
        { 0 }
    };

    write_str_test_cases(cases);
}

void test_write_str_invalid_leading_byte()
{

    struct write_str_case cases[] = {
        /*
         * Escaped leading hex (two hex, one valid unicode)
         */
        {
            "\x00\x01\xe3\x81\x82""abc", 8,  /* note that 0x01 is an invalid byte */
            "\\u0000\\u0001""\xe3\x81\x82""abc",  /* escape hex */
            FLB_TRUE
        },
        /*
         * Invalid unicode fragment (two byte fragment)
         * note that 0xf3 is a leading byte with 3 trailing bytes. note that 0xe3 is also a
         * leading byte with 2 trailing bytes. This should not be consumed by 0xf3 invalid
         * unicode character
         */
        {
            "\xf3\x81\x81\xe3\x81\x82""abc", 9,  /* note that 0xf3 0x81 0x81 is an invalid fragment */
            "\xee\x83\xb3" /* f3 fragment */ /* replace invalid unicode */
            "\xee\x82\x81" /* 81 fragment */
            "\xee\x82\x81" /* 81 fragment */
            "\xe3\x81\x82""abc", /* valid unicode */
            FLB_TRUE
        },
        /*
         * Invalid unicode (one bad leading byte + one bad trailing byte)
         * note that 0xf3 is a leading byte with 3 trailing bytes. 0x01 is an invalid byte
         */
        {
            "\xf3\x81\x01\xe3\x81\x82""abc", 9,  /* note that 0x01 is an invalid byte */
            "\xee\x83\xb3" /* f3 fragment */ /* replace invalid unicode */
            "\xee\x82\x81" /* 81 fragment */
            "\\u0001""\xe3\x81\x82""abc",
            FLB_TRUE
        },
        { 0 }
    };

    write_str_test_cases(cases);
}

void test_write_str_invalid_leading_byte_case_2()
{

    struct write_str_case cases[] = {
        /* Invalid leading bytes */
        {
            "\x81\x82""abc", 5,  /* note that 0x81 & 0x82 are invalid leading bytes */
            "\xee\x82\x81" /* 81 fragment */ /* replace invalid unicode */
            "\xee\x82\x82" /* 82 fragment */
            "abc",
            FLB_TRUE
        },
        /*
         * Invalid unicode (one bad leading byte + one bad trailing byte + one bad leading byte)
         * note that 0xf3 is a leading byte with 3 trailing bytes. 0x01 is an invalid byte
         * 0x81 & 0x82 are invalid leading bytes
         */
        {
            "\xf3\x81\x01\x81\x82""abc", 8,  /* note that 0x81 & 0x82 are invalid leading bytes */
            "\xee\x83\xb3" /* f3 fragment */ /* replace invalid unicode */
            "\xee\x82\x81" /* 81 fragment */
            "\\u0001"      /* 0x01 hex escape */
            "\xee\x82\x81" /* 81 fragment */
            "\xee\x82\x82" /* 82 fragment */
            "abc",
            FLB_TRUE
        },
        { 0 }
    };

    write_str_test_cases(cases);
}

void test_write_str_edge_cases()
{
    struct write_str_case cases[] = {
        /* Invalid unicode (one bad leading byte) */
        {
            "\xf3", 1,  /* will this buffer overrun? */
            "",  /* discard invalid unicode */
            FLB_TRUE
        },
        { 0 }
    };

    write_str_test_cases(cases);
}

void test_write_str_buffer_overrun()
{
    struct write_str_case cases[] = {
        {
            "aa""\x81", 3,
            "aa"
            "\xee\x82\x81", /* just enough space for 81 fragment */
            FLB_TRUE
        },
        {
            "aaa""\x81", 4, /* out buffer size: 5, needed bytes: 2 + 3 + 3 = 8 */
            "aaa",
            /* "\xee\x82\x81", */ /* 81 fragment -- would overrun */
            FLB_FALSE
        },
        {
            "aaa"
            "\xe3\x81\x82", 6, /* required is already grater than buffer */
            "",
            FLB_FALSE
        },
        {
            "\""
            "\xe3\x81\x82", 4, /* valid unicode */
            "\\\"""\xe3\x81\x82", /* just enough space for valid unicode */
            FLB_TRUE
        },
        {
            "\x81"
            "\xe3\x81\x82", 4, /* valid unicode */
            "\xee\x82\x81", /* 81 fragment */
            /* not enough space for valid unicode fragment "\xe3\x81\x82" */
            FLB_FALSE
        },
        { 0 }
    };
    write_str_test_cases_w_buf_size(cases, 5);
}

struct proxy_url_check {
    int ret;
    char *url;        /* full URL          */
    char *prot;       /* expected protocol */
    char *host;       /* expected host     */
    char *port;       /* expected port     */
    char *username;   /* expected username */
    char *password;   /* expected password */
};

struct proxy_url_check proxy_url_checks[] = {
    {0, "http://foo:bar@proxy.com:8080",
     "http", "proxy.com", "8080", "foo", "bar"},
    {0, "http://proxy.com",
     "http", "proxy.com", "80", NULL, NULL},
    {0, "http://proxy.com:8080",
     "http", "proxy.com", "8080", NULL, NULL},
    /* issue #5530. Password contains @ */
    {0, "http://example_user:example_pass_w_@_char@proxy.com:8080",
     "http", "proxy.com", "8080", "example_user", "example_pass_w_@_char"},
    {-1, "https://proxy.com:8080",
     NULL, NULL, NULL, NULL, NULL}

};

void test_proxy_url_split() {
    int i;
    int ret;
    int size;
    char *protocol;
    char *host;
    char *port;
    char *username;
    char *password;
    struct proxy_url_check *u;

    size = sizeof(proxy_url_checks) / sizeof(struct proxy_url_check);
    for (i = 0; i < size; i++) {
        u = &proxy_url_checks[i];

        protocol = NULL;
        host = NULL;
        port = NULL;
        username = NULL;
        password = NULL;

        ret = flb_utils_proxy_url_split(u->url, &protocol, &username, &password, &host, &port);
        TEST_CHECK(ret == u->ret);
        if (ret == -1) {
            continue;
        }

        /* Protocol */
        TEST_CHECK(protocol != NULL);
        ret = strcmp(u->prot, protocol);
        TEST_CHECK(ret == 0);
        TEST_MSG("Expected protocol: %s", u->prot);
        TEST_MSG("Produced protocol: %s", protocol);

        /* Host */
        TEST_CHECK(host != NULL);
        ret = strcmp(u->host, host);
        TEST_CHECK(ret == 0);
        TEST_MSG("Expected host: %s", u->host);
        TEST_MSG("Produced host: %s", host);

        /* Port */
        TEST_CHECK(port != NULL);
        ret = strcmp(u->port, port);
        TEST_CHECK(ret == 0);
        TEST_MSG("Expected port: %s", u->port);
        TEST_MSG("Produced port: %s", port);

        /* Username */
        if (u->username) {
            TEST_CHECK(port != NULL);
            ret = strcmp(u->port, port);
            TEST_CHECK(ret == 0);
            TEST_MSG("Expected username: %s", u->username);
            TEST_MSG("Produced username: %s", username);

        }
        else {
            TEST_CHECK(username == NULL);
        }

        /* Password */
        if (u->password) {
            TEST_CHECK(port != NULL);
            ret = strcmp(u->port, port);
            TEST_CHECK(ret == 0);
            TEST_MSG("Expected password: %s", u->password);
            TEST_MSG("Produced password: %s", password);
        }
        else {
            TEST_CHECK(password == NULL);
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
        if (username) {
            flb_free(username);
        }
        if (password) {
            flb_free(password);
        }
    }
}

TEST_LIST = {
    /* JSON maps iteration */
    { "url_split", test_url_split },
    { "write_str", test_write_str },
    { "test_write_str_invalid_trailing_bytes", test_write_str_invalid_trailing_bytes },
    { "test_write_str_invalid_leading_byte", test_write_str_invalid_leading_byte },
    { "test_write_str_edge_cases", test_write_str_edge_cases },
    { "test_write_str_invalid_leading_byte_case_2", test_write_str_invalid_leading_byte_case_2 },
    { "test_write_str_buffer_overrun", test_write_str_buffer_overrun },
    { "proxy_url_split", test_proxy_url_split },
    { 0 }
};
