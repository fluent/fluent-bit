/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <stdarg.h>
#include "flb_tests_internal.h"
#include "fluent-bit/flb_macros.h"


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

void test_url_split_sds()
{
    int i;
    int ret;
    int size;
    flb_sds_t protocol;
    flb_sds_t host;
    flb_sds_t port;
    flb_sds_t uri;
    struct url_check *u;

    size = sizeof(url_checks) / sizeof(struct url_check);
    for (i = 0; i < size; i ++) {
        u = &url_checks[i];

        protocol = NULL;
        host = NULL;
        port = NULL;
        uri = NULL;

        ret = flb_utils_url_split_sds(u->url, &protocol, &host, &port, &uri);
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
            flb_sds_destroy(protocol);
        }
        if (host) {
            flb_sds_destroy(host);
        }
        if (port) {
            flb_sds_destroy(port);
        }
        if (uri) {
            flb_sds_destroy(uri);
        }
    }
}

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
static void write_str_test_cases_w_buf_size(struct write_str_case *cases, int buf_size,
                                            int escape_unicode);
static void write_str_test_cases(struct write_str_case *cases) {
    write_str_test_cases_w_buf_size(cases, 100, FLB_TRUE);
}

static void write_raw_str_test_cases(struct write_str_case *cases) {
    write_str_test_cases_w_buf_size(cases, 100, FLB_FALSE);
}

/* test case loop for flb_utils_write_str */
static void write_str_test_cases_w_buf_size(struct write_str_case *cases, int buf_size,
                                            int escape_unicode)
{
    char *buf = flb_calloc(buf_size + 1, sizeof(char));
    int size = buf_size + 1;
    int off;
    int ret;

    struct write_str_case *tcase = cases;
    while (!(tcase->input == 0 && tcase->output == 0)) {
        memset(buf, 0, size);
        off = 0;
        ret = flb_utils_write_str(buf, &off, buf_size, tcase->input, tcase->input_len,
                                  escape_unicode);

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
    int off;
    int ret;
    char buf[10] = {0};
    int size = sizeof(buf);

    /* escaped Unicode representation of あ */
    char jp_expected_output[] = "\\u3042";

    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "a", 1, FLB_TRUE);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(memcmp(buf, "a", off) == 0);

    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "\n", 1, FLB_TRUE);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(memcmp(buf, "\\n", off) == 0);

    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "\xe3\x81\x82", 3, FLB_TRUE);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(memcmp(buf, jp_expected_output, off) == 0);

    /* Truncated bytes: 'buf' should not be touched and off == 0 */
    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "\xe3\x81\x82\xe3", 1, FLB_TRUE);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(off == 0);
    TEST_CHECK(memcmp(buf, jp_expected_output, off) == 0);

    /* Error: buffer too small */
    off = 0;
    ret = flb_utils_write_str(buf, &off, size, "aaaaaaaaaaa", 11, FLB_TRUE);
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
            "\\u0000\\u0001\\u3042""abc",  /* escape hex */
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
            "\\u3042""abc", /* valid unicode */
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
            "\\u0001""\\u3042""abc",
            FLB_TRUE
        },
        { 0 }
    };

    write_str_test_cases(cases);
}

void test_write_str_special_bytes()
{
    struct write_str_case cases[] = {
        /*
         * Escaped leading hex (two hex, one valid unicode)
         */
        {
            "你好世界", 12,
            "\\u4f60\\u597d\\u4e16\\u754c",
            FLB_TRUE
        },
        /*
         * Escaped leading hex (two hex, one valid unicode)
         */
        {
            "你好我来自一个汉字文化影响的地方", 48,
            "\\u4f60\\u597d\\u6211\\u6765\\u81ea\\u4e00\\u4e2a\\u6c49\\u5b57\\u6587\\u5316\\u5f71\\u54cd\\u7684\\u5730\\u65b9",
            FLB_TRUE
        },
        {
            "\xC3\xA1\x0A", 3,  /* UTF-8 encoding of á and newline */
            "\\u00e1\\n",       /* Expected escaped output */
            FLB_TRUE
        },
        { 0 }
    };

    write_str_test_cases(cases);
}

void test_write_raw_str_special_bytes()
{
    struct write_str_case cases[] = {
        /*
         * Input: "你好世界" (12 bytes)
         * Output: "你好世界" (raw)
         */
        {
            "\xE4\xBD\xA0\xE5\xA5\xBD\xE4\xB8\x96\xE7\x95\x8C", 12,
            "\xE4\xBD\xA0\xE5\xA5\xBD\xE4\xB8\x96\xE7\x95\x8C",
            FLB_TRUE
        },
        /*
         * Input: "你好我来自一个汉字文化影响的地方" (48 bytes)
         * Output: "你好我来自一个汉字文化影响的地方" (raw)
         */
        {
            "\xE4\xBD\xA0\xE5\xA5\xBD\xE6\x88\x91\xE6\x9D\xA5\xE8\x87\xAA" \
            "\xE4\xB8\x80\xE4\xB8\xAA\xE6\xB1\x89\xE5\xAD\x97\xE6\x96\x87" \
            "\xE5\x8C\x96\xE5\xBD\xB1\xE5\x93\x8D\xE7\x9A\x84\xE5\x9C\xB0" \
            "\xE6\x96\xB9",
            48,
            "\xE4\xBD\xA0\xE5\xA5\xBD\xE6\x88\x91\xE6\x9D\xA5\xE8\x87\xAA" \
            "\xE4\xB8\x80\xE4\xB8\xAA\xE6\xB1\x89\xE5\xAD\x97\xE6\x96\x87" \
            "\xE5\x8C\x96\xE5\xBD\xB1\xE5\x93\x8D\xE7\x9A\x84\xE5\x9C\xB0" \
            "\xE6\x96\xB9",
            FLB_TRUE
        },
        /* Test string with a quote */
        {
            "\"hello\"", 7,
            "\\\"hello\\\"",
            FLB_TRUE
        },
        { 0 }
    };

    write_raw_str_test_cases(cases);
}

void test_write_raw_str_invalid_sequences()
{
    struct write_str_case cases[] = {
        /*
         * Case 1: Stray continuation byte (0x80)
         */
        {
            "hello \x80 world", 13,
            "hello \xEF\xBF\xBD world",
            FLB_TRUE
        },

        /*
         * Case 2: Incomplete multi-byte sequence
         */
        {
            "a\xE6\x97""b", 4,
            "a""\xEF\xBF\xBD""\xEF\xBF\xBD""b",
            FLB_TRUE
        },

        /*
         * Case 3: Overlong encoding
         */
        {
            "a\xC0\xAF""b", 4,
            "a""\xEF\xBF\xBD""\xEF\xBF\xBD""b",
            FLB_TRUE
        },

        /*
         * Case 4: With an invalid starting byte
         */
        {
            "start-\xFF-end", 11,
            "start-\xEF\xBF\xBD-end",
            FLB_TRUE
        },

        /*
         * Case 5: Mix of valid and invalid sequences
         */
        {
            /* Input: "你好<stray_byte>世界" */
            "\xE4\xBD\xA0\xE5\xA5\xBD" "\x80" "\xE4\xB8\x96\xE7\x95\x8C", 13,
            /* Output: "你好<replacement_char>世界" */
            "\xE4\xBD\xA0\xE5\xA5\xBD" "\xEF\xBF\xBD" "\xE4\xB8\x96\xE7\x95\x8C",
            FLB_TRUE
        },

        /*
         * Case 6: Sequence with invalid continuation byte
         */
        {
            /* Input: "a" + 日(E6 97 A5) + ASCII "b" */
            "a\xE6\x97""b", 4,
            "a""\xEF\xBF\xBD""\xEF\xBF\xBD""b",
            FLB_TRUE
        },

        /* End of cases */
        { 0 }
    };

    write_raw_str_test_cases(cases);
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
            "a"
            "\xe3\x81\x82", 4, /* valid unicode */
            "a", /* just enough space for valid ascii */
            FLB_FALSE /* no space for \u3042 */
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
    write_str_test_cases_w_buf_size(cases, 5, FLB_TRUE);
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
    {0, "proxy.com:8080",
     "http", "proxy.com", "8080", NULL, NULL},
    {0, "foo:bar@proxy.com:8080",
     "http", "proxy.com", "8080", "foo", "bar"},
    {0, "proxy.com",
     "http", "proxy.com", "80", NULL, NULL},
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
            TEST_CHECK(username != NULL);
            ret = strcmp(u->username, username);
            TEST_CHECK(ret == 0);
            TEST_MSG("Expected username: %s", u->username);
            TEST_MSG("Produced username: %s", username);

        }
        else {
            TEST_CHECK(username == NULL);
        }

        /* Password */
        if (u->password) {
            TEST_CHECK(password != NULL);
            ret = strcmp(u->password, password);
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

static int compare_split_entry(const char* input, int separator, int max_split, int quoted, ...)
{
    va_list ap;
    int count = 1;
    char *expect;
    struct mk_list *split = NULL;
    struct mk_list *tmp_list = NULL;
    struct mk_list *head = NULL;
    struct flb_split_entry *entry = NULL;

    if (quoted) {
        split = flb_utils_split_quoted(input, separator, max_split);
    }
    else {
        split = flb_utils_split(input, separator, max_split);
    }

    if (!TEST_CHECK(split != NULL)) {
        TEST_MSG("flb_utils_split failed. input=%s", input);
        return -1;
    }
    if (!TEST_CHECK(mk_list_is_empty(split) != 0)) {
        TEST_MSG("list is empty. input=%s", input);
        return -1;
    }

    va_start(ap, quoted);
    mk_list_foreach_safe(head, tmp_list, split) {
        if (max_split > 0 && !TEST_CHECK(count <= max_split) ) {
            TEST_MSG("count error. got=%d expect=%d input=%s", count, max_split, input);
        }

        expect = va_arg(ap, char*);
        entry = mk_list_entry(head, struct flb_split_entry, _head);
        if (!TEST_CHECK(entry != NULL)) {
            TEST_MSG("entry is NULL. input=%s", input);
            goto comp_end;
        }
        /*
        printf("%d:%s\n", count, entry->value);
        */
        if (!TEST_CHECK(strcmp(expect, entry->value) == 0)) {
            TEST_MSG("mismatch. got=%s expect=%s. input=%s", entry->value, expect, input);
            goto comp_end;
        }
        count++;
    }
 comp_end:
    if (split != NULL) {
        flb_utils_split_free(split);
    }
    va_end(ap);
    return 0;
}

void test_flb_utils_split()
{
    compare_split_entry("aa,bb", ',', 2, FLB_FALSE, "aa","bb" );
    compare_split_entry("localhost:12345", ':', 2, FLB_FALSE, "localhost","12345" );
    compare_split_entry("https://fluentbit.io/announcements/", '/', -1, FLB_FALSE, "https:", "fluentbit.io","announcements" );

    /* /proc/net/dev example */
    compare_split_entry("enp0s3: 1955136    1768    0    0    0     0          0         0    89362     931    0    0    0     0       0          0",
                        ' ', 256, FLB_FALSE,
                        "enp0s3:", "1955136", "1768", "0", "0", "0", "0", "0", "0", "89362", "931", "0", "0", "0", "0", "0", "0", "0");

    /* filter_grep configuration */
    compare_split_entry("Regex test  *a*", ' ', 3, FLB_FALSE, "Regex", "test", "*a*");

    /* filter_modify configuration */
    compare_split_entry("Condition Key_Value_Does_Not_Equal cpustats  KNOWN", ' ', 4,
                        FLB_FALSE, "Condition", "Key_Value_Does_Not_Equal", "cpustats", "KNOWN");

    /* nginx_exporter_metrics example */
    compare_split_entry("Active connections: 1\nserver accepts handled requests\n 10 10 10\nReading: 0 Writing: 1 Waiting: 0", '\n', 4,
                        FLB_FALSE, "Active connections: 1", "server accepts handled requests", " 10 10 10","Reading: 0 Writing: 1 Waiting: 0");

    /* out_cloudwatch_logs example */
    compare_split_entry("dimension_1,dimension_2;dimension_3", ';', 256,
                        FLB_FALSE, "dimension_1,dimension_2", "dimension_3");
    /* separator is not contained */
    compare_split_entry("aa,bb", '/', 2, FLB_FALSE, "aa,bb");

    /* do not parse quotes when tokenizing */
    compare_split_entry("aa \"bb cc\" dd", ' ', 256, FLB_FALSE, "aa", "\"bb", "cc\"", "dd");
}

void test_flb_utils_split_quoted()
{
   /* Tokens quoted with "..." */
    compare_split_entry("aa \"double quote\" bb", ' ', 256, FLB_TRUE, "aa", "double quote", "bb");
    compare_split_entry("\"begin with double quote\" aa", ' ', 256, FLB_TRUE, "begin with double quote", "aa");
    compare_split_entry("aa \"end with double quote\"", ' ', 256, FLB_TRUE, "aa", "end with double quote");

    /* Tokens quoted with '...' */
    compare_split_entry("aa bb 'single quote' cc", ' ', 256, FLB_TRUE, "aa", "bb",  "single quote", "cc");
    compare_split_entry("'begin with single quote' aa", ' ', 256, FLB_TRUE, "begin with single quote", "aa");
    compare_split_entry("aa 'end with single quote'", ' ', 256, FLB_TRUE, "aa", "end with single quote");

    /* Tokens surrounded by more than one separator character */
    compare_split_entry("  aa   \" spaces bb \"  cc  '  spaces dd '  ff", ' ', 256, FLB_TRUE,
                        "aa", " spaces bb ", "cc", "  spaces dd ", "ff");

    /* Escapes within quoted token */
    compare_split_entry("aa \"escaped \\\" quote\" bb", ' ', 256, FLB_TRUE, "aa", "escaped \" quote", "bb");
    compare_split_entry("aa 'escaped \\' quote\' bb", ' ', 256, FLB_TRUE, "aa", "escaped \' quote", "bb");
    compare_split_entry("aa \"\\\"escaped balanced quotes\\\"\" bb", ' ', 256, FLB_TRUE,
                        "aa", "\"escaped balanced quotes\"", "bb");
    compare_split_entry("aa '\\'escaped balanced quotes\\'\' bb", ' ', 256, FLB_TRUE,
                        "aa", "'escaped balanced quotes'", "bb");
    compare_split_entry("aa 'escaped \\\\ escape\' bb", ' ', 256, FLB_TRUE, "aa", "escaped \\ escape", "bb");

    /* Escapes that are not processed */
    compare_split_entry("\\\"aa bb", ' ', 256, FLB_TRUE, "\\\"aa", "bb");
    compare_split_entry("\\'aa bb", ' ', 256, FLB_TRUE, "\\'aa", "bb");
    compare_split_entry("\\\\aa bb", ' ', 256, FLB_TRUE, "\\\\aa", "bb");
    compare_split_entry("aa\\ bb", ' ', 256, FLB_TRUE, "aa\\", "bb");

}

void test_flb_utils_split_quoted_errors()
{
    struct mk_list *split = NULL;

    split = flb_utils_split_quoted("aa \"unbalanced quotes should fail", ' ', 256);
    TEST_CHECK(split == NULL);
    split = flb_utils_split_quoted("aa 'unbalanced quotes should fail", ' ', 256);
    TEST_CHECK(split == NULL);
}

void test_flb_utils_get_machine_id()
{
    int ret;
    int idx;
    char *id = NULL;
    size_t size;
    char *id2 = NULL;
    size_t size2;

    ret = flb_utils_get_machine_id(&id, &size);
    TEST_CHECK(ret == 0 || ret == 2);
    TEST_CHECK(size != 0);
    TEST_CHECK(id != NULL);

    for (idx = 0; idx < size; idx++) {
        if (!TEST_CHECK(id[idx] != 0)) {
            fprintf(stderr, "zero in ID: id[%d] = 0x%02x\n", idx, id[idx]);
        }
    }

    ret = flb_utils_get_machine_id(&id2, &size2);
    TEST_CHECK(ret == 0 || ret == 2);
    TEST_CHECK(size2 != 0);
    TEST_CHECK(id2 != NULL);
    if (ret == 2) {
        TEST_CHECK(size2 == size);
    }
    else {
        TEST_CHECK(size2 == size);
        for (idx = 0; idx < size; idx++) {
            if (!TEST_CHECK(id[idx] == id2[idx])) {
                fprintf(stderr, "bad byte in id v2 id2: id[%d] = 0x%02x, id2[%d] = 0x%02x\n",
                        idx, id[idx], idx, id2[idx]);
            }
        }
    }

    flb_free(id);
    flb_free(id2);
}

struct size_to_bytes_check {
    char *size;      /* size in string    */
    int64_t ret;     /* expected size     */
};

struct size_to_bytes_check size_to_bytes_checks[] = {
    {"922337.63", 922337},
    {"2K",2000},
    {"5.7263K", 5726},
    {"9223372036854775.23K", -1},
    {"1M", 1000000},
    {"1.1M", 1100000},
    {"3.592M", 3592000},
    {"52.752383M", 52752383},
    {"9223372036854.42M", -1},
    {"492.364G",492364000000},
    {"1.2973G", 1297300000},
    {"9223372036.78G", -1},
};

void test_size_to_bytes()
{
    int i;
    int size;
    int64_t ret;
    struct size_to_bytes_check *u;

    size = sizeof(size_to_bytes_checks) / sizeof(struct size_to_bytes_check);
    for (i = 0; i < size; i++) {
        u = &size_to_bytes_checks[i];

        ret = flb_utils_size_to_bytes(u->size);
        TEST_CHECK(ret == u->ret);
    }
}

struct size_to_bytes_check size_to_binary_bytes_checks[] = {
    {"922337.63", 922337},
    {"2K",2048},
    {"5.7263K", 5863},
    {"5.7263KB", 5863},
    {"5.7263KiB", 5863},
    {"9223372036854775.23K", -1},
    {"1M", 1048576},
    {"1.1M", 1153433},
    {"1.1MB", 1153433},
    {"1.1MiB", 1153433},
    {"3.592M", 3766484},
    {"52.752383M", 55314882},
    {"52.752383MB", 55314882},
    {"52.752383MiB", 55314882},
    {"9223372036854.42M", -1},
    {"492.364G",528671819431},
    {"492.364GB",528671819431},
    {"492.364GiB",528671819431},
    {"1.2973G", 1392965268},
    {"9223372036.78G", -1},
};

void test_size_to_binary_bytes()
{
    int i;
    int size;
    int64_t ret;
    struct size_to_bytes_check *u;

    size = sizeof(size_to_binary_bytes_checks) / sizeof(struct size_to_bytes_check);
    for (i = 0; i < size; i++) {
        u = &size_to_binary_bytes_checks[i];

        ret = flb_utils_size_to_binary_bytes(u->size);
        TEST_CHECK_(ret == u->ret, "ret = %zu, u->ret = %zu", ret, u->ret);
    }
}

TEST_LIST = {
    /* JSON maps iteration */
    { "url_split", test_url_split },
    { "url_split_sds", test_url_split_sds },
    { "write_str", test_write_str },
    { "write_str_special_bytes", test_write_str_special_bytes },
    { "write_raw_str_special_bytes", test_write_raw_str_special_bytes },
    { "write_raw_str_invalid_bytes", test_write_raw_str_invalid_sequences},
    { "test_write_str_invalid_trailing_bytes", test_write_str_invalid_trailing_bytes },
    { "test_write_str_invalid_leading_byte", test_write_str_invalid_leading_byte },
    { "test_write_str_edge_cases", test_write_str_edge_cases },
    { "test_write_str_invalid_leading_byte_case_2", test_write_str_invalid_leading_byte_case_2 },
    { "test_write_str_buffer_overrun", test_write_str_buffer_overrun },
    { "proxy_url_split", test_proxy_url_split },
    { "test_flb_utils_split", test_flb_utils_split },
    { "test_flb_utils_split_quoted", test_flb_utils_split_quoted},
    { "test_flb_utils_split_quoted_errors", test_flb_utils_split_quoted_errors},
    { "test_flb_utils_get_machine_id", test_flb_utils_get_machine_id },
    { "test_size_to_bytes", test_size_to_bytes },
    { "test_size_to_bianry_bytes", test_size_to_binary_bytes },
    { 0 }
};
