/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_router.h>

#include "flb_tests_internal.h"

struct check {
    const char *tag;
    size_t      tag_len;
    const char *match;
    int         matched;
};

static const struct check wildcard_checks[] = {
    {"file.apache.log", 0, "file.*.log" , FLB_TRUE},
    {"cpu.rpi"        , 0, "cpu.rpi"    , FLB_TRUE},
    {"cpu.rpi"        , 0, "cpu.*"      , FLB_TRUE},
    {"cpu.rpi"        , 0, "*"          , FLB_TRUE},
    {"cpu.rpi"        , 0, "*.*"        , FLB_TRUE},
    {"cpu.rpi"        , 0, "*.rpi"      , FLB_TRUE},
    {"cpu.rpi"        , 0, "mem.*"      , FLB_FALSE},
    {"cpu.rpi"        , 0, "*u.r*"      , FLB_TRUE},
    {"hoge"           , 0, "hogeeeeeee" , FLB_FALSE},
    {"test"           , 0, "test"       , FLB_TRUE}
};

void test_router_wildcard()
{
    size_t i;
    int ret;
    size_t len;
    size_t checks = 0;
    const struct check *c;

    checks = sizeof(wildcard_checks) / sizeof(wildcard_checks[0]);
    for (i = 0; i < checks; i++) {
        c = &wildcard_checks[i];
        len = c->tag_len;
        if (len == 0 && c->tag) {
            len = strlen(c->tag);
        }
        ret = flb_router_match(c->tag, len, c->match, NULL);
        TEST_CHECK(ret == c->matched);
        if (ret != c->matched) {
            fprintf(stderr, "test %i failed: tag=%s match=%s expected_to_match=%s\n",
                    (int) i, c->tag, c->match, c->matched ? "YES": "NO");
        }
    }

    ret = flb_router_match("aaaX", 3, "aaa", NULL);
    TEST_CHECK(ret == FLB_TRUE);
}

static void print_tag(const char *tag, size_t len)
{
    size_t i;

    if (tag == NULL) {
        fputs("<NULL>", stderr);
        return;
    }

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char) tag[i];
        if (c < 0x20 || c > 0x7e) {
            fprintf(stderr, "\\x%02x", c);
        }
        else {
            fputc(c, stderr);
        }
    }
}

static const char raw_tag[] = {'m','e','t','r','i','c','s'};
static const char newline_tag[] = {'s','y','s','t','e','m','\n'};
static const char repeated_star[] = {'a','b','c','d'};
static const char truncated[] = {'a','b','c'};
static const char empty_tag[] = {'\0'};

static const struct check route_checks[] = {
    {raw_tag,     sizeof(raw_tag),     "metrics",   FLB_TRUE},
    {raw_tag,     sizeof(raw_tag),     "metrics.*", FLB_FALSE},
    {newline_tag, sizeof(newline_tag), "system\n",  FLB_TRUE},
    {newline_tag, sizeof(newline_tag), "system",    FLB_FALSE},
    {repeated_star, sizeof(repeated_star), "**d",   FLB_TRUE},
    {repeated_star, sizeof(repeated_star), "*c*",   FLB_TRUE},
    {repeated_star, sizeof(repeated_star), "*e*",   FLB_FALSE},
    {NULL,        0,                   "",          FLB_TRUE},
    {NULL,        0,                   "*",         FLB_TRUE},
    {empty_tag,   0,                   "",          FLB_TRUE},
    {empty_tag,   0,                   "*",         FLB_TRUE},
    {raw_tag,     sizeof(raw_tag),     NULL,        FLB_FALSE},
    {truncated,   2,                   "ab",        FLB_TRUE},
    {truncated,   2,                   "abc",       FLB_FALSE}
};

void test_router_edge_cases()
{
    size_t i;
    int ret;
    size_t checks = sizeof(route_checks) / sizeof(route_checks[0]);

    for (i = 0; i < checks; i++) {
        const struct check *c = &route_checks[i];

        ret = flb_router_match(c->tag, (int) c->tag_len, c->match, NULL);
        TEST_CHECK(ret == c->matched);
        if (ret != c->matched) {
            const char *match = c->match ? c->match : "<NULL>";
            fprintf(stderr, "edge test %zu failed: tag=", i);
            print_tag(c->tag, c->tag_len);
            fprintf(stderr, " match=%s expected_to_match=%s\n",
                    match, c->matched ? "YES" : "NO");
        }
    }
}

TEST_LIST = {
    { "wildcard", test_router_wildcard},
    { "edge_cases", test_router_edge_cases},
    { 0 }
};
