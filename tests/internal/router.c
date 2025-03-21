/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_router.h>

#include "flb_tests_internal.h"

struct check {
    char *tag;
    char *match;
    int matched;
};

struct check route_checks[] = {

    {"file.apache.log", "file.*.log" , FLB_TRUE},
    {"cpu.rpi"        , "cpu.rpi"    , FLB_TRUE},
    {"cpu.rpi"        , "cpu.*"      , FLB_TRUE},
    {"cpu.rpi"        , "*"          , FLB_TRUE},
    {"cpu.rpi"        , "*.*"        , FLB_TRUE},
    {"cpu.rpi"        , "*.rpi"      , FLB_TRUE},
    {"cpu.rpi"        , "mem.*"      , FLB_FALSE},
    {"cpu.rpi"        , "*u.r*"      , FLB_TRUE},
    {"hoge"           , "hogeeeeeee" , FLB_FALSE},
    {"test"           , "test"       , FLB_TRUE}
};

void test_router_wildcard()
{
    int i;
    int ret;
    int len;
    int checks = 0;
    struct check *c;

    checks = sizeof(route_checks) / sizeof(struct check);
    for (i = 0; i < checks; i++) {
        c = &route_checks[i];
        len = strlen(c->tag);
        ret = flb_router_match(c->tag, len, c->match, NULL);
        TEST_CHECK(ret == c->matched);
        if (ret != c->matched) {
            fprintf(stderr, "test %i failed: tag=%s match=%s expected_to_match=%s\n",
                    i, c->tag, c->match, c->matched ? "YES": "NO");
        }
    }

    ret = flb_router_match("aaaX", 3, "aaa", NULL);
    TEST_CHECK(ret == FLB_TRUE);
}

TEST_LIST = {
    { "wildcard", test_router_wildcard},
    { 0 }
};
