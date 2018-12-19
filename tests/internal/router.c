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
    {"hogeeeeee"      , "hoge"       , FLB_FALSE},
    {"hoge"           , "AhogeA"     , FLB_FALSE},
    {"test"           , "test"       , FLB_TRUE}
};

void test_router_wildcard()
{
    int i;
    int ret;
    int tag_len;
    int match_len;
    int checks = 0;
    struct check *c;

    checks = sizeof(route_checks) / sizeof(struct check);
    for (i = 0; i < checks; i++) {
        c = &route_checks[i];
        tag_len = strlen(c->tag);
        match_len = strlen(c->match);
        printf("tag:%s match:%s\n",c->tag, c->match);
        ret = flb_router_match(c->tag, tag_len, c->match, match_len, NULL);
        TEST_CHECK(ret == c->matched);
    }
}

TEST_LIST = {
    { "wildcard", test_router_wildcard},
    { 0 }
};
