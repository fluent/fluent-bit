/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>

#include "flb_tests_internal.h"

struct tz_check {
    char *val;
    int diff;
};

struct tz_check entries_ok[] = {
    {"+0000",       0},
    {"+00:00",      0},
    {"+00:59",   3540},
    {"-0600",  -21000},
    {"-06:00", -21000},
};

struct tz_check entries_error[] = {
    {"0000",   0},
    {"+00:90", 0},
    {"--600",  0},
    {"-06:00", -21000},
};

/* Pack a simple JSON map */
void test_parser_tzone_offset()
{
    int i;
    int len;
    int ret;
    int diff;
    struct tz_check *t;

    /* Valid offsets */
    for (i = 0; i < sizeof(entries_ok) / sizeof(struct tz_check); i++) {
        t = &entries_ok[0];
        len = strlen(t->val);

        ret = flb_parser_tzone_offset(t->val, len, &diff);
        TEST_CHECK(ret == 0 && diff == t->diff);
    }

    /* Invalid offsets */
    for (i = 0; i < sizeof(entries_error) / sizeof(struct tz_check); i++) {
        t = &entries_error[0];
        len = strlen(t->val);

        ret = flb_parser_tzone_offset(t->val, len, &diff);
        TEST_CHECK(ret != 0);
    }
}

TEST_LIST = {
    { "parser_tzone_offset", test_parser_tzone_offset},
    { 0 }
};
