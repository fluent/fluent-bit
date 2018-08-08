/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */
#include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/common/json_small.h"   /* JSON_SMALL   */

/* Test functions */
void flb_test_syslog_json_invalid(void);

/* Test list */
TEST_LIST = {
    {"json_invalid",    flb_test_syslog_json_invalid   },
    {NULL, NULL}
};


#define TEST_LOGFILE "flb_test_syslog_dummy.log"

void flb_test_syslog_json_invalid(void)
{
    // TODO
}
