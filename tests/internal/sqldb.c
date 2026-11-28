/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sqldb.h>

#include "flb_tests_internal.h"

static void test_open_missing_directory()
{
    struct flb_config *config;
    struct flb_sqldb *db;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        return;
    }

    db = flb_sqldb_open("/nonexistent-flb-sqldb-dir/sub/test.db", "missing", config);
    TEST_CHECK(db == NULL);
    TEST_CHECK(mk_list_size(&config->sqldb_list) == 0);

    if (db) {
        flb_sqldb_close(db);
    }

    flb_config_exit(config);
}

static void test_open_close_memory()
{
    struct flb_config *config;
    struct flb_sqldb *db;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        return;
    }

    db = flb_sqldb_open(":memory:", "memory", config);
    TEST_CHECK(db != NULL);

    if (db) {
        TEST_CHECK(db->shared == FLB_FALSE);
        TEST_CHECK(mk_list_size(&config->sqldb_list) == 1);

        flb_sqldb_close(db);
        TEST_CHECK(mk_list_size(&config->sqldb_list) == 0);
    }

    flb_config_exit(config);
}

static void test_open_shared_handle()
{
    struct flb_config *config;
    struct flb_sqldb *first;
    struct flb_sqldb *second;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (!config) {
        return;
    }

    first = flb_sqldb_open(":memory:", "first", config);
    TEST_CHECK(first != NULL);
    if (!first) {
        flb_config_exit(config);
        return;
    }

    second = flb_sqldb_open(":memory:", "second", config);
    TEST_CHECK(second != NULL);

    if (second) {
        TEST_CHECK(second->shared == FLB_TRUE);
        TEST_CHECK(second->parent == first);
        TEST_CHECK(second->handler == first->handler);
        TEST_CHECK(first->users == 1);

        flb_sqldb_close(second);
        TEST_CHECK(first->users == 0);
    }

    flb_sqldb_close(first);
    TEST_CHECK(mk_list_size(&config->sqldb_list) == 0);

    flb_config_exit(config);
}

TEST_LIST = {
    {"open_missing_directory", test_open_missing_directory},
    {"open_close_memory", test_open_close_memory},
    {"open_shared_handle", test_open_shared_handle},
    {0}
};
