#include "sp_cb_functions.h"

#ifndef FLB_TEST_SP_SELECT_KEYS
#define FLB_TEST_SP_SELECT_KEYS

/* Tests for 'test_select_keys' */
struct task_check select_keys_checks[] = {
    {
        0, 0, 0, 0,
        "select_all",
        "SELECT * FROM STREAM:FLB;",
        cb_select_all
    },
    {
        1, 0, 0, 0,
        "select_id",
        "SELECT id, word2 FROM STREAM:FLB;",
        cb_select_id
    },

    /* Conditionals */
    {
        2, 0, 0, 0,
        "select_cond_1",
        "SELECT * FROM STREAM:FLB WHERE bytes > 10.290;",
        cb_select_cond_1
    },
    {
        3, 0, 0, 0,
        "select_cond_2",
        "SELECT * FROM STREAM:FLB WHERE word2 = 'rlz' or word3 = 'rlz';",
        cb_select_cond_2
    },
    {
        4, 0, 0, 0,
        "select_cond_not_null",
        "SELECT * FROM STREAM:FLB WHERE word2 = 'rlz' and word3 IS NOT NULL;",
        cb_select_cond_not_null
    },
    {
        5, 0, 0, 0,
        "select_cond_null",
        "SELECT * FROM STREAM:FLB WHERE word3 IS NULL;",
        cb_select_cond_null
    },
    {
        6, 0, 0, 0,
        "select_not_equal_1",
        "SELECT * FROM STREAM:FLB WHERE bool != true;",
        cb_select_not_equal_1
    },
    {
        7, 0, 0, 0,
        "select_not_equal_2",
        "SELECT * FROM STREAM:FLB WHERE bytes <> 10;",
        cb_select_not_equal_2
    },


    /* Aggregation functions */
    {
        8, 0, 0, 0,
        "select_aggr",
        "SELECT MIN(id), MAX(id), COUNT(*), SUM(bytes), AVG(bytes) " \
        "FROM STREAM:FLB;",
        cb_select_aggr,
    },
    {
        9, 0, 0, 0,
        "select_aggr_coount",
        "SELECT COUNT(*) " \
        "FROM STREAM:FLB;",
        cb_select_aggr_count,
    },
    {
        10, 0, 0, 0,
        "select_aggr_window_tumbling",
        "SELECT MIN(id), MAX(id), COUNT(*), SUM(bytes), AVG(bytes) FROM STREAM:FLB;",
        cb_select_aggr,
    },
    {
        11, 0, 0, 0,
        "select_aggr_window_tumbling_groupby",
        "SELECT bool, MIN(id), MAX(id), COUNT(*), SUM(bytes), AVG(bytes) " \
        "FROM STREAM:FLB WHERE word3 IS NOT NULL GROUP BY bool;",
        cb_select_groupby,
    },

    /* Time functions */
    {
        12, 0, 0, 0,
        "func_time_now",
        "SELECT NOW(), NOW() as tnow FROM STREAM:FLB WHERE bytes > 10;",
        cb_func_time_now,
    },
    {
        13, 0, 0, 0,
        "func_time_unix_timestamp",
        "SELECT UNIX_TIMESTAMP(), UNIX_TIMESTAMP() as ts " \
        "FROM STREAM:FLB WHERE bytes > 10;",
        cb_func_time_unix_timestamp,
    },

    /* Stream selection using Tag rules */
    {
        14, 0, 0, 0,
        "select_from_tag_error",
        "SELECT id FROM TAG:'no-matches' WHERE bytes > 10;",
        cb_select_tag_error,
    },
    {
        15, 0, 0, 0,
        "select_from_tag",
        "SELECT id FROM TAG:'samples' WHERE bytes > 10;",
        cb_select_tag_ok,
    },
    {
        16, 0, 0, 0,
        "@recond.contains",
        "SELECT id FROM TAG:'samples' WHERE bytes = 10 AND @record.contains(word2);",
        cb_record_contains,
    },
    {
        17, 0, 0, 0,
        "@recond.contains",
        "SELECT id FROM TAG:'samples' WHERE @record.contains(x);",
        cb_record_not_contains,
    },

    /* Operator precedence */
    {
        18, 0, 0, 0,
        "and_or_precedence",
        "SELECT id FROM STREAM:FLB WHERE false AND true OR true;",
        cb_select_and_or_precedence,
    },
    {
        19, 0, 0, 0,
        "not_or_precedence",
        "SELECT id FROM STREAM:FLB WHERE NOT true OR true;",
        cb_select_not_or_precedence,
    },
    {
        20, 0, 0, 0,
        "not_and_precedence",
        "SELECT id FROM STREAM:FLB WHERE NOT true AND false;",
        cb_select_not_and_precedence,
    },
};

#endif
