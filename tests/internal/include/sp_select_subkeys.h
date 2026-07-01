#include "sp_cb_functions.h"

#ifndef FLB_TEST_SP_SELECT_SUBKEYS
#define FLB_TEST_SP_SELECT_SUBKEYS

/* Tests for 'test_select_subkeys' */
struct task_check select_subkeys_checks[] = {
    {
        0, 0, 0, 0,
        "select_sub_blue",
        "SELECT * FROM STREAM:FLB WHERE map['sub1']['sub2']['color'] = 'blue';",
        cb_select_sub_blue
    },
    {
        1, 0, 0, 0,
        "select_sub_num",
        "SELECT * FROM STREAM:FLB WHERE map['sub1']['sub2'] = 123;",
        cb_select_sub_num
    },
    {
        2, 0, 0, 0,
        "select_sub_colors",
        "SELECT * FROM STREAM:FLB WHERE "            \
        "map['sub1']['sub2']['color'] = 'blue' OR "  \
        "map['sub1']['sub2']['color'] = 'red'  OR "  \
        "map['color'] = 'blue'; ",
        cb_select_sub_colors
    },
    {
        3, 0, 0, 0,
        "cb_select_sub_record_contains",
        "SELECT * FROM STREAM:FLB WHERE "            \
        "@record.contains(map['sub1']['sub3']) OR "  \
        "@record.contains(map['color']); ",
        cb_select_sub_record_contains
    },
    {   4, 0, 0, 0,
        "cb_select_sub_keys",
        "SELECT map['sub1']['sub2']['color'] FROM STREAM:FLB WHERE "    \
        "map['sub1']['sub2']['color'] = 'blue';",
        cb_select_sub_keys},
    {   5, 0, 0, 0,
        "cb_select_sum_sub_keys",
        "SELECT SUM(map['sub1']['sub2']) FROM STREAM:FLB WHERE "    \
        "map['sub1']['sub2'] = 123;",
        cb_select_sum_sub_keys},
    {   6, 0, 0, 0,
        "cb_select_avg_sub_keys",
        "SELECT AVG(map['sub1']['sub2']) FROM STREAM:FLB WHERE "    \
        "map['sub1']['sub2'] = 123;",
        cb_select_avg_sub_keys},
    {   7, 0, 0, 0,
        "cb_select_count_sub_keys",
        "SELECT COUNT(map['sub1']['sub2']) FROM STREAM:FLB WHERE "    \
        "map['sub1']['sub2'] = 123;",
        cb_select_count_sub_keys},
    {   8, 0, 0, 0,
        "cb_select_min_sub_keys",
        "SELECT MIN(map['sub1']['sub2']) FROM STREAM:FLB WHERE "  \
        "map['sub1']['sub2'] > 0;",
        cb_select_min_sub_keys},
    {   9, 0, 0, 0,
        "cb_select_max_sub_keys",
        "SELECT MAX(map['sub1']['sub3']) FROM STREAM:FLB WHERE "  \
        "map['sub1']['sub3'] > 0;",
        cb_select_max_sub_keys},
    {   10, 0, 0, 0,
        "cb_select_sum_sub_keys_group_by",
        "SELECT SUM(map['sub1']['sub3']) FROM STREAM:FLB "  \
        "GROUP BY map['mtype'];",
        cb_select_sum_sub_keys_group_by},
    {   11, 0, 0, 0,
        "cb_select_sum_sub_keys_group_by_2",
        "SELECT map['sub1']['stype'], map['mtype'], SUM(map['sub1']['sub3']) " \
        "FROM STREAM:FLB GROUP BY map['mtype'], map['sub1']['stype'];",
        cb_select_sum_sub_keys_group_by_2},
    {   12, 0, 0, 0,
        "cb_select_sum_sub_keys_group_by_3",
        "SELECT map['sub1']['stype'], map['sub1']['sub4'], SUM(map['sub1']['sub3']) " \
        "FROM STREAM:FLB GROUP BY map['sub1']['stype'], map['sub1']['sub4'];",
        cb_select_sum_sub_keys_group_by_3}
};

#endif
