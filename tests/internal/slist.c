/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_slist.h>

#include "flb_tests_internal.h"

void test_slist_add()
{
    int ret;
    struct mk_list list;
    struct flb_slist_entry *e;

    ret = flb_slist_create(&list);
    TEST_CHECK(ret == 0);

    ret = flb_slist_add(&list, "");
    TEST_CHECK(ret == -1);

    ret = flb_slist_add(&list, NULL);
    TEST_CHECK(ret == -1);

    TEST_CHECK(mk_list_is_empty(&list) == 0);

    ret = flb_slist_add(&list, "test");
    TEST_CHECK(ret == 0);

    e = mk_list_entry_last(&list, struct flb_slist_entry, _head);
    TEST_CHECK(flb_sds_len(e->str) == 4);

    ret = flb_slist_add_n(&list, "test", 3);
    TEST_CHECK(ret == 0);

    e = mk_list_entry_last(&list, struct flb_slist_entry, _head);
    TEST_CHECK(flb_sds_len(e->str) == 3);

    flb_slist_destroy(&list);
}

void test_slist_split_string()
{
    int ret;
    struct mk_list list;
    struct flb_slist_entry *e;

    ret = flb_slist_create(&list);
    TEST_CHECK(ret == 0);

    /* Simple string without separator */
    ret = flb_slist_split_string(&list, "abcdefg", ' ', -1);
    TEST_CHECK(ret == 1);
    TEST_CHECK(mk_list_size(&list) == 1);
    e = mk_list_entry_last(&list, struct flb_slist_entry, _head);
    TEST_CHECK(flb_sds_len(e->str) == 7);
    flb_slist_destroy(&list);

    /* Separated strings */
    ret = flb_slist_split_string(&list, "a bc defg", ' ', -1);
    TEST_CHECK(ret == 3);
    TEST_CHECK(mk_list_size(&list) == 3);
    e = mk_list_entry_last(&list, struct flb_slist_entry, _head);
    TEST_CHECK(flb_sds_len(e->str) == 4);
    flb_slist_destroy(&list);

    /* One char with empty spaces */
    ret = flb_slist_split_string(&list, "        a  ", ' ', 2);
    TEST_CHECK(ret == 1);
    TEST_CHECK(mk_list_size(&list) == 1);
    e = mk_list_entry_last(&list, struct flb_slist_entry, _head);
    TEST_CHECK(flb_sds_len(e->str) == 1);
    flb_slist_destroy(&list);

    /* Two separated characters */
    ret = flb_slist_split_string(&list, "        a        b    ", ' ', 2);
    TEST_CHECK(ret == 2);
    TEST_CHECK(mk_list_size(&list) == 2);
    e = mk_list_entry_last(&list, struct flb_slist_entry, _head);
    TEST_CHECK(flb_sds_len(e->str) == 1);
    flb_slist_destroy(&list);

    /* Comma separated strings */
    ret = flb_slist_split_string(&list, ",,,a ,,  b,c ,d,,e   ,f,g,  ,   ,", ',', -1);
    TEST_CHECK(ret == 7);
    TEST_CHECK(mk_list_size(&list) == 7);
    flb_slist_destroy(&list);

    /* Comma separated strings with limit */
    ret = flb_slist_split_string(&list, ",,,a ,,  b,  c ,d,,e   ,f,g,  ,   ,", ',', 2);
    TEST_CHECK(ret == 3);
    TEST_CHECK(mk_list_size(&list) == 3);
    e = mk_list_entry_last(&list, struct flb_slist_entry, _head);
    TEST_CHECK(flb_sds_len(e->str) == 22);
    flb_slist_destroy(&list);

    /* Nothing */
    ret = flb_slist_split_string(&list, ",,, ,, , ,   , ", ',', 2);
    TEST_CHECK(ret == 0);
    TEST_CHECK(mk_list_size(&list) == 0);
}

TEST_LIST = {
    { "add"  , test_slist_add},
    { "split", test_slist_split_string},
    { 0 }
};
