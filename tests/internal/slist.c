/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_slist.h>

#include "flb_tests_internal.h"

void token_check(struct mk_list *list, int id, char *str)
{
    int i = 0;
    int len;
    int ret;
    struct mk_list *head;
    struct flb_slist_entry *e = NULL;

    mk_list_foreach(head, list) {
        if (i == id) {
            e = mk_list_entry(head, struct flb_slist_entry, _head);
            break;
        }
        e = NULL;
        i++;
    }
    TEST_CHECK(e != NULL);

    len = strlen(str);
    ret = flb_sds_cmp(e->str, str, len);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        fprintf(stderr, "[token %i] expected '%s', got '%s'\n\n",
                i, str, e->str);
        exit(EXIT_FAILURE);
    }
}

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
    token_check(&list, 0, "abcdefg");
    flb_slist_destroy(&list);

    /* Separated strings */
    ret = flb_slist_split_string(&list, "a bc defg", ' ', -1);
    TEST_CHECK(ret == 3);
    TEST_CHECK(mk_list_size(&list) == 3);
    token_check(&list, 0, "a");
    token_check(&list, 1, "bc");
    token_check(&list, 2, "defg");
    flb_slist_destroy(&list);

    /* One char with empty spaces */
    ret = flb_slist_split_string(&list, "        a  ", ' ', 2);
    TEST_CHECK(ret == 1);
    TEST_CHECK(mk_list_size(&list) == 1);
    token_check(&list, 0, "a");
    flb_slist_destroy(&list);

    /* Two separated characters */
    ret = flb_slist_split_string(&list, "        a        b    ", ' ', 2);
    TEST_CHECK(ret == 2);
    TEST_CHECK(mk_list_size(&list) == 2);
    token_check(&list, 0, "a");
    token_check(&list, 1, "b");
    flb_slist_destroy(&list);

    /* Comma separated strings */
    ret = flb_slist_split_string(&list, ",,,a ,,  b,c ,d,,e   ,f,g,  ,   ,", ',', -1);
    TEST_CHECK(ret == 7);
    TEST_CHECK(mk_list_size(&list) == 7);
    token_check(&list, 0, "a");
    token_check(&list, 1, "b");
    token_check(&list, 2, "c");
    token_check(&list, 3, "d");
    token_check(&list, 4, "e");
    token_check(&list, 5, "f");
    token_check(&list, 6, "g");
    flb_slist_destroy(&list);

    /* Comma seperated strings for real world NO_PROXY example */
    ret = flb_slist_split_string(&list, "127.0.0.1, localhost, kubernetes.default.svc.cluster.local", ',', -1);
    TEST_CHECK(ret == 3);
    TEST_CHECK(mk_list_size(&list) == 3);
    token_check(&list, 0, "127.0.0.1");
    token_check(&list, 1, "localhost");
    token_check(&list, 2, "kubernetes.default.svc.cluster.local");
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

void test_slist_split_tokens()
{
    struct mk_list list;
    char *txt =                                             \
        "  this \"is a tokens parser\" \" apples    \", "
        "no\"quoted \"this is \\\"quoted\\\"\" "
        "don't escape insi\\\"de q\\\"uoted strings\\\"";

    mk_list_init(&list);
    flb_slist_split_tokens(&list, txt, -1);

    token_check(&list,  0, "this");
    token_check(&list,  1, "is a tokens parser");
    token_check(&list,  2, " apples    ");
    token_check(&list,  3, ",");
    token_check(&list,  4, "no\"quoted");
    token_check(&list,  5, "this is \"quoted\"");
    token_check(&list,  6, "don't");
    token_check(&list,  7, "escape");
    token_check(&list,  8, "insi\\\"de");
    token_check(&list,  9, "q\\\"uoted");
    token_check(&list, 10, "strings\\\"");

    flb_slist_destroy(&list);

    mk_list_init(&list);
    flb_slist_split_string(&list, "aaa bbb ccc ddd eee", ' ', 3);
    token_check(&list, 3, "ddd eee");
    flb_slist_destroy(&list);

    mk_list_init(&list);
    flb_slist_split_tokens(&list, "aaa bbb ccc ddd eee", 3);
    token_check(&list, 3, "ddd eee");
    flb_slist_destroy(&list);

}

void test_bugs()
{
    int ret;
    struct mk_list list;
    struct flb_slist_entry *e;

    ret = flb_slist_create(&list);

    /* Bug found during #293 development */
    ret = flb_slist_split_string(&list, "$key2 ab final-tag true", ' ', 4);
    TEST_CHECK(ret == 4);
    e = flb_slist_entry_get(&list, 2);
    TEST_CHECK(*e->str == 'f');

    flb_slist_destroy(&list);
}

TEST_LIST = {
    { "add"         , test_slist_add},
    { "split_string", test_slist_split_string},
    { "split_tokens", test_slist_split_tokens},
    { "bugs"        , test_bugs},
    { 0 }
};
