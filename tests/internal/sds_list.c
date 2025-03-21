/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_sds_list.h>

#include "flb_tests_internal.h"

static void test_sds_list_create_destroy()
{
    struct flb_sds_list *list = NULL;
    int ret = 0;

    list = flb_sds_list_create();
    if(!TEST_CHECK(list != NULL)) {
        TEST_MSG("failed to allocate flb_sds_list");
        exit(EXIT_FAILURE);
    }

    ret = flb_sds_list_destroy(list);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to destroy flb_sds_list");
        exit(EXIT_FAILURE);
    }
}

static void test_sds_list_add()
{
    struct flb_sds_list *list = NULL;
    int ret = 0;

    list = flb_sds_list_create();
    if(!TEST_CHECK(list != NULL)) {
        TEST_MSG("failed to allocate flb_sds_list");
        exit(EXIT_FAILURE);
    }

    ret = flb_sds_list_add(list, "hoge", 4);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to flb_sds_list_add");
        flb_sds_list_destroy(list);
        exit(EXIT_FAILURE);
    }

    ret = flb_sds_list_destroy(list);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to destroy flb_sds_list");
        exit(EXIT_FAILURE);
    }
}

static void test_sds_list_array()
{
    struct flb_sds_list *list = NULL;
    char *c_array[] = {
        "hoge", "moge", "aaa", NULL
    };
    char **ret_array = NULL;
    int i;
    int ret = 0;

    list = flb_sds_list_create();
    if(!TEST_CHECK(list != NULL)) {
        TEST_MSG("failed to allocate flb_sds_list");
        exit(EXIT_FAILURE);
    }

    for (i=0; c_array[i] != NULL; i++) {
        ret = flb_sds_list_add(list, c_array[i], strlen(c_array[i]));
        if(!TEST_CHECK(ret == 0)) {
            TEST_MSG("flb_sds_list_add failed");
            flb_sds_list_destroy(list);
            exit(EXIT_FAILURE);
        }
    }

    ret_array = flb_sds_list_create_str_array(list);
    if (!TEST_CHECK(ret_array != NULL)) {
        TEST_MSG("flb_sds_list_create_str_array failed");
        flb_sds_list_destroy(list);
        exit(EXIT_FAILURE);
    }

    for (i=0; c_array[i] != NULL; i++) {
        if (!TEST_CHECK(ret_array[i] != NULL)) {
            TEST_MSG("ret_array[%d] should not be NULL", i);
            flb_sds_list_destroy_str_array(ret_array);
            flb_sds_list_destroy(list);
            exit(EXIT_FAILURE);
        }
        if(!TEST_CHECK(strcmp(c_array[i], ret_array[i]) == 0)) {
            TEST_MSG("%d:mismatch. c=%s sds=%s",i, c_array[i], ret_array[i]);
            flb_sds_list_destroy_str_array(ret_array);
            flb_sds_list_destroy(list);
            exit(EXIT_FAILURE);
        }
    }

    ret = flb_sds_list_destroy_str_array(ret_array);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_sds_list_destroy_str_array failed");
        flb_sds_list_destroy(list);
        exit(EXIT_FAILURE);
    }

    ret = flb_sds_list_destroy(list);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to destroy flb_sds_list");
        exit(EXIT_FAILURE);
    }
}

static void test_sds_list_size()
{
    struct flb_sds_list *list = NULL;
    char *c_array[] = {
        "hoge", "moge", "aaa", NULL
    };
    int i;
    int ret = 0;
    size_t size = 0;

    list = flb_sds_list_create();
    if(!TEST_CHECK(list != NULL)) {
        TEST_MSG("failed to allocate flb_sds_list");
        exit(EXIT_FAILURE);
    }

    for (i=0; c_array[i] != NULL; i++) {
        ret = flb_sds_list_add(list, c_array[i], strlen(c_array[i]));
        size++;
        if(!TEST_CHECK(ret == 0)) {
            TEST_MSG("flb_sds_list_add failed");
            flb_sds_list_destroy(list);
            exit(EXIT_FAILURE);
        }

        if (!TEST_CHECK(size == flb_sds_list_size(list))) {
            TEST_MSG("%d: size mismatch. got=%lu expect=%lu",i, flb_sds_list_size(list), size);
        }
    }

    ret = flb_sds_list_destroy(list);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to destroy flb_sds_list");
        exit(EXIT_FAILURE);
    }
}

static void test_sds_list_del_last_entry()
{
    struct flb_sds_list *list = NULL;
    char *c_array[] = {
        "hoge", "moge", "aaa", NULL
    };
    char **str_array = NULL;
    int i;
    int ret = 0;
    size_t size = 0;

    list = flb_sds_list_create();
    if(!TEST_CHECK(list != NULL)) {
        TEST_MSG("failed to allocate flb_sds_list");
        exit(EXIT_FAILURE);
    }

    for (i=0; c_array[i] != NULL; i++) {
        ret = flb_sds_list_add(list, c_array[i], strlen(c_array[i]));
        size++;
        if(!TEST_CHECK(ret == 0)) {
            TEST_MSG("flb_sds_list_add failed");
            flb_sds_list_destroy(list);
            exit(EXIT_FAILURE);
        }

        if (!TEST_CHECK(size == flb_sds_list_size(list))) {
            TEST_MSG("%d: size mismatch. got=%zu expect=%zu",i, flb_sds_list_size(list), size);
        }
    }

    size = flb_sds_list_size(list);

    while(size > 0) {
        ret = flb_sds_list_del_last_entry(list);
        if (!TEST_CHECK(ret==0)) {
            TEST_MSG("flb_sds_list_del_last_entry failed");
            flb_sds_list_destroy(list);
            exit(EXIT_FAILURE);
        }
        size--;
        if (!TEST_CHECK(size == flb_sds_list_size(list))) {
            TEST_MSG("size mismatch. got=%zu expect=%zu",flb_sds_list_size(list), size);
            flb_sds_list_destroy(list);
            exit(EXIT_FAILURE);
        }
        if (size == 0) {
            break;
        }

        str_array = flb_sds_list_create_str_array(list);
        if (!TEST_CHECK(str_array != NULL)) {
            TEST_MSG("flb_sds_list_create_str_array failed. size=%zu", size);
            flb_sds_list_destroy(list);
            exit(EXIT_FAILURE);
        }

        for (i=0; str_array[i] != NULL; i++) {
            if (!TEST_CHECK(str_array[i] != NULL)) {
                TEST_MSG("str_array[%d] should not be NULL", i);
                flb_sds_list_destroy_str_array(str_array);
                flb_sds_list_destroy(list);
                exit(EXIT_FAILURE);
            }
            if(!TEST_CHECK(strcmp(c_array[i], str_array[i]) == 0)) {
                TEST_MSG("%d:mismatch. c=%s sds=%s",i, c_array[i], str_array[i]);
                flb_sds_list_destroy_str_array(str_array);
                flb_sds_list_destroy(list);
                exit(EXIT_FAILURE);
            }
        }
        flb_sds_list_destroy_str_array(str_array);
    }

    ret = flb_sds_list_destroy(list);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to destroy flb_sds_list");
        exit(EXIT_FAILURE);
    }
}

TEST_LIST = {
    { "sds_list_create_destroy" , test_sds_list_create_destroy},
    { "sds_list_add" , test_sds_list_add},
    { "sds_list_array" , test_sds_list_array},
    { "sds_list_size" , test_sds_list_size},
    { "sds_list_del_last_entry" , test_sds_list_del_last_entry},
    { 0 }
};
