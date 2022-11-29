/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <cfl/cfl.h>
#include <cfl/cfl_variant.h>

#include "cfl_tests_internal.h"

static int compare(FILE *fp, char *expect, int ignore_len)
{
    int ret;
    size_t len = strlen(expect);
    size_t ret_fp;
    char buf[1024] = {0};

    ret = fseek(fp, 0, SEEK_SET);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("fseek failed");
        return ret;
    }

    ret_fp = fread(&buf[0], 1, sizeof(buf), fp);
    if (ret_fp == 0) {
        if (!TEST_CHECK(feof(fp) == 0)) {
            TEST_MSG("fread error.");
            return -1;
        }
    }
    if (ignore_len) {
        if (!TEST_CHECK(strstr(&buf[0], expect) != NULL)) {
            TEST_MSG("compare error. got=%s expect=%s", &buf[0], expect);
            return -1;
        }

    } else {
        if (!TEST_CHECK(strlen(buf) == len)) {
            TEST_MSG("length error. len=%d got=%s expect=%s", strlen(buf), &buf[0], expect);
            return -1;
        }
        if (!TEST_CHECK(strncmp(expect, &buf[0], len) == 0)) {
            TEST_MSG("compare error. got=%s expect=%s", &buf[0], expect);
            return -1;
        }
    }
    return 0;
}

static void test_variant_print_bool()
{
    int ret;
    int i;
    int inputs[] = {CFL_TRUE, CFL_FALSE};
    char *expects[] = {"true", "false"};

    FILE *fp = NULL;
    struct cfl_variant *val = NULL;

    for (i=0; i<sizeof(inputs)/sizeof(int); i++) {
        fp = tmpfile();
        if (!TEST_CHECK(fp != NULL)) {
            TEST_MSG("%d: fp is NULL", i);
            continue;
        }

        val = cfl_variant_create_from_bool(inputs[i]);
        if (!TEST_CHECK(val != NULL)) {
            TEST_MSG("%d: cfl_variant_create_from_bool failed", i);
            fclose(fp);
            continue;
        }

        ret = cfl_variant_print(fp, val);
        /* Check whether EOF or not. Not checking for positive
         * number here. */
        if (!TEST_CHECK(ret != EOF)) {
            TEST_MSG("%d:cfl_variant_print failed", i);
            cfl_variant_destroy(val);
            fclose(fp);
            continue;
        }
        ret = compare(fp, expects[i], 0);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("%d:compare failed", i);
        }
        cfl_variant_destroy(val);
        fclose(fp);
    }
}

static void test_variant_print_int64()
{
    int ret;
    int i;
    int inputs[] = {1, 0, -123};
    char *expects[] = {"1", "0", "-123"};

    FILE *fp = NULL;
    struct cfl_variant *val = NULL;

    for (i=0; i<sizeof(inputs)/sizeof(int); i++) {
        fp = tmpfile();
        if (!TEST_CHECK(fp != NULL)) {
            TEST_MSG("%d: fp is NULL", i);
            continue;
        }
        val = cfl_variant_create_from_int64(inputs[i]);
        if (!TEST_CHECK(val != NULL)) {
            TEST_MSG("%d: cfl_variant_create_from_int64 failed", i);
            fclose(fp);
            continue;
        }

        ret = cfl_variant_print(fp, val);
        if (!TEST_CHECK(ret > 0)) {
            TEST_MSG("%d:cfl_variant_print failed", i);
            cfl_variant_destroy(val);
            fclose(fp);
            continue;
        }
        ret = compare(fp, expects[i], 0);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("%d:compare failed", i);
        }
        cfl_variant_destroy(val);
        fclose(fp);
    }
}

static void test_variant_print_array()
{
    int ret;
    int i;
    int64_t inputs[] = {1, 0, -123};
    char *expect = {"[1,0,-123]"};

    FILE *fp = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *val = NULL;

    fp = tmpfile();
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("fp is NULL");
        exit(1);
    }

    array = cfl_array_create(sizeof(inputs)/sizeof(int64_t));
    if (!TEST_CHECK(array != NULL)) {
        TEST_MSG("cfl_array_create failed");
        fclose(fp);
        exit(1);
    }


    for (i=0; i<sizeof(inputs)/sizeof(int64_t); i++) {
        ret = cfl_array_append_int64(array, inputs[i]);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("%d: cfl_array_append_int64 failed", i);
            fclose(fp);
            cfl_array_destroy(array);
            exit(1);
        }
    }


    val = cfl_variant_create_from_array(array);
    if (!TEST_CHECK(val != NULL)) {
        TEST_MSG("cfl_variant_create_from_array failed");
        cfl_array_destroy(array);
        fclose(fp);
        exit(1);
    }
    ret = cfl_variant_print(fp, val);
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("cfl_variant_print failed");
        cfl_variant_destroy(val);
        fclose(fp);
        exit(1);
    }
    ret = compare(fp, expect, 0);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
    }
    cfl_variant_destroy(val);
    fclose(fp);
}

static void test_variant_print_kvlist()
{
    int ret;
    int i;
    char *key_inputs[] = {"key", "key2", "aaa"};
    int64_t val_inputs[] = {1, 0, -123};
    char *expect = {"{\"key\":1,\"key2\":0,\"aaa\":-123}"};

    FILE *fp = NULL;
    struct cfl_kvlist *list = NULL;
    struct cfl_variant *val = NULL;

    if (!TEST_CHECK(sizeof(key_inputs)/sizeof(char*) == sizeof(val_inputs)/sizeof(int64_t))) {
        TEST_MSG("key val array size mismatch. key_len=%d val_len=%d", 
                 sizeof(key_inputs)/sizeof(char*),
                 sizeof(val_inputs)/sizeof(int64_t));
        exit(1);
    }

    fp = tmpfile();
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("fp is NULL");
        exit(1);
    }

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        fclose(fp);
        exit(1);
    }

    for (i=0; i<sizeof(key_inputs)/sizeof(char*); i++) {
        ret = cfl_kvlist_insert_int64(list, key_inputs[i], val_inputs[i]);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("%d: cfl_kvlist_insert_int64 failed", i);
            fclose(fp);
            cfl_kvlist_destroy(list);
            exit(1);
        }
    }

    val = cfl_variant_create_from_kvlist(list);
    if (!TEST_CHECK(val != NULL)) {
        TEST_MSG("cfl_variant_create_from_kvlist failed");
        cfl_kvlist_destroy(list);
        fclose(fp);
        exit(1);
    }
    ret = cfl_variant_print(fp, val);
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("cfl_variant_print failed");
        cfl_variant_destroy(val);
        fclose(fp);
        exit(1);
    }
    ret = compare(fp, expect, 0);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
    }
    cfl_variant_destroy(val);
    fclose(fp);
}

static void test_variant_print_double()
{
    int ret;
    int i;
    double inputs[] = {1.0, -12.3};
    char *expects[] = {"1.0", "-12.3"};

    FILE *fp = NULL;
    struct cfl_variant *val = NULL;

    for (i=0; i<sizeof(inputs)/sizeof(double); i++) {
        fp = tmpfile();
        if (!TEST_CHECK(fp != NULL)) {
            TEST_MSG("%d: fp is NULL", i);
            continue;
        }
        val = cfl_variant_create_from_double(inputs[i]);
        if (!TEST_CHECK(val != NULL)) {
            TEST_MSG("%d: cfl_variant_create_from_double failed", i);
            fclose(fp);
            continue;
        }

        ret = cfl_variant_print(fp, val);
        if (!TEST_CHECK(ret > 0)) {
            TEST_MSG("%d:cfl_variant_print failed", i);
            cfl_variant_destroy(val);
            fclose(fp);
            continue;
        }
        ret = compare(fp, expects[i], 1);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("%d:compare failed", i);
        }
        cfl_variant_destroy(val);
        fclose(fp);
    }
}

static void test_variant_print_string()
{
    int ret;
    int i;
    char *inputs[] = {"hoge", "aaa"};
    char *expects[] = {"\"hoge\"", "\"aaa\""};

    FILE *fp = NULL;
    struct cfl_variant *val = NULL;

    for (i=0; i<sizeof(inputs)/sizeof(char*); i++) {
        fp = tmpfile();
        if (!TEST_CHECK(fp != NULL)) {
            TEST_MSG("%d: fp is NULL", i);
            continue;
        }

        val = cfl_variant_create_from_string(inputs[i]);
        if (!TEST_CHECK(val != NULL)) {
            TEST_MSG("%d: cfl_variant_create_from_string failed", i);
            fclose(fp);
            continue;
        }

        ret = cfl_variant_print(fp, val);
        if (!TEST_CHECK(ret > 0)) {
            TEST_MSG("%d:cfl_variant_print failed", i);
            cfl_variant_destroy(val);
            fclose(fp);
            continue;
        }
        ret = compare(fp, expects[i], 0);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("%d:compare failed", i);
        }
        cfl_variant_destroy(val);
        fclose(fp);
    }
}

static void test_variant_print_bytes()
{
    int ret;
    char input[] = {0x1f, 0xaa, 0x0a, 0xff};
    char *expect = "1faa0aff";

    FILE *fp = NULL;
    struct cfl_variant *val = NULL;

    fp = tmpfile();
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("fp is NULL");
        exit(1);
    }

    val = cfl_variant_create_from_bytes(input, 4);
    if (!TEST_CHECK(val != NULL)) {
        TEST_MSG("cfl_variant_create_from_bytes failed");
        fclose(fp);
        exit(1);
    }

    ret = cfl_variant_print(fp, val);
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("cfl_variant_print failed");
        cfl_variant_destroy(val);
        fclose(fp);
        exit(1);
    }
    ret = compare(fp, expect, 0);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
    }
    cfl_variant_destroy(val);
    fclose(fp);
}


static void test_variant_print_reference()
{
    int ret;
    int *input = (int*)0x12345678;
    char expect[] = "0x12345678";

    FILE *fp = NULL;
    struct cfl_variant *val = NULL;

    fp = tmpfile();
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("fp is NULL");
        exit(1);
    }

    val = cfl_variant_create_from_reference(input);
    if (!TEST_CHECK(val != NULL)) {
        TEST_MSG("cfl_variant_create_from_reference failed");
        fclose(fp);
        exit(1);
    }

    ret = cfl_variant_print(fp, val);
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("cfl_variant_print failed");
        fclose(fp);
        cfl_variant_destroy(val);
        exit(1);
    }
    ret = compare(fp, &expect[0], 0);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
    }
    cfl_variant_destroy(val);
    fclose(fp);
}

static void test_variant_print_unknown()
{
    int ret;
    char expect[] = "Unknown";

    FILE *fp = NULL;
    struct cfl_variant *val = NULL;

    fp = tmpfile();
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("fp is NULL");
        exit(1);
    }

    val = cfl_variant_create();
    if (!TEST_CHECK(val != NULL)) {
        TEST_MSG("cfl_variant_create failed");
        fclose(fp);
        exit(1);
    }

    ret = cfl_variant_print(fp, val);
    if (!TEST_CHECK(ret != EOF)) {
        TEST_MSG("cfl_variant_print failed");
        fclose(fp);
        cfl_variant_destroy(val);
        exit(1);
    }
    ret = compare(fp, &expect[0], 1);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
    }
    cfl_variant_destroy(val);
    fclose(fp);
}

TEST_LIST = {
    {"variant_print_bool", test_variant_print_bool},
    {"variant_print_int64", test_variant_print_int64},
    {"variant_print_double", test_variant_print_double},
    {"variant_print_string", test_variant_print_string},
    {"variant_print_bytes", test_variant_print_bytes},
    {"variant_print_array", test_variant_print_array},
    {"variant_print_kvlist", test_variant_print_kvlist},
    {"variant_print_reference", test_variant_print_reference},
    {"variant_print_unknown", test_variant_print_unknown},
    { 0 }
};
