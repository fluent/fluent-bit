/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022-2024 The CFL Authors
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

#include <cfl/cfl.h>

#include <float.h>
#include <math.h>

#include "cfl_tests_internal.h"

static int compare_split_entry(const char* input, int separator, int max_split, int quoted, ...)
{
    va_list ap;
    int count = 1;
    char *expect;
    struct cfl_list *split = NULL;
    struct cfl_list *tmp_list = NULL;
    struct cfl_list *head = NULL;
    struct cfl_split_entry *entry = NULL;

    if (quoted) {
        split = cfl_utils_split_quoted(input, separator, max_split);
    }
    else {
        split = cfl_utils_split(input, separator, max_split);
    }

    if (!TEST_CHECK(split != NULL)) {
        TEST_MSG("flb_utils_split failed. input=%s", input);
        return -1;
    }
    if (!TEST_CHECK(cfl_list_is_empty(split) != 1)) {
        TEST_MSG("list is empty. input=%s", input);
        return -1;
    }

    va_start(ap, quoted);
    cfl_list_foreach_safe(head, tmp_list, split) {
        if (max_split > 0 && !TEST_CHECK(count <= max_split) ) {
            TEST_MSG("count error. got=%d expect=%d input=%s", count, max_split, input);
        }

        expect = va_arg(ap, char*);
        entry = cfl_list_entry(head, struct cfl_split_entry, _head);
        if (!TEST_CHECK(entry != NULL)) {
            TEST_MSG("entry is NULL. input=%s", input);
            goto comp_end;
        }
        /*
        printf("%d:%s\n", count, entry->value);
        */
        if (!TEST_CHECK(strcmp(expect, entry->value) == 0)) {
            TEST_MSG("mismatch. got=%s expect=%s. input=%s", entry->value, expect, input);
            goto comp_end;
        }
        count++;
    }
 comp_end:
    if (split != NULL) {
        cfl_utils_split_free(split);
    }
    va_end(ap);
    return 0;
}

void test_cfl_utils_split()
{
    compare_split_entry("aa,bb", ',', 2, CFL_FALSE, "aa","bb" );
    compare_split_entry("localhost:12345", ':', 2, CFL_FALSE, "localhost","12345" );
    compare_split_entry("https://fluentbit.io/announcements/", '/', -1, CFL_FALSE, "https:", "fluentbit.io","announcements" );

    /* /proc/net/dev example */
    compare_split_entry("enp0s3: 1955136    1768    0    0    0     0          0         0    89362     931    0    0    0     0       0          0",
                        ' ', 256, CFL_FALSE,
                        "enp0s3:", "1955136", "1768", "0", "0", "0", "0", "0", "0", "89362", "931", "0", "0", "0", "0", "0", "0", "0");

    /* filter_grep configuration */
    compare_split_entry("Regex test  *a*", ' ', 3, CFL_FALSE, "Regex", "test", "*a*");

    /* filter_modify configuration */
    compare_split_entry("Condition Key_Value_Does_Not_Equal cpustats  KNOWN", ' ', 4,
                        CFL_FALSE, "Condition", "Key_Value_Does_Not_Equal", "cpustats", "KNOWN");

    /* nginx_exporter_metrics example */
    compare_split_entry("Active connections: 1\nserver accepts handled requests\n 10 10 10\nReading: 0 Writing: 1 Waiting: 0", '\n', 4,
                        CFL_FALSE, "Active connections: 1", "server accepts handled requests", " 10 10 10","Reading: 0 Writing: 1 Waiting: 0");

    /* out_cloudwatch_logs example */
    compare_split_entry("dimension_1,dimension_2;dimension_3", ';', 256,
                        CFL_FALSE, "dimension_1,dimension_2", "dimension_3");
    /* separator is not contained */
    compare_split_entry("aa,bb", '/', 2, CFL_FALSE, "aa,bb");

    /* do not parse quotes when tokenizing */
    compare_split_entry("aa \"bb cc\" dd", ' ', 256, CFL_FALSE, "aa", "\"bb", "cc\"", "dd");
}

void test_cfl_utils_split_quoted()
{
   /* Tokens quoted with "..." */
    compare_split_entry("aa \"double quote\" bb", ' ', 256, CFL_TRUE, "aa", "double quote", "bb");
    compare_split_entry("\"begin with double quote\" aa", ' ', 256, CFL_TRUE, "begin with double quote", "aa");
    compare_split_entry("aa \"end with double quote\"", ' ', 256, CFL_TRUE, "aa", "end with double quote");

    /* Tokens quoted with '...' */
    compare_split_entry("aa bb 'single quote' cc", ' ', 256, CFL_TRUE, "aa", "bb",  "single quote", "cc");
    compare_split_entry("'begin with single quote' aa", ' ', 256, CFL_TRUE, "begin with single quote", "aa");
    compare_split_entry("aa 'end with single quote'", ' ', 256, CFL_TRUE, "aa", "end with single quote");

    /* Tokens surrounded by more than one separator character */
    compare_split_entry("  aa   \" spaces bb \"  cc  '  spaces dd '  ff", ' ', 256, CFL_TRUE,
                        "aa", " spaces bb ", "cc", "  spaces dd ", "ff");

    /* Escapes within quoted token */
    compare_split_entry("aa \"escaped \\\" quote\" bb", ' ', 256, CFL_TRUE, "aa", "escaped \" quote", "bb");
    compare_split_entry("aa 'escaped \\' quote\' bb", ' ', 256, CFL_TRUE, "aa", "escaped \' quote", "bb");
    compare_split_entry("aa \"\\\"escaped balanced quotes\\\"\" bb", ' ', 256, CFL_TRUE,
                        "aa", "\"escaped balanced quotes\"", "bb");
    compare_split_entry("aa '\\'escaped balanced quotes\\'\' bb", ' ', 256, CFL_TRUE,
                        "aa", "'escaped balanced quotes'", "bb");
    compare_split_entry("aa 'escaped \\\\ escape\' bb", ' ', 256, CFL_TRUE, "aa", "escaped \\ escape", "bb");

    /* Escapes that are not processed */
    compare_split_entry("\\\"aa bb", ' ', 256, CFL_TRUE, "\\\"aa", "bb");
    compare_split_entry("\\'aa bb", ' ', 256, CFL_TRUE, "\\'aa", "bb");
    compare_split_entry("\\\\aa bb", ' ', 256, CFL_TRUE, "\\\\aa", "bb");
    compare_split_entry("aa\\ bb", ' ', 256, CFL_TRUE, "aa\\", "bb");
}

void test_cfl_utils_split_quoted_errors()
{
    struct cfl_list *split = NULL;

    split = cfl_utils_split_quoted("aa \"unbalanced quotes should fail", ' ', 256);
    TEST_CHECK(split == NULL);
    split = cfl_utils_split_quoted("aa 'unbalanced quotes should fail", ' ', 256);
    TEST_CHECK(split == NULL);
}


TEST_LIST = {
    { "test_flb_utils_split", test_cfl_utils_split },
    { "test_flb_utils_split_quoted", test_cfl_utils_split_quoted},
    { "test_flb_utils_split_quoted_errors", test_cfl_utils_split_quoted_errors},
    { 0 }
};
