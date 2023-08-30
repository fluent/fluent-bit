/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_sds.h>
#include <sys/stat.h>

#include <cfl/cfl.h>
#include <cfl/cfl_list.h>

#include "flb_tests_internal.h"

#define FLB_000 FLB_TESTS_DATA_PATH "/data/config_format/classic/fluent-bit.conf"
#define FLB_001 FLB_TESTS_DATA_PATH "/data/config_format/classic/issue_5880.conf"
#define FLB_002 FLB_TESTS_DATA_PATH "/data/config_format/classic/indent_level_error.conf"
#define FLB_003 FLB_TESTS_DATA_PATH "/data/config_format/classic/recursion.conf"
#define FLB_004 FLB_TESTS_DATA_PATH "/data/config_format/classic/issue6281.conf"
#define FLB_005 FLB_TESTS_DATA_PATH "/data/config_format/classic/nolimitline.conf"

#define ERROR_LOG "fluentbit_conf_error.log"

/* data/config_format/fluent-bit.conf */
void test_basic()
{
    struct mk_list *head;
	struct flb_cf *cf;
    struct flb_cf_section *s;
    struct flb_cf_group *g;

    cf = flb_cf_fluentbit_create(NULL, FLB_000, NULL, 0);
    TEST_CHECK(cf != NULL);

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 8);

	/* SERVICE check */
    TEST_CHECK(cf->service != NULL);
    if (cf->service) {
        TEST_CHECK(cfl_list_size(&cf->service->properties->list) == 3);
    }

    /* Meta commands */
    TEST_CHECK(mk_list_size(&cf->metas) == 2);

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->parsers) == 1);
    TEST_CHECK(mk_list_size(&cf->multiline_parsers) == 1);
    TEST_CHECK(mk_list_size(&cf->customs) == 1);
    TEST_CHECK(mk_list_size(&cf->inputs) == 1);
    TEST_CHECK(mk_list_size(&cf->filters) == 1);
    TEST_CHECK(mk_list_size(&cf->outputs) == 1);
    TEST_CHECK(mk_list_size(&cf->others) == 1);

    /* groups */
    s = flb_cf_section_get_by_name(cf, "input");
    TEST_CHECK(s != NULL);
    TEST_CHECK(mk_list_size(&s->groups) == 2);

    mk_list_foreach(head, &s->groups) {
        g = mk_list_entry(head, struct flb_cf_group, _head);
        TEST_CHECK(cfl_list_size(&g->properties->list) == 2);
    }

    printf("\n");
    flb_cf_dump(cf);

    flb_cf_destroy(cf);
}

struct str_list {
    size_t size;
    char **lists;
};

static int check_str_list(struct str_list *list, FILE *fp)
{
    flb_sds_t error_str = NULL;
    char *p = NULL;
    size_t size;
    int str_size = 4096;
    int i;
    int fd = fileno(fp);
    struct stat st;

    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("list is NULL");
        return -1;
    }
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("fp is NULL");
        return -1;
    }

    if (!TEST_CHECK(fstat(fd, &st) == 0)) {
        TEST_MSG("fstat failed");
        return -1;
    }
    str_size = st.st_size;
    error_str = flb_sds_create_size(str_size);
    if (!TEST_CHECK(error_str != NULL)) {
        TEST_MSG("flb_sds_create_size failed.");
        return -1;
    }

    size = fread(error_str, 1, str_size, fp);
    if (size < str_size) {
        if (!TEST_CHECK(ferror(fp) == 0)) {
            TEST_MSG("fread failed.");
            clearerr(fp);
            flb_sds_destroy(error_str);
            return -1;
        }
        clearerr(fp);
    }

    for (i=0; i<list->size; i++) {
        p = strstr(error_str, list->lists[i]);
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("  Got   :%s\n  expect:%s", error_str, list->lists[i]);
        }
    }

    flb_sds_destroy(error_str);
    return 0;
}


/* https://github.com/fluent/fluent-bit/issues/5880 */
void missing_value()
{
	struct flb_cf *cf;
    FILE *fp = NULL;
    char *expected_strs[] = {"undefined value", ":9:" /* lieno*/ };
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    unlink(ERROR_LOG);

    fp = freopen(ERROR_LOG, "w+", stderr);
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("freopen failed. errno=%d path=%s", errno, ERROR_LOG);
        exit(EXIT_FAILURE);
    }

    cf = flb_cf_fluentbit_create(NULL, FLB_001, NULL, 0);
    TEST_CHECK(cf == NULL);
    fflush(fp);
    fclose(fp);

    fp = fopen(ERROR_LOG, "r");
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("fopen failed. errno=%d path=%s", errno, ERROR_LOG);
        unlink(ERROR_LOG);
        exit(EXIT_FAILURE);
    }

    check_str_list(&expected, fp);

    fclose(fp);
    unlink(ERROR_LOG);
}

void indent_level_error()
{
	struct flb_cf *cf;
    FILE *fp = NULL;
    char *expected_strs[] = {"invalid", "indent", "level"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    unlink(ERROR_LOG);

    fp = freopen(ERROR_LOG, "w+", stderr);
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("freopen failed. errno=%d path=%s", errno, ERROR_LOG);
        exit(EXIT_FAILURE);
    }

    cf = flb_cf_create();
    if (!TEST_CHECK(cf != NULL)) {
        TEST_MSG("flb_cf_create failed");
        exit(EXIT_FAILURE);
    }

    cf = flb_cf_fluentbit_create(cf, FLB_002, NULL, 0);
    TEST_CHECK(cf == NULL);
    fflush(fp);
    fclose(fp);

    fp = fopen(ERROR_LOG, "r");
    if (!TEST_CHECK(fp != NULL)) {
        TEST_MSG("fopen failed. errno=%d path=%s", errno, ERROR_LOG);
        if (cf != NULL) {
            flb_cf_destroy(cf);
        }
        unlink(ERROR_LOG);
        exit(EXIT_FAILURE);
    }

    check_str_list(&expected, fp);
    if (cf != NULL) {
        flb_cf_destroy(cf);
    }
    fclose(fp);
    unlink(ERROR_LOG);
}

void recursion()
{
	struct flb_cf *cf;

    cf = flb_cf_create();
    if (!TEST_CHECK(cf != NULL)) {
        TEST_MSG("flb_cf_create failed");
        exit(EXIT_FAILURE);
    }

    cf = flb_cf_fluentbit_create(cf, FLB_003, NULL, 0);

    /* No SIGSEGV means success */
}


/*
 *  https://github.com/fluent/fluent-bit/issues/6281
 *
 *  Fluent-bit loads issue6281.conf that loads issue6281_input/output.conf.
 *
 *    config dir -+-- issue6281.conf
 *                |
 *                +-- issue6281_input.conf
 *                |
 *                +-- issue6281_output.conf
 */
void not_current_dir_files()
{
    struct flb_cf *cf;

    cf = flb_cf_create();
    if (!TEST_CHECK(cf != NULL)) {
        TEST_MSG("flb_cf_create failed");
        exit(EXIT_FAILURE);
    }

    cf = flb_cf_fluentbit_create(cf, FLB_004, NULL, 0);
    if (!TEST_CHECK(cf != NULL)) {
        TEST_MSG("flb_cf_fluentbit_create failed");
        exit(EXIT_FAILURE);
    }

    if (cf != NULL) {
        flb_cf_destroy(cf);
    }
}

/* data/config_format/nolimitline.conf */
void test_nolimit_line()
{
    struct flb_cf *cf;
    struct flb_cf_section *s;
    struct cfl_list *p_head;
    struct cfl_kvpair *kv;

    cf = flb_cf_fluentbit_create(NULL, FLB_005, NULL, 0);
    TEST_CHECK(cf != NULL);

    /* Total number of sections */
    TEST_CHECK(mk_list_size(&cf->sections) == 3);

    /* SERVICE check */
    TEST_CHECK(cf->service == NULL);

    /* Meta commands */
    TEST_CHECK(mk_list_size(&cf->metas) == 0);

    /* Check number sections per list */
    TEST_CHECK(mk_list_size(&cf->inputs) == 1);
    TEST_CHECK(mk_list_size(&cf->filters) == 1);
    TEST_CHECK(mk_list_size(&cf->outputs) == 1);

    /* Check the previous line buffer limit */
    s = flb_cf_section_get_by_name(cf, "filter");
    TEST_CHECK(s != NULL);
    TEST_CHECK(mk_list_size(&s->groups) == 0);

    if (cfl_list_size(&s->properties->list) > 0) {
        TEST_CHECK(cfl_list_size(&s->properties->list) == 4);
        cfl_list_foreach(p_head, &s->properties->list) {
            kv = cfl_list_entry(p_head, struct cfl_kvpair, _head);
            if (strcmp(kv->key, "code") == 0) {
                TEST_CHECK(cfl_sds_len(kv->val->data.as_string) > FLB_DEFAULT_CF_BUF_SIZE);
            }
        }
    }

    printf("\n");
    flb_cf_dump(cf);

    flb_cf_destroy(cf);
}

static inline int check_snake_case(char *input, char *output)
{
    int len;
    int ret;
    flb_sds_t out;
    struct flb_cf *cf;


    cf = flb_cf_create();
    flb_cf_set_origin_format(cf, FLB_CF_CLASSIC);

    len = strlen(input);
    out = flb_cf_key_translate(cf, input, len);

    ret = strcmp(out, output);

    flb_sds_destroy(out);

    flb_cf_destroy(cf);

    if (ret == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static void test_snake_case_key()
{
    /* normal conversion */
    TEST_CHECK(check_snake_case("a", "a") == FLB_TRUE);
    TEST_CHECK(check_snake_case("aB", "ab") == FLB_TRUE);
    TEST_CHECK(check_snake_case("aBc", "abc") == FLB_TRUE);
    TEST_CHECK(check_snake_case("interval_Sec", "interval_sec") == FLB_TRUE);
}

TEST_LIST = {
    { "basic"    , test_basic},
    { "missing_value_issue5880" , missing_value},
    { "indent_level_error" , indent_level_error},
    { "recursion" , recursion},
    { "not_current_dir_files", not_current_dir_files},
    { "no_limit_line", test_nolimit_line},
    { "snake_case_key", test_snake_case_key},
    { 0 }
};
