/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_sds.h>
#include <sys/stat.h>

#include "flb_tests_internal.h"

#define FLB_000 FLB_TESTS_DATA_PATH "/data/config_format/classic/fluent-bit.conf"
#define FLB_001 FLB_TESTS_DATA_PATH "/data/config_format/classic/issue_5880.conf"

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
        TEST_CHECK(mk_list_size(&cf->service->properties) == 3);
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
        TEST_CHECK(mk_list_size(&g->properties) == 2);
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

TEST_LIST = {
    { "basic"    , test_basic},
    { "missing_value_issue5880" , missing_value},
    { 0 }
};
