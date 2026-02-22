#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include "flb_tests_internal.h"

#ifdef FLB_SYSTEM_WINDOWS
#include <fluent-bit/flb_glob_win32.h>

void test_glob_basic()
{
    glob_t glob_data;
    int ret;
    FILE *fp;

    /* Create some dummy files */
    fp = fopen("test_glob_1.txt", "w");
    if (fp) fclose(fp);
    fp = fopen("test_glob_2.txt", "w");
    if (fp) fclose(fp);

    ret = glob("test_glob_*.txt", 0, NULL, &glob_data);
    TEST_CHECK(ret == 0);
    TEST_CHECK(glob_data.gl_pathc == 2);

    globfree(&glob_data);

    /* Cleanup */
    unlink("test_glob_1.txt");
    unlink("test_glob_2.txt");
}

void test_glob_nomatch()
{
    glob_t glob_data = {0};
    int ret;

    ret = glob("non_existent_*.txt", 0, NULL, &glob_data);
    TEST_CHECK(ret == GLOB_NOMATCH);

    globfree(&glob_data);
}

void test_glob_wildcard()
{
    glob_t glob_data;
    int ret;
    FILE *fp;

    /* Create dummy file */
    fp = fopen("test_wildcard.txt", "w");
    if (fp) fclose(fp);

    ret = glob("test_wild*.txt", 0, NULL, &glob_data);
    TEST_CHECK(ret == 0);
    TEST_CHECK(glob_data.gl_pathc == 1);
    if (glob_data.gl_pathc > 0) {
        TEST_CHECK(strstr(glob_data.gl_pathv[0], "test_wildcard.txt") != NULL);
    }

    globfree(&glob_data);
    unlink("test_wildcard.txt");
}

TEST_LIST = {
    { "basic", test_glob_basic },
    { "nomatch", test_glob_nomatch },
    { "wildcard", test_glob_wildcard },
    { 0 }
};
#else
TEST_LIST = {
    { 0 }
};
#endif