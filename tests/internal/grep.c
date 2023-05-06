/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_grep.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>
#include <string.h>

#include "flb_tests_internal.h"

void create_destroy()
{
    int ret;
    struct flb_grep *grep;

    /* legacy */
    grep = flb_grep_create(FLB_GREP_LOGICAL_OP_LEGACY);
    if (!TEST_CHECK(grep != NULL)) {
        TEST_MSG("flb_grep_create failed. op is legacy");
        return;
    }
    ret = flb_grep_destroy(grep);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_destroy failed. ret=%d op is legacy", ret);
    }

    /* or */
    grep = flb_grep_create(FLB_GREP_LOGICAL_OP_OR);
    if (!TEST_CHECK(grep != NULL)) {
        TEST_MSG("flb_grep_create failed. op is or");
        return;
    }
    ret = flb_grep_destroy(grep);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_destroy failed. ret=%d op is or", ret);
    }

    /* and */
    grep = flb_grep_create(FLB_GREP_LOGICAL_OP_AND);
    if (!TEST_CHECK(grep != NULL)) {
        TEST_MSG("flb_grep_create failed. op is and");
        return;
    }
    ret = flb_grep_destroy(grep);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_destroy failed. ret=%d op is and", ret);
    }
}


struct test_grep
{
    char *out_buf;
    size_t out_size;
    msgpack_unpacked result;
};

static struct test_grep* test_grep_create(char *json)
{
    int ret;
    int type;
    struct test_grep *test_grep;

    if (!TEST_CHECK(json != NULL)) {
        TEST_MSG("json is NULL");
        return NULL;
    }

    test_grep = flb_calloc(1, sizeof(struct test_grep));
    if (!TEST_CHECK(test_grep != NULL)) {
        TEST_MSG("calloc failed");
        return NULL;
    }

    ret = flb_pack_json(json, strlen(json), &test_grep->out_buf, &test_grep->out_size,
                        &type, NULL);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_pack_json failed");
        flb_free(test_grep);
        return NULL;
    }

    msgpack_unpacked_init(&test_grep->result);

    return test_grep;
}

static int test_grep_destroy(struct test_grep* test_grep)
{
    flb_free(test_grep->out_buf);
    msgpack_unpacked_destroy(&test_grep->result);
    flb_free(test_grep);
    return 0;
}

static const char* grep_action_str(int ret)
{
    switch (ret) {
    case FLB_GREP_RET_KEEP:
        return "FLB_GREP_RET_KEEP";
        break;
    case FLB_GREP_RET_EXCLUDE:
        return "FLB_GREP_RET_EXCLUDE";
        break;
    default:
        return "unknown value";
    }
    return NULL;
}

static const char* grep_op_str(int ret)
{
    switch (ret) {
    case FLB_GREP_LOGICAL_OP_LEGACY:
        return "Legacy";
        break;
    case FLB_GREP_LOGICAL_OP_OR:
        return "Or";
        break;
    case FLB_GREP_LOGICAL_OP_AND:
        return "And";
        break;
    default:
        return "unknown value";
    }
    return NULL;
}

static int test_grep_simple(enum flb_grep_logical_op op, char *json, 
                            enum flb_grep_rule_type type, char *rule,
                            int expect)
{
    int ret;
    size_t off = 0;
    struct flb_grep *grep;
    struct test_grep *test_grep;

    grep = flb_grep_create(op);
    if (!TEST_CHECK(grep != NULL)) {
        TEST_MSG("flb_grep_create failed. op is %s", grep_op_str(op));
        return -1;
    }

    ret = flb_grep_set_rule_str(grep, type, rule);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_set_rule_str failed");
        flb_grep_destroy(grep);
        return -1;
    }

    test_grep = test_grep_create(json);
    if (!TEST_CHECK(test_grep != NULL)) {
        TEST_MSG("test_grep_create failed");
        flb_grep_destroy(grep);
        return -1;
    }

    msgpack_unpack_next(&test_grep->result, test_grep->out_buf, test_grep->out_size, &off);
    ret = flb_grep_filter(test_grep->result.data, grep);
    if (!TEST_CHECK(ret == expect)) {
        TEST_MSG("test_grep_filter failed. ret=%s", grep_action_str(ret));
        test_grep_destroy(test_grep);
        flb_grep_destroy(grep);
        return -1;
    }

    test_grep_destroy(test_grep);
    ret = flb_grep_destroy(grep);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_destroy failed");
        return -1;
    }

    return 0;
}

void legacy_regex_match()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_LEGACY, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_REGEX, "key match", FLB_GREP_RET_KEEP);
}

void legacy_regex_unmatch()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_LEGACY, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_REGEX, "key unmatch", FLB_GREP_RET_EXCLUDE);
}

void legacy_exclude_match()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_LEGACY, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_EXCLUDE, "key match", FLB_GREP_RET_EXCLUDE);
}

void legacy_exclude_unmatch()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_LEGACY, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_EXCLUDE, "key unmatch", FLB_GREP_RET_KEEP);
}

void or_regex_match()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_OR, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_REGEX, "key match", FLB_GREP_RET_KEEP);
}

void or_regex_unmatch()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_OR, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_REGEX, "key unmatch", FLB_GREP_RET_EXCLUDE);
}

void or_exclude_match()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_OR, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_EXCLUDE, "key match", FLB_GREP_RET_EXCLUDE);
}

void or_exclude_unmatch()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_OR, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_EXCLUDE, "key unmatch", FLB_GREP_RET_KEEP);
}


void and_regex_match()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_AND, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_REGEX, "key match", FLB_GREP_RET_KEEP);
}

void and_regex_unmatch()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_AND, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_REGEX, "key unmatch", FLB_GREP_RET_EXCLUDE);
}

void and_exclude_match()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_AND, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_EXCLUDE, "key match", FLB_GREP_RET_EXCLUDE);
}

void and_exclude_unmatch()
{
    test_grep_simple(FLB_GREP_LOGICAL_OP_AND, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                     FLB_GREP_EXCLUDE, "key unmatch", FLB_GREP_RET_KEEP);
}

void or_regex_exclude_rules()
{
    int ret;
    struct flb_grep *grep;

    grep = flb_grep_create(FLB_GREP_LOGICAL_OP_OR);
    if (!TEST_CHECK(grep != NULL)) {
        TEST_MSG("flb_grep_create failed. op is Or");
        return;
    }

    ret = flb_grep_set_rule_str(grep, FLB_GREP_EXCLUDE, "key unmatch");
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_set_rule_str failed");
        flb_grep_destroy(grep);
        return;
    }

    /* Error! */
    ret = flb_grep_set_rule_str(grep, FLB_GREP_REGEX, "key match");
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("flb_grep_set_rule_str failed");
        flb_grep_destroy(grep);
        return;
    }
    ret = flb_grep_destroy(grep);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_destroy failed");
        return;
    }
}

void and_regex_exclude_rules()
{
    int ret;
    struct flb_grep *grep;

    grep = flb_grep_create(FLB_GREP_LOGICAL_OP_AND);
    if (!TEST_CHECK(grep != NULL)) {
        TEST_MSG("flb_grep_create failed. op is And");
        return;
    }

    ret = flb_grep_set_rule_str(grep, FLB_GREP_EXCLUDE, "key unmatch");
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_set_rule_str failed");
        flb_grep_destroy(grep);
        return;
    }

    /* Error! */
    ret = flb_grep_set_rule_str(grep, FLB_GREP_REGEX, "key match");
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("flb_grep_set_rule_str failed");
        flb_grep_destroy(grep);
        return;
    }
    ret = flb_grep_destroy(grep);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_destroy failed");
        return;
    }
}

struct str_list {
    size_t size;
    char **lists;
};

int test_grep_multi_rules(enum flb_grep_logical_op op, char *json,
                          enum flb_grep_rule_type type, struct str_list *list,
                          int expect)
{
    int ret;
    size_t i;
    size_t off = 0;
    struct flb_grep *grep;
    struct test_grep *test_grep;

    grep = flb_grep_create(op);
    if (!TEST_CHECK(grep != NULL)) {
        TEST_MSG("flb_grep_create failed. op is %s", grep_op_str(op));
        return -1;
    }

    for (i=0; i<list->size; i++) {
        ret = flb_grep_set_rule_str(grep, type, list->lists[i]);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("%zd : flb_grep_set_rule_str failed", i);
            flb_grep_destroy(grep);
            return -1;
        }
    }

    test_grep = test_grep_create(json);
    if (!TEST_CHECK(test_grep != NULL)) {
        TEST_MSG("test_grep_create failed");
        flb_grep_destroy(grep);
        return -1;
    }

    msgpack_unpack_next(&test_grep->result, test_grep->out_buf, test_grep->out_size, &off);
    ret = flb_grep_filter(test_grep->result.data, grep);
    if (!TEST_CHECK(ret == expect)) {
        TEST_MSG("test_grep_filter failed. ret=%s", grep_action_str(ret));
        test_grep_destroy(test_grep);
        flb_grep_destroy(grep);
        return -1;
    }

    test_grep_destroy(test_grep);
    ret = flb_grep_destroy(grep);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_grep_destroy failed");
        return -1;
    }

    return 0;
}

void or_regexs_match(){
    char *rules[] = {"aa bb", "cc dd", "key match"};
    struct str_list rule_list = {
        .size = sizeof(rules)/sizeof(char*),
        .lists = &rules[0],
    };

    test_grep_multi_rules(FLB_GREP_LOGICAL_OP_OR, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                          FLB_GREP_REGEX, &rule_list, FLB_GREP_RET_KEEP);
}

void or_regexs_unmatch(){
    char *rules[] = {"aa bb", "cc dd", "key unmatch"};
    struct str_list rule_list = {
        .size = sizeof(rules)/sizeof(char*),
        .lists = &rules[0],
    };

    test_grep_multi_rules(FLB_GREP_LOGICAL_OP_OR, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                          FLB_GREP_REGEX, &rule_list, FLB_GREP_RET_EXCLUDE);
}

void or_excludes_match(){
    char *rules[] = {"aa bb", "cc dd", "key match"};
    struct str_list rule_list = {
        .size = sizeof(rules)/sizeof(char*),
        .lists = &rules[0],
    };

    test_grep_multi_rules(FLB_GREP_LOGICAL_OP_OR, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                          FLB_GREP_EXCLUDE, &rule_list, FLB_GREP_RET_EXCLUDE);
}

void or_excludes_unmatch(){
    char *rules[] = {"aa bb", "cc dd", "key unmatch"};
    struct str_list rule_list = {
        .size = sizeof(rules)/sizeof(char*),
        .lists = &rules[0],
    };

    test_grep_multi_rules(FLB_GREP_LOGICAL_OP_OR, "{\"key\":\"match\", \"hoge\":\"aaa\"}",
                          FLB_GREP_EXCLUDE, &rule_list, FLB_GREP_RET_KEEP);
}

void and_regexs_match(){
    char *rules[] = {"aa bb", "cc dd", "key match"};
    struct str_list rule_list = {
        .size = sizeof(rules)/sizeof(char*),
        .lists = &rules[0],
    };

    test_grep_multi_rules(FLB_GREP_LOGICAL_OP_AND, 
                          "{\"key\":\"match\", \"cc\":\"dd\", \"aa\":\"bb\"}",
                          FLB_GREP_REGEX, &rule_list, FLB_GREP_RET_KEEP);
}

void and_regexs_unmatch(){
    char *rules[] = {"aa bb", "cc dd", "key unmatch"};
    struct str_list rule_list = {
        .size = sizeof(rules)/sizeof(char*),
        .lists = &rules[0],
    };
    test_grep_multi_rules(FLB_GREP_LOGICAL_OP_AND,
                          "{\"key\":\"match\", \"cc\":\"dd\", \"aa\":\"bb\"}",
                          FLB_GREP_REGEX, &rule_list, FLB_GREP_RET_EXCLUDE);
}

void and_excludes_match(){
    char *rules[] = {"aa bb", "cc dd", "key match"};
    struct str_list rule_list = {
        .size = sizeof(rules)/sizeof(char*),
        .lists = &rules[0],
    };

    test_grep_multi_rules(FLB_GREP_LOGICAL_OP_AND,
                          "{\"key\":\"match\", \"cc\":\"dd\", \"aa\":\"bb\"}",
                          FLB_GREP_EXCLUDE, &rule_list, FLB_GREP_RET_EXCLUDE);
}

void and_excludes_unmatch(){
    char *rules[] = {"aa bb", "cc dd", "key unmatch"};
    struct str_list rule_list = {
        .size = sizeof(rules)/sizeof(char*),
        .lists = &rules[0],
    };

    test_grep_multi_rules(FLB_GREP_LOGICAL_OP_AND,
                          "{\"key\":\"match\", \"cc\":\"dd\", \"aa\":\"bb\"}",
                          FLB_GREP_EXCLUDE, &rule_list, FLB_GREP_RET_KEEP);
}

TEST_LIST = {
    {"create_destroy", create_destroy},

    /* legacy */
    {"legacy_regex_match", legacy_regex_match},
    {"legacy_regex_unmatch", legacy_regex_unmatch},
    {"legacy_exclude_match", legacy_exclude_match},
    {"legacy_exclude_unmatch", legacy_exclude_unmatch},

    /* OR */
    {"or_regex_match", or_regex_match},
    {"or_regex_unmatch", or_regex_unmatch},
    {"or_exclude_match", or_exclude_match},
    {"or_exclude_unmatch", or_exclude_unmatch},

    {"or_regexs_match", or_regexs_match},
    {"or_regexs_unmatch", or_regexs_unmatch},
    {"or_excludes_match", or_excludes_match},
    {"or_excludes_unmatch", or_excludes_unmatch},

    /* AND */
    {"and_regex_match", and_regex_match},
    {"and_regex_unmatch", and_regex_unmatch},
    {"and_exclude_match", and_exclude_match},
    {"and_exclude_unmatch", and_exclude_unmatch},

    {"and_regexs_match", and_regexs_match},
    {"and_regexs_unmatch", and_regexs_unmatch},
    {"and_excludes_match", and_excludes_match},
    {"and_excludes_unmatch", and_excludes_unmatch},

    /* error case */
    {"or_regex_exclude_rules", or_regex_exclude_rules},
    {"and_regex_exclude_rules", and_regex_exclude_rules},

    { 0 }
};
