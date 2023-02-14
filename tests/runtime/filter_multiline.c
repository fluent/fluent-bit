/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
};

struct filter_test_result {
    char *expected_pattern;     /* string that must occur in output */
    int expected_pattern_index; /* which record to check for the pattern */
    int expected_records;       /* expected number of outputted records */
    int actual_records;         /* actual number of outputted records */
};

/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    struct filter_test_result *expected;
    char *result;

    expected = (struct filter_test_result *) data;
    result = (char *) record;

    if (expected->expected_pattern_index == expected->actual_records) {
        p = strstr(result, expected->expected_pattern);
        TEST_CHECK(p != NULL);

        if (!p) {
            flb_error("Expected to find: '%s' in result '%s'",
                    expected->expected_pattern, result);
        }
        /*
        * If you want to debug your test
        *
        * printf("Expect: '%s' in result '%s'\n", expected->expected_pattern, result);
        */
    }

    expected->actual_records++;

    flb_free(record);
    return 0;
}


pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    set_output_num(0);
}

struct str_list {
    size_t size; /* size of lists */
    int ignore_min_line_num; /* ignore line if the length is less than this value */
    char **lists; /* string lists */
};

/* Callback to check expected results */
static int cb_check_str_list(void *record, size_t size, void *data)
{
    char *p;
    char *out_line = record;
    int num = get_output_num();
    int count = 0;
    size_t i;
    struct str_list *l = (struct str_list *)data;

    if (!TEST_CHECK(out_line != NULL)) {
        TEST_MSG("out_line is NULL");
        return -1;
    }

    if (!TEST_CHECK(l != NULL)) {
        TEST_MSG("l is NULL");
        flb_free(out_line);
        return -1;
    }

    if (strlen(out_line) < l->ignore_min_line_num) {
        flb_free(out_line);
        return 0;
    }

    for (i=0; i<l->size; i++) {
        p = strstr(out_line, l->lists[i]);
        if (p != NULL) {
            count++;
        }
    }
    if(!TEST_CHECK(count != 0)) {
        TEST_MSG("%s is not matched", out_line);
    }
    set_output_num(num+count);

    flb_free(out_line);
    return 0;
}



static struct filter_test *filter_test_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct filter_test *ctx;

    ctx = flb_malloc(sizeof(struct filter_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd >= 0);
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "multiline", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "*", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test*",
                   "format", "json",
                   NULL);

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void flb_test_multiline_buffered_two_output_record()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "multiline.parser", "go",
                         "buffer", "on",
                         "flush_ms", "1500",
                         "debug_flush", "on",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 1; /* 1 record with all lines concatenated */
    expected.expected_pattern = "main.main.func1(0xc420024120)";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"panic: my panic\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"\n\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"goroutine 4 [running]:\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"panic(0x45cb40, 0x47ad70)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent separately */
    p = "[0, {\"log\":\"  /usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"main.main.func1(0xc420024120)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(3);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_multiline_buffered_one_output_record()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "multiline.parser", "go",
                         "buffer", "on",
                         "debug_flush", "on",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 2; /* 1 record with all lines concatenated */
    expected.expected_pattern = "main.main.func1(0xc420024120)";
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"panic: my panic\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"\n\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"goroutine 4 [running]:\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"panic(0x45cb40, 0x47ad70)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent separately */
    p = "[0, {\"log\":\"  /usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"main.main.func1(0xc420024120)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"one more line, no multiline\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_multiline_unbuffered()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "multiline.parser", "go",
                         "buffer", "off",
                         "debug_flush", "on",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 6; /* no concatenation */
    expected.expected_pattern = "panic";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"panic: my panic\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"\n\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"goroutine 4 [running]:\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"panic(0x45cb40, 0x47ad70)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"  /usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"main.main.func1(0xc420024120)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_multiline_partial_message_concat()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "mode", "partial_message",
                         "buffer", "on",
                         "debug_flush", "on",
                         "flush_ms", "666",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 1; /* 1 record with all lines concatenated */
    expected.expected_pattern = "one..two";
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"one..\", \"partial_message\":\"true\", \"partial_id\": \"1\", \"partial_ordinal\": \"1\", \"partial_last\": \"false\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"two..\", \"partial_message\":\"true\", \"partial_id\": \"1\", \"partial_ordinal\": \"2\", \"partial_last\": \"false\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    
    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_multiline_partial_message_concat_two_ids()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "mode", "partial_message",
                         "buffer", "on",
                         "debug_flush", "on",
                         "flush_ms", "666",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 2; /* 2 records, one for each partial_id*/
    expected.expected_pattern = "one..two";
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* two different partial IDs, interlaced */
    p = "[0, {\"log\":\"one..\", \"partial_message\":\"true\", \"partial_id\": \"1\", \"partial_ordinal\": \"1\", \"partial_last\": \"false\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"three..\", \"partial_message\":\"true\", \"partial_id\": \"2\", \"partial_ordinal\": \"1\", \"partial_last\": \"false\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"two..\", \"partial_message\":\"true\", \"partial_id\": \"1\", \"partial_ordinal\": \"2\", \"partial_last\": \"true\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"two..\", \"partial_message\":\"true\", \"partial_id\": \"2\", \"partial_ordinal\": \"2\", \"partial_last\": \"true\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    
    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}


/*
 * create 2 in_lib instances and pass multiline
 * https://github.com/fluent/fluent-bit/issues/5524
*/
static void flb_test_ml_buffered_two_streams()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int i_ffd_2;
    int ret;
    int i;
    int bytes;
    int len;
    char line_buf[2048] = {0};
    int line_num;
    int num;

    char *expected_strs[] = {"Exception in thread main java.lang.IllegalStateException: ..null property\\n     at com.example.myproject.Author.getBookIds(xx.java:38)\\n     at com.example.myproject.Bootstrap.main(Bootstrap.java:14)\\nCaused by: java.lang.NullPointerException\\n     at com.example.myproject.Book.getId(Book.java:22)\\n     at com.example.myproject.Author.getBookIds(Author.java:35)\\n     ... 1 more",
    "Dec 14 06:41:08 Exception in thread main java.lang.RuntimeException: Something has gone wrong, aborting!\\n    at com.myproject.module.MyProject.badMethod(MyProject.java:22)\\n    at com.myproject.module.MyProject.oneMoreMethod(MyProject.java:18)\\n    at com.myproject.module.MyProject.anotherMethod(MyProject.java:14)\\n    at com.myproject.module.MyProject.someMethod(MyProject.java:10)\\n    at com.myproject.module.MyProject.main(MyProject.java:6)"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
                                .ignore_min_line_num = 64,
    };

    char *ml_logs_1[] = {"Exception in thread main java.lang.IllegalStateException: ..null property",
                         "     at com.example.myproject.Author.getBookIds(xx.java:38)",
                         "     at com.example.myproject.Bootstrap.main(Bootstrap.java:14)",
                         "Caused by: java.lang.NullPointerException",
                         "     at com.example.myproject.Book.getId(Book.java:22)",
                         "     at com.example.myproject.Author.getBookIds(Author.java:35)",
                         "     ... 1 more",
                         "single line"};
    char *ml_logs_2[] = {
                         "single line...",
                         "Dec 14 06:41:08 Exception in thread main java.lang.RuntimeException: Something has gone wrong, aborting!",
                         "    at com.myproject.module.MyProject.badMethod(MyProject.java:22)",
                         "    at com.myproject.module.MyProject.oneMoreMethod(MyProject.java:18)",
                         "    at com.myproject.module.MyProject.anotherMethod(MyProject.java:14)",
                         "    at com.myproject.module.MyProject.someMethod(MyProject.java:10)",
                         "    at com.myproject.module.MyProject.main(MyProject.java:6)",
                         "another line..."};

    cb_data.cb = cb_check_str_list;
    cb_data.data = (void *)&expected;

    clear_output_num();

    TEST_CHECK(sizeof(ml_logs_1)/sizeof(char*) == sizeof(ml_logs_2)/sizeof(char*));
    line_num = sizeof(ml_logs_1)/sizeof(char*);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    i_ffd_2 = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd_2 >= 0);
    flb_input_set(ctx->flb, i_ffd_2, "tag", "test2", NULL);

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "multiline.parser", "java",
                         "buffer", "on",
                         "debug_flush", "on",
                         NULL);
    TEST_CHECK(ret == 0);


    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    for (i=0; i<line_num; i++) {
        sprintf(&line_buf[0], "[%d, {\"log\":\"%s\"}]", i, ml_logs_1[i]);
        len = strlen(line_buf);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, &line_buf[0], len);
        TEST_CHECK(bytes == len);


        sprintf(&line_buf[0], "[%d, {\"log\":\"%s\"}]", i, ml_logs_2[i]);
        len = strlen(line_buf);
        bytes = flb_lib_push(ctx->flb, i_ffd_2, &line_buf[0], len);
        TEST_CHECK(bytes == len);
    }
    sleep(3);

    num = get_output_num();
    if (!TEST_CHECK(num == 2))  {
        TEST_MSG("output error. got %d expect 2", num);
    }

    filter_test_destroy(ctx);
}

static void flb_test_ml_buffered_16_streams()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int i_ffds[16] = {0};
    int ffd_num = sizeof(i_ffds)/sizeof(int);
    int ret;
    int i;
    int j;
    int bytes;
    int len;
    char line_buf[2048] = {0};
    char tag_buf[32] = {0};
    int line_num;
    int num;

    char *expected_strs[] = {"Exception in thread main java.lang.IllegalStateException: ..null property\\n     at com.example.myproject.Author.getBookIds(xx.java:38)\\n     at com.example.myproject.Bootstrap.main(Bootstrap.java:14)\\nCaused by: java.lang.NullPointerException\\n     at com.example.myproject.Book.getId(Book.java:22)\\n     at com.example.myproject.Author.getBookIds(Author.java:35)\\n     ... 1 more"};

    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
                                .ignore_min_line_num = 64,
    };

    char *ml_logs[] = {"Exception in thread main java.lang.IllegalStateException: ..null property",
                       "     at com.example.myproject.Author.getBookIds(xx.java:38)",
                       "     at com.example.myproject.Bootstrap.main(Bootstrap.java:14)",
                       "Caused by: java.lang.NullPointerException",
                       "     at com.example.myproject.Book.getId(Book.java:22)",
                       "     at com.example.myproject.Author.getBookIds(Author.java:35)",
                       "     ... 1 more",
                       "single line"};

    cb_data.cb = cb_check_str_list;
    cb_data.data = (void *)&expected;

    clear_output_num();

    line_num = sizeof(ml_logs)/sizeof(char*);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    i_ffds[0] = ctx->i_ffd;
    for (i=1; i<ffd_num; i++) {
        i_ffds[i] = flb_input(ctx->flb, (char *) "lib", NULL);
        TEST_CHECK(i_ffds[i] >= 0);
        sprintf(&tag_buf[0], "test%d", i);
        flb_input_set(ctx->flb, i_ffds[i], "tag", tag_buf, NULL);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "multiline.parser", "java",
                         "buffer", "on",
                         "debug_flush", "on",
                         NULL);
    TEST_CHECK(ret == 0);


    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    for (i=0; i<line_num; i++) {
        sprintf(&line_buf[0], "[%d, {\"log\":\"%s\"}]", i, ml_logs[i]);
        len = strlen(line_buf);
        for (j=0; j<ffd_num; j++)  {
            bytes = flb_lib_push(ctx->flb, i_ffds[j], &line_buf[0], len);
            TEST_CHECK(bytes == len);
        }
    }
    sleep(3);

    num = get_output_num();
    if (!TEST_CHECK(num == ffd_num))  {
        TEST_MSG("output error. got %d expect %d", num, ffd_num);
    }

    filter_test_destroy(ctx);
}




TEST_LIST = {
    {"ml_buffered_two_streams" , flb_test_ml_buffered_two_streams},
    {"ml_buffered_16_streams" , flb_test_ml_buffered_16_streams},

    {"multiline_buffered_one_record"                      , flb_test_multiline_buffered_one_output_record },
    {"multiline_buffered_two_record"                      , flb_test_multiline_buffered_two_output_record },
    {"flb_test_multiline_unbuffered"                      , flb_test_multiline_unbuffered },

    {"flb_test_multiline_partial_message_concat"          , flb_test_multiline_partial_message_concat },
    {"flb_test_multiline_partial_message_concat_two_ids"  , flb_test_multiline_partial_message_concat_two_ids },
    {NULL, NULL}
};
