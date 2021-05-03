/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/multiline/flb_ml.h>
#include "flb_tests_internal.h"

struct record_check {
    char *buf;
};

struct expected_result {
    int current_record;
    char *key;
    struct record_check *out_records;
};

struct record_check docker_input[] = {
  {"{\"log\": \"aa\\n\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01231z\"}"},
  {"{\"log\": \"bb\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01232z\"}"},
  {"{\"log\": \"cc\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01233z\"}"},
  {"{\"log\": \"dd\\n\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01234z\"}"},
  {"{\"log\": \"ee\\n\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01235z\"}"},
  {"{\"log\": \"ff\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01236z\"}"},
  {"{\"log\": \"gg\\n\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01237z\"}"},
};

struct record_check docker_output[] = {
  {"aa\n"},
  {"bbccdd\n"},
  {"ee\n"},
  {"ffgg\n"}
};

struct record_check cri_input[] = {
  {"2019-05-07T18:57:50.904275087+00:00 stdout P 1. some "},
  {"2019-05-07T18:57:51.904275088+00:00 stdout P multiline "},
  {"2019-05-07T18:57:52.904275089+00:00 stdout F log"},
  {"2019-05-07T18:57:53.904275090+00:00 stdout P 2. another "},
  {"2019-05-07T18:57:54.904275091+00:00 stdout P multiline "},
  {"2019-05-07T18:57:55.904275092+00:00 stdout F log"},
  {"2019-05-07T18:57:56.904275093+00:00 stdout F 3. non multiline 1"},
  {"2019-05-07T18:57:57.904275094+00:00 stdout F 4. non multiline 2"}
};

struct record_check cri_output[] = {
  {"1. some multiline log"},
  {"2. another multiline log"},
  {"3. non multiline 1"},
  {"4. non multiline 2"}
};

struct record_check java_input[] = {
  {"Exception in thread \"main\" java.lang.IllegalStateException: ..null property\n"},
  {"     at com.example.myproject.Author.getBookIds(xx.java:38)\n"},
  {"     at com.example.myproject.Bootstrap.main(Bootstrap.java:14)\n"},
  {"Caused by: java.lang.NullPointerException\n"},
  {"     at com.example.myproject.Book.getId(Book.java:22)\n"},
  {"     at com.example.myproject.Author.getBookIds(Author.java:35)\n"},
  {"     ... 1 more"},
  {"single line"}
};

struct record_check java_output[] = {
  {
    "Exception in thread \"main\" java.lang.IllegalStateException: ..null property\n"
    "     at com.example.myproject.Author.getBookIds(xx.java:38)\n"
    "     at com.example.myproject.Bootstrap.main(Bootstrap.java:14)\n"
    "Caused by: java.lang.NullPointerException\n"
    "     at com.example.myproject.Book.getId(Book.java:22)\n"
    "     at com.example.myproject.Author.getBookIds(Author.java:35)\n"
    "     ... 1 more"
  },
  {
    "single line"
  }
};

struct record_check python_input[] = {
  {"Traceback (most recent call last):\n"},
  {"  File \"/base/data/home/runtimes/python27/python27_lib/versions/third_party/webapp2-2.5.2/webapp2.py\", line 1535, in __call__\n"},
  {"    rv = self.handle_exception(request, response, e)\n"},
  {"  File \"/base/data/home/apps/s~nearfieldspy/1.378705245900539993/nearfieldspy.py\", line 17, in start\n"},
  {"    return get()\n"},
  {"  File \"/base/data/home/apps/s~nearfieldspy/1.378705245900539993/nearfieldspy.py\", line 5, in get\n"},
  {"    raise Exception('spam', 'eggs')\n"},
  {"Exception: ('spam', 'eggs')\n"},
  {"hello world, not multiline\n"}
};

struct record_check python_output[] = {
  {
      "Traceback (most recent call last):\n"
      "  File \"/base/data/home/runtimes/python27/python27_lib/versions/third_party/webapp2-2.5.2/webapp2.py\", line 1535, in __call__\n"
      "    rv = self.handle_exception(request, response, e)\n"
      "  File \"/base/data/home/apps/s~nearfieldspy/1.378705245900539993/nearfieldspy.py\", line 17, in start\n"
      "    return get()\n"
      "  File \"/base/data/home/apps/s~nearfieldspy/1.378705245900539993/nearfieldspy.py\", line 5, in get\n"
      "    raise Exception('spam', 'eggs')\n"
      "Exception: ('spam', 'eggs')\n"
  },
  {"hello world, not multiline\n"}
};

struct record_check elastic_input[] = {
  {"[some weird test] IndexNotFoundException[no such index]\n"},
  {"    at org.elasticsearch.cluster.metadata.IndexNameExpressionResolver....\n"},
  {"    at org.elasticsearch.cluster.metadata.IndexNameExpressionResolver.java:133)\n"},
  {"    at org.elasticsearch.action.admin.indices.delete.java:75)\n"},
  {"another separate log line\n"}
};

struct record_check elastic_output[] = {
  {
      "[some weird test] IndexNotFoundException[no such index]\n"
      "    at org.elasticsearch.cluster.metadata.IndexNameExpressionResolver....\n"
      "    at org.elasticsearch.cluster.metadata.IndexNameExpressionResolver.java:133)\n"
      "    at org.elasticsearch.action.admin.indices.delete.java:75)\n"
  },
  {
      "another separate log line\n"
  }
};

struct record_check go_input[] = {
    {"panic: my panic\n"},
    {"\n"},
    {"goroutine 4 [running]:\n"},
    {"panic(0x45cb40, 0x47ad70)\n"},
    {"	/usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c\n"},
    {"main.main.func1(0xc420024120)\n"},
    {"	foo.go:6 +0x39 fp=0xc42003f7d8 sp=0xc42003f7b8 pc=0x451339\n"},
    {"runtime.goexit()\n"},
    {"	/usr/local/go/src/runtime/asm_amd64.s:2337 +0x1 fp=0xc42003f7e0 sp=0xc42003f7d8 pc=0x44b4d1\n"},
    {"created by main.main\n"},
    {"	foo.go:5 +0x58\n"},
    {"\n"},
    {"goroutine 1 [chan receive]:\n"},
    {"runtime.gopark(0x4739b8, 0xc420024178, 0x46fcd7, 0xc, 0xc420028e17, 0x3)\n"},
    {"	/usr/local/go/src/runtime/proc.go:280 +0x12c fp=0xc420053e30 sp=0xc420053e00 pc=0x42503c\n"},
    {"runtime.goparkunlock(0xc420024178, 0x46fcd7, 0xc, 0x1000f010040c217, 0x3)\n"},
    {"	/usr/local/go/src/runtime/proc.go:286 +0x5e fp=0xc420053e70 sp=0xc420053e30 pc=0x42512e\n"},
    {"runtime.chanrecv(0xc420024120, 0x0, 0xc420053f01, 0x4512d8)\n"},
    {"	/usr/local/go/src/runtime/chan.go:506 +0x304 fp=0xc420053f20 sp=0xc420053e70 pc=0x4046b4\n"},
    {"runtime.chanrecv1(0xc420024120, 0x0)\n"},
    {"	/usr/local/go/src/runtime/chan.go:388 +0x2b fp=0xc420053f50 sp=0xc420053f20 pc=0x40439b\n"},
    {"main.main()\n"},
    {"	foo.go:9 +0x6f fp=0xc420053f80 sp=0xc420053f50 pc=0x4512ef\n"},
    {"runtime.main()\n"},
    {"	/usr/local/go/src/runtime/proc.go:185 +0x20d fp=0xc420053fe0 sp=0xc420053f80 pc=0x424bad\n"},
    {"runtime.goexit()\n"},
    {"	/usr/local/go/src/runtime/asm_amd64.s:2337 +0x1 fp=0xc420053fe8 sp=0xc420053fe0 pc=0x44b4d1\n"},
    {"\n"},
    {"goroutine 2 [force gc (idle)]:\n"},
    {"runtime.gopark(0x4739b8, 0x4ad720, 0x47001e, 0xf, 0x14, 0x1)\n"},
    {"	/usr/local/go/src/runtime/proc.go:280 +0x12c fp=0xc42003e768 sp=0xc42003e738 pc=0x42503c\n"},
    {"runtime.goparkunlock(0x4ad720, 0x47001e, 0xf, 0xc420000114, 0x1)\n"},
    {"	/usr/local/go/src/runtime/proc.go:286 +0x5e fp=0xc42003e7a8 sp=0xc42003e768 pc=0x42512e\n"},
    {"runtime.forcegchelper()\n"},
    {"	/usr/local/go/src/runtime/proc.go:238 +0xcc fp=0xc42003e7e0 sp=0xc42003e7a8 pc=0x424e5c\n"},
    {"runtime.goexit()\n"},
    {"	/usr/local/go/src/runtime/asm_amd64.s:2337 +0x1 fp=0xc42003e7e8 sp=0xc42003e7e0 pc=0x44b4d1\n"},
    {"created by runtime.init.4\n"},
    {"	/usr/local/go/src/runtime/proc.go:227 +0x35\n"},
    {"\n"},
    {"goroutine 3 [GC sweep wait]:\n"},
    {"runtime.gopark(0x4739b8, 0x4ad7e0, 0x46fdd2, 0xd, 0x419914, 0x1)\n"},
    {"	/usr/local/go/src/runtime/proc.go:280 +0x12c fp=0xc42003ef60 sp=0xc42003ef30 pc=0x42503c\n"},
    {"runtime.goparkunlock(0x4ad7e0, 0x46fdd2, 0xd, 0x14, 0x1)\n"},
    {"	/usr/local/go/src/runtime/proc.go:286 +0x5e fp=0xc42003efa0 sp=0xc42003ef60 pc=0x42512e\n"},
    {"runtime.bgsweep(0xc42001e150)\n"},
    {"	/usr/local/go/src/runtime/mgcsweep.go:52 +0xa3 fp=0xc42003efd8 sp=0xc42003efa0 pc=0x419973\n"},
    {"runtime.goexit()\n"},
    {"	/usr/local/go/src/runtime/asm_amd64.s:2337 +0x1 fp=0xc42003efe0 sp=0xc42003efd8 pc=0x44b4d1\n"},
    {"created by runtime.gcenable\n"},
    {"	/usr/local/go/src/runtime/mgc.go:216 +0x58\n"},
    {"one more line, no multiline"}
};

struct record_check go_output[] = {
    {
        "panic: my panic\n"
        "\n"
        "goroutine 4 [running]:\n"
        "panic(0x45cb40, 0x47ad70)\n"
        "	/usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c\n"
        "main.main.func1(0xc420024120)\n"
        "	foo.go:6 +0x39 fp=0xc42003f7d8 sp=0xc42003f7b8 pc=0x451339\n"
        "runtime.goexit()\n"
        "	/usr/local/go/src/runtime/asm_amd64.s:2337 +0x1 fp=0xc42003f7e0 sp=0xc42003f7d8 pc=0x44b4d1\n"
        "created by main.main\n"
        "	foo.go:5 +0x58\n"
        "\n"
        "goroutine 1 [chan receive]:\n"
        "runtime.gopark(0x4739b8, 0xc420024178, 0x46fcd7, 0xc, 0xc420028e17, 0x3)\n"
        "	/usr/local/go/src/runtime/proc.go:280 +0x12c fp=0xc420053e30 sp=0xc420053e00 pc=0x42503c\n"
        "runtime.goparkunlock(0xc420024178, 0x46fcd7, 0xc, 0x1000f010040c217, 0x3)\n"
        "	/usr/local/go/src/runtime/proc.go:286 +0x5e fp=0xc420053e70 sp=0xc420053e30 pc=0x42512e\n"
        "runtime.chanrecv(0xc420024120, 0x0, 0xc420053f01, 0x4512d8)\n"
        "	/usr/local/go/src/runtime/chan.go:506 +0x304 fp=0xc420053f20 sp=0xc420053e70 pc=0x4046b4\n"
        "runtime.chanrecv1(0xc420024120, 0x0)\n"
        "	/usr/local/go/src/runtime/chan.go:388 +0x2b fp=0xc420053f50 sp=0xc420053f20 pc=0x40439b\n"
        "main.main()\n"
        "	foo.go:9 +0x6f fp=0xc420053f80 sp=0xc420053f50 pc=0x4512ef\n"
        "runtime.main()\n"
        "	/usr/local/go/src/runtime/proc.go:185 +0x20d fp=0xc420053fe0 sp=0xc420053f80 pc=0x424bad\n"
        "runtime.goexit()\n"
        "	/usr/local/go/src/runtime/asm_amd64.s:2337 +0x1 fp=0xc420053fe8 sp=0xc420053fe0 pc=0x44b4d1\n"
        "\n"
        "goroutine 2 [force gc (idle)]:\n"
        "runtime.gopark(0x4739b8, 0x4ad720, 0x47001e, 0xf, 0x14, 0x1)\n"
        "	/usr/local/go/src/runtime/proc.go:280 +0x12c fp=0xc42003e768 sp=0xc42003e738 pc=0x42503c\n"
        "runtime.goparkunlock(0x4ad720, 0x47001e, 0xf, 0xc420000114, 0x1)\n"
        "	/usr/local/go/src/runtime/proc.go:286 +0x5e fp=0xc42003e7a8 sp=0xc42003e768 pc=0x42512e\n"
        "runtime.forcegchelper()\n"
        "	/usr/local/go/src/runtime/proc.go:238 +0xcc fp=0xc42003e7e0 sp=0xc42003e7a8 pc=0x424e5c\n"
        "runtime.goexit()\n"
        "	/usr/local/go/src/runtime/asm_amd64.s:2337 +0x1 fp=0xc42003e7e8 sp=0xc42003e7e0 pc=0x44b4d1\n"
        "created by runtime.init.4\n"
        "	/usr/local/go/src/runtime/proc.go:227 +0x35\n"
        "\n"
        "goroutine 3 [GC sweep wait]:\n"
        "runtime.gopark(0x4739b8, 0x4ad7e0, 0x46fdd2, 0xd, 0x419914, 0x1)\n"
        "	/usr/local/go/src/runtime/proc.go:280 +0x12c fp=0xc42003ef60 sp=0xc42003ef30 pc=0x42503c\n"
        "runtime.goparkunlock(0x4ad7e0, 0x46fdd2, 0xd, 0x14, 0x1)\n"
        "	/usr/local/go/src/runtime/proc.go:286 +0x5e fp=0xc42003efa0 sp=0xc42003ef60 pc=0x42512e\n"
        "runtime.bgsweep(0xc42001e150)\n"
        "	/usr/local/go/src/runtime/mgcsweep.go:52 +0xa3 fp=0xc42003efd8 sp=0xc42003efa0 pc=0x419973\n"
        "runtime.goexit()\n"
        "	/usr/local/go/src/runtime/asm_amd64.s:2337 +0x1 fp=0xc42003efe0 sp=0xc42003efd8 pc=0x44b4d1\n"
        "created by runtime.gcenable\n"
        "	/usr/local/go/src/runtime/mgc.go:216 +0x58\n"
    },
    {"one more line, no multiline"}
};

/*
 * Flush callback is invoked every time a multiline stream has completed a multiline
 * message or a message is not multiline.
 */
static int flush_callback(struct flb_ml *ml,
                          struct flb_ml_stream *mst,
                          void *data, void *buf_data, size_t buf_size)
{
    int i;
    int ret;
    int len;
    int found = FLB_FALSE;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object *map;
    msgpack_object key;
    msgpack_object val;
    struct flb_time tm;
    struct expected_result *res = data;
    struct record_check *exp;

    fprintf(stdout, "\n%s----- MULTILINE FLUSH -----%s\n", ANSI_YELLOW, ANSI_RESET);

    /* Print incoming flush buffer */
    flb_pack_print(buf_data, buf_size);

    fprintf(stdout, "%s----------- EOF -----------%s\n",
            ANSI_YELLOW, ANSI_RESET);

    /* Validate content */
    msgpack_unpacked_init(&result);

    off = 0;
    ret = msgpack_unpack_next(&result, buf_data, buf_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

    flb_time_pop_from_msgpack(&tm, &result, &map);

    exp = &res->out_records[res->current_record];
    len = strlen(res->key);
    for (i = 0; i < map->via.map.size; i++) {
        key = map->via.map.ptr[i].key;
        val = map->via.map.ptr[i].val;

        if (key.via.str.size != len) {
            continue;
        }

        if (strncmp(key.via.str.ptr, res->key, len) == 0) {
            found = FLB_TRUE;
            break;
        }
    }
    TEST_CHECK(found == FLB_TRUE);

    len = strlen(exp->buf);
    TEST_CHECK(val.via.str.size == len);
    if (val.via.str.size != len) {
        printf("expected length: %i, received: %i\n", len, val.via.str.size);
    }
    TEST_CHECK(memcmp(val.via.str.ptr, exp->buf, len) == 0);
    res->current_record++;

    msgpack_unpacked_destroy(&result);
    return 0;
}

static void test_mode_docker()
{
    int i;
    int len;
    int entries;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_stream *mst;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = docker_output;

    /*
     * Retrieve a docker parser. We test the multiline mode in two separate ways:
     *
     * 1. packed JSON as Fluent Bit msgpack format
     * 2. raw text with a parser context
     */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_mode_docker(config, 1000);
    TEST_CHECK(ml != NULL);

    mst = flb_ml_stream_create(ml, "docker", flush_callback, (void *) &res);
    TEST_CHECK(mst != NULL);

    entries = sizeof(docker_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &docker_input[i];
        len = strlen(r->buf);

        flb_time_get(&tm);

        /* Package as msgpack */
        flb_ml_append(ml, mst, FLB_ML_TYPE_TEXT, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_mode_cri()
{
    int i;
    int len;
    int entries;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_stream *mst;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = cri_output;

    /*
     * Retrieve a docker parser. We test the multiline mode in two separate ways:
     *
     * 1. packed JSON as Fluent Bit msgpack format
     * 2. raw text with a parser context
     */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_mode_cri(config, 1000);
    TEST_CHECK(ml != NULL);

    mst = flb_ml_stream_create(ml, "cri", flush_callback, (void *) &res);
    TEST_CHECK(mst != NULL);

    entries = sizeof(cri_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &cri_input[i];
        len = strlen(r->buf);
        flb_time_get(&tm);

        /* Package as msgpack */
        flb_ml_append(ml, mst, FLB_ML_TYPE_TEXT, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_mode_java()
{
    int i;
    int len;
    int entries;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_stream *mst;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = java_output;

    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_mode_java(config, 1000, NULL);
    TEST_CHECK(ml != NULL);

    mst = flb_ml_stream_create(ml, "java", flush_callback, (void *) &res);
    TEST_CHECK(mst != NULL);


    entries = sizeof(java_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &java_input[i];
        len = strlen(r->buf);

        /* Package as msgpack */
        flb_time_get(&tm);
        flb_ml_append(ml, mst, FLB_ML_TYPE_TEXT, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_mode_python()
{
    int i;
    int len;
    int ret;
    int entries;
    size_t off = 0;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object *map;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_stream *mst;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = python_output;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Retrieve a docker parser. We test the multiline mode in two separate ways:
     *
     * 1. packed JSON as Fluent Bit msgpack format
     * 2. raw text with a parser context
     */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_mode_python(config, 1000, "log");
    TEST_CHECK(ml != NULL);

    mst = flb_ml_stream_create(ml, "python", flush_callback, (void *) &res);
    TEST_CHECK(mst != NULL);

    flb_time_get(&tm);

    printf("\n");
    entries = sizeof(python_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &python_input[i];
        len = strlen(r->buf);

        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        /* Package raw text as a msgpack record */
        msgpack_pack_array(&mp_pck, 2);
        flb_time_append_to_msgpack(&tm, &mp_pck, 0);

        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str(&mp_pck, 3);
        msgpack_pack_str_body(&mp_pck, "log", 3);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, r->buf, len);

        /* Unpack and lookup the content map */
        msgpack_unpacked_init(&result);
        off = 0;
        ret = msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, &off);
        TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

        root = result.data;
        map = &root.via.array.ptr[1];

        /* Package as msgpack */
        flb_ml_append_object(ml, mst, &tm, map);
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_mode_elastic()
{
    int i;
    int len;
    int ret;
    int entries;
    size_t off = 0;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object *map;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_stream *mst;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = elastic_output;

    /*
     * Retrieve a docker parser. We test the multiline mode in two separate ways:
     *
     * 1. packed JSON as Fluent Bit msgpack format
     * 2. raw text with a parser context
     */
    config = flb_config_init();

    ml = flb_ml_create(config,
                       FLB_ML_REGEX,         /* type      */
                       NULL,                 /* match_str */
                       FLB_FALSE,            /* negate    */
                       1000,                 /* flush_ms  */
                       "log",                /* key_content */
                       NULL,                 /* key_pattern */
                       NULL);                /* parser */

    ret = flb_ml_rule_create(ml, "start_state", "/^\\[/", "elastic_cont", NULL);
    if (ret != 0) {
        fprintf(stderr, "error creating rule 1");
    }

    ret = flb_ml_rule_create(ml, "elastic_cont", "/^\\s+/", "elastic_cont", NULL);
    if (ret != 0) {
        fprintf(stderr, "error creating rule 2");
    }

    mst = flb_ml_stream_create(ml, "elastic", flush_callback, (void *) &res);
    TEST_CHECK(mst != NULL);

    ret = flb_ml_init(ml);
    if (ret != 0) {
        fprintf(stderr, "error initializing multiline\n");
        flb_ml_destroy(ml);
        return;
    }

    printf("\n");
    entries = sizeof(elastic_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &elastic_input[i];
        len = strlen(r->buf);

        /* initialize buffers */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        /* Package raw text as a msgpack record */
        msgpack_pack_array(&mp_pck, 2);

        flb_time_get(&tm);
        flb_time_append_to_msgpack(&tm, &mp_pck, 0);

        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str(&mp_pck, 3);
        msgpack_pack_str_body(&mp_pck, "log", 3);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, r->buf, len);

        /* Unpack and lookup the content map */
        msgpack_unpacked_init(&result);
        off = 0;
        ret = msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, &off);
        TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

        root = result.data;
        map = &root.via.array.ptr[1];

        /* Package as msgpack */
        ret = flb_ml_append_object(ml, mst, &tm, map);
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_mode_go()
{
    int i;
    int len;
    int entries;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_stream *mst;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = go_output;

    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_mode_go(config, 1000, NULL);
    TEST_CHECK(ml != NULL);

    mst = flb_ml_stream_create(ml, "go", flush_callback, (void *) &res);
    TEST_CHECK(mst != NULL);

    entries = sizeof(go_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &go_input[i];
        len = strlen(r->buf);

        /* Package as msgpack */
        flb_time_get(&tm);
        flb_ml_append(ml, mst, FLB_ML_TYPE_TEXT, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

TEST_LIST = {
    { "mode_docker",  test_mode_docker},
    { "mode_cri",     test_mode_cri},
    { "mode_java",    test_mode_java},
    { "mode_python",  test_mode_python},
    { "mode_elastic", test_mode_elastic},
    { "mode_go",      test_mode_go},
    { 0 }
};
