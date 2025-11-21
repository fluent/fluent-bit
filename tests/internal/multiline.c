/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_rule.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

#include "flb_tests_internal.h"

struct record_check {
    char *buf;
};

struct expected_result {
    int current_record;
    char *key;
    struct record_check *out_records;
};

/* Docker */
struct record_check docker_input[] = {
  {"{\"log\": \"aa\\n\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01231z\"}"},
  {"{\"log\": \"aa\\n\", \"stream\": \"stderr\", \"time\": \"2021-02-01T16:45:03.01231z\"}"},
  {"{\"log\": \"bb\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01232z\"}"},
  {"{\"log\": \"cc\n\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01233z\"}"},
  {"{\"log\": \"dd\", \"stream\": \"stderr\", \"time\": \"2021-02-01T16:45:03.01233z\"}"},
  {"single line to force pending flush of the previous line"},
  {"{\"log\": \"ee\\n\", \"stream\": \"stderr\", \"time\": \"2021-02-01T16:45:03.01234z\"}"},
};

struct record_check docker_output[] = {
  {"aa\n"},
  {"aa\n"},
  {"bbcc\n"},
  {"dd"},
  {"single line to force pending flush of the previous line"},
  {"ee\n"},
};

/* CRI */
struct record_check cri_input[] = {
  {"2019-05-07T18:57:50.904275087+00:00 stdout P 1a. some "},
  {"2019-05-07T18:57:51.904275088+00:00 stdout P multiline "},
  {"2019-05-07T18:57:52.904275089+00:00 stdout F log"},
  {"2019-05-07T18:57:50.904275087+00:00 stderr P 1b. some "},
  {"2019-05-07T18:57:51.904275088+00:00 stderr P multiline "},
  {"2019-05-07T18:57:52.904275089+00:00 stderr F log"},
  {"2019-05-07T18:57:53.904275090+00:00 stdout P 2a. another "},
  {"2019-05-07T18:57:54.904275091+00:00 stdout P multiline "},
  {"2019-05-07T18:57:55.904275092+00:00 stdout F log"},
  {"2019-05-07T18:57:53.904275090+00:00 stderr P 2b. another "},
  {"2019-05-07T18:57:54.904275091+00:00 stderr P multiline "},
  {"2019-05-07T18:57:55.904275092+00:00 stderr F log"},
  {"2019-05-07T18:57:56.904275093+00:00 stdout F 3a. non multiline 1"},
  {"2019-05-07T18:57:57.904275094+00:00 stdout F 4a. non multiline 2"},
  {"2019-05-07T18:57:56.904275093+00:00 stderr F 3b. non multiline 1"},
  {"2019-05-07T18:57:57.904275094+00:00 stderr F 4b. non multiline 2"}
};

struct record_check cri_output[] = {
  {"1a. some multiline log"},
  {"1b. some multiline log"},
  {"2a. another multiline log"},
  {"2b. another multiline log"},
  {"3a. non multiline 1"},
  {"4a. non multiline 2"},
  {"3b. non multiline 1"},
  {"4b. non multiline 2"}
};

/* ENDSWITH */
struct record_check endswith_input[] = {
  {"1a. some multiline log \\"},
  {"1b. some multiline log"},
  {"2a. another multiline log\\"},
  {"2b. another multiline log"},
  {"3a. non multiline 1"},
  {"4a. non multiline 2"}
};

struct record_check endswith_output[] = {
  {"1a. some multiline log \\\n1b. some multiline log\n"},
  {"2a. another multiline log\\\n2b. another multiline log\n"},
  {"3a. non multiline 1\n"},
  {"4a. non multiline 2\n"}
};

/* Mixed lines of Docker and CRI logs in different streams (stdout/stderr) */
struct record_check container_mix_input[] = {
  {"{\"log\": \"a1\\n\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01231z\"}"},
  {"{\"log\": \"a2\\n\", \"stream\": \"stderr\", \"time\": \"2021-02-01T16:45:03.01231z\"}"},
  {"{\"log\": \"bb\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01232z\"}"},
  {"{\"log\": \"cc\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01233z\"}"},
  {"{\"log\": \"dd\", \"stream\": \"stderr\", \"time\": \"2021-02-01T16:45:03.01232z\"}"},
  {"{\"log\": \"ee\n\", \"stream\": \"stderr\", \"time\": \"2021-02-01T16:45:03.01233z\"}"},
  {"2019-05-07T18:57:52.904275089+00:00 stdout F single full"},
  {"2019-05-07T18:57:50.904275087+00:00 stdout P 1a. some "},
  {"2019-05-07T18:57:51.904275088+00:00 stdout P multiline "},
  {"2019-05-07T18:57:52.904275089+00:00 stdout F log"},
  {"2019-05-07T18:57:50.904275087+00:00 stderr P 1b. some "},
  {"2019-05-07T18:57:51.904275088+00:00 stderr P multiline "},
  {"2019-05-07T18:57:52.904275089+00:00 stderr F log"},
  {"{\"log\": \"dd-out\\n\", \"stream\": \"stdout\", \"time\": \"2021-02-01T16:45:03.01234z\"}"},
  {"{\"log\": \"dd-err\\n\", \"stream\": \"stderr\", \"time\": \"2021-02-01T16:45:03.01234z\"}"},
};

/*
 * The docker parser should emit each container fragment as soon as the log
 * stream provides a newline. CRI lines handled by the chained parser are
 * expected to flush immediately even if the docker stream still has buffered
 * fragments waiting for a later newline (e.g. "bb" + "cc" + "dd-out\n").
 */
struct record_check container_mix_output[] = {
  {"a1\n"},
  {"a2\n"},
  {"ddee\n"},
  {"single full"},
  {"1a. some multiline log"},
  {"1b. some multiline log"},
  {"bbccdd-out\n"},
  {"dd-err\n"},
};

/*
 * Regression guard: when docker is the first parser in the chain and a CRI
 * record arrives, the docker parser must decline the line so the CRI parser
 * can consume it instead of buffering the payload until the flush timer
 * expires. The strings below mimic container runtime output without trailing
 * newlines as seen in the reported issue.
 */
struct record_check docker_cri_chain_input[] = {
  {"2025-09-22T19:07:06.115398289Z stdout F first message"},
  {"2025-09-22T19:07:06.116725604Z stdout F second message"},
  {"2025-09-22T19:07:08.582112316Z stdout F third message"},
};

struct record_check docker_cri_chain_output[] = {
  {"first message"},
  {"second message"},
  {"third message"},
};

/* Java stacktrace detection */
struct record_check java_input[] = {
  {"Exception in thread \"main\" java.lang.IllegalStateException: ..null property\n"},
  {"     at com.example.myproject.Author.getBookIds(xx.java:38)\n"},
  {"     at com.example.myproject.Bootstrap.main(Bootstrap.java:14)\n"},
  {"Caused by: java.lang.NullPointerException\n"},
  {"     at com.example.myproject.Book.getId(Book.java:22)\n"},
  {"     at com.example.myproject.Author.getBookIds(Author.java:35)\n"},
  {"     ... 1 more\n"},
  {"single line\n"}
};

struct record_check java_output[] = {
  {
    "Exception in thread \"main\" java.lang.IllegalStateException: ..null property\n"
    "     at com.example.myproject.Author.getBookIds(xx.java:38)\n"
    "     at com.example.myproject.Bootstrap.main(Bootstrap.java:14)\n"
    "Caused by: java.lang.NullPointerException\n"
    "     at com.example.myproject.Book.getId(Book.java:22)\n"
    "     at com.example.myproject.Author.getBookIds(Author.java:35)\n"
    "     ... 1 more\n"
  },
  {
    "single line\n"
  }
};

struct record_check ruby_input[] = {
    {"/app/config/routes.rb:6:in `/': divided by 0 (ZeroDivisionError)"},
    {"	from /app/config/routes.rb:6:in `block in <main>'"},
    {"	from /var/lib/gems/3.0.0/gems/actionpack-7.0.4/lib/action_dispatch/routing/route_set.rb:428:in `instance_exec'"},
    {"	from /var/lib/gems/3.0.0/gems/actionpack-7.0.4/lib/action_dispatch/routing/route_set.rb:428:in `eval_block'"},
    {"	from /var/lib/gems/3.0.0/gems/actionpack-7.0.4/lib/action_dispatch/routing/route_set.rb:410:in `draw'"},
    {"	from /app/config/routes.rb:1:in `<main>'"},
    {"hello world, not multiline\n"}
};

struct record_check ruby_output[] = {
    {
        "/app/config/routes.rb:6:in `/': divided by 0 (ZeroDivisionError)\n"
        "	from /app/config/routes.rb:6:in `block in <main>'\n"
        "	from /var/lib/gems/3.0.0/gems/actionpack-7.0.4/lib/action_dispatch/routing/route_set.rb:428:in `instance_exec'\n"
        "	from /var/lib/gems/3.0.0/gems/actionpack-7.0.4/lib/action_dispatch/routing/route_set.rb:428:in `eval_block'\n"
        "	from /var/lib/gems/3.0.0/gems/actionpack-7.0.4/lib/action_dispatch/routing/route_set.rb:410:in `draw'\n"
        "	from /app/config/routes.rb:1:in `<main>'\n"
    },
    {"hello world, not multiline\n"}
};

/* Python stacktrace detection */
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

/* Custom example for Elasticsearch stacktrace */
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

/* Go */
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
    {"one more line, no multiline\n"}
};

/*
 * Issue 3817 (case: 1)
 * --------------------
 * Source CRI messages (need first CRI multiline parsing) + a custom multiline
 * parser.
 *
 *   - https://github.com/fluent/fluent-bit/issues/3817
 *
 * The 'case 1' represents the problems of identifying two consecutive multiline
 * messages within the same stream.
 */
struct record_check issue_3817_1_input[] = {
    {"2021-05-17T17:35:01.184675702Z stdout F [DEBUG] 1 start multiline - "},
    {"2021-05-17T17:35:01.184747208Z stdout F 1 cont A"},
    {"2021-05-17T17:35:01.184675702Z stdout F [DEBUG] 2 start multiline - "},
    {"2021-05-17T17:35:01.184747208Z stdout F 2 cont B"},
    {"another isolated line"}
};

struct record_check issue_3817_1_output[] = {
    {
      "[DEBUG] 1 start multiline - \n"
      "1 cont A"
    },

    {
      "[DEBUG] 2 start multiline - \n"
      "2 cont B"
    },

    {
      "another isolated line"
    }
};

/*
 * Flush callback is invoked every time a multiline stream has completed a multiline
 * message or a message is not multiline.
 */
static int flush_callback(struct flb_ml_parser *parser,
                          struct flb_ml_stream *mst,
                          void *data, char *buf_data, size_t buf_size)
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

    if (!res) {
        return 0;
    }

    /* Validate content */
    msgpack_unpacked_init(&result);
    off = 0;
    ret = msgpack_unpack_next(&result, buf_data, buf_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

    flb_time_pop_from_msgpack(&tm, &result, &map);

    TEST_CHECK(flb_time_to_nanosec(&tm) != 0L);

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
        printf("== received ==\n");
        msgpack_object_print(stdout, val);
        printf("\n\n");
        printf("== expected ==\n%s\n", exp->buf);
        exit(1);
    }
    TEST_CHECK(memcmp(val.via.str.ptr, exp->buf, len) == 0);
    res->current_record++;

    msgpack_unpacked_destroy(&result);
    return 0;
}

static void test_parser_docker()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = docker_output;

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "test-docker");
    TEST_CHECK(ml != NULL);

    /* Load instances of the parsers for current 'ml' context */
    mlp_i = flb_ml_parser_instance_create(ml, "cri");
    TEST_CHECK(mlp_i != NULL);

    /* Generate an instance of multiline docker parser */
    mlp_i = flb_ml_parser_instance_create(ml, "docker");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "docker", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    entries = sizeof(docker_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &docker_input[i];
        len = strlen(r->buf);

        flb_time_get(&tm);

        /* Package as msgpack */
        flb_ml_append_text(ml, stream_id, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_parser_cri()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = cri_output;

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "cri-test");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of multiline docker parser */
    mlp_i = flb_ml_parser_instance_create(ml, "docker");
    TEST_CHECK(mlp_i != NULL);

    /* Load instances of the parsers for current 'ml' context */
    mlp_i = flb_ml_parser_instance_create(ml, "cri");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "cri", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    entries = sizeof(cri_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &cri_input[i];
        len = strlen(r->buf);
        flb_time_get(&tm);

        /* Package as msgpack */
        flb_ml_append_text(ml, stream_id, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_container_mix()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = container_mix_output;

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "container-mix-test");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of multiline docker parser */
    mlp_i = flb_ml_parser_instance_create(ml, "docker");
    TEST_CHECK(mlp_i != NULL);

    /* Load instances of the parsers for current 'ml' context */
    mlp_i = flb_ml_parser_instance_create(ml, "cri");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "container-mix", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    entries = sizeof(container_mix_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &container_mix_input[i];
        len = strlen(r->buf);
        flb_time_get(&tm);

        /* Package as msgpack */
        flb_ml_append_text(ml, stream_id, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_parser_docker_cri_chain()
{
    int i;
    int len;
    int ret;
    int entries;
    int expected;
    uint64_t stream_id;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = docker_cri_chain_output;

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "docker-cri-chain");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of multiline docker parser */
    mlp_i = flb_ml_parser_instance_create(ml, "docker");
    TEST_CHECK(mlp_i != NULL);

    /* Load instances of the parsers for current 'ml' context */
    mlp_i = flb_ml_parser_instance_create(ml, "cri");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "docker-cri-chain", -1, flush_callback,
                               (void *) &res, &stream_id);
    TEST_CHECK(ret == 0);

    entries = sizeof(docker_cri_chain_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &docker_cri_chain_input[i];
        len = strlen(r->buf);

        flb_time_get(&tm);

        /* Package as msgpack */
        flb_ml_append_text(ml, stream_id, &tm, r->buf, len);
    }

    /* Flush any pending data to ensure no buffered records remain */
    flb_ml_flush_pending_now(ml);

    expected = sizeof(docker_cri_chain_output) / sizeof(struct record_check);
    TEST_CHECK(res.current_record == expected);

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_parser_java()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Expected results context */
    res.key = "log";
    res.out_records = java_output;

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "java-test");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of multiline java parser */
    mlp_i = flb_ml_parser_instance_create(ml, "java");
    TEST_CHECK(mlp_i != NULL);

    flb_ml_parser_instance_set(mlp_i, "key_content", "log");

    ret = flb_ml_stream_create(ml, "java", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object *map;

    entries = sizeof(java_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &java_input[i];
        len = strlen(r->buf);

        /* Package as msgpack */
        flb_time_get(&tm);

        /* initialize buffers */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

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

        flb_pack_print(mp_sbuf.data, mp_sbuf.size);

        root = result.data;
        map = &root.via.array.ptr[1];

        /* Package as msgpack */
        ret = flb_ml_append_object(ml, stream_id, &tm, NULL, map);

        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_parser_python()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = python_output;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "python-test");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of multiline python parser */
    mlp_i = flb_ml_parser_instance_create(ml, "python");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "python", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    flb_time_get(&tm);

    printf("\n");
    entries = sizeof(python_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &python_input[i];
        len = strlen(r->buf);

        /* Package as msgpack */
        flb_time_get(&tm);
        flb_ml_append_text(ml, stream_id, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_parser_ruby()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = ruby_output;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "ruby-test");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of multiline ruby parser */
    mlp_i = flb_ml_parser_instance_create(ml, "ruby");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "ruby", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    flb_time_get(&tm);

    printf("\n");
    entries = sizeof(ruby_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &ruby_input[i];
        len = strlen(r->buf);

        /* Package as msgpack */
        flb_time_get(&tm);
        flb_ml_append_text(ml, stream_id, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_issue_4949()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = python_output;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "python-test");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of multiline python parser */
    mlp_i = flb_ml_parser_instance_create(ml, "python");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "python", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    /* Generate an instance of multiline java parser */
    mlp_i = flb_ml_parser_instance_create(ml, "java");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "java", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    flb_time_get(&tm);

    printf("\n");
    entries = sizeof(python_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &python_input[i];
        len = strlen(r->buf);

        /* Package as msgpack */
        flb_time_get(&tm);
        flb_ml_append_text(ml, stream_id, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_parser_elastic()
{
    int i;
    int len;
    int ret;
    int entries;
    size_t off = 0;
    uint64_t stream_id;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object *map;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser *mlp;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = elastic_output;

    /* Initialize environment */
    config = flb_config_init();

    ml = flb_ml_create(config, "test-elastic");
    TEST_CHECK(ml != NULL);

    mlp = flb_ml_parser_create(config,
                               "elastic",            /* name      */
                               FLB_ML_REGEX,         /* type      */
                               NULL,                 /* match_str */
                               FLB_FALSE,            /* negate    */
                               1000,                 /* flush_ms  */
                               "log",                /* key_content */
                               NULL,                 /* key_pattern */
                               NULL,                 /* key_group */
                               NULL,                 /* parser ctx */
                               NULL);                /* parser name */
    TEST_CHECK(mlp != NULL);

    mlp_i = flb_ml_parser_instance_create(ml, "elastic");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_rule_create(mlp, "start_state", "/^\\[/", "elastic_cont", NULL);
    if (ret != 0) {
        fprintf(stderr, "error creating rule 1");
    }

    ret = flb_ml_rule_create(mlp, "elastic_cont", "/^\\s+/", "elastic_cont", NULL);
    if (ret != 0) {
        fprintf(stderr, "error creating rule 2");
    }

    ret = flb_ml_stream_create(ml, "elastic", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    ret = flb_ml_parser_init(mlp);
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
        ret = flb_ml_append_object(ml, stream_id, &tm, NULL, map);

        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_endswith()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id = 0;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser *mlp;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = endswith_output;

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "raw-endswith");
    TEST_CHECK(ml != NULL);

    mlp = flb_ml_parser_create(config,
                               "endswith",           /* name      */
                               FLB_ML_ENDSWITH,      /* type      */
                               "\\",                 /* match_str */
                               FLB_TRUE,             /* negate    */
                               1000,                 /* flush_ms  */
                               NULL,                 /* key_content */
                               NULL,                 /* key_pattern */
                               NULL,                 /* key_group */
                               NULL,                 /* parser ctx */
                               NULL);                /* parser name */
    TEST_CHECK(mlp != NULL);

    /* Generate an instance of 'endswith' custom parser parser */
    mlp_i = flb_ml_parser_instance_create(ml, "endswith");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "test", -1, flush_callback, (void *) &res, &stream_id);
    TEST_CHECK(ret == 0);

    entries = sizeof(endswith_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &endswith_input[i];
        len = strlen(r->buf);

        /* Package as msgpack */
        flb_time_get(&tm);
        flb_ml_append_text(ml, stream_id, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_parser_go()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id = 0;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};

    /* Expected results context */
    res.key = "log";
    res.out_records = go_output;

    /* Initialize environment */
    config = flb_config_init();

    /* Create docker multiline mode */
    ml = flb_ml_create(config, "go-test");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of multiline java parser */
    mlp_i = flb_ml_parser_instance_create(ml, "go");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "go", -1, flush_callback, (void *) &res, &stream_id);
    TEST_CHECK(ret == 0);

    entries = sizeof(go_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &go_input[i];
        len = strlen(r->buf);

        /* Package as msgpack */
        flb_time_get(&tm);
        flb_ml_append_text(ml, stream_id, &tm, r->buf, len);
    }

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static int flush_callback_to_buf(struct flb_ml_parser *parser,
                                 struct flb_ml_stream *mst,
                                 void *data, char *buf_data, size_t buf_size)
{
    msgpack_sbuffer *mp_sbuf = data;
    msgpack_sbuffer_write(mp_sbuf, buf_data, buf_size);

    return 0;
}

static void run_test(struct flb_config *config, char *test_name,
                     struct record_check *in, int in_len,
                     struct record_check *out, int out_len,
                     char *parser1, char *parser2)

{
    int i;
    int ret;
    int len;
    size_t off = 0;
    uint64_t stream1 = 0;
    uint64_t stream2 = 0;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *p1 = NULL;
    struct record_check *r;
    msgpack_sbuffer mp_sbuf1;
    msgpack_packer mp_pck1;
    msgpack_sbuffer mp_sbuf2;
    msgpack_packer mp_pck2;
    msgpack_object *map;
    struct flb_time tm;
    struct expected_result res = {0};
    msgpack_unpacked result;

    /* init buffers */
    msgpack_sbuffer_init(&mp_sbuf1);
    msgpack_packer_init(&mp_pck1, &mp_sbuf1, msgpack_sbuffer_write);
    msgpack_sbuffer_init(&mp_sbuf2);
    msgpack_packer_init(&mp_pck2, &mp_sbuf2, msgpack_sbuffer_write);

    /* Create docker multiline mode */
    ml = flb_ml_create(config, test_name);
    TEST_CHECK(ml != NULL);

    if (!parser1) {
        fprintf(stderr, "run_test(): parser1 is NULL\n");
        exit(1);
    }

    /* Parser 1 */
    p1 = flb_ml_parser_instance_create(ml, parser1);
    TEST_CHECK(p1 != NULL);


    /* Stream 1: use parser name (test_name) to generate the stream id */
    ret = flb_ml_stream_create(ml, test_name, -1,
                               flush_callback_to_buf,
                               (void *) &mp_sbuf1, &stream1);
    TEST_CHECK(ret == 0);

    /* Ingest input records into parser 1 */
    for (i = 0; i < in_len; i++) {
        r = &in[i];
        len = strlen(r->buf);

        flb_time_get(&tm);

        /* Package as msgpack */
        flb_ml_append_text(ml, stream1, &tm, r->buf, len);
    }

    flb_ml_destroy(ml);
    ml = flb_ml_create(config, test_name);

    flb_ml_parser_instance_create(ml, parser2);

    /*
     * After flb_ml_append above(), mp_sbuf1 has been populated with the
     * output results as structured messages. Now this data needs to be
     * passed to the next parser.
     */

    /* Expected results context */
    res.key = "log";
    res.out_records = out;

    /* Stream 2 */
    ret = flb_ml_stream_create(ml, "filter_multiline", -1,
                               flush_callback,
                               (void *) &res, &stream2);

    /* Ingest input records into parser 2 */
    off = 0;
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, mp_sbuf1.data, mp_sbuf1.size, &off)) {
        flb_time_pop_from_msgpack(&tm, &result, &map);

        /* Package as msgpack */
        ret = flb_ml_append_object(ml, stream2, &tm, NULL, map);
    }
    flb_ml_flush_pending_now(ml);

    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&mp_sbuf1);
    flb_ml_destroy(ml);
}

void test_issue_3817_1()
{
    int ret;
    int in_len  = sizeof(issue_3817_1_input) / sizeof(struct record_check);
    int out_len = sizeof(issue_3817_1_output) / sizeof(struct record_check);
    struct flb_config *config;
    struct flb_ml_parser *mlp;

    /*
     * Parser definition for a file:
     *
     * [MULTILINE_PARSER]
     *     name           parser_3817
     *     type           regex
     *     key_content    log
     *     #
     *     # Regex rules for multiline parsing
     *     # ---------------------------------
     *     #
     *     # rules |   state name  | regex pattern       | next state
     *     # ------|---------------|------------------------------------
     *     rule      "start_state"   "/- $/"                "cont"
     *     rule      "cont"          "/^([1-9].*$/"         "cont"
     *
     */

    /* Initialize environment */
    config = flb_config_init();

    /* Register custom parser */
    mlp = flb_ml_parser_create(config,
                               "parser_3817",        /* name      */
                               FLB_ML_REGEX,         /* type      */
                               NULL,                 /* match_str */
                               FLB_FALSE,            /* negate    */
                               1000,                 /* flush_ms  */
                               "log",                /* key_content */
                               NULL,                 /* key_pattern */
                               NULL,                 /* key_group */
                               NULL,                 /* parser ctx */
                               NULL);                /* parser name */
    TEST_CHECK(mlp != NULL);

    /* rule: start_state */
    ret = flb_ml_rule_create(mlp, "start_state", "/- $/", "cont", NULL);
    if (ret != 0) {
        fprintf(stderr, "error creating rule 1");
    }

    /* rule: cont */
    ret = flb_ml_rule_create(mlp, "cont", "/^([1-9]).*$/", "cont", NULL);
    if (ret != 0) {
        fprintf(stderr, "error creating rule 2");
    }

    /* initiaze the parser configuration */
    ret = flb_ml_parser_init(mlp);
    TEST_CHECK(ret == 0);

    /* Run the test */
    run_test(config, "issue_3817_1",
             issue_3817_1_input, in_len,
             issue_3817_1_output, out_len,
             "cri", "parser_3817");

    flb_config_exit(config);
}

static void test_issue_4034()
{
    int i;
    int len;
    int ret;
    int entries;
    uint64_t stream_id;
    struct record_check *r;
    struct flb_config *config;
    struct flb_time tm;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct expected_result res = {0};
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Expected results context */
    res.key = "log";
    res.out_records = cri_output;

    /* Initialize environment */
    config = flb_config_init();

    /* Create cri multiline mode */
    ml = flb_ml_create(config, "cri-test");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of multiline cri parser */
    mlp_i = flb_ml_parser_instance_create(ml, "cri");
    TEST_CHECK(mlp_i != NULL);

    flb_ml_parser_instance_set(mlp_i, "key_content", "log");

    ret = flb_ml_stream_create(ml, "cri", -1, flush_callback, (void *) &res,
                               &stream_id);
    TEST_CHECK(ret == 0);

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object *map;

    entries = sizeof(cri_input) / sizeof(struct record_check);
    for (i = 0; i < entries; i++) {
        r = &cri_input[i];
        len = strlen(r->buf);

        /* Package as msgpack */
        flb_time_get(&tm);

        /* initialize buffers */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

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

        flb_pack_print(mp_sbuf.data, mp_sbuf.size);

        root = result.data;
        map = &root.via.array.ptr[1];

        /* Package as msgpack */
        ret = flb_ml_append_object(ml, stream_id, &tm, NULL, map);

        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }
    flb_ml_flush_pending_now(ml);

    if (ml) {
        flb_ml_destroy(ml);
    }

    flb_config_exit(config);
}

static void test_issue_5504()
{
    uint64_t last_flush;
    struct flb_config *config;
    struct flb_ml *ml;
    struct flb_ml_parser_ins *mlp_i;
    struct mk_event_loop *evl;
    struct flb_sched *sched;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sched_timer *timer;
    void (*cb)(struct flb_config *, void *);
    int timeout = 500;

#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    /* Initialize environment */
    config = flb_config_init();

    /* Create the event loop */
    evl = config->evl;
    config->evl = mk_event_loop_create(32);
    TEST_CHECK(config->evl != NULL);

    /* Initialize the scheduler */
    sched = config->sched;
    config->sched = flb_sched_create(config, config->evl);
    TEST_CHECK(config->sched != NULL);

    /* Set the thread local scheduler */
    flb_sched_ctx_init();
    flb_sched_ctx_set(config->sched);

    ml = flb_ml_create(config, "5504-test");
    TEST_CHECK(ml != NULL);

    /* Generate an instance of any multiline parser */
    mlp_i = flb_ml_parser_instance_create(ml, "cri");
    TEST_CHECK(mlp_i != NULL);

    flb_ml_parser_instance_set(mlp_i, "key_content", "log");

    /* Set the flush timeout */
    ml->flush_ms = timeout;

    /* Initialize the auto flush */
    flb_ml_auto_flush_init(ml);

    /* Store the initial last_flush time */
    last_flush = ml->last_flush;

    /* Find the cb_ml_flush_timer callback from the timers */
    mk_list_foreach_safe(head, tmp, &((struct flb_sched *)config->sched)->timers) {
        timer = mk_list_entry(head, struct flb_sched_timer, _head);
        if (timer->type == FLB_SCHED_TIMER_CB_PERM) {
            cb = timer->cb;
        }
    }
    TEST_CHECK(cb != NULL);

    /* Trigger the callback without delay */
    cb(config, ml);
    /* This should not update the last_flush since it is before the timeout */
    TEST_CHECK(ml->last_flush == last_flush);

    /* Sleep just enough time to pass the timeout */
    flb_time_msleep(timeout + 1);

    /* Retrigger the callback */
    cb(config, ml);
    /* Ensure this time the last_flush has been updated */
    TEST_CHECK(ml->last_flush > last_flush);

    /* Cleanup */
    flb_sched_destroy(config->sched);
    config->sched = sched;
    mk_event_loop_destroy(config->evl);
    config->evl = evl;
    flb_ml_destroy(ml);
    flb_config_exit(config);

#ifdef _WIN32
    WSACleanup();
#endif
}

static void test_buffer_limit_truncation()
{
    int ret;
    uint64_t stream_id;
    struct flb_config *config;
    struct flb_ml *ml;
    struct flb_ml_parser *mlp;
    struct flb_ml_parser_ins *mlp_i;
    struct flb_time tm;

    /*
     * A realistic Docker log where the content of the "log" field will be
     * concatenated, and that concatenated buffer is what should be truncated.
     */
    char *line1 = "{\"log\": \"12345678901234567890\", \"stream\": \"stdout\"}";
    char *line2 = "{\"log\": \"abcdefghijklmnopqrstuvwxyz\", \"stream\": \"stdout\"}";

    config = flb_config_init();
    /* The buffer limit is for the concatenated 'log' content, not the full JSON */
    if (config->multiline_buffer_limit) {
        flb_free(config->multiline_buffer_limit);
    }
    config->multiline_buffer_limit = flb_strdup("80");

    /* This parser will trigger on any content, ensuring concatenation. */
    ml = flb_ml_create(config, "limit-test");
    TEST_CHECK(ml != NULL);

    /* --- New params-based initializer --- */
    struct flb_ml_parser_params params = flb_ml_parser_params_default("test-concat");
    params.type        = FLB_ML_REGEX;
    params.negate      = FLB_FALSE;
    params.flush_ms    = 1000;
    params.key_content = "log";
    params.parser_ctx  = NULL;
    params.parser_name = NULL;

    mlp = flb_ml_parser_create_params(config, &params);
    TEST_CHECK(mlp != NULL);

    /* Define rules that will always match the test data */
    ret = flb_ml_rule_create(mlp, "start_state", "/./", "cont", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_ml_rule_create(mlp, "cont", "/./", "cont", NULL);
    TEST_CHECK(ret == 0);

    /* Finalize parser initialization */
    ret = flb_ml_parser_init(mlp);
    TEST_CHECK(ret == 0);

    mlp_i = flb_ml_parser_instance_create(ml, "test-concat");
    TEST_CHECK(mlp_i != NULL);

    ret = flb_ml_stream_create(ml, "test", -1, flush_callback, NULL, &stream_id);
    TEST_CHECK(ret == 0);

    flb_time_get(&tm);

    /* Append the first line. It will match the 'start_state' and start a block. */
    ret = flb_ml_append_text(ml, stream_id, &tm, line1, strlen(line1));
    TEST_CHECK(ret == FLB_MULTILINE_OK);

    /*
     * Append the second line. This will match the 'cont' state and concatenate.
     * The concatenation will exceed the limit and correctly trigger truncation.
     */
    ret = flb_ml_append_text(ml, stream_id, &tm, line2, strlen(line2));
    TEST_CHECK(ret == FLB_MULTILINE_TRUNCATED);

    flb_ml_destroy(ml);
    flb_config_exit(config);
}

static void test_buffer_limit_disabled()
{
    struct flb_config *config;
    struct flb_ml *ml;

    config = flb_config_init();

    if (config->multiline_buffer_limit) {
        flb_free(config->multiline_buffer_limit);
        config->multiline_buffer_limit = NULL;
    }

    config->multiline_buffer_limit = flb_strdup("false");

    ml = flb_ml_create(config, "limit-disabled");
    TEST_CHECK(ml != NULL);

    TEST_CHECK(ml->buffer_limit == 0);

    flb_ml_destroy(ml);
    flb_config_exit(config);
}

TEST_LIST = {
    /* Normal features tests */
    { "parser_docker",  test_parser_docker},
    { "parser_cri",     test_parser_cri},
    { "parser_docker_cri_chain", test_parser_docker_cri_chain},
    { "parser_java",    test_parser_java},
    { "parser_python",  test_parser_python},
    { "parser_ruby",    test_parser_ruby},
    { "parser_elastic", test_parser_elastic},
    { "parser_go",      test_parser_go},
    { "container_mix",  test_container_mix},
    { "endswith",       test_endswith},
    { "buffer_limit_truncation", test_buffer_limit_truncation},
    { "buffer_limit_disabled", test_buffer_limit_disabled},

    /* Issues reported on Github */
    { "issue_3817_1"  , test_issue_3817_1},
    { "issue_4034"    , test_issue_4034},
    { "issue_4949"    , test_issue_4949},
    { "issue_5504"    , test_issue_5504},
    { 0 }
};
