/* SPDX-License-Identifier: Apache-2.0 */
/* SDK inspection: condition results, resolved topology and the record trace. */

#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/wasm/flb_wasm_inspect.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "Routing check failed at %d: %s\n", __LINE__, #condition); abort(); \
} } while (0)

static const char *records =
    "[{\"level\":\"error\",\"service\":\"web\",\"amount\":5,\"tags\":[\"a\"],\"nested\":{\"code\":503}},"
    "{\"level\":\"info\",\"service\":\"payments\",\"amount\":5},"
    "{\"level\":\"error\",\"service\":\"payments\",\"amount\":500},"
    "{\"level\":\"info\",\"service\":\"web\",\"amount\":1}]";

/* Evaluate one condition against the four records; returns the JSON result. */
static char *evaluate(const char *condition, const char *extra)
{
    char request[4096];
    char *out = NULL;
    size_t size = 0;
    int length;

    length = snprintf(request, sizeof(request), "{\"condition\":%s,\"records\":%s%s}",
                      condition, records, extra ? extra : "");
    CHECK(length > 0 && length < (int) sizeof(request));
    CHECK(flb_wasm_inspect_condition(request, length, &out, &size) == 0);
    CHECK(out != NULL && strlen(out) == size);
    return out;
}

static void expect(const char *condition, const char *result)
{
    char *out;

    out = evaluate(condition, NULL);
    if (strcmp(out, result) != 0) {
        fprintf(stderr, "condition %s\n  expected %s\n  received %s\n", condition, result, out);
        abort();
    }
    free(out);
}

static void expect_error(const char *condition, const char *fragment)
{
    char *out;

    out = evaluate(condition, NULL);
    if (strncmp(out, "{\"error\":", 9) != 0 || strstr(out, fragment) == NULL) {
        fprintf(stderr, "condition %s\n  expected an error with '%s'\n  received %s\n",
                condition, fragment, out);
        abort();
    }
    free(out);
}

static void conditions(void)
{
    char *out;
    size_t size;

    /* Every operator, on the body. */
    expect("{\"rules\":[{\"field\":\"$level\",\"op\":\"eq\",\"value\":\"error\"}]}",
           "{\"matched\":[true,false,true,false]}");
    expect("{\"rules\":[{\"field\":\"$level\",\"op\":\"neq\",\"value\":\"error\"}]}",
           "{\"matched\":[false,true,false,true]}");
    expect("{\"rules\":[{\"field\":\"$amount\",\"op\":\"gt\",\"value\":5}]}",
           "{\"matched\":[false,false,true,false]}");
    expect("{\"rules\":[{\"field\":\"$amount\",\"op\":\"gte\",\"value\":5}]}",
           "{\"matched\":[true,true,true,false]}");
    expect("{\"rules\":[{\"field\":\"$amount\",\"op\":\"lt\",\"value\":5}]}",
           "{\"matched\":[false,false,false,true]}");
    expect("{\"rules\":[{\"field\":\"$amount\",\"op\":\"lte\",\"value\":\"5\"}]}",
           "{\"matched\":[true,true,false,true]}");
    expect("{\"rules\":[{\"field\":\"$service\",\"op\":\"regex\",\"value\":\"^pay\"}]}",
           "{\"matched\":[false,true,true,false]}");
    expect("{\"rules\":[{\"field\":\"$service\",\"op\":\"not_regex\",\"value\":\"^pay\"}]}",
           "{\"matched\":[true,false,false,true]}");
    expect("{\"rules\":[{\"field\":\"$service\",\"op\":\"in\",\"value\":[\"web\",\"api\"]}]}",
           "{\"matched\":[true,false,false,true]}");
    expect("{\"rules\":[{\"field\":\"$service\",\"op\":\"not_in\",\"value\":[\"web\",\"api\"]}]}",
           "{\"matched\":[false,true,true,false]}");
    expect("{\"rules\":[{\"field\":\"$nested['code']\",\"op\":\"eq\",\"value\":503}]}",
           "{\"matched\":[true,false,false,false]}");

    /* Rules combine with 'and' unless 'op' says 'or'. */
    expect("{\"rules\":[{\"field\":\"$level\",\"op\":\"eq\",\"value\":\"error\"},"
           "{\"field\":\"$service\",\"op\":\"eq\",\"value\":\"payments\"}]}",
           "{\"matched\":[false,false,true,false]}");
    expect("{\"op\":\"or\",\"rules\":[{\"field\":\"$level\",\"op\":\"eq\",\"value\":\"error\"},"
           "{\"field\":\"$service\",\"op\":\"eq\",\"value\":\"payments\"}]}",
           "{\"matched\":[true,true,true,false]}");

    /* A default condition alone takes every record it is offered. */
    expect("{\"default\":true}", "{\"matched\":[true,true,true,true]}");

    /* Record metadata is a separate context. */
    out = evaluate("{\"rules\":[{\"field\":\"$source\",\"op\":\"eq\",\"value\":\"edge\","
                   "\"context\":\"metadata\"}]}",
                   ",\"metadata\":[{\"source\":\"edge\"},null,{\"source\":\"core\"},{\"source\":\"edge\"}]");
    CHECK(strcmp(out, "{\"matched\":[true,false,false,true]}") == 0);
    free(out);

    /* What the engine rejects is reported with its reason. */
    expect_error("{}", "needs 'rules' or 'default: true'");
    expect_error("{\"op\":\"xor\",\"default\":true}", "'op' must be 'and' or 'or'");
    expect_error("{\"rules\":[{\"field\":\"$level\",\"op\":\"eq\"}]}", "needs a 'value'");
    expect_error("{\"rules\":[{\"op\":\"eq\",\"value\":1}]}", "needs a 'field'");
    expect_error("{\"rules\":[{\"field\":\"$level\",\"op\":\"eq\",\"value\":1,\"context\":\"nowhere\"}]}",
                 "context");
    expect_error("{\"rules\":[{\"field\":\"$level\",\"op\":\"like\",\"value\":\"x\"}]}", "unknown 'op'");
    expect_error("{\"rules\":[{\"field\":\"$amount\",\"op\":\"gt\",\"value\":\"many\"}]}", "unknown 'op'");

    out = NULL;
    CHECK(flb_wasm_inspect_condition("{", 1, &out, &size) == 0);
    CHECK(strstr(out, "not valid JSON") != NULL);
    free(out);
    out = NULL;
    CHECK(flb_wasm_inspect_condition("{\"condition\":{\"default\":true},\"records\":[]}", 43,
                                     &out, &size) == 0);
    CHECK(strcmp(out, "{\"matched\":[]}") == 0);
    free(out);
}

static const char *pipeline =
    "service:\n"
    "  flush: 0.1\n"
    "  grace: 1\n"
    "  log_level: error\n"
    "pipeline:\n"
    "  inputs:\n"
    "    - name: lib\n"
    "      alias: app\n"
    "      tag: app.logs\n"
    "      routes:\n"
    "        logs:\n"
    "          - name: errors\n"
    "            condition:\n"
    "              rules:\n"
    "                - field: $level\n"
    "                  op: eq\n"
    "                  value: error\n"
    "            to:\n"
    "              outputs:\n"
    "                - alerts\n"
    "                - name: missing\n"
    "                  fallback: archive\n"
    "          - name: payments\n"
    "            condition:\n"
    "              op: or\n"
    "              rules:\n"
    "                - field: $service\n"
    "                  op: eq\n"
    "                  value: payments\n"
    "                - field: $amount\n"
    "                  op: gt\n"
    "                  value: 100\n"
    "            to:\n"
    "              outputs:\n"
    "                - alerts\n"
    "                - nowhere\n"
    "                - paid\n"
    "          - name: rest\n"
    "            condition:\n"
    "              default: true\n"
    "            to:\n"
    "              outputs:\n"
    "                - other\n"
    "    - name: lib\n"
    "      alias: plain\n"
    "      tag: plain.logs\n"
    "  filters:\n"
    "    - name: grep\n"
    "      match: errors\n"
    "      regex: level error\n"
    "    - name: grep\n"
    "      match_regex: ^(paym|plain).*\n"
    "      exclude: level info\n"
    "  outputs:\n"
    "    - name: 'null'\n"
    "      alias: alerts\n"
    "      match: nothing\n"
    "    - name: 'null'\n"
    "      alias: archive\n"
    "      match: 'plain.*'\n"
    "    - name: 'null'\n"
    "      alias: paid\n"
    "      match_regex: ^plain\n"
    "    - name: 'null'\n"
    "      alias: other\n";

static int input_id(flb_ctx_t *ctx, const char *alias)
{
    struct mk_list *head;
    struct flb_input_instance *instance;

    mk_list_foreach(head, &ctx->config->inputs) {
        instance = mk_list_entry(head, struct flb_input_instance, _head);
        if (instance->alias && strcmp(instance->alias, alias) == 0) {
            return instance->id;
        }
    }
    return -1;
}

static void has(const char *json, const char *fragment)
{
    if (strstr(json, fragment) == NULL) {
        fprintf(stderr, "missing %s\n  in %s\n", fragment, json);
        abort();
    }
}

static void lacks(const char *json, const char *fragment)
{
    if (strstr(json, fragment) != NULL) {
        fprintf(stderr, "unexpected %s\n  in %s\n", fragment, json);
        abort();
    }
}


static const char *service =
    "service:\n"
    "  flush: 0.1\n"
    "  grace: 1\n"
    "  log_level: error\n";

static int verbose;

/* Start an engine with tracing on for 'service' plus the given pipeline. */
static flb_ctx_t *engine_start(const char *name, const char *yaml)
{
    flb_ctx_t *ctx;
    FILE *file;

    file = fopen("/tmp/routing.yaml", "w");
    CHECK(file != NULL);
    CHECK(fputs(service, file) >= 0);
    CHECK(fputs(yaml, file) >= 0);
    CHECK(fclose(file) == 0);
    ctx = flb_create();
    CHECK(ctx != NULL);
    CHECK(flb_lib_config_file(ctx, "/tmp/routing.yaml") == 0);
    flb_wasm_trace_set(FLB_TRUE);
    CHECK(flb_start(ctx) == 0);
    if (verbose) {
        printf("== %s\n", name);
    }
    return ctx;
}

static char *topology(flb_ctx_t *ctx)
{
    char *out = NULL;
    size_t size;

    CHECK(flb_wasm_inspect_topology(ctx->config, &out, &size) == 0);
    CHECK(out != NULL && strlen(out) == size);
    if (verbose) {
        printf("topology %s\n", out);
    }
    return out;
}

static void push(flb_ctx_t *ctx, const char *alias, const char *data)
{
    size_t length;

    length = strlen(data);
    CHECK(flb_lib_push(ctx, input_id(ctx, alias), data, length) == (int) length);
}

static char *trace_take(void)
{
    char *out = NULL;
    size_t size;

    CHECK(flb_wasm_trace_take(&out, &size) == 0);
    CHECK(out != NULL && strlen(out) == size);
    return out;
}

/*
 * Collect the trace until 'fragment' shows up. Taking the trace empties it, so
 * the documents taken meanwhile are returned one after the other. Gives up
 * after 60 seconds.
 */
static char *trace_until(const char *fragment)
{
    char *all;
    char *out;
    char *grown;
    size_t length = 0;
    int settle = 0;
    int tries;

    all = calloc(1, 1);
    CHECK(all != NULL);
    for (tries = 0; tries < 600 && settle < 3; tries++) {
        usleep(100000);
        out = trace_take();
        if (strcmp(out, "{\"events\":[],\"dropped\":0}") != 0) {
            grown = realloc(all, length + strlen(out) + 2);
            CHECK(grown != NULL);
            all = grown;
            length += sprintf(all + length, "%s\n", out);
        }
        free(out);
        /* once found, wait a little more for events that may still follow */
        if (settle > 0 || strstr(all, fragment) != NULL) {
            settle++;
        }
    }
    if (verbose) {
        printf("trace %s", all);
    }
    return all;
}

static void engine_stop(flb_ctx_t *ctx)
{
    flb_wasm_trace_set(FLB_FALSE);
    CHECK(flb_stop(ctx) == 0);
    flb_destroy(ctx);
}

static const char *four =
    "[0,{\"level\":\"error\",\"service\":\"web\",\"amount\":5}]"
    "[0,{\"level\":\"info\",\"service\":\"payments\",\"amount\":5}]"
    "[0,{\"level\":\"error\",\"service\":\"payments\",\"amount\":500}]"
    "[0,{\"level\":\"info\",\"service\":\"web\",\"amount\":1}]";

#define INPUT(alias) \
    "    - name: lib\n" \
    "      alias: " alias "\n" \
    "      tag: " alias ".logs\n"

#define ROUTE(name) \
    "          - name: " name "\n"

#define ERRORS \
    "            condition:\n" \
    "              rules:\n" \
    "                - field: $level\n" \
    "                  op: eq\n" \
    "                  value: error\n"

#define DEFAULT \
    "            condition:\n" \
    "              default: true\n"

#define TO(output) \
    "            to:\n" \
    "              outputs:\n" \
    "                - " output "\n"

#define OUTPUT(alias) \
    "    - name: 'null'\n" \
    "      alias: " alias "\n"

#define MATCH(pattern) \
    "      match: '" pattern "'\n"

/* A route without a condition is not split: the chunk keeps the input's tag. */
static void unconditional_route(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("unconditional route",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "      routes:\n        logs:\n"
                       ROUTE("all") TO("kept")
                       "  outputs:\n"
                       OUTPUT("kept") MATCH("app.*"));
    out = topology(ctx);
    has(out, "\"name\":\"all\",\"signals\":[\"logs\"],\"conditional\":false,\"isDefault\":false,"
             "\"perRecord\":false,\"split\":false");
    has(out, "{\"requested\":\"kept\",\"fallback\":null,\"resolved\":0,\"usedFallback\":false,\"status\":\"connected\"}");
    free(out);

    push(ctx, "app", four);
    out = trace_until("\"tag\":\"app.logs\",\"output\":0,");
    has(out, "{\"stage\":\"append\",\"append\":1,\"input\":0,\"tag\":\"app.logs\",\"records\":4}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"app.logs\",\"output\":0,\"records\":4}");
    lacks(out, "\"stage\":\"route\"");
    lacks(out, "\"stage\":\"unrouted\"");
    free(out);
    engine_stop(ctx);
}

/* Beside a conditional route, the route without a condition gets the whole chunk. */
static void unconditional_beside_conditional(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("unconditional beside conditional",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "      routes:\n        logs:\n"
                       ROUTE("errors") ERRORS TO("alerts")
                       ROUTE("all") TO("everything")
                       "  outputs:\n"
                       OUTPUT("alerts") MATCH("nothing")
                       OUTPUT("everything") MATCH("nothing"));
    out = topology(ctx);
    has(out, "\"name\":\"errors\",\"signals\":[\"logs\"],\"conditional\":true,\"isDefault\":false,"
             "\"perRecord\":false,\"split\":true");
    has(out, "\"name\":\"all\",\"signals\":[\"logs\"],\"conditional\":false,\"isDefault\":false,"
             "\"perRecord\":false,\"split\":false");
    free(out);

    push(ctx, "app", four);
    out = trace_until("\"tag\":\"app.logs\",\"output\":1,");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":0,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":2,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"errors\",\"output\":0,\"records\":2}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"app.logs\",\"output\":1,\"records\":4}");
    lacks(out, "\"route\":\"all\"");
    lacks(out, "\"stage\":\"undelivered\"");
    /* The route without a condition takes what the conditional route does not. */
    lacks(out, "\"stage\":\"unrouted\"");
    free(out);
    engine_stop(ctx);
}

/* Without a default route, records no condition takes are reported as unrouted. */
static void conditional_without_default(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("conditional without default",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "      routes:\n        logs:\n"
                       ROUTE("errors") ERRORS TO("alerts")
                       "  outputs:\n"
                       OUTPUT("alerts"));
    out = topology(ctx);
    has(out, "\"matchedOutputs\":[],\"directOutputs\":[0]");
    free(out);

    push(ctx, "app", four);
    out = trace_until("\"tag\":\"errors\",\"output\":0,");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":0,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":2,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"unrouted\",\"append\":1,\"record\":1,\"input\":0}");
    has(out, "{\"stage\":\"unrouted\",\"append\":1,\"record\":3,\"input\":0}");
    lacks(out, "{\"stage\":\"unrouted\",\"append\":1,\"record\":0,");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"errors\",\"output\":0,\"records\":2}");
    free(out);
    engine_stop(ctx);
}

/* Record positions count log records only, not the group markers around them. */
static void grouped_records(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("grouped records",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "      processors:\n"
                       "        logs:\n"
                       "          - name: opentelemetry_envelope\n"
                       "      routes:\n        logs:\n"
                       ROUTE("errors") ERRORS TO("alerts")
                       ROUTE("rest") DEFAULT TO("other")
                       "  outputs:\n"
                       OUTPUT("alerts")
                       OUTPUT("other"));
    push(ctx, "app", four);
    out = trace_until("\"tag\":\"rest\",\"output\":1,");
    has(out, "{\"stage\":\"append\",\"append\":1,\"input\":0,\"tag\":\"app.logs\",\"records\":4}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":0,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":2,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":1,\"input\":0,\"route\":\"rest\",\"isDefault\":true}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":3,\"input\":0,\"route\":\"rest\",\"isDefault\":true}");
    lacks(out, "\"record\":4,");
    lacks(out, "\"stage\":\"unrouted\"");
    free(out);
    engine_stop(ctx);

    /* The same positions when no route takes a record. */
    ctx = engine_start("grouped records without default",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "      processors:\n"
                       "        logs:\n"
                       "          - name: opentelemetry_envelope\n"
                       "      routes:\n        logs:\n"
                       ROUTE("errors") ERRORS TO("alerts")
                       "  outputs:\n"
                       OUTPUT("alerts"));
    push(ctx, "app", four);
    out = trace_until("\"tag\":\"errors\",\"output\":0,");
    has(out, "{\"stage\":\"unrouted\",\"append\":1,\"record\":1,\"input\":0}");
    has(out, "{\"stage\":\"unrouted\",\"append\":1,\"record\":3,\"input\":0}");
    lacks(out, "\"record\":4,");
    free(out);
    engine_stop(ctx);
}

/* per_record_routing is reported, and such a route takes the records its condition meets. */
static void per_record_route(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("per record route",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "      routes:\n        logs:\n"
                       ROUTE("errors") "            per_record_routing: true\n" ERRORS TO("alerts")
                       ROUTE("rest") DEFAULT TO("other")
                       "  outputs:\n"
                       OUTPUT("alerts")
                       OUTPUT("other"));
    out = topology(ctx);
    has(out, "\"name\":\"errors\",\"signals\":[\"logs\"],\"conditional\":true,\"isDefault\":false,"
             "\"perRecord\":true,\"split\":true");
    has(out, "\"name\":\"rest\",\"signals\":[\"logs\"],\"conditional\":true,\"isDefault\":true,"
             "\"perRecord\":false,\"split\":true");
    free(out);

    push(ctx, "app", four);
    out = trace_until("\"tag\":\"rest\",\"output\":1,");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":0,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":2,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":1,\"input\":0,\"route\":\"rest\",\"isDefault\":true}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":3,\"input\":0,\"route\":\"rest\",\"isDefault\":true}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"errors\",\"output\":0,\"records\":2}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"rest\",\"output\":1,\"records\":2}");
    lacks(out, "\"stage\":\"unrouted\"");
    free(out);
    engine_stop(ctx);
}

/* A route names an output by instance name or by plugin name (the first one). */
static void output_names(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("output names",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "      routes:\n        logs:\n"
                       ROUTE("errors") ERRORS TO("'null.1'")
                       ROUTE("rest") DEFAULT TO("'null'")
                       "  outputs:\n"
                       "    - name: 'null'\n"
                       "    - name: 'null'\n");
    out = topology(ctx);
    has(out, "{\"requested\":\"null.1\",\"fallback\":null,\"resolved\":1,\"usedFallback\":false,\"status\":\"connected\"}");
    has(out, "{\"requested\":\"null\",\"fallback\":null,\"resolved\":0,\"usedFallback\":false,\"status\":\"connected\"}");
    has(out, "{\"index\":1,\"name\":\"null.1\",\"plugin\":\"null\",\"alias\":null,");
    free(out);

    push(ctx, "app", four);
    out = trace_until("\"tag\":\"rest\",\"output\":0,");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"errors\",\"output\":1,\"records\":2}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"rest\",\"output\":0,\"records\":2}");
    free(out);
    engine_stop(ctx);
}

/* Classic tag matching: wildcards, several outputs for a tag, and the lone pair. */
static void tag_matching(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("tag matching",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       INPUT("db")
                       "  outputs:\n"
                       OUTPUT("all") MATCH("*")
                       OUTPUT("apps") MATCH("app.*")
                       OUTPUT("exact") MATCH("db.logs")
                       OUTPUT("none") MATCH("other"));
    out = topology(ctx);
    has(out, "\"alias\":\"app\",\"tag\":\"app.logs\",\"matchedOutputs\":[0,1],\"directOutputs\":[],\"routes\":[]");
    has(out, "\"alias\":\"db\",\"tag\":\"db.logs\",\"matchedOutputs\":[0,2],\"directOutputs\":[],\"routes\":[]");
    free(out);

    push(ctx, "app", four);
    push(ctx, "db", four);
    out = trace_until("\"tag\":\"db.logs\",\"output\":2,");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"app.logs\",\"output\":0,\"records\":4}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"app.logs\",\"output\":1,\"records\":4}");
    has(out, "{\"stage\":\"output\",\"input\":1,\"tag\":\"db.logs\",\"output\":0,\"records\":4}");
    has(out, "{\"stage\":\"output\",\"input\":1,\"tag\":\"db.logs\",\"output\":2,\"records\":4}");
    lacks(out, "\"output\":3");
    lacks(out, "\"stage\":\"route\"");
    lacks(out, "\"stage\":\"undelivered\"");
    free(out);
    engine_stop(ctx);

    /* The only output of the only input is connected even without a match. */
    ctx = engine_start("one input, one output",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "  outputs:\n"
                       "    - name: 'null'\n");
    out = topology(ctx);
    has(out, "\"matchedOutputs\":[0],\"directOutputs\":[],\"routes\":[]");
    free(out);
    push(ctx, "app", four);
    out = trace_until("\"tag\":\"app.logs\",\"output\":0,");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"app.logs\",\"output\":0,\"records\":4}");
    free(out);
    engine_stop(ctx);

    /* No output selects the tag: the chunk is reported as undelivered. */
    ctx = engine_start("unmatched tag",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "  outputs:\n"
                       OUTPUT("first") MATCH("other")
                       OUTPUT("second") MATCH("db.*"));
    out = topology(ctx);
    has(out, "\"matchedOutputs\":[],\"directOutputs\":[],\"routes\":[]");
    free(out);
    push(ctx, "app", four);
    out = trace_until("\"stage\":\"undelivered\"");
    has(out, "{\"stage\":\"undelivered\",\"input\":0,\"tag\":\"app.logs\",\"records\":4}");
    lacks(out, "\"stage\":\"output\"");
    free(out);
    engine_stop(ctx);
}

/* Records re-emitted by rewrite_tag come from the emitter input, by tag match. */
static void rewrite_tag(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("rewrite tag",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "  filters:\n"
                       "    - name: rewrite_tag\n"
                       "      match: app.logs\n"
                       "      rule: $level ^(error)$ alert.$service false\n"
                       "  outputs:\n"
                       OUTPUT("alerts") MATCH("alert.*")
                       OUTPUT("rest") MATCH("app.logs"));
    out = topology(ctx);
    has(out, "\"plugin\":\"rewrite_tag\",\"alias\":null,\"match\":\"app.logs\",\"matchRegex\":false,\"matchesInputs\":[0]");
    has(out, "{\"index\":1,\"name\":\"emitter.1\",\"plugin\":\"emitter\",");
    free(out);

    push(ctx, "app", four);
    out = trace_until("\"tag\":\"alert.payments\",\"output\":0,");
    has(out, "{\"stage\":\"filter\",\"input\":0,\"tag\":\"app.logs\",\"filter\":0,\"recordsIn\":4,\"recordsOut\":2,\"modified\":true}");
    has(out, "\"input\":1,\"tag\":\"alert.web\",\"records\":1}");
    has(out, "\"input\":1,\"tag\":\"alert.payments\",\"records\":1}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"app.logs\",\"output\":1,\"records\":2}");
    has(out, "{\"stage\":\"output\",\"input\":1,\"tag\":\"alert.web\",\"output\":0,\"records\":1}");
    has(out, "{\"stage\":\"output\",\"input\":1,\"tag\":\"alert.payments\",\"output\":0,\"records\":1}");
    lacks(out, "\"tag\":\"app.logs\",\"output\":0");
    free(out);
    engine_stop(ctx);
}

/* Routes of different inputs can share an output; an input without routes still matches by tag. */
static void shared_output(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("shared output",
                       "pipeline:\n  inputs:\n"
                       INPUT("one")
                       "      routes:\n        logs:\n"
                       ROUTE("errors") ERRORS TO("shared")
                       INPUT("two")
                       "      routes:\n        logs:\n"
                       ROUTE("errors") ERRORS TO("shared")
                       ROUTE("rest") DEFAULT TO("shared")
                       INPUT("three")
                       "  outputs:\n"
                       OUTPUT("shared") MATCH("three.*"));
    out = topology(ctx);
    has(out, "\"alias\":\"one\",\"tag\":\"one.logs\",\"matchedOutputs\":[],\"directOutputs\":[0]");
    has(out, "\"alias\":\"three\",\"tag\":\"three.logs\",\"matchedOutputs\":[0],\"directOutputs\":[],\"routes\":[]");
    /* Each input owns one connection to the output; the second route of 'two' does not. */
    has(out, "\"name\":\"rest\",\"signals\":[\"logs\"],\"conditional\":true,\"isDefault\":true,\"perRecord\":false,"
             "\"split\":true,\"outputs\":[{\"requested\":\"shared\",\"fallback\":null,\"resolved\":0,"
             "\"usedFallback\":false,\"status\":\"already_connected\"}]");
    free(out);

    push(ctx, "one", four);
    push(ctx, "two", four);
    push(ctx, "three", four);
    out = trace_until("\"tag\":\"three.logs\",\"output\":0,");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"errors\",\"output\":0,\"records\":2}");
    has(out, "{\"stage\":\"output\",\"input\":1,\"tag\":\"errors\",\"output\":0,\"records\":2}");
    has(out, "{\"stage\":\"output\",\"input\":2,\"tag\":\"three.logs\",\"output\":0,\"records\":4}");
    lacks(out, "\"input\":2,\"route\"");
    free(out);
    engine_stop(ctx);
}

/* Routes are declared per signal; an output that cannot take the signal is not connected. */
static void signals(void)
{
    flb_ctx_t *ctx;
    char *out;

    ctx = engine_start("signals",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "      routes:\n"
                       "        metrics:\n" ROUTE("numbers") TO("sink")
                       "        traces:\n" ROUTE("spans") TO("sink")
                       "        any:\n" ROUTE("whatever") TO("sink")
                       "    - name: event_type\n"
                       "      alias: gauge\n"
                       "      tag: gauge\n"
                       "      type: metrics\n"
                       "      threaded: false\n"
                       "      interval_sec: 1\n"
                       "      routes:\n"
                       "        metrics:\n" ROUTE("numbers") TO("sink")
                       "  outputs:\n"
                       OUTPUT("sink") MATCH("gauge"));
    out = topology(ctx);
    has(out, "\"name\":\"numbers\",\"signals\":[\"metrics\"],\"conditional\":false,\"isDefault\":false,"
             "\"perRecord\":false,\"split\":false,\"outputs\":[{\"requested\":\"sink\",\"fallback\":null,"
             "\"resolved\":0,\"usedFallback\":false,\"status\":\"connected\"}]");
    /* The null output takes logs and metrics, not traces. */
    has(out, "\"name\":\"spans\",\"signals\":[\"traces\"],\"conditional\":false,\"isDefault\":false,"
             "\"perRecord\":false,\"split\":false,\"outputs\":[{\"requested\":\"sink\",\"fallback\":null,"
             "\"resolved\":null,\"usedFallback\":false,\"status\":\"signal_not_supported\"}]");
    has(out, "\"name\":\"whatever\",\"signals\":[\"logs\",\"metrics\",\"traces\"]");
    has(out, "\"plugin\":\"event_type\",\"alias\":\"gauge\",\"tag\":\"gauge\",\"matchedOutputs\":[0],\"directOutputs\":[0]");
    free(out);

    /* A metrics chunk is delivered through its route. */
    out = trace_until("\"tag\":\"gauge\",\"output\":0,");
    has(out, "{\"stage\":\"output\",\"input\":1,\"tag\":\"gauge\",\"output\":0,\"records\":");
    lacks(out, "\"stage\":\"route\"");
    free(out);
    engine_stop(ctx);
}

/* A long route name fills the byte limit of the trace with few records. */
#define LONG_NAME \
    "a_route_name_long_enough_to_fill_the_trace_buffer_with_a_few_records_" \
    "a_route_name_long_enough_to_fill_the_trace_buffer_with_a_few_records_" \
    "a_route_name_long_enough_to_fill_the_trace_buffer_with_a_few_records_" \
    "a_route_name_long_enough_to_fill_the_trace_buffer_with_a_few_records"

/* The trace is bounded: what does not fit is counted, not kept. */
static void trace_limit(void)
{
    const char record[] = "[0,{\"level\":\"error\"}]";
    const size_t count = 3000;
    flb_ctx_t *ctx;
    char *data;
    char *out;
    size_t i;

    data = malloc(count * (sizeof(record) - 1) + 1);
    CHECK(data != NULL);
    for (i = 0; i < count; i++) {
        memcpy(data + i * (sizeof(record) - 1), record, sizeof(record) - 1);
    }
    data[count * (sizeof(record) - 1)] = '\0';

    ctx = engine_start("trace limit",
                       "pipeline:\n  inputs:\n"
                       INPUT("app")
                       "      routes:\n        logs:\n"
                       ROUTE(LONG_NAME) ERRORS TO("alerts")
                       "  outputs:\n"
                       OUTPUT("alerts"));
    push(ctx, "app", data);
    free(data);
    /*
     * The trace is not taken while the records are routed, that would make
     * room in it: stopping the engine waits for the append to finish.
     */
    sleep(1);
    CHECK(flb_stop(ctx) == 0);
    out = trace_take();
    has(out, "{\"stage\":\"append\",\"append\":1,\"input\":0,\"tag\":\"app.logs\",\"records\":3000}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":0,\"input\":0,\"route\":\"" LONG_NAME "\",\"isDefault\":false}");
    lacks(out, "\"record\":2999,");
    /* 3000 route events of about 330 bytes each do not fit in 512 KiB */
    CHECK(strstr(out, "\"dropped\":0}") == NULL);
    CHECK(strlen(out) < 2 * 1024 * 1024);
    free(out);
    flb_wasm_trace_set(FLB_FALSE);
    flb_destroy(ctx);
}

static void scenarios(void)
{
    unconditional_route();
    unconditional_beside_conditional();
    conditional_without_default();
    per_record_route();
    grouped_records();
    output_names();
    tag_matching();
    rewrite_tag();
    shared_output();
    signals();
    trace_limit();
}

int main(int argc, char **argv)
{
    const char batch[] =
        "[0,{\"level\":\"error\",\"service\":\"web\",\"amount\":5}]"
        "[0,{\"level\":\"info\",\"service\":\"payments\",\"amount\":5}]"
        "[0,{\"level\":\"error\",\"service\":\"payments\",\"amount\":500}]"
        "[0,{\"level\":\"info\",\"service\":\"web\",\"amount\":1}]";
    const char plain[] = "[0,{\"level\":\"info\"}][0,{\"level\":\"warn\"}]";
    flb_ctx_t *ctx;
    FILE *file;
    char *out;
    size_t size;

    verbose = argc > 1 && strcmp(argv[1], "--print") == 0;
    conditions();

    file = fopen("/tmp/routing.yaml", "w");
    CHECK(file != NULL);
    CHECK(fputs(pipeline, file) >= 0);
    CHECK(fclose(file) == 0);
    ctx = flb_create();
    CHECK(ctx != NULL);
    CHECK(flb_lib_config_file(ctx, "/tmp/routing.yaml") == 0);
    flb_wasm_trace_set(FLB_TRUE);
    CHECK(flb_start(ctx) == 0);

    out = NULL;
    CHECK(flb_wasm_inspect_topology(ctx->config, &out, &size) == 0);
    if (verbose) {
        printf("topology %s\n", out);
    }
    /* Names resolve by alias; a missing name uses its fallback. */
    has(out, "{\"requested\":\"alerts\",\"fallback\":null,\"resolved\":0,\"usedFallback\":false,\"status\":\"connected\"}");
    has(out, "{\"requested\":\"missing\",\"fallback\":\"archive\",\"resolved\":1,\"usedFallback\":true,\"status\":\"connected\"}");
    /* A second route of the input to the same output does not own a connection. */
    has(out, "{\"requested\":\"alerts\",\"fallback\":null,\"resolved\":0,\"usedFallback\":false,\"status\":\"already_connected\"}");
    has(out, "{\"requested\":\"nowhere\",\"fallback\":null,\"resolved\":null,\"usedFallback\":false,\"status\":\"not_found\"}");
    has(out, "\"name\":\"rest\",\"signals\":[\"logs\"],\"conditional\":true,\"isDefault\":true");
    /* Routes replace tag matching for their input; the other input keeps it. */
    has(out, "\"alias\":\"app\",\"tag\":\"app.logs\",\"matchedOutputs\":[],\"directOutputs\":[0,1,2,3]");
    /* An output with neither 'match' nor 'match_regex' ('other') matches no tag. */
    has(out, "\"alias\":\"plain\",\"tag\":\"plain.logs\",\"matchedOutputs\":[1,2],\"directOutputs\":[]");
    /* Filters are matched against configured tags: neither input's tag is 'errors'. */
    has(out, "\"match\":\"errors\",\"matchRegex\":false,\"matchesInputs\":[]");
    has(out, "\"matchRegex\":true,\"matchesInputs\":[1]");
    free(out);

    CHECK(flb_lib_push(ctx, input_id(ctx, "app"), batch, sizeof(batch) - 1) == sizeof(batch) - 1);
    sleep(1);
    CHECK(flb_lib_push(ctx, input_id(ctx, "plain"), plain, sizeof(plain) - 1) == sizeof(plain) - 1);
    sleep(2);

    out = NULL;
    CHECK(flb_wasm_trace_take(&out, &size) == 0);
    if (verbose) {
        printf("trace %s\n", out);
    }
    has(out, "\"dropped\":0");
    has(out, "{\"stage\":\"append\",\"append\":1,\"input\":0,\"tag\":\"app.logs\",\"records\":4}");
    /* A record follows every route whose condition it meets; the default takes the rest. */
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":0,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":2,\"input\":0,\"route\":\"errors\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":1,\"input\":0,\"route\":\"payments\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":2,\"input\":0,\"route\":\"payments\",\"isDefault\":false}");
    has(out, "{\"stage\":\"route\",\"append\":1,\"record\":3,\"input\":0,\"route\":\"rest\",\"isDefault\":true}");
    lacks(out, "\"record\":1,\"input\":0,\"route\":\"errors\"");
    lacks(out, "\"record\":0,\"input\":0,\"route\":\"rest\"");
    lacks(out, "\"stage\":\"unrouted\"");
    /* Filters see the route name as the tag. */
    has(out, "{\"stage\":\"filter\",\"input\":0,\"tag\":\"errors\",\"filter\":0,\"recordsIn\":2,\"recordsOut\":2,");
    has(out, "{\"stage\":\"filter\",\"input\":0,\"tag\":\"payments\",\"filter\":1,\"recordsIn\":2,\"recordsOut\":1,\"modified\":true}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"errors\",\"output\":0,\"records\":2}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"errors\",\"output\":1,\"records\":2}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"payments\",\"output\":2,\"records\":1}");
    has(out, "{\"stage\":\"output\",\"input\":0,\"tag\":\"rest\",\"output\":3,\"records\":1}");
    /* 'payments' also names 'alerts', but the 'errors' route owns that connection. */
    lacks(out, "\"tag\":\"payments\",\"output\":0");
    /*
     * The unsplit chunk keeps the input tag and is only for routes without a
     * condition. This input has none, so that copy has no destination.
     */
    has(out, "{\"stage\":\"undelivered\",\"input\":0,\"tag\":\"app.logs\",\"records\":4}");
    /* An input without routes is delivered by tag match. */
    has(out, "{\"stage\":\"append\",\"append\":2,\"input\":1,\"tag\":\"plain.logs\",\"records\":2}");
    has(out, "{\"stage\":\"filter\",\"input\":1,\"tag\":\"plain.logs\",\"filter\":1,\"recordsIn\":2,\"recordsOut\":1,\"modified\":true}");
    has(out, "{\"stage\":\"output\",\"input\":1,\"tag\":\"plain.logs\",\"output\":1,\"records\":1}");
    has(out, "{\"stage\":\"output\",\"input\":1,\"tag\":\"plain.logs\",\"output\":2,\"records\":1}");
    lacks(out, "\"tag\":\"plain.logs\",\"output\":3");
    free(out);

    /* Taking the trace empties it; disabling it stops recording. */
    out = NULL;
    CHECK(flb_wasm_trace_take(&out, &size) == 0);
    CHECK(strcmp(out, "{\"events\":[],\"dropped\":0}") == 0);
    free(out);
    flb_wasm_trace_set(FLB_FALSE);
    CHECK(flb_lib_push(ctx, input_id(ctx, "plain"), plain, sizeof(plain) - 1) == sizeof(plain) - 1);
    sleep(1);
    out = NULL;
    CHECK(flb_wasm_trace_take(&out, &size) == 0);
    CHECK(strcmp(out, "{\"events\":[],\"dropped\":0}") == 0);
    free(out);

    CHECK(flb_stop(ctx) == 0);
    flb_destroy(ctx);

    scenarios();
    puts("WASM routing inspection passed: conditions, topology, record trace, routing types");
    return 0;
}
