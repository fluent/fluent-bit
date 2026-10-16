/* Fluent Bit: native log-policy regression tests, Apache-2.0. */
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_conditionals.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <ctraces/ctraces.h>
#include "flb_tests_internal.h"
#include <cfl/cfl_arena.h>
#include <math.h>
#include "../../plugins/processor_fts/fts.h"

static msgpack_object *field(msgpack_object *map, const char *key)
{
    size_t i;

    if (!map || map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }
    for (i = 0; i < map->via.map.size; i++) {
        if (map->via.map.ptr[i].key.type == MSGPACK_OBJECT_STR &&
            map->via.map.ptr[i].key.via.str.size == strlen(key) &&
            memcmp(map->via.map.ptr[i].key.via.str.ptr, key, strlen(key)) == 0) {
            return &map->via.map.ptr[i].val;
        }
    }
    return NULL;
}

static void run_policy(const char *code, int grouped, const char *error_mode,
                       int expected_records, int expected_groups, int conditional,
                       const char *limit_key, const char *limit)
{
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct flb_log_event_encoder *encoder;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    struct flb_time ts;
    msgpack_object *value;
    void *output = NULL;
    size_t output_size = 0;
    int i;
    int type;
    int records = 0;
    int groups = 0;
    int ret;
    int depth = 0;
    const char *kind;
    const char zero_id[16] = {0};
    msgpack_object empty_map = {.type = MSGPACK_OBJECT_MAP, .via.map = {0, NULL}};
    msgpack_object array_values[2] = {
        {.type = MSGPACK_OBJECT_STR, .via.str = {1, "\xff"}},
        {.type = MSGPACK_OBJECT_STR, .via.str = {2, "ok"}}
    };
    msgpack_object legacy_array = {.type = MSGPACK_OBJECT_ARRAY, .via.array = {2, array_values}};

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    processor = flb_processor_create(config, "lua_policy_test", NULL, 0);
    TEST_ASSERT(processor != NULL);
    unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS, "fts");
    TEST_ASSERT(unit != NULL);
    TEST_CHECK(flb_processor_unit_set_property_str(unit, "code", code) == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(unit, "error_mode", error_mode) == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(unit, "instruction_limit", limit_key ? "1000000" : "10000") == 0);
    if (limit_key) {
        TEST_CHECK(flb_processor_unit_set_property_str(unit, limit_key, limit) == 0);
    }
    if (conditional) {
        unit->condition = flb_condition_create(FLB_COND_OP_AND);
        TEST_ASSERT(unit->condition != NULL);
        TEST_CHECK(flb_condition_add_rule(unit->condition, "$kind", FLB_RULE_OP_EQ,
                                          "selected", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);
    }
    TEST_ASSERT(flb_processor_init(processor) == 0);
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    for (i = 0; i < 6; i++) {
        if (grouped && i % 3 == 0) {
            TEST_CHECK(flb_log_event_encoder_group_init(encoder) == 0);
            if (grouped == 3 || grouped >= 5) {
                ret = flb_log_event_encoder_append_metadata_values(encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("batch"), FLB_LOG_EVENT_CSTRING_VALUE("original"),
                    FLB_LOG_EVENT_CSTRING_VALUE("schema"), FLB_LOG_EVENT_CSTRING_VALUE("otlp"),
                    FLB_LOG_EVENT_CSTRING_VALUE("resource_id"), FLB_LOG_EVENT_INT64_VALUE(INT64_MAX),
                    FLB_LOG_EVENT_CSTRING_VALUE("scope_id"), FLB_LOG_EVENT_INT64_VALUE(INT64_MIN));
            }
            else {
                ret = flb_log_event_encoder_append_metadata_values(encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("batch"), FLB_LOG_EVENT_CSTRING_VALUE("original"),
                    FLB_LOG_EVENT_CSTRING_VALUE("schema"), FLB_LOG_EVENT_BOOLEAN_VALUE(FLB_FALSE));
            }
            TEST_CHECK(ret == 0);
            if (grouped == 5) {
                ret = flb_log_event_encoder_append_metadata_values(encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("duplicate"), FLB_LOG_EVENT_CSTRING_VALUE("one"),
                    FLB_LOG_EVENT_CSTRING_VALUE("duplicate"), FLB_LOG_EVENT_CSTRING_VALUE("two"));
                TEST_CHECK(ret == 0);
            }
            if (grouped == 6) {
                ret = flb_log_event_encoder_append_body_values(encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("empty"),
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&empty_map));
                TEST_CHECK(ret == 0);
            }
            ret = flb_log_event_encoder_append_body_values(encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("producer"), FLB_LOG_EVENT_CSTRING_VALUE("original"));
            TEST_CHECK(ret == 0);
            TEST_CHECK(flb_log_event_encoder_group_header_end(encoder) == 0);
        }
        if (grouped == 10 && i == 1) {
            TEST_CHECK(flb_log_event_encoder_group_init(encoder) == 0);
            ret = flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("batch"), FLB_LOG_EVENT_CSTRING_VALUE("original"),
                FLB_LOG_EVENT_CSTRING_VALUE("schema"), FLB_LOG_EVENT_BOOLEAN_VALUE(FLB_FALSE));
            TEST_CHECK(ret == 0);
            ret = flb_log_event_encoder_append_body_values(encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("producer"), FLB_LOG_EVENT_CSTRING_VALUE("original"));
            TEST_CHECK(ret == 0);
            TEST_CHECK(flb_log_event_encoder_group_header_end(encoder) == 0);
        }
        kind = i % 2 ? "other" : "selected";
        TEST_CHECK(flb_log_event_encoder_begin_record(encoder) == 0);
        flb_time_set(&ts, 1700000000 + i, i);
        TEST_CHECK(flb_log_event_encoder_set_timestamp(encoder, &ts) == 0);
        if (grouped == 3 || grouped >= 5) {
            ret = flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("severity_number"), FLB_LOG_EVENT_INT64_VALUE(30),
                FLB_LOG_EVENT_CSTRING_VALUE("trace_id"), FLB_LOG_EVENT_BINARY_VALUE(zero_id, sizeof(zero_id)));
            TEST_CHECK(ret == 0);
        }
        ret = flb_log_event_encoder_append_body_values(encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("index"), FLB_LOG_EVENT_INT64_VALUE(i),
            FLB_LOG_EVENT_CSTRING_VALUE("kind"),
            FLB_LOG_EVENT_CSTRING_VALUE(kind),
            FLB_LOG_EVENT_CSTRING_VALUE("secret"), FLB_LOG_EVENT_CSTRING_VALUE("one"),
            FLB_LOG_EVENT_CSTRING_VALUE("secret"), FLB_LOG_EVENT_CSTRING_VALUE("two"));
        TEST_CHECK(ret == 0);
        if (grouped == 3 || grouped >= 5) {
            ret = flb_log_event_encoder_append_body_values(encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("legacy_uint"), FLB_LOG_EVENT_UINT64_VALUE(UINT64_MAX));
            TEST_CHECK(ret == 0);
        }
        if (grouped == 9) {
            ret = flb_log_event_encoder_append_body_values(encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("legacy_array"),
                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&legacy_array));
            TEST_CHECK(ret == 0);
        }
        if (grouped == 7) {
            ret = flb_log_event_encoder_append_body_values(encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("duplicate_utf8"), FLB_LOG_EVENT_CSTRING_VALUE("valid"),
                FLB_LOG_EVENT_CSTRING_VALUE("duplicate_utf8"), FLB_LOG_EVENT_STRING_VALUE("\xff", 1));
            TEST_CHECK(ret == 0);
        }
        TEST_CHECK(flb_log_event_encoder_commit_record(encoder) == 0);
        if (grouped && i % 3 == 2 && !(grouped == 2 && i == 5)) {
            TEST_CHECK(flb_log_event_encoder_group_end(encoder) == 0);
            if (grouped == 10 && i == 2) {
                TEST_CHECK(flb_log_event_encoder_group_end(encoder) == 0);
            }
        }
    }
    ret = flb_processor_run(processor, 0, FLB_PROCESSOR_LOGS, "test", 4,
                            encoder->output_buffer, encoder->output_length, &output, &output_size);
    TEST_CHECK(ret == 0);
    if (output_size > 0) {
        TEST_ASSERT(flb_log_event_decoder_init(&decoder, output, output_size) == 0);
        flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);
        while (flb_log_event_decoder_next(&decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
            TEST_CHECK(flb_log_event_decoder_get_record_type(&event, &type) == 0);
            if (type == FLB_LOG_EVENT_GROUP_START) {
                TEST_CHECK(depth == 0);
                depth++;
                groups++;
                value = field(event.metadata, "batch");
                TEST_CHECK(value != NULL && value->type == MSGPACK_OBJECT_STR &&
                           value->via.str.size == 8 && memcmp(value->via.str.ptr, "original", 8) == 0);
                if (grouped == 6) {
                    TEST_CHECK(field(event.body, "empty") == NULL);
                }
                if (grouped == 8) {
                    TEST_CHECK(field(event.body, "resource") == NULL);
                    TEST_CHECK(field(event.body, "scope") == NULL);
                }
                value = field(event.body, "producer");
                TEST_ASSERT(value != NULL);
                if (expected_groups == 6) {
                    TEST_CHECK(value->type == MSGPACK_OBJECT_POSITIVE_INTEGER && value->via.u64 == records);
                }
                else {
                    TEST_CHECK(value->type == MSGPACK_OBJECT_STR && value->via.str.size == 8 &&
                               memcmp(value->via.str.ptr, "original", 8) == 0);
                }
            }
            else if (type == FLB_LOG_EVENT_GROUP_END) {
                TEST_CHECK(depth == 1);
                depth--;
            }
            else {
                TEST_CHECK(depth == !!grouped);
                value = field(event.body, "index");
                TEST_ASSERT(value != NULL && value->type == MSGPACK_OBJECT_POSITIVE_INTEGER);
                if (expected_records == 6) {
                    TEST_CHECK(value->via.u64 == records);
                }
                if (conditional) {
                    TEST_CHECK(value->via.u64 == 2 * records + 1);
                }
                if (strcmp(error_mode, "keep") == 0) {
                    TEST_CHECK(field(event.body, "grow") == NULL);
                    TEST_CHECK(field(event.body, "verified") == NULL);
                    TEST_CHECK(event.body->via.map.size == (grouped == 3 ? 5 : 4));
                }
                if (grouped == 3 || grouped >= 5) {
                    value = field(event.body, "legacy_uint");
                    TEST_ASSERT(value != NULL);
                    TEST_CHECK(value->type == MSGPACK_OBJECT_POSITIVE_INTEGER && value->via.u64 == UINT64_MAX);
                    value = field(event.metadata, "severity_number");
                    TEST_ASSERT(value != NULL);
                    TEST_CHECK(value->via.u64 == 30);
                }
                if (grouped == 8) {
                    value = field(event.metadata, "otlp");
                    TEST_ASSERT(value != NULL && value->type == MSGPACK_OBJECT_MAP);
                    TEST_CHECK(field(value, "attributes") == NULL);
                    TEST_CHECK(field(value, "event_name") != NULL);
                }
                if (grouped == 9) {
                    value = field(event.body, "legacy_array");
                    TEST_ASSERT(value != NULL && value->type == MSGPACK_OBJECT_ARRAY);
                    TEST_ASSERT(value->via.array.size == 3);
                    TEST_CHECK(value->via.array.ptr[0].type == MSGPACK_OBJECT_STR);
                    TEST_CHECK(value->via.array.ptr[0].via.str.size == 3);
                    TEST_CHECK(memcmp(value->via.array.ptr[0].via.str.ptr, "new", 3) == 0);
                    TEST_CHECK(value->via.array.ptr[1].via.str.size == 1);
                    TEST_CHECK((unsigned char) value->via.array.ptr[1].via.str.ptr[0] == 255);
                }
                records++;
                if (field(event.body, "verified")) {
                    TEST_CHECK(field(event.body, "secret") == NULL);
                    TEST_CHECK(event.body->via.map.size == (grouped == 3 ? 4 : 3));
                }
            }
        }
        TEST_CHECK(depth == 0);
        flb_log_event_decoder_destroy(&decoder);
    }
    TEST_CHECK(records == expected_records);
    TEST_CHECK(groups == expected_groups);
    if (output && output != encoder->output_buffer) {
        flb_free(output);
    }
    flb_log_event_encoder_destroy(encoder);
    flb_processor_destroy(processor);
    flb_config_exit(config);
}

static void generic_context_isolation(void)
{
    run_policy("function process(log) "
               "assert(log.resource == nil and log.scope == nil and log.attributes == nil); "
               "assert(log.context.attributes:get_string('producer') == 'original'); "
               "assert(log.context.metadata:get_string('batch') == 'original'); "
               "log.context.attributes:set('producer', log.body:get('index')); "
               "log.body:remove('secret'); log.body:set('verified', true) end",
               1, "drop", 6, 6, 0, NULL, NULL);
}

static void generic_read_does_not_split(void)
{
    run_policy("function process(log) assert(log.context.metadata:get_string('batch') == 'original') end",
               1, "drop", 6, 2, 0, NULL, NULL);
}

static void plain_logs_do_not_gain_context(void)
{
    run_policy("function process(log) assert(log.context == nil and log.resource == nil); "
               "log.body:remove('secret'); log.body:set('verified', true) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void conditional_drop_preserves_groups(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) return fb.DROP end",
               1, "drop", 3, 2, 1, NULL, NULL);
}

static void drop_all_removes_empty_groups(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) return fb.DROP end",
               1, "drop", 0, 0, 0, NULL, NULL);
}

static void duplicate_redaction_canonicalizes(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "fb.redact(log.body, {'secret'}); assert(log.body:len() == 3); "
               "log.body:remove('secret'); log.body:set('verified', true) end",
               1, "drop", 6, 2, 0, NULL, NULL);
}

static void errors_restore_body_and_context(void)
{
    run_policy("function process(log) log.body:remove('secret'); "
               "log.context.attributes:set('producer','partial'); error('failure') end",
               1, "keep", 6, 2, 0, NULL, NULL);
}

static void instruction_exhaustion_drops(void)
{
    run_policy("function process(log) while true do end end",
               1, "drop", 0, 0, 0, NULL, NULL);
}

static void caught_budget_errors_terminate(void)
{
    run_policy("function process(log) while true do pcall(function() while true do end end) end end",
               0, "drop", 0, 0, 0, NULL, NULL);
}

static void vm_memory_exhaustion_drops(void)
{
    run_policy("function process(log) local s=string.rep('x', 2000000); log.body:set('large',s) end",
               1, "drop", 0, 0, 0, "memory_limit", "1M");
}

static void native_memory_exhaustion_drops(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) local a=fb.array(); "
               "for i=1,5000 do a:append(fb.int64(i)) end end",
               1, "drop", 0, 0, 0, "memory_limit", "1M");
}

static void strict_parsing_and_time(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "assert(fb.parse_json('18446744073709551615'):value() == '18446744073709551615'); "
               "assert(fb.parse_json('-9223372036854775808'):value() == '-9223372036854775808'); "
               "assert(not pcall(fb.parse_json, '{\"a\":1,\"a\":2}')); "
               "assert(not pcall(fb.parse_json, '{} garbage')); "
               "assert(not pcall(fb.parse_json, '18446744073709551616')); "
               "assert(fb.parse_time('1970-01-01T01:00:00+01:00').sec == 0); "
               "assert(fb.parse_time('2024-02-29T00:00:00.000000001Z').nsec == 1); "
               "assert(not pcall(fb.parse_time,'2100-02-29T00:00:00Z')) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void output_growth_fails_closed(void)
{
    run_policy("function process(log) log.body:set('grow', string.rep('x',300000)) end",
               1, "drop", 0, 0, 0, "output_limit", "1M");
}

static void output_growth_keep_restores_whole_chunk(void)
{
    run_policy("function process(log) log.body:set('grow', string.rep('x',300000)) end",
               1, "keep", 6, 2, 0, "output_limit", "1M");
}

static void initialization_failures(void)
{
    const char *codes[] = {"while true do end", "function !syntax", "error('init failure')",
                          "function other() end", "require('ffi')", "io.open('/tmp/x')", NULL};
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    int i;

    for (i = 0; codes[i]; i++) {
        config = flb_config_init();
        TEST_ASSERT(config != NULL);
        processor = flb_processor_create(config, "init_failure", NULL, 0);
        TEST_ASSERT(processor != NULL);
        unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS, "fts");
        TEST_ASSERT(unit != NULL);
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "code", codes[i]) == 0);
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "instruction_limit", "10000") == 0);
        TEST_CHECK(flb_processor_init(processor) != 0);
        flb_processor_destroy(processor);
        flb_config_exit(config);
    }
}

static void unclosed_group_preserves_records(void)
{
    run_policy("function process(log) end", 2, "drop", 6, 2, 0, NULL, NULL);
}

static void exact_opaque_context_ids(void)
{
    run_policy("function process(log) "
               "assert(log.context.metadata:get('resource_id'):value() == '9223372036854775807'); "
               "assert(log.context.metadata:get('scope_id'):value() == '-9223372036854775808'); "
               "assert(log.resource and log.scope); "
               "log.body:remove('secret'); log.body:set('verified',true) end",
               3, "drop", 6, 2, 0, NULL, NULL);
}

static void context_replacement_during_collection(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "local replacement=fb.map(); "
               "for _,key in ipairs(log.context.metadata:keys()) do "
               "replacement:set(key,log.context.metadata:get(key)) end; "
               "log.body:remove('secret'); log.context.metadata=replacement; collectgarbage() end",
               1, "keep", 6, 2, 0, NULL, NULL);
    run_policy("local fb=require('fluentbit'); function process(log) "
               "log.body:remove('secret'); log.context.attributes=fb.map(); collectgarbage() end",
               1, "keep", 6, 2, 0, NULL, NULL);
}

static void deep_mutable_views(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) local node=log.body; "
               "for i=1,60 do node=node:ensure_map('child') end; "
               "node:set('value',fb.int64(1)); assert(node:get_number('value')==1); "
               "log.body:remove('child'); log.body:remove('secret'); "
               "log.body:set('verified',true) end",
               1, "drop", 6, 2, 0, NULL, NULL);
}

static void garbage_collector_is_private(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "assert(log.body.__gc == nil and fb.null.__gc == nil) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void trusted_policy_jit_compiles(void)
{
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct flb_processor_instance *instance;
    struct fts_runtime *runtime;
    lua_State *l;
    const char *probe = "return jit.status(), require('jit.util').traceinfo(1)";

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    processor = flb_processor_create(config, "fts_jit_test", NULL, 0);
    TEST_ASSERT(processor != NULL);
    unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS, "fts");
    TEST_ASSERT(unit != NULL);
    TEST_CHECK(flb_processor_unit_set_property_str(unit, "jit", "true") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(unit, "instruction_limit", "0") == 0);
    TEST_CHECK(flb_processor_unit_set_property_str(unit, "code",
               "local sum=0; for j=1,30 do for i=1,100000 do sum=sum+i end end; "
               "function process(log) end") == 0);
    TEST_ASSERT(flb_processor_init(processor) == 0);
    instance = unit->ctx;
    runtime = instance->context;
    l = runtime->vm->state;
    TEST_CHECK(lua_gethookmask(l) == 0);
    TEST_ASSERT(luaL_loadbuffer(l, probe, strlen(probe), "jit_test") == 0);
    lua_rawgeti(l, LUA_REGISTRYINDEX, runtime->helpers_env_ref);
    lua_setfenv(l, -2);
    TEST_ASSERT(lua_pcall(l, 0, 2, 0) == 0);
    TEST_CHECK(lua_toboolean(l, -2));
    TEST_CHECK(lua_istable(l, -1));
    lua_pop(l, 2);
    flb_processor_destroy(processor);
    flb_config_exit(config);
}

static void native_histogram_buckets_are_preserved(void)
{
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct cmt *input;
    struct cmt *output;
    struct cmt_histogram *histogram;
    struct cmt_histogram_buckets *buckets;
    void *result;
    size_t result_size;
    int edit;

    for (edit = 0; edit < 2; edit++) {
        config = flb_config_init();
        TEST_ASSERT(config != NULL);
        processor = flb_processor_create(config, "fts_histogram_test", NULL, 0);
        TEST_ASSERT(processor != NULL);
        unit = flb_processor_unit_create(processor, FLB_PROCESSOR_METRICS, "fts");
        TEST_ASSERT(unit != NULL);
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "code", edit ?
                   "function process(metric) metric.name = 'renamed' end" :
                   "function process(metric) end") == 0);
        TEST_ASSERT(flb_processor_init(processor) == 0);
        input = cmt_create();
        TEST_ASSERT(input != NULL);
        buckets = cmt_histogram_buckets_create(2, 4.0, 7.0);
        TEST_ASSERT(buckets != NULL);
        histogram = cmt_histogram_create(input, "", "", "native", "native", buckets, 0, NULL);
        TEST_ASSERT(histogram != NULL);
        TEST_CHECK(cmt_histogram_observe(histogram, 100, 2.0, 0, NULL) == 0);
        TEST_CHECK(cmt_histogram_observe(histogram, 100, 5.0, 0, NULL) == 0);
        TEST_CHECK(cmt_histogram_observe(histogram, 100, 8.0, 0, NULL) == 0);
        result = NULL;
        result_size = 0;
        TEST_CHECK(flb_processor_run(processor, 0, FLB_PROCESSOR_METRICS, "native", 6,
                                    input, 0, &result, &result_size) == 0);
        output = result;
        TEST_ASSERT(output != NULL);
        TEST_ASSERT(cfl_list_size(&output->histograms) == 1);
        histogram = cfl_list_entry_first(&output->histograms, struct cmt_histogram, _head);
        TEST_CHECK(strcmp(histogram->opts.name, edit ? "renamed" : "native") == 0);
        TEST_CHECK(histogram->map->metric.hist_buckets[0] == 1);
        TEST_CHECK(histogram->map->metric.hist_buckets[1] == 2);
        TEST_CHECK(histogram->map->metric.hist_buckets[2] == 3);
        TEST_CHECK(cmt_metric_hist_get_count_value(&histogram->map->metric) == 3);
        TEST_CHECK(cmt_metric_hist_get_sum_value(&histogram->map->metric) == 15.0);
        if (output != input) {
            cmt_destroy(output);
        }
        cmt_destroy(input);
        flb_processor_destroy(processor);
        flb_config_exit(config);
    }
}

static void native_metric_scalar_preservation(void)
{
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct cmt *input;
    struct cmt *output;
    struct cmt_gauge *gauge;
    struct cmt_gauge *sibling;
    struct cfl_list *head;
    int found;
    void *result;
    size_t result_size;
    int mode;

    for (mode = 0; mode < 4; mode++) {
        config = flb_config_init();
        TEST_ASSERT(config != NULL);
        processor = flb_processor_create(config, "fts_metric_test", NULL, 0);
        TEST_ASSERT(processor != NULL);
        unit = flb_processor_unit_create(processor, FLB_PROCESSOR_METRICS, "fts");
        TEST_ASSERT(unit != NULL);
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "code",
                   "function process(metric) metric.name = 'renamed' end") == 0);
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "error_mode", mode == 2 ? "drop" : "keep") == 0);
        TEST_ASSERT(flb_processor_init(processor) == 0);
        input = cmt_create();
        TEST_ASSERT(input != NULL);
        gauge = cmt_gauge_create(input, "", "", "native", "native", 0, NULL);
        TEST_ASSERT(gauge != NULL);
        gauge->map->metric_static_set = CMT_TRUE;
        if (mode == 0) {
            cmt_metric_set_int64(&gauge->map->metric, 100, INT64_MIN);
        }
        else if (mode == 3) {
            /* uint64 values that fit int64 still run the policy. */
            cmt_metric_set_uint64(&gauge->map->metric, 100, 5);
        }
        else {
            cmt_metric_set_uint64(&gauge->map->metric, 100, UINT64_MAX);
            sibling = cmt_gauge_create(input, "", "", "healthy", "healthy", 0, NULL);
            TEST_ASSERT(sibling != NULL);
            TEST_ASSERT(cmt_gauge_set(sibling, 100, 42, 0, NULL) == 0);
        }
        result = NULL;
        result_size = 0;
        TEST_CHECK(flb_processor_run(processor, 0, FLB_PROCESSOR_METRICS, "native", 6,
                                    input, 0, &result, &result_size) == 0);
        output = result;
        TEST_ASSERT(output != NULL);
        if (mode == 0) {
            gauge = cfl_list_entry_first(&output->gauges, struct cmt_gauge, _head);
            TEST_ASSERT(gauge != NULL);
            TEST_CHECK(strcmp(gauge->opts.name, "renamed") == 0);
            TEST_CHECK(cmt_metric_get_value_type(&gauge->map->metric) == CMT_METRIC_VALUE_INT64);
            TEST_CHECK(cmt_metric_get_int64_value(&gauge->map->metric) == INT64_MIN);
        }
        else if (mode == 3) {
            TEST_CHECK(cfl_list_size(&output->gauges) == 1);
            gauge = cfl_list_entry_first(&output->gauges, struct cmt_gauge, _head);
            TEST_CHECK(strcmp(gauge->opts.name, "renamed") == 0);
            TEST_CHECK(cmt_metric_get_value(&gauge->map->metric) == 5);
        }
        else if (mode == 1) {
            TEST_CHECK(cfl_list_size(&output->gauges) == 2);
            found = 0;
            cfl_list_foreach(head, &output->gauges) {
                sibling = cfl_list_entry(head, struct cmt_gauge, _head);
                if (strcmp(sibling->opts.name, "native") == 0) {
                    found++;
                    TEST_CHECK(cmt_metric_get_value_type(&sibling->map->metric) == CMT_METRIC_VALUE_UINT64);
                    TEST_CHECK(cmt_metric_get_uint64_value(&sibling->map->metric) == UINT64_MAX);
                }
            }
            TEST_CHECK(found == 1);
        }
        else {
            TEST_CHECK(cfl_list_size(&output->gauges) == 1);
        }
        if (mode == 1) {
            /* Kept families are copied: the producer still owns its context. */
            TEST_CHECK(output != input);
            TEST_CHECK(cfl_list_size(&input->gauges) == 2);
        }
        if (mode == 1 || mode == 2) {
            found = 0;
            cfl_list_foreach(head, &output->gauges) {
                sibling = cfl_list_entry(head, struct cmt_gauge, _head);
                if (strcmp(sibling->opts.name, "renamed") == 0) {
                    TEST_CHECK(cmt_metric_get_value(&sibling->map->metric) == 42);
                    found++;
                }
            }
            TEST_CHECK(found == 1);
        }
        if (output != input) {
            cmt_destroy(output);
        }
        cmt_destroy(input);
        flb_processor_destroy(processor);
        flb_config_exit(config);
    }
}

static void untouched_otel_fields_are_preserved(void)
{
    run_policy("function process(log) end", 3, "drop", 6, 2, 0, NULL, NULL);
    run_policy("function process(log) log.body:set('edited', true) end", 3, "drop", 6, 2, 0, NULL, NULL);
}

static void schema_promotion_is_record_local(void)
{
    const char *policy = "function process(log) if log.body:get('index'):number() == 0 then "
                         "log.context.metadata:set('schema', 'otlp') end end";

    run_policy(policy, 1, "keep", 6, 2, 0, NULL, NULL);
    run_policy(policy, 1, "drop", 5, 2, 0, NULL, NULL);
}

static void reserved_timestamps_are_record_errors(void)
{
    run_policy("function process(log) if log.body:get('index'):number() == 0 then "
               "log.timestamp.sec = 4294967294; log.timestamp.nsec = 1 end end",
               0, "keep", 6, 0, 0, NULL, NULL);
    run_policy("function process(log) if log.body:get('index'):number() == 0 then "
               "log.timestamp.sec = 4294967295; log.timestamp.nsec = 0 end end",
               0, "drop", 5, 0, 0, NULL, NULL);
}

static void small_record_batch_uses_wire_budget(void)
{
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct flb_log_event_encoder *encoder;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    struct flb_time timestamp;
    void *output;
    size_t output_size;
    int index;
    int count;
    int ret;

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    processor = flb_processor_create(config, "fts_wire_budget", NULL, 0);
    TEST_ASSERT(processor != NULL);
    unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS, "fts");
    TEST_ASSERT(unit != NULL);
    TEST_CHECK(flb_processor_unit_set_property_str(unit, "code", "function process(log) end") == 0);
    TEST_ASSERT(flb_processor_init(processor) == 0);
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    flb_time_set(&timestamp, 1, 0);
    for (index = 0; index < 75000; index++) {
        TEST_CHECK(flb_log_event_encoder_begin_record(encoder) == 0);
        TEST_CHECK(flb_log_event_encoder_set_timestamp(encoder, &timestamp) == 0);
        ret = flb_log_event_encoder_append_body_values(encoder,
                   FLB_LOG_EVENT_CSTRING_VALUE("value"), FLB_LOG_EVENT_INT64_VALUE(index % 10));
        TEST_CHECK(ret == 0);
        TEST_CHECK(flb_log_event_encoder_commit_record(encoder) == 0);
    }
    output = NULL;
    output_size = 0;
    TEST_CHECK(flb_processor_run(processor, 0, FLB_PROCESSOR_LOGS, "wire", 4,
                                encoder->output_buffer, encoder->output_length, &output, &output_size) == 0);
    TEST_ASSERT(output != NULL);
    TEST_CHECK(output_size < 3 * 1024 * 1024);
    TEST_ASSERT(flb_log_event_decoder_init(&decoder, output, output_size) == 0);
    count = 0;
    while (flb_log_event_decoder_next(&decoder, &event) == FLB_EVENT_DECODER_SUCCESS) { count++; }
    TEST_CHECK(count == 75000);
    flb_log_event_decoder_destroy(&decoder);
    if (output != encoder->output_buffer) { flb_free(output); }
    flb_log_event_encoder_destroy(encoder);
    flb_processor_destroy(processor);
    flb_config_exit(config);
}

static void event_metatable_cannot_bypass_validation(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "local context=log.context; local metadata=log.metadata; local n=0; "
               "rawset(log,'context',nil); setmetatable(log,{__index=function(_,key) "
               "if key=='context' then n=n+1; if n==6 then "
               "local otlp=metadata:ensure_map('otlp'); "
               "otlp:set('severity_number',fb.int64(999)); otlp:set('trace_id',fb.bytes('abc')); "
               "end; return context end end}) end",
               3, "drop", 0, 0, 0, NULL, NULL);
}

static void replaced_and_redacted_values_do_not_accumulate_charges(void)
{
    run_policy("local fb=require('fluentbit'); local shared=fb.map(); "
               "function process(log) for i=1,2000 do "
               "shared:set('secret',true); fb.redact(shared,{'secret'}); "
               "shared:remove('secret') end; "
               "log.body:remove('secret'); log.body:set('verified',true) end",
               0, "drop", 6, 0, 0, "memory_limit", "1M");
}

static int exhaust_or_recover_memory(lua_State *l)
{
    static char payload[300000];
    char small[1024];
    size_t index;

    if (lua_touserdata(l, 1) == NULL) {
        lua_gc(l, LUA_GCSTOP, 0);
        lua_newtable(l);
        for (index = 0; index < 10000; index++) {
            memset(small, 'x', sizeof(small));
            snprintf(small, 32, "%zu", index);
            lua_pushlstring(l, small, sizeof(small));
            lua_rawseti(l, -2, index + 1);
        }
        return luaL_error(l, "expected memory exhaustion");
    }
    memset(payload, 'x', sizeof(payload));
    lua_pushlstring(l, payload, sizeof(payload));
    return 1;
}

static void memory_exhaustion_does_not_poison_later_callbacks(void)
{
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct flb_processor_instance *instance;
    struct fts_runtime *runtime;
    lua_State *l;

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    processor = flb_processor_create(config, "memory_recovery", NULL, 0);
    TEST_ASSERT(processor != NULL);
    unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS, "fts");
    TEST_ASSERT(unit != NULL);
    TEST_ASSERT(flb_processor_unit_set_property_str(unit, "code", "function process(log) end") == 0);
    TEST_ASSERT(flb_processor_unit_set_property_str(unit, "memory_limit", "1M") == 0);
    TEST_ASSERT(flb_processor_init(processor) == 0);
    instance = unit->ctx;
    runtime = instance->context;
    l = runtime->vm->state;
    luaL_unref(l, LUA_REGISTRYINDEX, runtime->callback_ref);
    lua_pushcfunction(l, exhaust_or_recover_memory);
    runtime->callback_ref = luaL_ref(l, LUA_REGISTRYINDEX);
    TEST_CHECK(fts_runtime_call(runtime, NULL, 1) == LUA_ERRMEM);
    lua_settop(l, 0);
    TEST_CHECK(fts_runtime_call(runtime, runtime, 1) == 0);
    TEST_CHECK(lua_objlen(l, -1) == 300000);
    lua_settop(l, 0);
    flb_processor_destroy(processor);
    flb_config_exit(config);
}

static void policies_cannot_stop_automatic_gc(void)
{
    run_policy("function process(log) "
               "assert(not pcall(collectgarbage,'stop')); "
               "log.body:remove('secret'); log.body:set('verified',true) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void duplicate_context_metadata_does_not_split_groups(void)
{
    run_policy("function process(log) end", 5, "drop", 6, 2, 0, NULL, NULL);
}

static void removing_empty_context_field_is_preserved(void)
{
    run_policy("function process(log) log.context.attributes:remove('empty') end",
               6, "drop", 6, 2, 0, NULL, NULL);
}

static void inherited_duplicate_invalid_utf8_is_preserved(void)
{
    run_policy("function process(log) log.body:set('edited',true) end",
               7, "drop", 6, 2, 0, NULL, NULL);
}

static void json_source_limit_allows_large_scalar(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "local text='\"'..string.rep('x',1048574)..'\"'; "
               "assert(#fb.parse_json(text):value() == 1048574) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void documented_depth_is_enforced(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "local text=string.rep('[',65)..string.rep(']',65); "
               "assert(not pcall(fb.parse_json,text)) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void minimum_memory_initializes_all_signals(void)
{
    int signals[] = {FLB_PROCESSOR_LOGS, FLB_PROCESSOR_METRICS, FLB_PROCESSOR_TRACES};
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    size_t index;

    for (index = 0; index < sizeof(signals) / sizeof(signals[0]); index++) {
        config = flb_config_init();
        TEST_ASSERT(config != NULL);
        processor = flb_processor_create(config, "minimum_memory", NULL, 0);
        TEST_ASSERT(processor != NULL);
        unit = flb_processor_unit_create(processor, signals[index], "fts");
        TEST_ASSERT(unit != NULL);
        TEST_ASSERT(flb_processor_unit_set_property_str(unit, "code", "function process(item) end") == 0);
        TEST_ASSERT(flb_processor_unit_set_property_str(unit, "memory_limit", "262144") == 0);
        TEST_CHECK(flb_processor_init(processor) == 0);
        flb_processor_destroy(processor);
        flb_config_exit(config);
    }
}

static void print_is_not_a_host_io_escape(void)
{
    run_policy("function process(log) assert(print==nil) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void json_duplicate_detection_is_byte_exact(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "assert(fb.parse_json([[{\"a\\u0000x\":1,\"a\\u0000y\":2,\"\":true}]]):len()==3); "
               "assert(not pcall(fb.parse_json,[[{\"a\\u0000x\":1,\"a\\u0000x\":2}]])) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void log_edits_do_not_export_empty_read_placeholders(void)
{
    run_policy("function process(log) log.metadata:ensure_map('otlp'):set('event_name','changed') end",
               8, "drop", 6, 2, 0, NULL, NULL);
}

static void mixed_integer_addition_preserves_exact_values(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "local v=fb._fts_add(fb.int64(9007199254740991),fb.uint64(2)); "
               "assert(v:type()=='int64' and v:value()=='9007199254740993'); "
               "v=fb._fts_add(fb.int64('-9223372036854775808'),fb.uint64('18446744073709551615')); "
               "assert(v:type()=='int64' and v:value()=='9223372036854775807'); "
               "v=fb._fts_add(fb.int64('9223372036854775807'),fb.uint64(1)); "
               "assert(v:type()=='uint64' and v:value()=='9223372036854775808'); "
               "assert(not pcall(fb._fts_add,fb.int64(1),fb.uint64('18446744073709551615'))) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void invalid_mutations_do_not_accumulate_charges(void)
{
    run_policy("local fb=require('fluentbit'); local shared=fb.map(); "
               "function process(log) for i=1,5000 do "
               "assert(not pcall(function() shared:set('bad',{}) end)) end; "
               "log.body:remove('secret'); log.body:set('verified',true) end",
               0, "drop", 6, 0, 0, "memory_limit", "1M");
}

static void native_nan_equality_preserves_unchanged_values(void)
{
    struct cfl_variant *left;
    struct cfl_variant *right;

    left = cfl_variant_create_from_double(NAN);
    TEST_ASSERT(left != NULL);
    right = fts_copy_value(left, 0);
    TEST_ASSERT(right != NULL);
    TEST_CHECK(fts_values_equal(left, right, 0));
    cfl_variant_destroy(left);
    cfl_variant_destroy(right);
    left = cfl_variant_create_from_double(-0.0);
    right = cfl_variant_create_from_double(0.0);
    TEST_ASSERT(left != NULL && right != NULL);
    TEST_CHECK(!fts_values_equal(left, right, 0));
    cfl_variant_destroy(left);
    cfl_variant_destroy(right);
}

static void array_insert_preserves_inherited_invalid_value(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "local original=log.body:get('legacy_array'); local result=fb.array(); "
               "result:append('new'); for i=1,original:len() do result:append(original:get(i)) end; "
               "log.body:set('legacy_array',result) end",
               9, "drop", 6, 2, 0, NULL, NULL);
}

static void nested_and_stray_group_markers_preserve_records(void)
{
    run_policy("function process(log) end", 10, "drop", 6, 3, 0, NULL, NULL);
}

static void dropped_spans_remove_empty_resource_groups(void)
{
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct ctrace *input;
    struct ctrace_resource_span *resource;
    struct ctrace_scope_span *scope;
    void *output = NULL;
    size_t output_size = 0;

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    processor = flb_processor_create(config, "empty_traces", NULL, 0);
    TEST_ASSERT(processor != NULL);
    unit = flb_processor_unit_create(processor, FLB_PROCESSOR_TRACES, "fts");
    TEST_ASSERT(unit != NULL);
    TEST_ASSERT(flb_processor_unit_set_property_str(unit, "code",
        "local fb=require('fluentbit'); function process(span) return fb.DROP end") == 0);
    TEST_ASSERT(flb_processor_init(processor) == 0);
    input = ctr_create(NULL);
    TEST_ASSERT(input != NULL);
    resource = ctr_resource_span_create(input);
    TEST_ASSERT(resource != NULL);
    scope = ctr_scope_span_create(resource);
    TEST_ASSERT(scope != NULL);
    TEST_ASSERT(ctr_span_create(input, scope, "dropped", NULL) != NULL);
    TEST_ASSERT(flb_processor_run(processor, 0, FLB_PROCESSOR_TRACES, "test", 4,
                                 input, 0, &output, &output_size) == 0);
    TEST_CHECK(output == input);
    TEST_CHECK(cfl_list_is_empty(&input->span_list));
    TEST_CHECK(cfl_list_is_empty(&input->resource_spans));
    ctr_destroy(input);
    flb_processor_destroy(processor);
    flb_config_exit(config);
}

static void copied_values_preserve_binary_data_and_source_lifetime(void)
{
    struct cfl_kvlist *map;
    struct cfl_variant *source;
    struct cfl_variant *copy;
    struct cfl_kvpair *pair;
    char payload[] = {'a', '\0', '\xff'};

    map = cfl_kvlist_create();
    TEST_ASSERT(map != NULL);
    TEST_ASSERT(cfl_kvlist_insert_s(map, "string", 6,
        cfl_variant_create_from_string_s(payload, sizeof(payload), CFL_TRUE)) == 0);
    TEST_ASSERT(cfl_kvlist_insert_s(map, "bytes", 5,
        cfl_variant_create_from_bytes(payload, sizeof(payload), CFL_TRUE)) == 0);
    TEST_ASSERT(cfl_kvlist_insert_s(map, "empty", 5,
        cfl_variant_create_from_string_s("", 0, CFL_TRUE)) == 0);
    source = cfl_variant_create_from_kvlist(map);
    TEST_ASSERT(source != NULL);
    copy = fts_copy_value(source, 0);
    TEST_ASSERT(copy != NULL);
    memset(payload, 'x', sizeof(payload));
    cfl_variant_destroy(source);
    pair = fts_find_pair(copy, "string", 6);
    TEST_ASSERT(pair != NULL);
    TEST_CHECK(pair->val->type == CFL_VARIANT_STRING);
    TEST_CHECK(cfl_variant_size_get(pair->val) == 3);
    TEST_CHECK(memcmp(pair->val->data.as_string, "a\0\xff", 3) == 0);
    pair = fts_find_pair(copy, "bytes", 5);
    TEST_ASSERT(pair != NULL);
    TEST_CHECK(pair->val->type == CFL_VARIANT_BYTES);
    TEST_CHECK(cfl_variant_size_get(pair->val) == 3);
    TEST_CHECK(memcmp(pair->val->data.as_bytes, "a\0\xff", 3) == 0);
    pair = fts_find_pair(copy, "empty", 5);
    TEST_ASSERT(pair != NULL);
    TEST_CHECK(cfl_variant_size_get(pair->val) == 0);
    cfl_variant_destroy(copy);
}

static void plain_log_fast_path_preserves_root_validation(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "log.metadata=fb.map() end", 0, "drop", 0, 0, 0, NULL, NULL);
    run_policy("function process(log) log.context={} end",
               0, "drop", 0, 0, 0, NULL, NULL);
    run_policy("function process(log) log.context.metadata:set('schema','otlp') end",
               1, "drop", 0, 0, 0, NULL, NULL);
    run_policy("function process(log) log.metadata=nil end",
               0, "keep", 6, 0, 0, NULL, NULL);
}

static void scalar_getters_preserve_types_and_live_paths(void)
{
    run_policy("local fb=require('fluentbit'); function process(log) "
               "local m=fb.map(); m:set('s','a'..string.char(0)..'b'); m:set('b',false); "
               "m:set('i',fb.int64('-9007199254740991')); "
               "m:set('u',fb.uint64('9007199254740991')); m:set('n',fb.null); "
               "assert(m:get_string('s')=='a'..string.char(0)..'b'); "
               "assert(m:get_bool('b')==false and m:get_number('i')==-9007199254740991); "
               "assert(m:get_number('u')==9007199254740991); "
               "assert(m:get_string('missing')==nil and m:get_bool('missing')==nil "
               "and m:get_number('missing')==nil); "
               "for _,k in ipairs({'b','i','n'}) do assert(not pcall(m.get_string,m,k)) end; "
               "assert(not pcall(m.get_bool,m,'s') and not pcall(m.get_number,m,'n')); "
               "m:set('u',fb.uint64('9007199254740992')); "
               "assert(not pcall(m.get_number,m,'u')); "
               "m:set('i',fb.int64('-9007199254740992')); "
               "assert(not pcall(m.get_number,m,'i')); "
               "m:set('bytes',fb.bytes('abc')); assert(not pcall(m.get_string,m,'bytes')); "
               "local a=fb.parse_json('[1,\"s\",true,null]'); "
               "assert(a:get_number(1)==1 and a:get_string(2)=='s' and a:get_bool(3)); "
               "for _,k in ipairs({0,5,1.5,math.huge,'1'}) do "
               "assert(not pcall(a.get_number,a,k)) end; "
               "assert(not pcall(a.get_string,a,4) and not pcall(m.get_string,m,1)); "
               "local child=m:ensure_map('child'); child:set('s','before'); "
               "m:set('child',fb.parse_json('{\"s\":\"after\"}')); "
               "assert(child:get_string('s')=='after'); m:remove('child'); "
               "assert(not pcall(child.get_string,child,'s')); "
               "log.body:remove('secret'); log.body:set('verified',true) end",
               0, "drop", 6, 0, 0, NULL, NULL);
}

static void native_result_arena_does_not_own_lua_snapshots(void)
{
    struct cfl_arena *arena;
    struct cfl_variant *source;
    struct cfl_variant *pooled;
    struct cfl_variant *snapshot;
    struct cfl_kvlist *map;
    struct cfl_array *array;
    char binary[] = {'a', '\0', (char) 0xff};

    arena = cfl_arena_create(4096);
    TEST_ASSERT(arena != NULL);
    map = cfl_kvlist_create();
    array = cfl_array_create(2);
    TEST_ASSERT(map != NULL && array != NULL);
    TEST_ASSERT(cfl_kvlist_insert_bytes(map, "binary", binary, sizeof(binary), CFL_FALSE) == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(map, "duplicate", "first") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(map, "duplicate", "second") == 0);
    TEST_ASSERT(cfl_array_append_uint64(array, UINT64_MAX) == 0);
    TEST_ASSERT(cfl_array_append_int64(array, INT64_MIN) == 0);
    TEST_ASSERT(cfl_kvlist_insert_array(map, "array", array) == 0);
    source = cfl_variant_create_from_kvlist(map);
    TEST_ASSERT(source != NULL);
    pooled = fts_copy_value_in(source, 0, arena);
    TEST_ASSERT(pooled != NULL && pooled->arena == arena);
    TEST_CHECK(fts_values_equal(source, pooled, 0));
    snapshot = fts_copy_value(pooled, 0);
    TEST_ASSERT(snapshot != NULL && snapshot->arena == NULL);
    cfl_variant_destroy(source);
    TEST_CHECK(fts_values_equal(snapshot, pooled, 0));
    cfl_variant_destroy(pooled);
    cfl_arena_destroy(arena);
    TEST_CHECK(cfl_variant_size_get(fts_find_pair(snapshot, "binary", 6)->val) == sizeof(binary));
    TEST_CHECK(memcmp(fts_find_pair(snapshot, "binary", 6)->val->data.as_bytes,
                      binary, sizeof(binary)) == 0);
    TEST_CHECK(snapshot->data.as_kvlist->arena == NULL);
    cfl_variant_destroy(snapshot);
}

/* A policy snapshot fits the minimum VM budget; a second commit tree does not. */
static void edited_record_needs_one_policy_tree(void)
{
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct flb_log_event_encoder *encoder;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    struct flb_time timestamp;
    msgpack_object *value;
    char *payload;
    void *output = NULL;
    size_t output_size = 0;
    int ret;
    const char binary[] = {'a', '\0', (char) 0xff};
    msgpack_object empty_map = {.type = MSGPACK_OBJECT_MAP, .via.map = {0, NULL}};
    msgpack_object empty_array = {.type = MSGPACK_OBJECT_ARRAY, .via.array = {0, NULL}};

    payload = flb_malloc(120000);
    TEST_ASSERT(payload != NULL);
    memset(payload, 'x', 120000);
    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    processor = flb_processor_create(config, "single_snapshot", NULL, 0);
    TEST_ASSERT(processor != NULL);
    unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS, "fts");
    TEST_ASSERT(unit != NULL);
    TEST_ASSERT(flb_processor_unit_set_property_str(unit, "code",
        "function process(log) log.body:set('edited',true) end") == 0);
    TEST_ASSERT(flb_processor_unit_set_property_str(unit, "memory_limit", "262144") == 0);
    TEST_ASSERT(flb_processor_unit_set_property_str(unit, "error_mode", "keep") == 0);
    TEST_ASSERT(flb_processor_init(processor) == 0);
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    TEST_ASSERT(flb_log_event_encoder_begin_record(encoder) == 0);
    flb_time_set(&timestamp, 1700000000, 0);
    TEST_ASSERT(flb_log_event_encoder_set_timestamp(encoder, &timestamp) == 0);
    ret = flb_log_event_encoder_append_body_values(encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("payload"), FLB_LOG_EVENT_STRING_VALUE(payload, 120000),
        FLB_LOG_EVENT_CSTRING_VALUE("binary"), FLB_LOG_EVENT_BINARY_VALUE(binary, sizeof(binary)),
        FLB_LOG_EVENT_CSTRING_VALUE("unsigned"), FLB_LOG_EVENT_UINT64_VALUE(UINT64_MAX),
        FLB_LOG_EVENT_CSTRING_VALUE("signed"), FLB_LOG_EVENT_INT64_VALUE(INT64_MIN),
        FLB_LOG_EVENT_CSTRING_VALUE("zero"), FLB_LOG_EVENT_DOUBLE_VALUE(-0.0),
        FLB_LOG_EVENT_CSTRING_VALUE("null"), FLB_LOG_EVENT_NULL_VALUE(),
        FLB_LOG_EVENT_CSTRING_VALUE("map"), FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&empty_map),
        FLB_LOG_EVENT_CSTRING_VALUE("array"), FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&empty_array));
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(flb_log_event_encoder_commit_record(encoder) == 0);
    TEST_ASSERT(flb_processor_run(processor, 0, FLB_PROCESSOR_LOGS, "test", 4,
        encoder->output_buffer, encoder->output_length, &output, &output_size) == 0);
    TEST_ASSERT(flb_log_event_decoder_init(&decoder, output, output_size) == 0);
    TEST_ASSERT(flb_log_event_decoder_next(&decoder, &event) == 0);
    value = field(event.body, "edited");
    TEST_CHECK(value != NULL && value->type == MSGPACK_OBJECT_BOOLEAN && value->via.boolean);
    value = field(event.body, "payload");
    TEST_CHECK(value != NULL && value->type == MSGPACK_OBJECT_STR && value->via.str.size == 120000);
    value = field(event.body, "binary");
    TEST_ASSERT(value != NULL && value->type == MSGPACK_OBJECT_BIN);
    TEST_CHECK(value->via.bin.size == sizeof(binary));
    TEST_CHECK(memcmp(value->via.bin.ptr, binary, sizeof(binary)) == 0);
    value = field(event.body, "unsigned");
    TEST_CHECK(value != NULL && value->type == MSGPACK_OBJECT_POSITIVE_INTEGER &&
               value->via.u64 == UINT64_MAX);
    value = field(event.body, "signed");
    TEST_CHECK(value != NULL && value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER &&
               value->via.i64 == INT64_MIN);
    value = field(event.body, "zero");
    TEST_CHECK(value != NULL && value->type == MSGPACK_OBJECT_FLOAT64 && signbit(value->via.f64));
    value = field(event.body, "null");
    TEST_CHECK(value != NULL && value->type == MSGPACK_OBJECT_NIL);
    value = field(event.body, "map");
    TEST_CHECK(value != NULL && value->type == MSGPACK_OBJECT_MAP && value->via.map.size == 0);
    value = field(event.body, "array");
    TEST_CHECK(value != NULL && value->type == MSGPACK_OBJECT_ARRAY && value->via.array.size == 0);
    flb_log_event_decoder_destroy(&decoder);
    if (output != encoder->output_buffer) {
        flb_free(output);
    }
    flb_log_event_encoder_destroy(encoder);
    flb_processor_destroy(processor);
    flb_config_exit(config);
    flb_free(payload);
}

static void empty_metadata_is_materialized_independently(void)
{
    run_policy("local previous; function process(log) "
               "if previous then previous:ensure_map('nested'):set('value','late') end; "
               "assert(log.metadata:len()==0); "
               "local set=log.metadata.set; assert(not pcall(set,{},'x',true)); "
               "log.metadata:ensure_map('nested'):set('value','current'); "
               "previous=log.metadata:copy() end", 0, "drop", 6, 0, 0, NULL, NULL);
}

TEST_LIST = {
    {"empty_metadata_cow_isolation", empty_metadata_is_materialized_independently},
    {"edited_record_one_policy_tree", edited_record_needs_one_policy_tree},
    {"native_result_arena_snapshot_lifetime", native_result_arena_does_not_own_lua_snapshots},
    {"scalar_getters_live_paths", scalar_getters_preserve_types_and_live_paths},
    {"copied_values_binary_source_lifetime", copied_values_preserve_binary_data_and_source_lifetime},
    {"plain_log_root_validation", plain_log_fast_path_preserves_root_validation},
    {"drop_spans_removes_empty_groups", dropped_spans_remove_empty_resource_groups},
    {"array_insert_inherited_invalid_value", array_insert_preserves_inherited_invalid_value},
    {"nested_stray_group_markers", nested_and_stray_group_markers_preserve_records},
    {"invalid_mutations_accounting", invalid_mutations_do_not_accumulate_charges},
    {"native_nan_equality", native_nan_equality_preserves_unchanged_values},
    {"mixed_integer_addition_exact", mixed_integer_addition_preserves_exact_values},
    {"log_edit_empty_placeholders", log_edits_do_not_export_empty_read_placeholders},
    {"minimum_memory_all_signals", minimum_memory_initializes_all_signals},
    {"print_host_io_unavailable", print_is_not_a_host_io_escape},
    {"json_duplicate_detection_byte_exact", json_duplicate_detection_is_byte_exact},
    {"duplicate_context_metadata_groups", duplicate_context_metadata_does_not_split_groups},
    {"remove_empty_context_field", removing_empty_context_field_is_preserved},
    {"inherited_duplicate_invalid_utf8", inherited_duplicate_invalid_utf8_is_preserved},
    {"json_source_limit_large_scalar", json_source_limit_allows_large_scalar},
    {"documented_depth_enforced", documented_depth_is_enforced},
    {"replaced_redacted_values_accounting", replaced_and_redacted_values_do_not_accumulate_charges},
    {"memory_exhaustion_callback_recovery", memory_exhaustion_does_not_poison_later_callbacks},
    {"policies_cannot_stop_automatic_gc", policies_cannot_stop_automatic_gc},
    {"event_metatable_cannot_bypass_validation", event_metatable_cannot_bypass_validation},
    {"untouched_otel_fields_are_preserved", untouched_otel_fields_are_preserved},
    {"schema_promotion_is_record_local", schema_promotion_is_record_local},
    {"reserved_timestamps_are_record_errors", reserved_timestamps_are_record_errors},
    {"small_record_batch_uses_wire_budget", small_record_batch_uses_wire_budget},
    {"trusted_policy_jit_compiles", trusted_policy_jit_compiles},
    {"native_histogram_buckets_are_preserved", native_histogram_buckets_are_preserved},
    {"native_metric_scalar_preservation", native_metric_scalar_preservation},
    {"generic_context_isolation", generic_context_isolation},
    {"generic_read_does_not_split", generic_read_does_not_split},
    {"plain_logs_do_not_gain_context", plain_logs_do_not_gain_context},
    {"conditional_drop_preserves_groups", conditional_drop_preserves_groups},
    {"drop_all_removes_empty_groups", drop_all_removes_empty_groups},
    {"duplicate_redaction_canonicalizes", duplicate_redaction_canonicalizes},
    {"errors_restore_body_and_context", errors_restore_body_and_context},
    {"instruction_exhaustion_drops", instruction_exhaustion_drops},
    {"caught_budget_errors_terminate", caught_budget_errors_terminate},
    {"vm_memory_exhaustion_drops", vm_memory_exhaustion_drops},
    {"native_memory_exhaustion_drops", native_memory_exhaustion_drops},
    {"strict_parsing_and_time", strict_parsing_and_time},
    {"output_growth_fails_closed", output_growth_fails_closed},
    {"output_growth_keep_restores_whole_chunk", output_growth_keep_restores_whole_chunk},
    {"initialization_failures", initialization_failures},
    {"unclosed_group_preserves_records", unclosed_group_preserves_records},
    {"exact_opaque_context_ids", exact_opaque_context_ids},
    {"context_replacement_during_collection", context_replacement_during_collection},
    {"deep_mutable_views", deep_mutable_views},
    {"garbage_collector_is_private", garbage_collector_is_private},
    {NULL, NULL}
};
