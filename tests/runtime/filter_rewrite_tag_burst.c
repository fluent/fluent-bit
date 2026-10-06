/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_time.h>
#include <chunkio/cio_utils.h>

#include "flb_tests_runtime.h"
#include "../include/flb_tests_tmpdir.h"
#include "../../plugins/filter_rewrite_tag/rewrite_tag.h"

#define RECORDS 3000
#define EXPANSION 3
#define GROUP_NONE 0
#define GROUP_SINGLE 1
#define GROUP_MIXED 2
#define GROUP_LARGE_RECORD 3
#define EMITTER_BATCH_TARGET (256 * 1024)

struct burst_options {
    int group_mode;
    int keep;
    int chained; /* 0: single rewrite, 1: forward creation order, 2: reverse */
    int pressure;
    int native;
    int filesystem;
    int stop_on_pause;
    int stop_before_collect;
    int shutdown_admission;
    int near_target_record;
};

struct burst_result {
    int received;
    int invalid_records;
    int invalid_groups;
    int last_sequence;
    int order_errors;
    int seen[RECORDS];
    size_t largest_chunk;
};

struct burst_test {
    pthread_mutex_t lock;
    flb_ctx_t *flb;
    struct flb_input_instance *source;
    int stop_on_pause;
    int stop_before_collect;
    int stop_requested;
    int shutdown_admission;
    int shutdown_admission_checked;
    int shutdown_admission_result;
    int near_target_record;
    flb_sds_t data;
    int collector;
    int sent;
    int append_result;
    int group_mode;
    struct burst_result emitted;
    struct burst_result retained;
    int pauses;
    int resumes;
    int paused_with_pending;
};

struct burst_output {
    struct burst_test *test;
    struct burst_result *result;
};

static int expected_group(struct burst_test *test, int sequence)
{
    if (test->group_mode == GROUP_SINGLE || test->group_mode == GROUP_LARGE_RECORD) {
        return 1;
    }
    if (test->group_mode == GROUP_MIXED) {
        if (sequence < RECORDS / 3) {
            return 1;
        }
        if (sequence >= 2 * RECORDS / 3) {
            return 2;
        }
    }
    return 0;
}

static size_t payload_size(struct burst_test *test, int sequence)
{
    if (test->near_target_record && sequence == 0) {
        return FLB_INPUT_CHUNK_FS_MAX_SIZE - 4096;
    }
    if (test->group_mode == GROUP_LARGE_RECORD && sequence == RECORDS / 2) {
        return FLB_INPUT_CHUNK_FS_MAX_SIZE + 4096;
    }
    /* Small records after rollover must not backfill an older buffer. */
    return sequence % 101 == 0 ? 16 : 4096;
}

static void make_burst(struct burst_test *test)
{
    struct flb_log_event_encoder *encoder;
    struct flb_time timestamp;
    char *payload;
    size_t capacity;
    int sequence;
    int group;
    int ret;
    int active_group = 0;

    capacity = test->group_mode == GROUP_LARGE_RECORD || test->near_target_record ?
               FLB_INPUT_CHUNK_FS_MAX_SIZE + 4096 : 4096;
    payload = flb_malloc(capacity);
    TEST_ASSERT(payload != NULL);
    memset(payload, 'x', capacity);
    flb_time_set(&timestamp, 1700000000, 123456789);
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    for (sequence = 0; sequence < RECORDS; sequence++) {
        group = expected_group(test, sequence);
        if (group != active_group) {
            if (active_group) {
                TEST_ASSERT(flb_log_event_encoder_group_end(encoder) == 0);
            }
            if (group) {
                TEST_ASSERT(flb_log_event_encoder_group_init(encoder) == 0);
                ret = flb_log_event_encoder_append_metadata_values(encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("group"),
                            FLB_LOG_EVENT_INT32_VALUE(group));
                TEST_ASSERT(ret == 0);
                ret = flb_log_event_encoder_append_body_values(encoder,
                            FLB_LOG_EVENT_CSTRING_VALUE("resource"),
                            FLB_LOG_EVENT_INT32_VALUE(group));
                TEST_ASSERT(ret == 0);
                TEST_ASSERT(flb_log_event_encoder_group_header_end(encoder) == 0);
            }
            active_group = group;
        }
        TEST_ASSERT(flb_log_event_encoder_begin_record(encoder) == 0);
        TEST_ASSERT(flb_log_event_encoder_set_timestamp(encoder, &timestamp) == 0);
        ret = flb_log_event_encoder_append_body_values(encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("key"),
                    FLB_LOG_EVENT_CSTRING_VALUE("rewrite"),
                    FLB_LOG_EVENT_CSTRING_VALUE("sequence"),
                    FLB_LOG_EVENT_INT32_VALUE(sequence),
                    FLB_LOG_EVENT_CSTRING_VALUE("payload"),
                    FLB_LOG_EVENT_STRING_VALUE(payload, payload_size(test, sequence)));
        TEST_ASSERT(ret == 0);
        TEST_ASSERT(flb_log_event_encoder_commit_record(encoder) == 0);
    }
    if (active_group) {
        TEST_ASSERT(flb_log_event_encoder_group_end(encoder) == 0);
    }
    test->data = flb_sds_create_len(encoder->output_buffer, encoder->output_length);
    TEST_ASSERT(test->data != NULL);
    flb_log_event_encoder_destroy(encoder);
    flb_free(payload);
}

/* Submit a complete burst in one real collector invocation. This fixture does
 * not depend on the optional dummy plugin or on how lib input reads a pipe. */
static int collect_burst(struct flb_input_instance *in, struct flb_config *config, void *data)
{
    struct burst_test *test = data;
    struct flb_input_instance *emitter;
    struct flb_input_collector *collector;
    struct mk_list *head;
    struct mk_list *collector_head;

    if (test->sent) {
        return 0;
    }
    test->sent = FLB_TRUE;
    if (test->stop_before_collect) {
        /* Hold the real collectors until shutdown, independent of timer order. */
        mk_list_foreach(head, &config->inputs) {
            emitter = mk_list_entry(head, struct flb_input_instance, _head);
            if (strcmp(emitter->p->name, "emitter") != 0) {
                continue;
            }
            mk_list_foreach(collector_head, &emitter->collectors) {
                collector = mk_list_entry(collector_head, struct flb_input_collector, _head);
                TEST_ASSERT(flb_input_collector_pause(collector->id, emitter) == 0);
            }
        }
    }
    test->append_result = flb_input_log_append(in, "rewrite", 7,
                                              test->data, flb_sds_len(test->data));
    if (test->stop_before_collect) {
        TEST_ASSERT(flb_engine_exit(config) >= 0);
    }
    return test->append_result;
}

static int source_init(struct flb_input_instance *in, struct flb_config *config, void *data)
{
    struct burst_test *test = data;

    test->source = in;
    flb_input_set_context(in, test);
    test->collector = flb_input_set_collector_time(in, collect_burst, 0, 10000000, config);
    return test->collector < 0 ? -1 : 0;
}

static void source_pause(void *data, struct flb_config *config)
{
    struct burst_test *test = data;
    struct flb_input_instance *in;
    struct flb_input_instance *emitter = NULL;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    struct mk_list *head;
    size_t limit;

    flb_input_collector_pause(test->collector, test->source);
    pthread_mutex_lock(&test->lock);
    test->pauses++;
    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        if (strcmp(flb_input_name(in), "burst_emitter") == 0) {
            emitter = in;
            if (in->mem_chunks_size > 0 &&
                in->mem_chunks_size < EXPANSION * flb_sds_len(test->data)) {
                test->paused_with_pending = FLB_TRUE;
            }
        }
    }
    pthread_mutex_unlock(&test->lock);

    if (test->shutdown_admission && !test->shutdown_admission_checked &&
        config->is_shutting_down == FLB_TRUE) {
        /* Existing pending buffers must drain, but an ordinary emitter must
         * still reject new records once its memory budget is exhausted. */
        test->shutdown_admission_checked = FLB_TRUE;
        TEST_ASSERT(emitter != NULL);
        TEST_ASSERT(flb_log_event_decoder_init(&decoder, test->data,
                                              flb_sds_len(test->data)) == 0);
        TEST_ASSERT(flb_log_event_decoder_next(&decoder, &event) == 0);
        limit = emitter->mem_buf_limit;
        emitter->mem_buf_limit = 1;
        test->shutdown_admission_result = in_emitter_add_record("updated", 7,
                                    decoder.record_base, decoder.record_length,
                                    emitter, test->source);
        emitter->mem_buf_limit = limit;
        flb_log_event_decoder_destroy(&decoder);
    }
    if (test->stop_on_pause && !test->stop_requested && !config->is_shutting_down) {
        test->stop_requested = FLB_TRUE;
        TEST_ASSERT(flb_engine_exit(config) >= 0);
    }
}

static void source_resume(void *data, struct flb_config *config)
{
    struct burst_test *test = data;

    flb_input_collector_resume(test->collector, test->source);
    pthread_mutex_lock(&test->lock);
    test->resumes++;
    pthread_mutex_unlock(&test->lock);
}

static struct flb_input_plugin burst_source = {
    .name = "rollover_test_source",
    .description = "Collector-driven rollover regression source",
    .cb_init = source_init,
    .cb_pause = source_pause,
    .cb_resume = source_resume
};

/* Expand records after emitter admission so the real engine memory limit pauses
 * the collector mid-drain. No pause flags or accounting counters are mocked. */
static int expand_records(const void *data, size_t size, const char *tag, int tag_len,
                          void **out_buf, size_t *out_size,
                          struct flb_filter_instance *filter,
                          struct flb_input_instance *in, void *context,
                          struct flb_config *config)
{
    struct flb_log_event_decoder decoder;
    struct flb_log_event_encoder encoder;
    struct flb_log_event event;
    int copy;

    TEST_ASSERT(flb_log_event_decoder_init(&decoder, (char *) data, size) == 0);
    TEST_ASSERT(flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_DEFAULT) == 0);
    while (flb_log_event_decoder_next(&decoder, &event) == 0) {
        for (copy = 0; copy < EXPANSION; copy++) {
            TEST_ASSERT(flb_log_event_encoder_emit_raw_record(&encoder,
                        decoder.record_base, decoder.record_length) == 0);
        }
    }
    TEST_CHECK(flb_log_event_decoder_get_last_result(&decoder) == 0);
    flb_log_event_decoder_destroy(&decoder);
    *out_buf = encoder.output_buffer;
    *out_size = encoder.output_length;
    flb_log_event_encoder_claim_internal_buffer_ownership(&encoder);
    flb_log_event_encoder_destroy(&encoder);
    return FLB_FILTER_MODIFIED;
}

static struct flb_filter_plugin expansion_filter = {
    .name = "rollover_test_expand",
    .description = "Post-emitter expansion for real memory pressure",
    .cb_filter = expand_records
};

static msgpack_object *map_value(msgpack_object *map, const char *key)
{
    msgpack_object_kv *entry;
    size_t index;
    size_t length = strlen(key);

    if (!map || map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }
    for (index = 0; index < map->via.map.size; index++) {
        entry = &map->via.map.ptr[index];
        if (entry->key.type == MSGPACK_OBJECT_STR &&
            entry->key.via.str.size == length &&
            memcmp(entry->key.via.str.ptr, key, length) == 0) {
            return &entry->val;
        }
    }
    return NULL;
}

static int map_integer(msgpack_object *map, const char *key)
{
    msgpack_object *value = map_value(map, key);

    if (value && value->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        return (int) value->via.u64;
    }
    return -1;
}

/* Chunk mode lends the real engine buffer. Decode each chunk independently,
 * checking both inherited group fields as well as delivery and ordering. */
static int capture_burst(void *data, size_t size, void *context)
{
    struct burst_output *output = context;
    struct burst_test *test = output->test;
    struct burst_result *result = output->result;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    msgpack_object *payload;
    size_t index;
    int sequence;
    int group;

    TEST_ASSERT(flb_log_event_decoder_init(&decoder, data, size) == 0);
    pthread_mutex_lock(&test->lock);
    if (size > result->largest_chunk) {
        result->largest_chunk = size;
    }
    while (flb_log_event_decoder_next(&decoder, &event) == 0) {
        result->received++;
        sequence = map_integer(event.body, "sequence");
        if (sequence < 0 || sequence >= RECORDS) {
            result->invalid_records++;
            continue;
        }
        result->seen[sequence]++;
        payload = map_value(event.body, "payload");
        if (!payload || payload->type != MSGPACK_OBJECT_STR ||
            payload->via.str.size != payload_size(test, sequence) ||
            event.timestamp.tm.tv_sec != 1700000000 || event.timestamp.tm.tv_nsec != 123456789) {
            result->invalid_records++;
        }
        else {
            for (index = 0; index < payload->via.str.size; index++) {
                if (payload->via.str.ptr[index] != 'x') {
                    result->invalid_records++;
                    break;
                }
            }
        }
        if (sequence < result->last_sequence) {
            result->order_errors++;
        }
        result->last_sequence = sequence;
        group = expected_group(test, sequence);
        if (group) {
            if (map_integer(event.group_metadata, "group") != group ||
                map_integer(event.group_attributes, "resource") != group) {
                result->invalid_groups++;
            }
        }
        else if (event.group_metadata || event.group_attributes) {
            result->invalid_groups++;
        }
    }
    if (flb_log_event_decoder_get_last_result(&decoder) != 0) {
        result->invalid_records++;
    }
    pthread_mutex_unlock(&test->lock);
    flb_log_event_decoder_destroy(&decoder);
    return 0;
}

static void check_result(struct burst_result *result, int copies, const char *name)
{
    int sequence;

    TEST_CHECK(result->received == RECORDS * copies);
    TEST_MSG("%s: received %d records, expected %d", name, result->received, RECORDS * copies);
    TEST_CHECK(result->invalid_records == 0);
    TEST_CHECK(result->invalid_groups == 0);
    TEST_MSG("%s: records with wrong group context: %d", name, result->invalid_groups);
    TEST_CHECK(result->order_errors == 0);
    for (sequence = 0; sequence < RECORDS; sequence++) {
        TEST_CHECK(result->seen[sequence] == copies);
    }
}

/* Native finalization normalizes group markers before re-encoding. A no-op
 * here catches framing defects that a direct decoder alone would tolerate. */
static int process_records(struct flb_processor_instance *ins, void *data,
                           const char *tag, int tag_len)
{
    struct flb_mp_chunk_cobj *chunk = data;
    struct flb_mp_chunk_record *record;

    while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
    }
    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_processor_plugin native_processor = {
    .name = "rollover_test_native",
    .description = "Native processor framing regression",
    .cb_process_logs = process_records
};

static int add_rewrite(flb_ctx_t *flb, const char *match, const char *rule,
                       const char *name, const char *limit)
{
    int filter;

    filter = flb_filter(flb, "rewrite_tag", NULL);
    TEST_ASSERT(filter >= 0);
    TEST_ASSERT(flb_filter_set(flb, filter, "Match", match, "Rule", rule,
                              "Emitter_Name", name, "Emitter_Mem_Buf_Limit", limit, NULL) == 0);
    return filter;
}

static void run_burst(const struct burst_options *options)
{
    struct burst_test test = {0};
    struct burst_output emitted = { .test = &test, .result = &test.emitted };
    struct burst_output retained = { .test = &test, .result = &test.retained };
    struct flb_input_plugin *source;
    struct flb_filter_plugin *expander;
    struct flb_processor_plugin *native;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct flb_lib_out_cb output;
    struct flb_lib_out_cb original = { .cb = capture_burst, .data = &retained };
    const char *rule;
    char *storage_path = NULL;
    size_t chunk_limit = FLB_INPUT_CHUNK_FS_MAX_SIZE + EMITTER_BATCH_TARGET;
    int input;
    int filter;
    int last_filter = -1;
    int sink;
    int received;
    int original_received;
    int pauses;
    int resumes;
    int pending;
    int attempt;
    int copies = options->pressure ? EXPANSION : 1;
    int original_copies = options->keep ? 1 : 0;

    pthread_mutex_init(&test.lock, NULL);
    test.emitted.last_sequence = -1;
    test.retained.last_sequence = -1;
    test.group_mode = options->group_mode;
    test.stop_on_pause = options->stop_on_pause;
    test.stop_before_collect = options->stop_before_collect;
    test.shutdown_admission = options->shutdown_admission;
    test.near_target_record = options->near_target_record;
    make_burst(&test);
    test.flb = flb_create();
    TEST_ASSERT(test.flb != NULL);
    source = flb_malloc(sizeof(*source));
    TEST_ASSERT(source != NULL);
    *source = burst_source;
    mk_list_add(&source->_head, &test.flb->config->in_plugins);
    TEST_ASSERT(flb_service_set(test.flb, "Flush", "0.2", "Grace", "5",
                                "Log_Level", "error", NULL) == 0);
    input = flb_input(test.flb, source->name, &test);
    TEST_ASSERT(input >= 0);
    if (options->chained == 2) {
        last_filter = add_rewrite(test.flb, "intermediate", "$key . updated false",
                                  "burst_emitter", options->pressure ? "16M" : "64M");
    }
    if (options->chained) {
        rule = options->keep ? "$key . intermediate true" : "$key . intermediate false";
    }
    else {
        rule = options->keep ? "$key . updated true" : "$key . updated false";
    }
    filter = add_rewrite(test.flb, "rewrite", rule,
                         options->chained ? "first_emitter" : "burst_emitter",
                         options->pressure && !options->chained ? "16M" : "64M");
    if (options->chained == 1) {
        last_filter = add_rewrite(test.flb, "intermediate", "$key . updated false",
                                  "burst_emitter", options->pressure ? "16M" : "64M");
    }
    else if (!options->chained) {
        last_filter = filter;
    }
    if (options->filesystem) {
        storage_path = flb_test_tmpdir_cat("/flb-emitter-rollover-XXXXXX");
        TEST_ASSERT(storage_path != NULL);
        TEST_ASSERT(mkdtemp(storage_path) != NULL);
        TEST_ASSERT(flb_service_set(test.flb, "storage.path", storage_path,
                                   "storage.max_chunks_up", "1", NULL) == 0);
        TEST_ASSERT(flb_filter_set(test.flb, last_filter,
                                  "Emitter_Storage.type", "filesystem", NULL) == 0);
    }
    if (options->pressure) {
        expander = flb_malloc(sizeof(*expander));
        TEST_ASSERT(expander != NULL);
        *expander = expansion_filter;
        mk_list_add(&expander->_head, &test.flb->config->filter_plugins);
        filter = flb_filter(test.flb, expander->name, NULL);
        TEST_ASSERT(filter >= 0);
        TEST_ASSERT(flb_filter_set(test.flb, filter, "Match", "updated", NULL) == 0);
    }
    output.cb = capture_burst;
    output.data = &emitted;
    sink = flb_output(test.flb, "lib", &output);
    TEST_ASSERT(sink >= 0);
    TEST_ASSERT(flb_output_set(test.flb, sink, "Match", "updated", "data_mode", "chunk",
                               "workers", "0", NULL) == 0);
    if (options->native) {
        native = flb_malloc(sizeof(*native));
        TEST_ASSERT(native != NULL);
        *native = native_processor;
        mk_list_add(&native->_head, &test.flb->config->processor_plugins);
        processor = flb_processor_create(test.flb->config, "rollover", NULL, 0);
        TEST_ASSERT(processor != NULL);
        unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS, native->name);
        TEST_ASSERT(unit != NULL);
        TEST_ASSERT(flb_output_set_processor(test.flb, sink, processor) == 0);
    }
    /* Check originals independently; source chunks are not emitter batches. */
    sink = flb_output(test.flb, "lib", &original);
    TEST_ASSERT(sink >= 0);
    TEST_ASSERT(flb_output_set(test.flb, sink, "Match", "rewrite", "data_mode", "chunk",
                              "workers", "0", NULL) == 0);
    TEST_ASSERT(flb_start(test.flb) == 0);
    for (attempt = 0; attempt < 300; attempt++) {
        flb_time_msleep(100);
        pthread_mutex_lock(&test.lock);
        received = test.emitted.received;
        original_received = test.retained.received;
        pauses = test.pauses;
        resumes = test.resumes;
        pending = test.paused_with_pending;
        pthread_mutex_unlock(&test.lock);
        if (received >= RECORDS * copies && original_received >= RECORDS * original_copies) {
            break;
        }
    }
    flb_stop(test.flb);
    flb_destroy(test.flb);

    TEST_CHECK(test.append_result == 0);
    check_result(&test.emitted, copies, "emitted");
    check_result(&test.retained, original_copies, "retained");
    if (options->stop_on_pause) {
        TEST_CHECK(test.stop_requested == FLB_TRUE);
        TEST_CHECK(pauses > 0);
    }
    if (options->shutdown_admission) {
        TEST_CHECK(test.shutdown_admission_checked == FLB_TRUE);
        TEST_CHECK(test.shutdown_admission_result < 0);
    }
    if (options->pressure) {
        TEST_CHECK(pending == FLB_TRUE);
        if (!options->stop_on_pause && !options->stop_before_collect) {
            /* These observations precede shutdown's own pause notifications. */
            TEST_CHECK(pauses > 0);
            TEST_CHECK(resumes > 0);
        }
    }
    else if (!options->native) {
        if (options->group_mode == GROUP_LARGE_RECORD) {
            /* The oversized record is larger than the core target, but its
             * complete envelope is smaller than target + batch size. */
            chunk_limit += FLB_INPUT_CHUNK_FS_MAX_SIZE;
        }
        TEST_CHECK(test.emitted.largest_chunk <= chunk_limit);
        TEST_MSG("largest chunk: %zu bytes", test.emitted.largest_chunk);
        if (options->near_target_record) {
            TEST_CHECK(test.emitted.largest_chunk > FLB_INPUT_CHUNK_FS_MAX_SIZE);
        }
    }
    if (storage_path) {
        cio_utils_recursive_delete(storage_path);
        flb_free(storage_path);
    }
    flb_sds_destroy(test.data);
    pthread_mutex_destroy(&test.lock);
}

static void flb_test_chained_emitter_burst(void)
{
    run_burst(&(struct burst_options) { .chained = 1 });
}

static void flb_test_keep_original_burst(void)
{
    run_burst(&(struct burst_options) { .group_mode = GROUP_MIXED, .keep = 1 });
}

static void flb_test_chained_group_transitions(void)
{
    run_burst(&(struct burst_options) { .group_mode = GROUP_MIXED, .chained = 1 });
}

static void flb_test_native_group_transitions(void)
{
    run_burst(&(struct burst_options) { .group_mode = GROUP_MIXED, .chained = 1, .native = 1 });
}

static void flb_test_real_memory_pause_resume(void)
{
    run_burst(&(struct burst_options) { .pressure = 1 });
}

static void flb_test_grouped_oversized_record(void)
{
    run_burst(&(struct burst_options) { .group_mode = GROUP_LARGE_RECORD });
}

static void flb_test_partially_filled_core_chunk(void)
{
    run_burst(&(struct burst_options) { .group_mode = GROUP_SINGLE, .near_target_record = 1 });
}

static void flb_test_shutdown_memory_pressure(void)
{
    run_burst(&(struct burst_options) { .pressure = 1, .stop_on_pause = 1 });
}

static void flb_test_shutdown_chained_memory_pressure(void)
{
    run_burst(&(struct burst_options) { .chained = 2, .pressure = 1, .stop_on_pause = 1 });
}

static void flb_test_shutdown_chained_pending(void)
{
    run_burst(&(struct burst_options) { .chained = 1, .stop_before_collect = 1 });
}

static void flb_test_shutdown_reverse_chained_pending(void)
{
    run_burst(&(struct burst_options) { .chained = 2, .stop_before_collect = 1 });
}

static void flb_test_shutdown_late_chained_memory_pressure(void)
{
    run_burst(&(struct burst_options) { .chained = 2, .pressure = 1,
                                         .stop_before_collect = 1 });
}

static void flb_test_shutdown_new_record_admission(void)
{
    run_burst(&(struct burst_options) { .stop_before_collect = 1,
                                         .shutdown_admission = 1 });
}

#ifdef FLB_HAVE_IN_STORAGE_BACKLOG
static void flb_test_shutdown_filesystem_pressure(void)
{
    run_burst(&(struct burst_options) { .filesystem = 1, .stop_on_pause = 1 });
}

static void flb_test_shutdown_late_chained_filesystem_pressure(void)
{
    run_burst(&(struct burst_options) { .chained = 2, .filesystem = 1,
                                         .stop_before_collect = 1 });
}
#endif

TEST_LIST = {
    {"chained_emitter_burst", flb_test_chained_emitter_burst},
    {"keep_original_burst", flb_test_keep_original_burst},
    {"chained_group_transitions", flb_test_chained_group_transitions},
    {"native_group_transitions", flb_test_native_group_transitions},
    {"real_memory_pause_resume", flb_test_real_memory_pause_resume},
    {"grouped_oversized_record", flb_test_grouped_oversized_record},
    {"partially_filled_core_chunk", flb_test_partially_filled_core_chunk},
    {"shutdown_memory_pressure", flb_test_shutdown_memory_pressure},
    {"shutdown_chained_memory_pressure", flb_test_shutdown_chained_memory_pressure},
    {"shutdown_chained_pending", flb_test_shutdown_chained_pending},
    {"shutdown_reverse_chained_pending", flb_test_shutdown_reverse_chained_pending},
    {"shutdown_late_chained_memory_pressure", flb_test_shutdown_late_chained_memory_pressure},
    {"shutdown_new_record_admission", flb_test_shutdown_new_record_admission},
#ifdef FLB_HAVE_IN_STORAGE_BACKLOG
    {"shutdown_filesystem_pressure", flb_test_shutdown_filesystem_pressure},
    {"shutdown_late_chained_filesystem_pressure",
     flb_test_shutdown_late_chained_filesystem_pressure},
#endif
    {NULL, NULL}
};
