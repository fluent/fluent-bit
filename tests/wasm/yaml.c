/* SPDX-License-Identifier: Apache-2.0 */

#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_counter.h>
#include <ctraces/ctr_decode_msgpack.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "YAML check failed at %d: %s\n", __LINE__, #condition); abort(); \
} } while (0)

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int logs;
static int metrics;
static int traces;

static int capture_init(struct flb_output_instance *instance, struct flb_config *config, void *data)
{
    return 0;
}

static void capture(struct flb_event_chunk *chunk, struct flb_output_flush *flush,
                     struct flb_input_instance *input, void *context, struct flb_config *config)
{
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    struct cmt *cmt;
    struct cmt_counter *counter;
    struct cfl_list *head;
    struct ctrace *trace;
    cfl_sds_t text;
    size_t offset = 0;

    pthread_mutex_lock(&lock);
    if (chunk->type == FLB_EVENT_TYPE_LOGS) {
        CHECK(flb_log_event_decoder_init(&decoder, chunk->data, chunk->size) == 0);
        while (flb_log_event_decoder_next(&decoder, &event) == 0) {
            text = flb_msgpack_to_json_str(1024, event.body, FLB_TRUE);
            CHECK(text != NULL);
            CHECK(strstr(text, "\"wasm\":\"browser\"") != NULL);
            CHECK(strstr(text, "\"keep\":\"yes\"") != NULL);
            CHECK(strstr(text, "\"keep\":\"no\"") == NULL);
            flb_free(text);
            logs++;
        }
        flb_log_event_decoder_destroy(&decoder);
    }
    else if (chunk->type == FLB_EVENT_TYPE_METRICS) {
        while (offset < chunk->size) {
            CHECK(cmt_decode_msgpack_create(&cmt, chunk->data, chunk->size, &offset) == 0);
            CHECK(!cfl_list_is_empty(&cmt->counters));
            cfl_list_foreach(head, &cmt->counters) {
                counter = cfl_list_entry(head, struct cmt_counter, _head);
                CHECK(counter->aggregation_type == CMT_AGGREGATION_TYPE_DELTA);
            }
            text = cmt_encode_text_create(cmt);
            CHECK(text != NULL);
            CHECK(strstr(text, "runtime=\"browser\"") != NULL);
            CHECK(strstr(text, "k8s_network_load_histogram") == NULL);
            cmt_encode_text_destroy(text);
            cmt_destroy(cmt);
            metrics++;
        }
    }
    else if (chunk->type == FLB_EVENT_TYPE_TRACES) {
        while (offset < chunk->size) {
            CHECK(ctr_decode_msgpack_create(&trace, chunk->data, chunk->size, &offset) == 0);
            CHECK(!cfl_list_is_empty(&trace->span_list));
            ctr_destroy(trace);
            traces++;
        }
    }
    pthread_mutex_unlock(&lock);
    FLB_OUTPUT_RETURN(FLB_OK);
}

int main(void)
{
    const char input[] = "[0,{\"keep\":\"yes\"}][0,{\"keep\":\"no\"}]";
    struct flb_output_plugin *output;
    struct flb_input_instance *instance;
    struct mk_list *head;
    flb_ctx_t *ctx;
    FILE *file;
    int attempt;
    int done = 0;
    int input_id = -1;

    ctx = flb_create();
    CHECK(ctx != NULL);
    file = fopen("/tmp/invalid.yaml", "w");
    CHECK(file != NULL);
    CHECK(fputs("pipeline: [\n", file) >= 0);
    CHECK(fclose(file) == 0);
    CHECK(flb_lib_config_file(ctx, "/tmp/invalid.yaml") == -1);
    CHECK(unlink("/tmp/invalid.yaml") == 0);
    flb_destroy(ctx);

    ctx = flb_create();
    CHECK(ctx != NULL);
    output = flb_calloc(1, sizeof(*output));
    CHECK(output != NULL);
    output->name = "wasm_capture";
    output->description = "Browser test signal capture";
    output->event_type = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS | FLB_OUTPUT_TRACES;
    output->cb_init = capture_init;
    output->cb_flush = capture;
    mk_list_add(&output->_head, &ctx->config->out_plugins);
    CHECK(flb_lib_config_file(ctx, "/wasm-tests/processors.yaml") == 0);
    CHECK(flb_start(ctx) == 0);
    mk_list_foreach(head, &ctx->config->inputs) {
        instance = mk_list_entry(head, struct flb_input_instance, _head);
        if (strcmp(instance->p->name, "lib") == 0) {
            input_id = instance->id;
        }
    }
    CHECK(input_id >= 0);
    CHECK(flb_lib_push(ctx, input_id, input, sizeof(input) - 1) == sizeof(input) - 1);
    for (attempt = 0; attempt < 1000; attempt++) {
        pthread_mutex_lock(&lock);
        done = logs == 1 && metrics > 0 && traces > 0;
        pthread_mutex_unlock(&lock);
        if (done) {
            break;
        }
        usleep(10000);
    }
    if (!done) {
        fprintf(stderr, "Captured logs=%d metrics=%d traces=%d\n", logs, metrics, traces);
    }
    CHECK(done);
    CHECK(flb_stop(ctx) == 0);
    flb_destroy(ctx);
    CHECK(logs == 1);
    puts("WASM YAML passed: filesystem chunks, seven processors, logs/metrics/traces");
    return 0;
}
