/* SPDX-License-Identifier: Apache-2.0 */
/* The public SDK submits owned messages; only this pthread owns the engine. */
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_metric.h>
#include <fluent-bit/flb_input_trace.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/wasm/flb_wasm_inspect.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <ctraces/ctraces.h>
#include <emscripten.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SDK_START 1
#define SDK_STOP 2
#define SDK_PUSH 3
#define SDK_DESTROY 4
#define SDK_DRAIN 5
/* Inspection: report what the engine decides. 'grace' carries the argument. */
#define SDK_EVALUATE 6
#define SDK_TOPOLOGY 7
#define SDK_TRACE 8
#define SDK_TRACE_TAKE 0
#define SDK_TRACE_ENABLE 1
#define SDK_TRACE_DISABLE 2
/* OTLP/JSON metrics and traces for a lib input. Logs keep using SDK_PUSH. */
#define SDK_PUSH_METRICS 9
#define SDK_PUSH_TRACES 10
/* Advertised to the worker so callers can feature-detect. */
#define SDK_FEATURES "condition,topology,trace,otlp"
#define SDK_PAYLOAD_LIMIT (1024 * 1024)

struct sdk_command {
    int id;
    int operation;
    int grace;
    char *name;
    unsigned char *data;
    size_t size;
};

static pthread_mutex_t command_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t command_ready = PTHREAD_COND_INITIALIZER;
static struct sdk_command pending_command;
static int command_pending;
static pthread_cond_t drain_ready = PTHREAD_COND_INITIALIZER;
static enum {
    SDK_DRAIN_IDLE,
    SDK_DRAIN_QUEUED,
    SDK_DRAIN_ACTIVE
} drain_state;
static int drain_result;
/* Set when the engine shuts down, by a stop or on its own: it answers no more events. */
static int engine_stopped;
/* One decoded OTLP payload waiting for the engine thread to append it. */
static pthread_cond_t ingest_ready = PTHREAD_COND_INITIALIZER;
static struct {
    int pending;
    int result;
    struct flb_input_instance *input;
    struct cfl_list *metrics;
    struct ctrace *traces;
} ingest;

/* The SDK owns one engine. All pipeline inspection runs on its engine thread. */
static void sdk_drain_complete(int result)
{
    drain_result = result;
    drain_state = SDK_DRAIN_IDLE;
    pthread_cond_signal(&drain_ready);
}

/* Appending runs the input's processors, which belong to the engine thread. */
static void sdk_engine_ingest(int cancel)
{
    struct cfl_list *head;
    struct cmt *metrics;
    int result;

    pthread_mutex_lock(&command_mutex);
    if (cancel) {
        engine_stopped = 1;
    }
    if (!ingest.pending) {
        pthread_mutex_unlock(&command_mutex);
        return;
    }
    result = 0;
    if (cancel) {
        result = -1;
    }
    else if (ingest.metrics != NULL) {
        /* The caller keeps the contexts. An empty one adds no chunk. */
        cfl_list_foreach(head, ingest.metrics) {
            metrics = cfl_list_entry(head, struct cmt, _head);
            if (flb_input_metrics_append(ingest.input, NULL, 0, metrics) != 0) {
                result = -1;
            }
        }
    }
    else {
        /* Released by the engine on success, by the caller otherwise. */
        result = flb_input_trace_append(ingest.input, NULL, 0, ingest.traces);
        if (result == 0) {
            ingest.traces = NULL;
        }
    }
    ingest.result = result;
    ingest.pending = 0;
    pthread_cond_signal(&ingest_ready);
    pthread_mutex_unlock(&command_mutex);
}

static void sdk_engine_drain(struct flb_config *config, int stage)
{
    struct mk_list *head;
    struct mk_list *collector_head;
    struct flb_input_instance *input;
    struct flb_input_collector *collector;
    struct flb_output_instance *output;
    struct pollfd descriptor;
    int ret;
    int memory_chunks;
    int filesystem_chunks;

    if (stage == FLB_WASM_INGEST || stage == FLB_WASM_DRAIN_CANCEL) {
        sdk_engine_ingest(stage == FLB_WASM_DRAIN_CANCEL);
        if (stage == FLB_WASM_INGEST) {
            return;
        }
    }
    pthread_mutex_lock(&command_mutex);
    if (drain_state == SDK_DRAIN_IDLE) {
        pthread_mutex_unlock(&command_mutex);
        return;
    }
    if (stage == FLB_WASM_DRAIN_CANCEL) {
        sdk_drain_complete(-3);
    }
    else if (stage == FLB_WASM_DRAIN_BEGIN) {
        /* Network retries and autonomous inputs have no local completion bound. */
        mk_list_foreach(head, &config->inputs) {
            input = mk_list_entry(head, struct flb_input_instance, _head);
            if (strcmp(input->p->name, "lib") != 0 || input->is_threaded ||
                input->storage_type != FLB_STORAGE_MEM) {
                sdk_drain_complete(-2);
                goto done;
            }
        }
        mk_list_foreach(head, &config->outputs) {
            output = mk_list_entry(head, struct flb_output_instance, _head);
            if (strcmp(output->p->name, "stdout") != 0 && strcmp(output->p->name, "null") != 0) {
                sdk_drain_complete(-2);
                goto done;
            }
        }
        /* A flush must not overtake bytes still waiting in a lib input pipe.
         * No new push can execute until this command completes. A collector
         * reads at most 4 MiB, so repeat for larger sequences of SDK pushes. */
        mk_list_foreach(head, &config->inputs) {
            input = mk_list_entry(head, struct flb_input_instance, _head);
            mk_list_foreach(collector_head, &input->collectors) {
                collector = mk_list_entry(collector_head, struct flb_input_collector, _head);
                descriptor.fd = collector->fd_event;
                descriptor.events = POLLIN;
                while ((ret = poll(&descriptor, 1, 0)) > 0 && (descriptor.revents & POLLIN)) {
                    if (collector->cb_collect(input, config, input->context) != 0) {
                        sdk_drain_complete(-1);
                        goto done;
                    }
                }
                if (ret < 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL))) {
                    sdk_drain_complete(-1);
                    goto done;
                }
            }
        }
        drain_state = SDK_DRAIN_ACTIVE;
        flb_engine_flush(config, NULL);
    }
    if (drain_state == SDK_DRAIN_ACTIVE) {
        /* Dispatch may be capped by the engine's in-flight limit. Continue
         * dispatching after completions free capacity, without a flush tick. */
        if (stage == FLB_WASM_DRAIN_CHECK) {
            flb_engine_flush(config, NULL);
        }
        flb_storage_chunk_count(config, &memory_chunks, &filesystem_chunks);
        if (memory_chunks == 0 && filesystem_chunks == 0 && config->flush_in_flight == 0) {
            fflush(stdout);
            fflush(stderr);
            sdk_drain_complete(0);
        }
    }
done:
    pthread_mutex_unlock(&command_mutex);
}

static int sdk_drain(flb_ctx_t *context)
{
    uint64_t event;
    int result;

    if (context == NULL) {
        return -3;
    }
    event = FLB_ENGINE_EV_WASM_DRAIN;
    pthread_mutex_lock(&command_mutex);
    if (engine_stopped) {
        pthread_mutex_unlock(&command_mutex);
        return -1;
    }
    drain_state = SDK_DRAIN_QUEUED;
    if (flb_pipe_w(context->config->ch_manager[1], &event, sizeof(event)) != sizeof(event)) {
        drain_state = SDK_DRAIN_IDLE;
        pthread_mutex_unlock(&command_mutex);
        return -1;
    }
    while (drain_state != SDK_DRAIN_IDLE) {
        pthread_cond_wait(&drain_ready, &command_mutex);
    }
    result = drain_result;
    pthread_mutex_unlock(&command_mutex);
    return result;
}

/* Ownership transfers only on success. This entry point never runs the engine. */
EMSCRIPTEN_KEEPALIVE int flb_wasm_sdk_submit(int id, int operation, char *name,
                                            unsigned char *data, size_t size, int grace)
{
    if (id <= 0 || operation < SDK_START || operation > SDK_PUSH_TRACES ||
        size > SDK_PAYLOAD_LIMIT || (size != 0 && data == NULL) || grace < 0 || grace > 30) {
        return -1;
    }
    pthread_mutex_lock(&command_mutex);
    if (command_pending) {
        pthread_mutex_unlock(&command_mutex);
        return -2;
    }
    pending_command.id = id;
    pending_command.operation = operation;
    pending_command.name = name;
    pending_command.data = data;
    pending_command.size = size;
    pending_command.grace = grace;
    command_pending = 1;
    pthread_cond_signal(&command_ready);
    pthread_mutex_unlock(&command_mutex);
    return 0;
}

static int sdk_start(flb_ctx_t **context, struct sdk_command *command, double *elapsed)
{
    flb_ctx_t *ctx;
    FILE *file;
    char grace[16];
    int ret;
    double begin;

    if (*context != NULL || command->size == 0 || command->size > 65536 ||
        memchr(command->data, '\0', command->size) != NULL) {
        return -1;
    }
    file = fopen("/config/.fluent-bit-sdk.yaml", "wb");
    if (file == NULL) {
        return -2;
    }
    ret = fwrite(command->data, 1, command->size, file) == command->size ? 0 : -1;
    if (fclose(file) != 0 || ret != 0) {
        return -2;
    }
    begin = emscripten_get_now();
    ctx = flb_create();
    if (ctx == NULL) {
        unlink("/config/.fluent-bit-sdk.yaml");
        return -2;
    }
    pthread_mutex_lock(&command_mutex);
    engine_stopped = 0;
    pthread_mutex_unlock(&command_mutex);
    ctx->config->cb_wasm_drain = sdk_engine_drain;
    ret = flb_lib_config_file(ctx, "/config/.fluent-bit-sdk.yaml");
    snprintf(grace, sizeof(grace), "%d", command->grace);
    if (ret != 0 || flb_service_set(ctx, "grace", grace, NULL) != 0 || flb_start(ctx) != 0) {
        flb_destroy(ctx);
        unlink("/config/.fluent-bit-sdk.yaml");
        OPENSSL_thread_stop();
        return -3;
    }
    *context = ctx;
    *elapsed = emscripten_get_now() - begin;
    return 0;
}

static int sdk_stop(flb_ctx_t **context)
{
    int ret;

    if (*context == NULL) {
        return 0;
    }
    ret = flb_stop(*context);
    flb_destroy(*context);
    *context = NULL;
    unlink("/config/.fluent-bit-sdk.yaml");
    OPENSSL_thread_stop();
    fflush(stdout);
    fflush(stderr);
    return ret;
}

/* The alias must select exactly one lib input. */
static struct flb_input_instance *sdk_input(flb_ctx_t *context, const char *alias)
{
    struct mk_list *head;
    struct flb_input_instance *input;
    struct flb_input_instance *selected;

    selected = NULL;
    mk_list_foreach(head, &context->config->inputs) {
        input = mk_list_entry(head, struct flb_input_instance, _head);
        if (strcmp(input->p->name, "lib") == 0 && input->alias != NULL &&
            strcmp(input->alias, alias) == 0) {
            if (selected != NULL) {
                return NULL;
            }
            selected = input;
        }
    }
    return selected;
}

static int sdk_push(flb_ctx_t *context, struct sdk_command *command)
{
    struct flb_input_instance *selected;

    if (context == NULL || command->name == NULL || command->size == 0) {
        return -1;
    }
    selected = sdk_input(context, command->name);
    if (selected == NULL) {
        return -2;
    }
    return flb_lib_push(context, selected->id, command->data, command->size);
}

/* Validate the whole request without replacing the bytes passed to the decoder. */
static int sdk_otlp_json_valid(const unsigned char *data, size_t size)
{
    char *packed;
    size_t packed_size;
    size_t consumed;
    int root_type;
    int records;
    int result;

    packed = NULL;
    consumed = 0;
    result = flb_pack_json_recs((const char *) data, size, &packed, &packed_size,
                               &root_type, &records, &consumed);
    flb_free(packed);
    if (result != 0 || root_type != JSMN_OBJECT || records != 1) {
        return FLB_FALSE;
    }
    while (consumed < size && (data[consumed] == ' ' || data[consumed] == '\t' ||
                              data[consumed] == '\r' || data[consumed] == '\n')) {
        consumed++;
    }
    return consumed == size;
}

/* Decode here, append on the engine thread. -4 reports a payload that is not OTLP/JSON. */
static int sdk_push_otlp(flb_ctx_t *context, struct sdk_command *command)
{
    struct cfl_list metrics;
    struct cfl_list *head;
    struct ctrace *traces;
    struct flb_input_instance *selected;
    uint64_t event;
    int status;
    int result;

    if (context == NULL || command->name == NULL || command->size == 0) {
        return -1;
    }
    /* Shutdown sets engine_stopped under this lock before freeing input aliases. */
    pthread_mutex_lock(&command_mutex);
    if (engine_stopped) {
        pthread_mutex_unlock(&command_mutex);
        return -1;
    }
    selected = sdk_input(context, command->name);
    pthread_mutex_unlock(&command_mutex);
    if (selected == NULL) {
        return -2;
    }
    if (!sdk_otlp_json_valid(command->data, command->size)) {
        return -4;
    }
    traces = NULL;
    if (command->operation == SDK_PUSH_METRICS) {
        if (flb_opentelemetry_metrics_json_to_cmt(&metrics, (const char *) command->data,
                                                  command->size) != 0) {
            /* A failed decode has already released its contexts. */
            return -4;
        }
        /* A request can decode into contexts that hold no metric: nothing to append. */
        result = -4;
        cfl_list_foreach(head, &metrics) {
            if (!flb_metrics_is_empty(cfl_list_entry(head, struct cmt, _head))) {
                result = 0;
                break;
            }
        }
        if (result != 0) {
            cmt_decode_opentelemetry_destroy(&metrics);
            return -4;
        }
    }
    else {
        status = 0;
        traces = flb_opentelemetry_json_traces_to_ctrace((const char *) command->data,
                                                         command->size, &status);
        if (traces == NULL) {
            return -4;
        }
    }
    event = FLB_ENGINE_EV_WASM_INGEST;
    pthread_mutex_lock(&command_mutex);
    ingest.input = selected;
    ingest.metrics = traces == NULL ? &metrics : NULL;
    ingest.traces = traces;
    ingest.pending = 1;
    /* An engine that has stopped reads no event: do not wait for it. */
    if (engine_stopped ||
        flb_pipe_w(context->config->ch_manager[1], &event, sizeof(event)) != sizeof(event)) {
        ingest.pending = 0;
        ingest.result = -1;
    }
    while (ingest.pending) {
        pthread_cond_wait(&ingest_ready, &command_mutex);
    }
    result = ingest.result;
    traces = ingest.traces;
    pthread_mutex_unlock(&command_mutex);
    if (command->operation == SDK_PUSH_METRICS) {
        cmt_decode_opentelemetry_destroy(&metrics);
    }
    else if (traces != NULL) {
        ctr_destroy(traces);
    }
    return result == 0 ? 0 : -1;
}

/* Results are JSON in a malloc(3) buffer that the worker copies and frees. */
static int sdk_inspect(flb_ctx_t *context, struct sdk_command *command,
                       char **output, size_t *output_size)
{
    if (command->operation == SDK_EVALUATE) {
        if (command->size == 0) {
            return -1;
        }
        return flb_wasm_inspect_condition((const char *) command->data, command->size,
                                          output, output_size);
    }
    if (command->operation == SDK_TOPOLOGY) {
        /* Instance lists and routes are fixed once the engine has started. */
        if (context == NULL) {
            return -3;
        }
        return flb_wasm_inspect_topology(context->config, output, output_size);
    }
    if (command->grace == SDK_TRACE_TAKE) {
        return flb_wasm_trace_take(output, output_size);
    }
    flb_wasm_trace_set(command->grace == SDK_TRACE_ENABLE);
    return 0;
}

int main(void)
{
    flb_ctx_t *context;
    struct sdk_command command;
    int result;
    double elapsed;
    char *output;
    size_t output_size;

    context = NULL;
    MAIN_THREAD_EM_ASM({ Module['onSdkReady'](1, UTF8ToString($0), UTF8ToString($1)); },
                       FLB_VERSION_STR, SDK_FEATURES);
    for (;;) {
        pthread_mutex_lock(&command_mutex);
        while (!command_pending) {
            pthread_cond_wait(&command_ready, &command_mutex);
        }
        command = pending_command;
        memset(&pending_command, 0, sizeof(pending_command));
        command_pending = 0;
        pthread_mutex_unlock(&command_mutex);
        elapsed = 0;
        output = NULL;
        output_size = 0;
        if (command.operation >= SDK_PUSH_METRICS) {
            result = sdk_push_otlp(context, &command);
        }
        else if (command.operation >= SDK_EVALUATE) {
            result = sdk_inspect(context, &command, &output, &output_size);
        }
        else if (command.operation == SDK_START) {
            result = sdk_start(&context, &command, &elapsed);
        }
        else if (command.operation == SDK_PUSH) {
            result = sdk_push(context, &command);
        }
        else if (command.operation == SDK_DRAIN) {
            result = sdk_drain(context);
        }
        else {
            result = sdk_stop(&context);
        }
        free(command.name);
        free(command.data);
        if (command.operation == SDK_DESTROY) {
            OPENSSL_thread_stop();
            return result == 0 ? 0 : 1;
        }
        MAIN_THREAD_EM_ASM({ Module['onSdkResult']($0, $1, $2, $3, $4); },
                           command.id, result, elapsed, output, output_size);
    }
}
