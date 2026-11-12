/* SPDX-License-Identifier: Apache-2.0 */
/* The public SDK submits owned messages; only this pthread owns the engine. */
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_version.h>
#include <emscripten.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SDK_START 1
#define SDK_STOP 2
#define SDK_PUSH 3
#define SDK_DESTROY 4
#define SDK_DRAIN 5
#define SDK_PUSH_BYTES 6
#define SDK_REQUEST 7
#define SDK_PAYLOAD_LIMIT (1024 * 1024)

/* Results of the host-driven ingestion commands (SDK_PUSH_BYTES, SDK_REQUEST) */
#define SDK_INGEST_INVALID       -1
#define SDK_INGEST_UNKNOWN_INPUT -2
#define SDK_INGEST_BUSY          -10
#define SDK_INGEST_TOO_LARGE     -11
#define SDK_INGEST_NOT_SUPPORTED -12
#define SDK_INGEST_NOT_RUNNING   -13
#define SDK_INGEST_FAILED        -14

/*
 * Replies of requests. A slot is taken when the request is admitted and it
 * is held until the main thread takes the completion, so an admitted request
 * always has room for its outcome.
 */
#define SDK_REPLY_SLOTS 64
#define SDK_REPLY_LIMIT (64 * 1024)

#define SDK_REPLY_FREE    0
#define SDK_REPLY_PENDING 1
#define SDK_REPLY_DONE    2

struct sdk_reply {
    int state;
    int id;                    /* id of the command that submitted it */
    int outcome;               /* FLB_INPUT_INGEST_REPLIED, ...       */
    int status;
    int truncated;
    unsigned char *data;       /* serialized headers and body         */
    size_t size;
};

static pthread_mutex_t reply_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sdk_reply replies[SDK_REPLY_SLOTS];

static void sdk_replies_dispose(void);

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

/* The SDK owns one engine. All pipeline inspection runs on its engine thread. */
static void sdk_drain_complete(int result)
{
    drain_result = result;
    drain_state = SDK_DRAIN_IDLE;
    pthread_cond_signal(&drain_ready);
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
    if (id <= 0 || operation < SDK_START || operation > SDK_REQUEST ||
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
    sdk_replies_dispose();
    unlink("/config/.fluent-bit-sdk.yaml");
    OPENSSL_thread_stop();
    fflush(stdout);
    fflush(stderr);
    return ret;
}

static int sdk_push(flb_ctx_t *context, struct sdk_command *command)
{
    struct mk_list *head;
    struct flb_input_instance *input;
    struct flb_input_instance *selected;

    if (context == NULL || command->name == NULL || command->size == 0) {
        return -1;
    }
    selected = NULL;
    mk_list_foreach(head, &context->config->inputs) {
        input = mk_list_entry(head, struct flb_input_instance, _head);
        if (strcmp(input->p->name, "lib") == 0 && input->alias != NULL &&
            strcmp(input->alias, command->name) == 0) {
            if (selected != NULL) {
                return -2;
            }
            selected = input;
        }
    }
    if (selected == NULL) {
        return -2;
    }
    return flb_lib_push(context, selected->id, command->data, command->size);
}

/* An input in external mode is addressed by its alias */
static struct flb_input_instance *sdk_external_input(flb_ctx_t *context,
                                                     const char *alias)
{
    struct mk_list *head;
    struct flb_input_instance *input;
    struct flb_input_instance *selected;

    selected = NULL;
    mk_list_foreach(head, &context->config->inputs) {
        input = mk_list_entry(head, struct flb_input_instance, _head);
        if (flb_input_is_external(input) && input->alias != NULL &&
            strcmp(input->alias, alias) == 0) {
            if (selected != NULL) {
                return NULL;
            }
            selected = input;
        }
    }

    return selected;
}

static int sdk_ingest_result(int result)
{
    switch (result) {
    case FLB_INPUT_INGEST_OK:
        return 0;
    case FLB_INPUT_INGEST_BUSY:
        return SDK_INGEST_BUSY;
    case FLB_INPUT_INGEST_TOO_LARGE:
        return SDK_INGEST_TOO_LARGE;
    case FLB_INPUT_INGEST_NOT_SUPPORTED:
        return SDK_INGEST_NOT_SUPPORTED;
    case FLB_INPUT_INGEST_NOT_RUNNING:
        return SDK_INGEST_NOT_RUNNING;
    case FLB_INPUT_INGEST_FAILED:
        return SDK_INGEST_FAILED;
    default:
        return SDK_INGEST_INVALID;
    }
}

static int sdk_push_bytes(flb_ctx_t *context, struct sdk_command *command)
{
    struct flb_input_instance *input;

    if (context == NULL || command->name == NULL || command->size == 0) {
        return SDK_INGEST_INVALID;
    }

    input = sdk_external_input(context, command->name);
    if (input == NULL) {
        return SDK_INGEST_UNKNOWN_INPUT;
    }

    return sdk_ingest_result(
               flb_input_ingest_submit(input, FLB_INPUT_INGEST_STREAM_BYTES,
                                       command->data, command->size,
                                       NULL, NULL, NULL));
}

static uint32_t sdk_read_u32(const unsigned char *data)
{
    return (uint32_t) data[0] | ((uint32_t) data[1] << 8) |
           ((uint32_t) data[2] << 16) | ((uint32_t) data[3] << 24);
}

static void sdk_write_u32(unsigned char *data, uint32_t value)
{
    data[0] = (unsigned char) (value & 0xff);
    data[1] = (unsigned char) ((value >> 8) & 0xff);
    data[2] = (unsigned char) ((value >> 16) & 0xff);
    data[3] = (unsigned char) ((value >> 24) & 0xff);
}

/* Take 'length' bytes of the serialized request, or fail when it is short */
static const char *sdk_request_take(const unsigned char *data, size_t size,
                                    size_t *offset, size_t length)
{
    const char *start;

    if (length > size - *offset) {
        return NULL;
    }

    start = (const char *) data + *offset;
    *offset += length;

    return start;
}

/*
 * The reply callback runs on the engine thread. It stores a bounded copy of
 * the reply in the slot reserved at admission and wakes the main thread
 * without waiting for it.
 */
static void sdk_reply_cb(int outcome, const struct flb_input_ingest_reply *reply,
                         void *data)
{
    size_t i;
    size_t size;
    size_t body_size;
    unsigned char *buffer;
    unsigned char *cursor;
    struct sdk_reply *slot;

    slot = data;
    buffer = NULL;
    size = 0;
    body_size = 0;

    if (outcome == FLB_INPUT_INGEST_REPLIED && reply != NULL) {
        /* Headers are kept whole; the body takes what is left of the bound */
        size = 4;
        for (i = 0; i < reply->header_count && size <= SDK_REPLY_LIMIT; i++) {
            size += 8 + reply->headers[i].name_len + reply->headers[i].value_len;
        }

        if (size > SDK_REPLY_LIMIT) {
            outcome = FLB_INPUT_INGEST_REPLY_FAILED;
        }
        else {
            body_size = reply->body_size;
            if (body_size > SDK_REPLY_LIMIT - size) {
                body_size = SDK_REPLY_LIMIT - size;
            }
            buffer = malloc(size + body_size);
            if (buffer == NULL) {
                outcome = FLB_INPUT_INGEST_REPLY_FAILED;
            }
        }
    }

    if (buffer != NULL) {
        cursor = buffer;
        sdk_write_u32(cursor, (uint32_t) reply->header_count);
        cursor += 4;
        for (i = 0; i < reply->header_count; i++) {
            sdk_write_u32(cursor, (uint32_t) reply->headers[i].name_len);
            sdk_write_u32(cursor + 4, (uint32_t) reply->headers[i].value_len);
            cursor += 8;
            memcpy(cursor, reply->headers[i].name, reply->headers[i].name_len);
            cursor += reply->headers[i].name_len;
            memcpy(cursor, reply->headers[i].value, reply->headers[i].value_len);
            cursor += reply->headers[i].value_len;
        }
        if (body_size > 0) {
            memcpy(cursor, reply->body, body_size);
        }
    }

    pthread_mutex_lock(&reply_mutex);
    slot->outcome = outcome;
    slot->status = buffer != NULL ? reply->status : 0;
    slot->truncated = buffer != NULL && body_size < reply->body_size;
    slot->data = buffer;
    slot->size = buffer != NULL ? size + body_size : 0;
    slot->state = SDK_REPLY_DONE;
    pthread_mutex_unlock(&reply_mutex);

    MAIN_THREAD_ASYNC_EM_ASM({ Module['onSdkReply'](); });
}

/* Main thread: index of a completed reply, or -1 when there is none */
EMSCRIPTEN_KEEPALIVE int flb_wasm_sdk_reply_next(void)
{
    int i;
    int found;

    found = -1;
    pthread_mutex_lock(&reply_mutex);
    for (i = 0; i < SDK_REPLY_SLOTS; i++) {
        if (replies[i].state == SDK_REPLY_DONE) {
            found = i;
            break;
        }
    }
    pthread_mutex_unlock(&reply_mutex);

    return found;
}

/* Main thread: fields of a completed reply: 0 id, 1 outcome, 2 status,
 * 3 truncated, 4 data pointer, 5 data size. */
EMSCRIPTEN_KEEPALIVE int flb_wasm_sdk_reply_field(int index, int field)
{
    int value;
    struct sdk_reply *slot;

    if (index < 0 || index >= SDK_REPLY_SLOTS) {
        return -1;
    }

    slot = &replies[index];
    value = -1;

    pthread_mutex_lock(&reply_mutex);
    if (slot->state == SDK_REPLY_DONE) {
        switch (field) {
        case 0:
            value = slot->id;
            break;
        case 1:
            value = slot->outcome;
            break;
        case 2:
            value = slot->status;
            break;
        case 3:
            value = slot->truncated;
            break;
        case 4:
            value = (int) (intptr_t) slot->data;
            break;
        case 5:
            value = (int) slot->size;
            break;
        }
    }
    pthread_mutex_unlock(&reply_mutex);

    return value;
}

/* Main thread: the completion was taken, its slot can be used again */
EMSCRIPTEN_KEEPALIVE void flb_wasm_sdk_reply_release(int index)
{
    unsigned char *data;

    if (index < 0 || index >= SDK_REPLY_SLOTS) {
        return;
    }

    data = NULL;
    pthread_mutex_lock(&reply_mutex);
    if (replies[index].state == SDK_REPLY_DONE) {
        data = replies[index].data;
        memset(&replies[index], 0, sizeof(struct sdk_reply));
    }
    pthread_mutex_unlock(&reply_mutex);

    free(data);
}

/* The engine is gone: every callback has run, drop what was not taken */
static void sdk_replies_dispose(void)
{
    int i;

    pthread_mutex_lock(&reply_mutex);
    for (i = 0; i < SDK_REPLY_SLOTS; i++) {
        free(replies[i].data);
        memset(&replies[i], 0, sizeof(struct sdk_reply));
    }
    pthread_mutex_unlock(&reply_mutex);
}

/*
 * Serialized request, little endian:
 *   u32 method length, u32 path length, u32 header count, u32 body length,
 *   method, path, { u32 name length, u32 value length, name, value }, body
 */
static int sdk_request(flb_ctx_t *context, struct sdk_command *command)
{
    int i;
    int result;
    size_t offset;
    uint32_t method_len;
    uint32_t path_len;
    uint32_t header_count;
    uint32_t body_len;
    const char *body;
    struct sdk_reply *slot;
    struct flb_input_instance *input;
    struct flb_input_ingest_request request;
    struct flb_input_ingest_header headers[FLB_INPUT_INGEST_HEADER_MAX];

    if (context == NULL || command->name == NULL || command->size < 16) {
        return SDK_INGEST_INVALID;
    }

    input = sdk_external_input(context, command->name);
    if (input == NULL) {
        return SDK_INGEST_UNKNOWN_INPUT;
    }

    method_len = sdk_read_u32(command->data);
    path_len = sdk_read_u32(command->data + 4);
    header_count = sdk_read_u32(command->data + 8);
    body_len = sdk_read_u32(command->data + 12);
    offset = 16;

    if (header_count > FLB_INPUT_INGEST_HEADER_MAX) {
        return SDK_INGEST_TOO_LARGE;
    }

    memset(&request, 0, sizeof(request));
    request.method = sdk_request_take(command->data, command->size, &offset, method_len);
    request.method_len = method_len;
    if (request.method == NULL) {
        return SDK_INGEST_INVALID;
    }
    request.path = sdk_request_take(command->data, command->size, &offset, path_len);
    request.path_len = path_len;
    if (request.path == NULL) {
        return SDK_INGEST_INVALID;
    }

    for (i = 0; i < (int) header_count; i++) {
        if (command->size - offset < 8) {
            return SDK_INGEST_INVALID;
        }
        headers[i].name_len = sdk_read_u32(command->data + offset);
        headers[i].value_len = sdk_read_u32(command->data + offset + 4);
        offset += 8;
        headers[i].name = sdk_request_take(command->data, command->size, &offset,
                                           headers[i].name_len);
        if (headers[i].name == NULL) {
            return SDK_INGEST_INVALID;
        }
        headers[i].value = sdk_request_take(command->data, command->size, &offset,
                                            headers[i].value_len);
        if (headers[i].value == NULL) {
            return SDK_INGEST_INVALID;
        }
    }
    request.headers = headers;
    request.header_count = header_count;

    body = sdk_request_take(command->data, command->size, &offset, body_len);
    if (body == NULL || offset != command->size) {
        return SDK_INGEST_INVALID;
    }

    /* Reserve the completion before the request can be dispatched */
    slot = NULL;
    pthread_mutex_lock(&reply_mutex);
    for (i = 0; i < SDK_REPLY_SLOTS; i++) {
        if (replies[i].state == SDK_REPLY_FREE) {
            slot = &replies[i];
            memset(slot, 0, sizeof(struct sdk_reply));
            slot->state = SDK_REPLY_PENDING;
            slot->id = command->id;
            break;
        }
    }
    pthread_mutex_unlock(&reply_mutex);

    if (slot == NULL) {
        return SDK_INGEST_BUSY;
    }

    result = flb_input_ingest_submit(input, FLB_INPUT_INGEST_HTTP_REQUEST,
                                     body, body_len, &request,
                                     sdk_reply_cb, slot);
    if (result != FLB_INPUT_INGEST_OK) {
        /* Not admitted: no reply will come */
        pthread_mutex_lock(&reply_mutex);
        memset(slot, 0, sizeof(struct sdk_reply));
        pthread_mutex_unlock(&reply_mutex);
    }

    return sdk_ingest_result(result);
}

int main(void)
{
    flb_ctx_t *context;
    struct sdk_command command;
    int result;
    double elapsed;

    context = NULL;
    MAIN_THREAD_EM_ASM({ Module['onSdkReady'](1, UTF8ToString($0)); }, FLB_VERSION_STR);
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
        if (command.operation == SDK_START) {
            result = sdk_start(&context, &command, &elapsed);
        }
        else if (command.operation == SDK_PUSH) {
            result = sdk_push(context, &command);
        }
        else if (command.operation == SDK_DRAIN) {
            result = sdk_drain(context);
        }
        else if (command.operation == SDK_PUSH_BYTES) {
            result = sdk_push_bytes(context, &command);
        }
        else if (command.operation == SDK_REQUEST) {
            result = sdk_request(context, &command);
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
        MAIN_THREAD_EM_ASM({ Module['onSdkResult']($0, $1, $2); }, command.id, result, elapsed);
    }
}
