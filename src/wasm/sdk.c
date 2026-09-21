/* SPDX-License-Identifier: Apache-2.0 */
/* The public SDK submits owned messages; only this pthread owns the engine. */
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_version.h>
#include <emscripten.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SDK_START 1
#define SDK_STOP 2
#define SDK_PUSH 3
#define SDK_DESTROY 4
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

/* Ownership transfers only on success. This entry point never runs the engine. */
EMSCRIPTEN_KEEPALIVE int flb_wasm_sdk_submit(int id, int operation, char *name,
                                            unsigned char *data, size_t size, int grace)
{
    if (id <= 0 || operation < SDK_START || operation > SDK_DESTROY ||
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
