/* SPDX-License-Identifier: Apache-2.0 */

#include <fluent-bit/flb_lib.h>
#include <emscripten.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEMO_CONFIG_LIMIT (64 * 1024)

static atomic_int stop_requested;

/* The browser may call this on its main thread: only touch an atomic flag.
 * Engine start/stop/destroy and their blocking joins stay on the C worker. */
EMSCRIPTEN_KEEPALIVE void flb_wasm_demo_request_stop(void)
{
    atomic_store(&stop_requested, 1);
}

int main(int argc, char **argv)
{
    flb_ctx_t *ctx;
    FILE *file;
    char *end;
    size_t size;
    long seconds;
    double deadline;
    double create_begin;
    double create_end;
    double config_end;
    double start_end;
    int ret;

    if (argc != 3) {
        fprintf(stderr, "Demo requires YAML text and a duration in seconds\n");
        return 1;
    }
    size = strlen(argv[1]);
    seconds = strtol(argv[2], &end, 10);
    if (size == 0 || size > DEMO_CONFIG_LIMIT || *end != '\0' || seconds < 1 || seconds > 300) {
        fprintf(stderr, "Demo requires 1-65536 YAML bytes and a duration of 1-300 seconds\n");
        return 1;
    }
    file = fopen("/demo.yaml", "wb");
    if (!file) {
        perror("Cannot create virtual demo configuration");
        return 1;
    }
    ret = fwrite(argv[1], 1, size, file) == size ? 0 : -1;
    if (fclose(file) != 0 || ret != 0) {
        fprintf(stderr, "Cannot write virtual demo configuration\n");
        return 1;
    }
    create_begin = emscripten_get_now();
    ctx = flb_create();
    create_end = emscripten_get_now();
    if (!ctx) {
        return 1;
    }
    if (flb_lib_config_file(ctx, "/demo.yaml") != 0) {
        flb_destroy(ctx);
        return 1;
    }
    config_end = emscripten_get_now();
    /* Keep Stop bounded for the interactive demo, regardless of user YAML. */
    if (flb_service_set(ctx, "grace", "1", NULL) != 0 || flb_start(ctx) != 0) {
        fprintf(stderr, "Demo engine startup failed; check configuration and enabled plugins\n");
        flb_destroy(ctx);
        return 1;
    }
    start_end = emscripten_get_now();
    MAIN_THREAD_EM_ASM({
        if (Module['onDemoState']) {
            Module['onDemoState'](1, {create_ms: $0, config_ms: $1, start_ms: $2});
        }
    }, create_end - create_begin, config_end - create_end, start_end - config_end);
    deadline = emscripten_get_now() + seconds * 1000.0;
    while (!atomic_load(&stop_requested) && emscripten_get_now() < deadline) {
        usleep(50000);
    }
    MAIN_THREAD_EM_ASM({
        if (Module['onDemoState']) { Module['onDemoState'](2); }
    });
    ret = flb_stop(ctx);
    flb_destroy(ctx);
    unlink("/demo.yaml");
    fflush(stdout);
    return ret == 0 ? 0 : 1;
}
