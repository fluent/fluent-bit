/* SPDX-License-Identifier: Apache-2.0 */
/* Exercise the SDK command path without starting its command loop. */
#define main sdk_command_main
#include "../../src/wasm/sdk.c"
#undef main

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "SDK ingest check failed at %d: %s\n", __LINE__, #condition); abort(); \
} } while (0)

int main(void)
{
    flb_ctx_t context;
    struct sdk_command command;
    const char *payload = "{\"resourceMetrics\":[]}";

    /* Once cancellation has run, inputs may already have been destroyed.
     * A stopped engine must reject before accessing even the config pointer. */
    memset(&context, 0, sizeof(context));
    memset(&command, 0, sizeof(command));
    command.name = "app";
    command.data = (unsigned char *) payload;
    command.size = strlen(payload);
    sdk_engine_ingest(1);
    command.operation = SDK_PUSH_METRICS;
    CHECK(sdk_push_otlp(&context, &command) == -1);
    command.operation = SDK_PUSH_TRACES;
    CHECK(sdk_push_otlp(&context, &command) == -1);

    puts("SDK ingestion after engine cancellation passed");
    return 0;
}
