/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "pipeline check failed at line %d: %s\n", __LINE__, #condition); \
        abort(); \
    } \
} while (0)

struct result {
    pthread_mutex_t lock;
    int records;
};

static int output_callback(void *buffer, size_t size, void *data)
{
    struct result *result;
    char *text;

    result = data;
    text = flb_malloc(size + 1);
    CHECK(text != NULL);
    memcpy(text, buffer, size);
    text[size] = '\0';
    CHECK(strstr(text, "\"wasm\":\"browser\"") != NULL);
    CHECK(strstr(text, "\"keep\":\"yes\"") != NULL);
    CHECK(strstr(text, "\"keep\":\"no\"") == NULL);
    pthread_mutex_lock(&result->lock);
    result->records++;
    pthread_mutex_unlock(&result->lock);
    flb_free(text);
    flb_free(buffer);
    return 0;
}

static void exercise_pipeline(void)
{
    const char input[] = "[0,{\"keep\":\"yes\"}][0,{\"keep\":\"no\"}]";
    const char dropped[] = "[0,{\"keep\":\"no\"}]";
    struct flb_lib_out_cb callbacks[2];
    struct result results[2];
    flb_ctx_t *context;
    int input_id;
    int filter_id;
    int output_id;
    int index;
    int attempt;
    int received;

    context = flb_create();
    CHECK(context != NULL);
    CHECK(flb_service_set(context, "Flush", "0.1", "Grace", "1",
                          "Log_Level", "error", NULL) == 0);
    input_id = flb_input(context, "lib", NULL);
    CHECK(input_id >= 0);
    CHECK(flb_input_set(context, input_id, "tag", "browser", NULL) == 0);
    filter_id = flb_filter(context, "modify", NULL);
    CHECK(filter_id >= 0);
    CHECK(flb_filter_set(context, filter_id, "match", "*",
                         "set", "wasm browser", NULL) == 0);
    filter_id = flb_filter(context, "grep", NULL);
    CHECK(filter_id >= 0);
    CHECK(flb_filter_set(context, filter_id, "match", "*",
                         "regex", "keep ^yes$", NULL) == 0);

    for (index = 0; index < 2; index++) {
        CHECK(pthread_mutex_init(&results[index].lock, NULL) == 0);
        results[index].records = 0;
        callbacks[index].cb = output_callback;
        callbacks[index].data = &results[index];
        output_id = flb_output(context, "lib", &callbacks[index]);
        CHECK(output_id >= 0);
        CHECK(flb_output_set(context, output_id, "match", "*", "format", "json",
                             "workers", "0", NULL) == 0);
    }

    CHECK(flb_start(context) == 0);
    CHECK(flb_lib_push(context, input_id, input, sizeof(input) - 1) == sizeof(input) - 1);
    for (attempt = 0; attempt < 500; attempt++) {
        received = 0;
        for (index = 0; index < 2; index++) {
            pthread_mutex_lock(&results[index].lock);
            received += results[index].records;
            pthread_mutex_unlock(&results[index].lock);
        }
        if (received == 2) {
            break;
        }
        usleep(10000);
    }
    CHECK(received == 2);
    CHECK(flb_lib_push(context, input_id, dropped, sizeof(dropped) - 1) == sizeof(dropped) - 1);
    usleep(200000);
    CHECK(flb_stop(context) == 0);
    flb_destroy(context);
    for (index = 0; index < 2; index++) {
        CHECK(results[index].records == 1);
        pthread_mutex_destroy(&results[index].lock);
    }
}

int main(void)
{
    const unsigned char expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    unsigned char digest[32];
    int index;

    CHECK(flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) "abc", 3,
                           digest, sizeof(digest)) == FLB_CRYPTO_SUCCESS);
    CHECK(memcmp(digest, expected, sizeof(digest)) == 0);
    for (index = 0; index < 3; index++) {
        exercise_pipeline();
    }
    /* Process exit runs on the browser thread, not this proxied main worker. */
    OPENSSL_thread_stop();
    puts("WASM pipeline passed: SHA-256, modify, grep, all-drop, fan-out, repeated start/stop");
    return 0;
}
