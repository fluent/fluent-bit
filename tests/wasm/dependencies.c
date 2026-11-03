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

#include <stdio.h>
#include <string.h>

#include <yyjson.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_prometheus.h>

static int check_json(void)
{
    const char input[] = "{\"message\":\"browser\",\"count\":42}";
    yyjson_doc *document;
    yyjson_val *root;
    const char *message;
    int result;

    document = yyjson_read(input, sizeof(input) - 1, 0);
    if (document == NULL) {
        return -1;
    }

    root = yyjson_doc_get_root(document);
    message = yyjson_get_str(yyjson_obj_get(root, "message"));
    result = message != NULL && strcmp(message, "browser") == 0 &&
             yyjson_get_int(yyjson_obj_get(root, "count")) == 42;
    yyjson_doc_free(document);
    if (!result) {
        return -1;
    }

    document = yyjson_read("{", 1, 0);
    if (document != NULL) {
        yyjson_doc_free(document);
        return -1;
    }

    return 0;
}

static int check_metrics(void)
{
    struct cmt *metrics;
    struct cmt *decoded = NULL;
    struct cmt_counter *counter;
    char *buffer = NULL;
    size_t size = 0;
    size_t offset = 0;
    cfl_sds_t text = NULL;
    int result = -1;

    cmt_initialize();
    metrics = cmt_create();
    if (metrics == NULL) {
        return -1;
    }

    counter = cmt_counter_create(metrics, "browser", "wasm", "events_total",
                                 "Events processed", 0, NULL);
    if (counter == NULL || cmt_counter_add(counter, 1000000000, 42, 0, NULL) != 0) {
        goto cleanup;
    }

    if (cmt_encode_msgpack_create(metrics, &buffer, &size) != 0) {
        goto cleanup;
    }

    if (cmt_decode_msgpack_create(&decoded, buffer, size, &offset) != 0 || offset != size) {
        goto cleanup;
    }

    text = cmt_encode_prometheus_create(decoded, CMT_FALSE);
    if (text == NULL || strstr(text, "browser_wasm_events_total 42\n") == NULL) {
        goto cleanup;
    }

    cmt_decode_msgpack_destroy(decoded);
    decoded = NULL;
    offset = 0;

    /* A reserved MessagePack byte must not produce a metrics context. */
    if (cmt_decode_msgpack_create(&decoded, "\xc1", 1, &offset) == 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    if (text != NULL) {
        cmt_encode_prometheus_destroy(text);
    }
    if (decoded != NULL) {
        cmt_decode_msgpack_destroy(decoded);
    }
    if (buffer != NULL) {
        cmt_encode_msgpack_destroy(buffer);
    }
    cmt_destroy(metrics);
    return result;
}

int main(void)
{
    if (check_json() != 0 || check_metrics() != 0) {
        fprintf(stderr, "WASM dependency smoke test failed\n");
        return 1;
    }

    printf("WASM dependency smoke test passed: JSON and metrics round trip\n");
    return 0;
}
