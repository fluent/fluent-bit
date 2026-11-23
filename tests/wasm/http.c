/* SPDX-License-Identifier: Apache-2.0 */
#include <fluent-bit/wasm/flb_wasm_http.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_http_client.h>
#include <emscripten.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "HTTP bridge check failed at %d: %s\n", __LINE__, #value); abort(); \
} } while (0)

static int await_result(int id)
{
    double deadline;
    int status;

    deadline = emscripten_get_now() + 3000;
    do {
        status = flb_wasm_http_poll(id);
        if (status != 0) {
            return status;
        }
        emscripten_sleep(5);
    } while (emscripten_get_now() < deadline);
    CHECK(0);
    return -1;
}

int main(void)
{
    struct mk_list headers;
    unsigned char *body;
    int id;
    int i;
    struct flb_http_client *client;
    flb_sds_t response_header;
    double deadline;

    EM_ASM({
        Module.testHttpMode = 'ok';
        globalThis.fetch = async (url, options) => {
            if (options.credentials !== 'omit' || options.redirect !== 'error' || options.mode !== 'cors') {
                throw new Error('Unsafe transport options');
            }
            if (Module.testHttpMode === 'hang') {
                return new Promise((resolve, reject) => {
                    options.signal.addEventListener('abort', () => reject(new Error('Aborted')), {once: true});
                });
            }
            await new Promise(resolve => setTimeout(resolve, 10));
            if (options.body[0] !== 0 || options.body[1] !== 255 || options.body[2] !== 42 || options.body[3] !== 17) {
                throw new Error('Binary request copy corrupted');
            }
            if (Module.testHttpMode === 'large') { return new Response(new Uint8Array(65537)); }
            return new Response(new Uint8Array([0, 255, 42, 17]),
                {status: 201, headers: {'X-Response': 'accepted'}});
        };
    });
    CHECK(flb_wasm_http_validate("https://example.invalid/collect") == 0);
    CHECK(flb_wasm_http_validate("http://example.invalid/collect") == -1);
    CHECK(flb_wasm_http_validate("https://user:secret@example.invalid/") == -1);
    CHECK(flb_wasm_http_validate("https://example.invalid/#fragment") == -1);
    CHECK(flb_wasm_http_validate(NULL) == -1);
    mk_list_init(&headers);
    CHECK(flb_kv_item_create(&headers, "X-Demo", "bridge") != NULL);
    body = malloc(4);
    CHECK(body != NULL);
    body[0] = 0;
    body[1] = 255;
    body[2] = 42;
    body[3] = 17;
    id = flb_wasm_http_begin(&headers, "https://example.invalid/", "POST", &headers, body, 4, 1000, 0);
    CHECK(id > 0);
    memset(body, 0, 4);
    free(body);
    flb_kv_release(&headers);
    CHECK(await_result(id) == 201);
    CHECK(flb_wasm_http_poll(id) == -1);

    /* Use the unmodified legacy allocation, header lookup and destroy APIs. */
    for (i = 0; i < 2; i++) {
        client = flb_http_dummy_client(NULL, FLB_HTTP_POST, "/", NULL, 0,
                                       "example.invalid", 443, NULL, 0);
        CHECK(client != NULL);
        CHECK(flb_http_basic_auth(client, "demo", "demo") == 0);
        id = flb_wasm_http_begin(client, "https://example.invalid/", "POST",
                                 &client->headers, "\0\xff\x2a\x11", 4, 1000, 0);
        CHECK(id > 0);
        deadline = emscripten_get_now() + 3000;
        while (EM_ASM_INT({ return Module.flbBrowserHttp.result($0).status; }, id) == 0) {
            CHECK(emscripten_get_now() < deadline);
            emscripten_sleep(5);
        }
        if (i == 1) {
            client->resp.data_size_max = 1;
            CHECK(flb_wasm_http_read_response(client, id) == -1);
        }
        else {
            CHECK(flb_wasm_http_read_response(client, id) == 0);
            CHECK(client->resp.status == 201 && client->resp.payload_size == 4);
            CHECK(memcmp(client->resp.payload, "\0\xff\x2a\x11", 4) == 0);
            CHECK(client->resp.payload[4] == '\0');
            response_header = flb_http_get_response_header(client, "X-Response", 10);
            CHECK(response_header && strcmp(response_header, "accepted") == 0);
            flb_sds_destroy(response_header);
            response_header = flb_http_get_response_header(client, "Content-Length", 14);
            CHECK(response_header && strcmp(response_header, "4") == 0);
            flb_sds_destroy(response_header);
        }
        flb_http_client_destroy(client);
        CHECK(EM_ASM_INT({ return Module.flbBrowserHttp.pending(); }) == 0);
    }

    EM_ASM({ Module.testHttpMode = 'large'; });
    id = flb_wasm_http_begin(&headers, "https://example.invalid/", "POST", &headers, "\0\xff\x2a\x11", 4, 1000, 0);
    CHECK(await_result(id) == -1);
    CHECK(flb_kv_item_create(&headers, "Host", "other.example") != NULL);
    CHECK(flb_wasm_http_begin(&headers, "https://example.invalid/", "POST", &headers, "", 0, 1000, 0) == -1);
    flb_kv_release(&headers);
    CHECK(flb_wasm_http_begin(&headers, "https://example.invalid/", "POST", &headers, "", 8 * 1024 * 1024 + 1, 1000, 0) == -1);

    EM_ASM({ Module.testHttpMode = 'hang'; });
    id = flb_wasm_http_begin(&headers, "https://example.invalid/", "POST", &headers, "", 0, 20, 0);
    CHECK(await_result(id) == -1);
    for (i = 0; i < 32; i++) {
        CHECK(flb_wasm_http_begin(&headers, "https://example.invalid/", "POST", &headers, "", 0, 1000, 0) > 0);
    }
    CHECK(flb_wasm_http_begin(&headers, "https://example.invalid/", "POST", &headers, "", 0, 1000, 0) == -1);
    flb_wasm_http_cancel_owner(&headers);
    emscripten_sleep(20);
    CHECK(EM_ASM_INT({ return Module.flbBrowserHttp.pending(); }) == 0);
    puts("WASM HTTP bridge passed: binary copies, bounds, timeout, cancellation");
    return 0;
}
