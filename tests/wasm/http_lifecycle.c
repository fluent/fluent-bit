/* SPDX-License-Identifier: Apache-2.0 */
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/wasm/flb_wasm_http.h>
#include <emscripten.h>

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "HTTP lifecycle check failed at %d: %s\n", __LINE__, #value); abort(); \
} } while (0)

struct test_request {
    struct flb_config *config;
    int completed;
    int use_ng;
};

static void flush_request(void)
{
    struct flb_coro *coro;
    struct test_request *request;
    struct flb_upstream upstream = {0};
    struct flb_connection connection = {0};
    struct flb_http_client *client;
    struct flb_http_client_ng ng;
    struct flb_http_client_session *session;
    struct flb_http_request *http_request;
    char *payload;
    size_t bytes;

    coro = flb_coro_get();
    request = coro->data;
    upstream.base.config = request->config;
    upstream.tcp_host = "example.invalid";
    upstream.tcp_port = 443;
    connection.upstream = &upstream;
    connection.net = &upstream.base.net;
    connection.fd = -1;
    payload = flb_strdup("plugin-owned payload");
    CHECK(payload != NULL);
    if (request->use_ng) {
        CHECK(flb_http_client_ng_init(&ng, NULL, &upstream, HTTP_PROTOCOL_VERSION_AUTODETECT, 0) == 0);
        session = flb_http_client_session_create(&ng, HTTP_PROTOCOL_VERSION_AUTODETECT, NULL);
        CHECK(session != NULL);
        session->connection = &connection;
        http_request = flb_http_client_request_begin(session);
        CHECK(http_request != NULL);
        CHECK(flb_http_request_set_method(http_request, HTTP_METHOD_POST) == 0);
        CHECK(flb_http_request_set_body(http_request, (unsigned char *) payload, strlen(payload), NULL) == 0);
        CHECK(flb_http_client_request_execute(http_request) == NULL);
        /* The test borrows a stack connection instead of taking one from an upstream. */
        session->connection = NULL;
        flb_http_client_request_destroy(http_request, FLB_TRUE);
        flb_http_client_ng_destroy(&ng);
    }
    else {
        client = flb_http_client(&connection, FLB_HTTP_POST, "/", payload, strlen(payload),
                             "example.invalid", 443, NULL, 0);
        CHECK(client != NULL);
        CHECK(flb_http_do(client, &bytes) == -1);
        flb_http_client_destroy(client);
    }
    flb_free(payload);
    request->completed = 1;
    flb_coro_yield(coro, FLB_TRUE);
    abort();
}

int main(void)
{
    struct flb_config config = {0};
    struct test_request requests[2] = {{0}};
    struct flb_coro *coroutines[2];
    struct mk_event_loop *evl;
    struct flb_sched *sched;
    size_t stack_size;
    int timer_count;
    int i;

    MAIN_THREAD_EM_ASM({
        globalThis.fetch = (url, options) => new Promise((resolve, reject) => {
            options.signal.addEventListener('abort', () => reject(new Error('Cancelled')), {once: true});
        });
    });
    flb_coro_init();
    config.is_running = FLB_TRUE;
    flb_sched_ctx_init();
    evl = mk_event_loop_create(32);
    CHECK(evl != NULL);
    sched = flb_sched_create(&config, evl);
    CHECK(sched != NULL);
    flb_sched_ctx_set(sched);
    timer_count = mk_list_size(&sched->timers);
    for (i = 0; i < 2; i++) {
        requests[i].config = &config;
        requests[i].use_ng = i;
        coroutines[i] = flb_coro_create(&requests[i]);
        CHECK(coroutines[i] != NULL);
        coroutines[i]->callee = co_create(256 * 1024, flush_request, &stack_size);
        CHECK(coroutines[i]->callee != NULL);
        flb_coro_resume(coroutines[i]);
        CHECK(requests[i].completed == 0);
    }
    CHECK(MAIN_THREAD_EM_ASM_INT({ return Module.flbBrowserHttp.pending(); }) == 2);
    CHECK(mk_list_size(&sched->timers) == timer_count + 2);
    config.is_shutting_down = FLB_TRUE;
    config.is_running = FLB_FALSE;
    flb_wasm_http_shutdown(&config);
    CHECK(MAIN_THREAD_EM_ASM_INT({ return Module.flbBrowserHttp.pending(); }) == 0);
    CHECK(mk_list_size(&sched->timers) == timer_count);
    for (i = 0; i < 2; i++) {
        CHECK(requests[i].completed == 1);
        flb_coro_destroy(coroutines[i]);
    }
    flb_coro_set(NULL);
    flb_sched_ctx_set(NULL);
    flb_sched_destroy(sched);
    mk_event_loop_destroy(evl);
    puts("HTTP forced shutdown passed: both callbacks cleaned up, no pending requests or timers");
    return 0;
}
