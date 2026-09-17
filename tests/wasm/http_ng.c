/* SPDX-License-Identifier: Apache-2.0 */
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/wasm/flb_wasm_http.h>
#include <emscripten.h>

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "HTTP NG check failed at %d: %s\n", __LINE__, #value); abort(); \
} } while (0)

static int completed;

static void requests(void)
{
    struct flb_coro *coro;
    struct flb_config *config;
    struct flb_upstream *upstream;
    struct flb_http_client_ng *client;
    struct flb_http_request *request;
    struct flb_http_client_session *session;
    struct flb_http_response *response;
    int methods[] = {HTTP_METHOD_GET, HTTP_METHOD_HEAD, HTTP_METHOD_POST,
                     HTTP_METHOD_PUT, HTTP_METHOD_DELETE, HTTP_METHOD_OPTIONS};
    const char *names[] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"};
    char *header;
    int i;

    coro = flb_coro_get();
    config = coro->data;
    upstream = flb_upstream_create(config, "example.invalid", 443, FLB_IO_TCP, NULL);
    CHECK(upstream != NULL);
    CHECK(flb_http_client_ng_create(NULL, upstream, HTTP_PROTOCOL_VERSION_20, 0) == NULL);
    client = flb_http_client_ng_create(NULL, upstream, HTTP_PROTOCOL_VERSION_AUTODETECT,
                                       FLB_HTTP_CLIENT_FLAG_AUTO_DEFLATE);
    CHECK(client != NULL);
    CHECK(flb_http_client_session_create(client, HTTP_PROTOCOL_VERSION_20, NULL) == NULL);
    session = flb_http_client_session_begin(client);
    CHECK(session != NULL);
    request = flb_http_client_request_begin(session);
    CHECK(request != NULL);
    flb_http_client_request_destroy(request, FLB_FALSE);
    CHECK(cfl_list_is_empty(&session->streams));
    request = flb_http_client_request_begin(session);
    CHECK(request != NULL);
    flb_http_client_request_destroy(request, FLB_TRUE);
    for (i = 0; i < 18; i++) {
        MAIN_THREAD_EM_ASM({ Module.expectedMethod = UTF8ToString($0); }, names[i % 6]);
        request = flb_http_client_request_builder(client,
                    FLB_HTTP_CLIENT_ARGUMENT_METHOD(methods[i % 6]),
                    FLB_HTTP_CLIENT_ARGUMENT_HOST("example.invalid"),
                    FLB_HTTP_CLIENT_ARGUMENT_URI("/binary"),
                    FLB_HTTP_CLIENT_ARGUMENT_BASIC_AUTHORIZATION("test", "secret"));
        CHECK(request != NULL);
        CHECK(flb_http_request_set_query_string(request, "a=1&b=%2F") == 0);
        if (i < 6) {
            CHECK(flb_http_request_set_content_type(request, "application/octet-stream") == 0);
        }
        else if (i < 12) {
            CHECK(flb_http_request_set_header(request, "content-type", 0,
                                               "application/octet-stream", 0) == 0);
        }
        else {
            CHECK(flb_http_request_set_content_type(request, "application/json") == 0);
            CHECK(flb_http_request_set_header(request, "Content-Type", 0,
                                               "application/octet-stream", 0) == 0);
        }
        if (i % 6 >= 2) {
            CHECK(flb_http_request_set_body(request, (unsigned char *) "\0\xff\x2a", 3, NULL) == 0);
        }
        response = flb_http_client_request_execute_step(request);
        CHECK(response != NULL && response->status == 201);
        CHECK(request->stream->status == HTTP_STREAM_STATUS_READY);
        CHECK(flb_http_client_request_execute(request) == response);
        CHECK(response->body && cfl_sds_len(response->body) == 4);
        CHECK(memcmp(response->body, "\0\xff\x2a\x11", 4) == 0);
        CHECK(response->content_length == 4);
        CHECK(response->content_type && strcmp(response->content_type, "application/octet-stream") == 0);
        header = flb_http_response_get_header(response, "X-Response");
        CHECK(header && strcmp(header, "accepted") == 0);
        header = flb_http_response_get_header(response, "X-Empty");
        CHECK(header && *header == '\0');
        header = flb_http_response_get_header(response, "Content-Length");
        CHECK(header && strcmp(header, "4") == 0);
        flb_http_client_request_destroy(request, FLB_TRUE);
    }
    request = flb_http_client_request_builder(client,
                FLB_HTTP_CLIENT_ARGUMENT_METHOD(HTTP_METHOD_POST),
                FLB_HTTP_CLIENT_ARGUMENT_URI("/"));
    CHECK(request != NULL);
    CHECK(flb_http_request_set_url(request, "http://example.invalid/") == -1);
    CHECK(flb_http_request_set_header(request, "Host", 0, "other.invalid", 0) == 0);
    CHECK(flb_http_client_request_execute(request) == NULL);
    flb_http_client_request_destroy(request, FLB_TRUE);
    request = flb_http_client_request_builder(client,
                FLB_HTTP_CLIENT_ARGUMENT_CONTENT_TYPE("application/grpc"));
    CHECK(request != NULL);
    CHECK(flb_http_client_request_execute(request) == NULL);
    /* Leave this session to client destruction to exercise ownership cleanup. */
    flb_http_client_ng_destroy(client);
    flb_upstream_destroy(upstream);
    CHECK(MAIN_THREAD_EM_ASM_INT({ return Module.flbBrowserHttp.pending(); }) == 0);
    CHECK(MAIN_THREAD_EM_ASM_INT({ return Module.testCalls; }) == 18);
    completed = 1;
    flb_coro_yield(coro, FLB_TRUE);
    abort();
}

/* Object ownership can also be checked under ASan without switching fiber stacks. */
static void objects(void)
{
    struct flb_upstream upstream = {0};
    struct flb_http_client_ng *client;
    struct flb_http_client_session *session;
    struct flb_http_request *request;
    int i;

    for (i = 0; i < 32; i++) {
        client = flb_http_client_ng_create(NULL, &upstream, HTTP_PROTOCOL_VERSION_AUTODETECT,
                                           FLB_HTTP_CLIENT_FLAG_AUTO_DEFLATE);
        CHECK(client != NULL);
        session = flb_http_client_session_create(client, HTTP_PROTOCOL_VERSION_AUTODETECT, NULL);
        CHECK(session != NULL);
        request = flb_http_client_request_begin(session);
        CHECK(request != NULL);
        CHECK(flb_http_request_set_url(request, "https://example.invalid:443/path?a=1") == 0);
        CHECK(flb_http_request_set_authorization(request, HTTP_WWW_AUTHORIZATION_SCHEME_BEARER,
                                                 "example-token") == 0);
        CHECK(flb_http_request_set_body(request, (unsigned char *) "hello", 5, "gzip") == 0);
        CHECK(flb_http_request_get_header(request, "Content-Encoding") != NULL);
        CHECK(flb_http_response_set_header(&request->stream->response, "X-Empty", 0, "", 0) == 0);
        CHECK(flb_http_response_set_body(&request->stream->response, (unsigned char *) "\0\xff", 2) == 0);
        if (i % 2 == 0) {
            flb_http_client_request_destroy(request, FLB_TRUE);
        }
        /* Otherwise the client owns and destroys its remaining session/stream. */
        flb_http_client_ng_destroy(client);
        CHECK(flb_http_client_ng_create(NULL, &upstream, HTTP_PROTOCOL_VERSION_20, 0) == NULL);
    }
    puts("HTTP NG objects passed: URL, bearer auth, compression, response and ownership");
}

int main(int argc, char **argv)
{
    struct flb_config config = {0};
    struct flb_coro *coro;
    struct mk_event_loop *evl;
    struct mk_event *event;
    struct flb_sched *sched;
    size_t stack_size;
    double deadline;

    objects();
    if (argc > 1 && strcmp(argv[1], "--objects-only") == 0) {
        return 0;
    }
    MAIN_THREAD_EM_ASM({
        Module.testCalls = 0;
        globalThis.fetch = async (url, options) => {
            if (url !== 'https://example.invalid:443/binary?a=1&b=%2F' ||
                options.method !== Module.expectedMethod ||
                options.headers.get('authorization') !== 'Basic dGVzdDpzZWNyZXQ=' ||
                options.headers.get('content-type') !== 'application/octet-stream') {
                throw new Error('Incorrect request mapping: ' + url + ' ' + options.method);
            }
            if (!['GET', 'HEAD'].includes(options.method) &&
                String(Array.from(options.body)) !== '0,255,42') {
                throw new Error('Incorrect binary body');
            }
            Module.testCalls++;
            return new Response(new Uint8Array([0, 255, 42, 17]), {
                status: 201, headers: {'X-Response': 'accepted', 'X-Empty': '',
                                       'Content-Type': 'application/octet-stream'}
            });
        };
    });
    flb_coro_init();
    flb_upstream_init();
    flb_sched_ctx_init();
    mk_list_init(&config.upstreams);
    config.is_running = FLB_TRUE;
    evl = mk_event_loop_create(32);
    CHECK(evl != NULL);
    sched = flb_sched_create(&config, evl);
    CHECK(sched != NULL);
    flb_sched_ctx_set(sched);
    coro = flb_coro_create(&config);
    CHECK(coro != NULL);
    coro->callee = co_create(256 * 1024, requests, &stack_size);
    CHECK(coro->callee != NULL);
    flb_coro_resume(coro);
    deadline = emscripten_get_now() + 10000;
    while (!completed) {
        CHECK(emscripten_get_now() < deadline);
        CHECK(mk_event_wait_2(evl, 100) >= 0);
        mk_event_foreach(event, evl) {
            CHECK(flb_sched_event_handler(&config, event) == 0);
        }
    }
    flb_coro_destroy(coro);
    flb_coro_set(NULL);
    flb_sched_ctx_set(NULL);
    flb_sched_destroy(sched);
    mk_event_loop_destroy(evl);
    puts("HTTP NG passed: method mapping, builder, query, auth, binary response, headers, ownership, rejection");
    return 0;
}
