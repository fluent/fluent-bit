/* SPDX-License-Identifier: Apache-2.0 */
#include <fluent-bit/wasm/flb_wasm_http.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_time_utils.h>
#include <emscripten.h>

struct browser_wait {
    struct browser_wait *next;
    struct flb_config *config;
    struct flb_coro *coro;
    struct flb_sched_timer *timer;
    int request_id;
};

static _Thread_local struct browser_wait *active_waits;

static void browser_wakeup(struct flb_config *config, void *data)
{
    struct browser_wait *wait = data;

    wait->timer = NULL;
    flb_coro_resume(wait->coro);
}

int flb_wasm_http_wait_response(int request_id, struct flb_config *config)
{
    struct browser_wait wait;
    struct browser_wait **link;
    struct flb_sched *sched;
    int status = -1;

    wait.coro = flb_coro_get();
    sched = flb_sched_ctx_get();
    if (!wait.coro || !sched) {
        return -1;
    }
    wait.config = config;
    wait.request_id = request_id;
    wait.timer = NULL;
    wait.next = active_waits;
    active_waits = &wait;
    /* Preserve the engine's grace period; cancel only at actual teardown. */
    while (config->is_running) {
        status = MAIN_THREAD_EM_ASM_INT({
            var request = Module.flbBrowserHttp.result($0);
            return request ? request.status : -1;
        }, request_id);
        if (status != 0) {
            break;
        }
        if (flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_ONESHOT, 20,
                                      browser_wakeup, &wait, &wait.timer) != 0) {
            status = -1;
            break;
        }
        flb_coro_yield(wait.coro, FLB_FALSE);
    }
    for (link = &active_waits; *link != &wait; link = &(*link)->next) {
    }
    *link = wait.next;
    return config->is_running ? status : -1;
}

void flb_wasm_http_shutdown(struct flb_config *config)
{
    struct browser_wait *wait;
    struct flb_coro *caller;

    caller = flb_coro_get();
    for (;;) {
        for (wait = active_waits; wait && wait->config != config; wait = wait->next) {
        }
        if (!wait) {
            flb_coro_set(caller);
            return;
        }
        MAIN_THREAD_EM_ASM({ Module.flbBrowserHttp.cancel($0); }, wait->request_id);
        if (wait->timer) {
            flb_sched_timer_cb_disable(wait->timer);
            flb_sched_timer_cb_destroy(wait->timer);
            wait->timer = NULL;
        }
        /* The resumed callback removes its wait and frees plugin-owned buffers. */
        flb_coro_resume(wait->coro);
    }
}

int flb_wasm_http_validate(const char *url)
{
    if (!url) {
        return -1;
    }
    return MAIN_THREAD_EM_ASM_INT({
        return Module['flbBrowserHttp'].validate(UTF8ToString($0)) ? 0 : -1;
    }, url);
}

int flb_wasm_http_begin(void *owner, const char *url, const char *method,
                       struct mk_list *headers, const void *body, size_t size,
                       int timeout_ms, int log_response)
{
    const char *pairs[256];
    struct mk_list *head;
    struct flb_kv *kv;
    int count = 0;

    if (!url || !method || size > 8 * 1024 * 1024 || (!body && size > 0)) {
        return -1;
    }
    mk_list_foreach(head, headers) {
        if (count == 128) {
            return -1;
        }
        kv = mk_list_entry(head, struct flb_kv, _head);
        pairs[count * 2] = kv->key;
        pairs[count * 2 + 1] = kv->val;
        count++;
    }
    return MAIN_THREAD_EM_ASM_INT({
        var headers = [];
        for (var i = 0; i < $4; i++) {
            headers.push([UTF8ToString(HEAPU32[($3 >> 2) + i * 2]),
                          UTF8ToString(HEAPU32[($3 >> 2) + i * 2 + 1])]);
        }
        return Module['flbBrowserHttp'].begin($0, UTF8ToString($1), UTF8ToString($2),
            headers, HEAPU8.slice($5, $5 + $6), $7, Boolean($8));
    }, owner, url, method, pairs, count, body, size, timeout_ms, log_response);
}

int flb_wasm_http_poll(int request_id)
{
    return MAIN_THREAD_EM_ASM_INT({
        return Module['flbBrowserHttp'].poll($0);
    }, request_id);
}

void flb_wasm_http_cancel_owner(void *owner)
{
    MAIN_THREAD_EM_ASM({ Module['flbBrowserHttp'].cancelOwner($0); }, owner);
}
