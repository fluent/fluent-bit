/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FLB_WASM_HTTP_H
#define FLB_WASM_HTTP_H

struct flb_http_request;
struct flb_http_response;

struct flb_http_response *flb_wasm_http_request_execute(struct flb_http_request *request);

#include <stddef.h>
#include <monkey/mk_core/mk_list.h>
struct flb_http_client;
struct flb_config;

/* begin copies all request data before returning an opaque positive ID.
 * No C pointers survive in asynchronous JS callbacks. wait_response runs in a
 * Fluent Bit coroutine. cancel_owner is required during owner teardown. */
int flb_wasm_http_validate(const char *url);
int flb_wasm_http_begin(void *owner, const char *url, const char *method,
                       struct mk_list *headers, const void *body, size_t size,
                       int timeout_ms, int log_response);
/* 0: pending, positive: HTTP status, -1: failed/cancelled; consumes completion. */
int flb_wasm_http_poll(int request_id);
void flb_wasm_http_cancel_owner(void *owner);
int flb_wasm_http_execute(struct flb_http_client *client, size_t *bytes);
int flb_wasm_http_read_response(struct flb_http_client *client, int request_id);
int flb_wasm_http_wait_response(int request_id, struct flb_config *config);
void flb_wasm_http_shutdown(struct flb_config *config);

#endif
