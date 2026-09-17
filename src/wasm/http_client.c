/* SPDX-License-Identifier: Apache-2.0 */
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/wasm/flb_wasm_http.h>
#include <emscripten.h>

static int browser_execute(struct flb_http_client *c, size_t *bytes, const char *method);

/* Both public client interfaces share the same Fetch limits and cancellation. */
struct flb_http_response *flb_wasm_http_request_execute(struct flb_http_request *request)
{
    struct flb_http_client_session *session;
    struct flb_http_client *client;
    struct flb_http_response *response;
    struct flb_hash_table_entry *entry;
    struct mk_list *head;
    flb_sds_t uri;
    char *line;
    char *end;
    char *colon;
    char *content_type;
    size_t bytes;
    int result;
    int method;

    method = FLB_HTTP_POST;

    if (!request || !request->stream || !request->stream->parent) {
        return NULL;
    }
    session = request->stream->parent;
    response = &request->stream->response;
    if (request->stream->status == HTTP_STREAM_STATUS_READY) {
        return response;
    }
    if (request->stream->status != HTTP_STREAM_STATUS_SENDING_HEADERS ||
        !session->connection || !request->headers ||
        (request->trailer_headers && request->trailer_headers->total_count > 0)) {
        return NULL;
    }
    /* The two public APIs use different integer values for HTTP methods. */
    switch (request->method) {
    case HTTP_METHOD_GET: method = FLB_HTTP_GET; break;
    case HTTP_METHOD_HEAD: method = FLB_HTTP_HEAD; break;
    case HTTP_METHOD_POST: method = FLB_HTTP_POST; break;
    case HTTP_METHOD_PUT: method = FLB_HTTP_PUT; break;
    case HTTP_METHOD_DELETE: method = FLB_HTTP_DELETE; break;
    case HTTP_METHOD_OPTIONS: break;
    default: return NULL;
    }
    content_type = flb_http_request_get_header(request, "content-type");
    if (!content_type) {
        content_type = request->content_type;
    }
    if (content_type && strncasecmp(content_type, "application/grpc", 16) == 0) {
        flb_error("[http_client] browser Fetch does not support native gRPC");
        return NULL;
    }
    uri = flb_sds_create(request->path ? request->path : "/");
    if (!uri) {
        return NULL;
    }
    if (request->query_string &&
        !flb_sds_printf(&uri, "%s%s", strchr(uri, '?') ? "&" : "?", request->query_string)) {
        flb_sds_destroy(uri);
        return NULL;
    }
    client = flb_http_client(session->connection, method, uri,
                             request->body, request->body ? cfl_sds_len(request->body) : 0,
                             request->host, request->port, NULL, 0);
    if (!client) {
        flb_sds_destroy(uri);
        return NULL;
    }
    /* JS bounds both the body and the browser-visible response headers to 64 KiB. */
    flb_http_buffer_size(client, 128 * 1024 + 1);
    /* The NG header table has one value per name. Explicit headers override
     * the content-type fallback without becoming a comma-separated value. */
    flb_http_allow_duplicated_headers(client, FLB_FALSE);
    result = 0;
    if (content_type) {
        result = flb_http_add_header(client, "Content-Type", 12, content_type, strlen(content_type));
    }
    mk_list_foreach(head, &request->headers->entries) {
        entry = mk_list_entry(head, struct flb_hash_table_entry, _head_parent);
        if (result != 0 || entry->val_size < 0 ||
            memchr(entry->key, '\0', entry->key_len) ||
            (entry->val_size > 1 && memchr(entry->val, '\0', entry->val_size - 1))) {
            result = -1;
            break;
        }
        result = flb_http_add_header(client, entry->key, entry->key_len,
                                     entry->val, strlen(entry->val));
    }
    if (result == 0) {
        request->stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;
        result = browser_execute(client, &bytes,
                                  request->method == HTTP_METHOD_OPTIONS ? "OPTIONS" : NULL);
    }
    if (result == 0) {
        response->status = client->resp.status;
        response->protocol_version = session->protocol_version;
        response->content_length = client->resp.payload_size;
        result = flb_http_response_set_body(response, (unsigned char *) client->resp.payload,
                                            client->resp.payload_size);
        /* This prefix was synthesized from Fetch headers, not parsed from a socket. */
        line = strstr(client->resp.data, "\r\n");
        while (result == 0 && line && line + 2 < client->resp.headers_end) {
            line += 2;
            end = strstr(line, "\r\n");
            if (!end || end == line) {
                break;
            }
            colon = memchr(line, ':', end - line);
            if (!colon) {
                result = -1;
                break;
            }
            *end = '\0';
            result = flb_http_response_set_header(response, line, colon - line,
                                                  colon + 2, end - colon - 2);
            *end = '\r';
            line = end;
        }
        content_type = flb_http_response_get_header(response, "content-type");
        if (result == 0 && content_type) {
            response->content_type = cfl_sds_create(content_type);
            if (!response->content_type) {
                result = -1;
            }
        }
    }
    flb_http_client_destroy(client);
    flb_sds_destroy(uri);
    request->stream->status = result == 0 ? HTTP_STREAM_STATUS_READY : HTTP_STREAM_STATUS_CLOSED;
    return result == 0 ? response : NULL;
}

/* Implement the legacy client's execution contract, not plugin retry policy. */
int flb_wasm_http_execute(struct flb_http_client *c, size_t *bytes)
{
    return browser_execute(c, bytes, NULL);
}

static int browser_execute(struct flb_http_client *c, size_t *bytes, const char *method)
{
    struct flb_upstream *u;
    struct flb_config *config;
    const char *host;
    flb_sds_t url;
    int port;
    int timeout;
    int id;
    int status;

    if (!c || !bytes) {
        return -1;
    }
    *bytes = 0;
    if (!c->u_conn || !c->u_conn->upstream || c->proxy.host || c->read_idle_timeout) {
        return -1;
    }
    u = c->u_conn->upstream;
    config = u->base.config;
    if (!config->is_running) {
        return -1;
    }
    if (!method) {
        switch (c->method) {
        case FLB_HTTP_GET: method = "GET"; break;
        case FLB_HTTP_HEAD: method = "HEAD"; break;
        case FLB_HTTP_POST: method = "POST"; break;
        case FLB_HTTP_PUT: method = "PUT"; break;
        case FLB_HTTP_PATCH: method = "PATCH"; break;
        case FLB_HTTP_DELETE: method = "DELETE"; break;
        default: return -1;
        }
    }
    if ((c->method == FLB_HTTP_GET || c->method == FLB_HTTP_HEAD) && c->body_len) {
        return -1;
    }
    timeout = c->response_timeout ? c->response_timeout : 30;
    if (c->request_net_setup.io_timeout > 0 && c->request_net_setup.io_timeout < timeout) {
        timeout = c->request_net_setup.io_timeout;
    }
    if (timeout < 1 || timeout > 120) {
        return -1;
    }
    if (u->browser_url) {
        url = flb_sds_create(u->browser_url);
    }
    else {
        host = c->host ? c->host : u->tcp_host;
        port = c->port ? c->port : u->tcp_port;
        if (!host || strpbrk(host, "/@?#\\\r\n") || port < 1 || port > 65535 ||
            !c->uri || c->uri[0] != '/') {
            return -1;
        }
        url = flb_sds_create_size(strlen(host) + strlen(c->uri) + 32);
        if (url && !flb_sds_printf(&url, "https://%s%s%s:%i%s",
                                   strchr(host, ':') && host[0] != '[' ? "[" : "",
                                   host, strchr(host, ':') && host[0] != '[' ? "]" : "",
                                   port, c->uri)) {
            flb_sds_destroy(url);
            return -1;
        }
    }
    if (!url) {
        return -1;
    }
    id = flb_wasm_http_begin(c, url, method, &c->headers, c->body_buf,
                             c->body_len, timeout * 1000, 0);
    flb_sds_destroy(url);
    if (id < 1) {
        return -1;
    }
    status = flb_wasm_http_wait_response(id, config);
    if (status < 0) {
        flb_wasm_http_cancel_owner(c);
        return -1;
    }
    if (flb_wasm_http_read_response(c, id) != 0) {
        return -1;
    }
    *bytes = c->body_len;
    return 0;
}

int flb_wasm_http_read_response(struct flb_http_client *c, int id)
{
    char *response;
    int status;
    int size;
    int header_size;

    status = MAIN_THREAD_EM_ASM_INT({
        var r = Module.flbBrowserHttp.result($0);
        return r ? r.status : -1;
    }, id);
    size = MAIN_THREAD_EM_ASM_INT({
        var r = Module.flbBrowserHttp.result($0);
        return r && r.response ? r.response.length : -1;
    }, id);
    header_size = MAIN_THREAD_EM_ASM_INT({
        var r = Module.flbBrowserHttp.result($0);
        return r ? r.headerLength : 0;
    }, id);
    if (status < 100 || size < header_size || header_size < 1 ||
        (c->resp.data_size_max && size + 1 > c->resp.data_size_max)) {
        flb_wasm_http_cancel_owner(c);
        return -1;
    }
    response = flb_malloc(size + 1);
    if (!response) {
        flb_wasm_http_cancel_owner(c);
        return -1;
    }
    MAIN_THREAD_EM_ASM({
        HEAPU8.set(Module.flbBrowserHttp.result($0).response, $1);
    }, id, response);
    response[size] = '\0';
    flb_wasm_http_cancel_owner(c);
    flb_free(c->resp.data);
    c->resp.data = response;
    c->resp.data_len = size;
    c->resp.data_size = size + 1;
    c->resp.headers_end = response + header_size;
    c->resp.payload = response + header_size;
    c->resp.payload_size = size - header_size;
    c->resp.content_length = size - header_size;
    c->resp.status = status;
    c->resp.chunked_encoding = FLB_FALSE;
    c->resp.connection_close = FLB_TRUE;
    flb_debug("[http_client] browser HTTPS status=%i", status);
    return 0;
}

/* Native plugins may link these paths even when OAuth2 is disabled. */
struct flb_oauth2 *flb_oauth2_create_from_config(struct flb_config *config,
                                               const struct flb_oauth2_config *cfg)
{
    flb_error("[oauth2] browser token acquisition is not implemented");
    return NULL;
}

void flb_oauth2_destroy(struct flb_oauth2 *ctx)
{
    /* No browser OAuth2 context can be created. */
}

int flb_oauth2_get_access_token(struct flb_oauth2 *ctx, flb_sds_t *token_out, int force_refresh)
{
    *token_out = NULL;
    return -1;
}

void flb_oauth2_invalidate_token(struct flb_oauth2 *ctx)
{
    /* Browser output initialization rejects OAuth2 configuration. */
}
