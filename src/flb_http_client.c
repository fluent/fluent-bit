/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

/*
 * This is a very simple HTTP Client interface which aims to provide an
 * easy way to issue HTTP requests and handle reponses from the input/output
 * plugins.
 *
 * It scope is:
 *
 * - Use upstream connections.
 * - Support 'retry' in case the HTTP server timeouts a connection.
 * - Get return Status, Headers and Body content if found.
 * - If Upstream supports keepalive, adjust headers
 */

#define _GNU_SOURCE
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_lock.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_http_common.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_http_client_debug.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/tls/flb_tls.h>
#include <time.h>
#include <fluent-bit/flb_signv4_ng.h>

void flb_http_client_debug(struct flb_http_client *c,
                           struct flb_callback *cb_ctx)
{
#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    if (cb_ctx) {
        flb_http_client_debug_enable(c, cb_ctx);
    }
#endif
}

/*
 * Removes the port from the host header
 */
int flb_http_strip_port_from_host(struct flb_http_client *c)
{
    struct mk_list *head;
    struct flb_kv *kv;
    char *out_host;
    struct flb_upstream *u;

    u = c->u_conn->upstream;

    if (!c->host) {
        if (!u->proxied_host) {
            out_host = u->tcp_host;
        } else {
            out_host = u->proxied_host;
        }
    } else {
        out_host = (char *) c->host;
    }

    mk_list_foreach(head, &c->headers) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp("Host", kv->key) == 0) {
            flb_sds_destroy(kv->val);
            kv->val = NULL;
            kv->val = flb_sds_create(out_host);
            if (!kv->val) {
                flb_errno();
                return -1;
            }
            return 0;
        }
    }

    return -1;
}

int flb_http_allow_duplicated_headers(struct flb_http_client *c, int allow)
{
    if (allow != FLB_TRUE && allow != FLB_FALSE) {
        return -1;
    }

    c->allow_dup_headers = allow;
    return 0;
}

/* check if there is enough space in the client header buffer */
static int header_available(struct flb_http_client *c, int bytes)
{
    int available;

    available = c->header_size - c->header_len;
    if (available < bytes) {
        return -1;
    }

    return 0;
}

/* Try to find a header value in the buffer */
static int header_lookup(struct flb_http_client *c,
                         const char *header, int header_len,
                         const char **out_val, int *out_len)
{
    char *p;
    char *crlf;
    char *end;

    if (!c->resp.data) {
        return FLB_HTTP_MORE;
    }

    /* Lookup the beginning of the header */
    p = strcasestr(c->resp.data, header);
    end = strstr(c->resp.data, "\r\n\r\n");
    if (!p) {
        if (end) {
            /* The headers are complete but the header is not there */
            return FLB_HTTP_NOT_FOUND;
        }

        /* We need more data */
        return FLB_HTTP_MORE;
    }

    /* Exclude matches in the body */
    if (end && p > end) {
        return FLB_HTTP_NOT_FOUND;
    }

    /* Lookup CRLF (end of line \r\n) */
    crlf = strstr(p, "\r\n");
    if (!crlf) {
        return FLB_HTTP_MORE;
    }

    p += header_len;

    *out_val = p;
    *out_len = (crlf - p);

    return FLB_HTTP_OK;
}

/* HTTP/1.1: Check if we have a Chunked Transfer Encoding */
static int check_chunked_encoding(struct flb_http_client *c)
{
    int ret;
    int len;
    const char *header = NULL;

    ret = header_lookup(c, "Transfer-Encoding: ", 19,
                        &header, &len);
    if (ret == FLB_HTTP_NOT_FOUND) {
        /* If the header is missing, this is fine */
        c->resp.chunked_encoding = FLB_FALSE;
        return FLB_HTTP_OK;
    }
    else if (ret == FLB_HTTP_MORE) {
        return FLB_HTTP_MORE;
    }

    if (strncasecmp(header, "chunked", len) == 0) {
        c->resp.chunked_encoding = FLB_TRUE;
    }

    return FLB_HTTP_OK;
}

/* Check response for a 'Content-Length' header */
static int check_content_length(struct flb_http_client *c)
{
    int ret;
    int len;
    const char *header;
    char tmp[256];

    if (c->resp.status == 204) {
        c->resp.content_length = -1;
        return FLB_HTTP_OK;
    }

    ret = header_lookup(c, "Content-Length: ", 16,
                        &header, &len);
    if (ret == FLB_HTTP_MORE) {
        return FLB_HTTP_MORE;
    }
    else if (ret == FLB_HTTP_NOT_FOUND) {
        return FLB_HTTP_NOT_FOUND;
    }

    if (len > sizeof(tmp) - 1) {
        /* Value too long */
        return FLB_HTTP_ERROR;
    }

    /* Copy to temporary buffer */
    memcpy(tmp, header, len);
    tmp[len] = '\0';

    c->resp.content_length = atoi(tmp);
    return FLB_HTTP_OK;
}

/* Check response for a 'Connection' header */
static int check_connection(struct flb_http_client *c)
{
    int ret;
    int len;
    const char *header;
    char *buf;

    ret = header_lookup(c, "Connection: ", 12,
                        &header, &len);
    if (ret == FLB_HTTP_NOT_FOUND) {
        return FLB_HTTP_NOT_FOUND;
    }
    else if (ret == FLB_HTTP_MORE) {
        return FLB_HTTP_MORE;
    }

    buf = flb_malloc(len + 1);
    if (!buf) {
        flb_errno();
        return FLB_HTTP_ERROR;
    }

    memcpy(buf, header, len);
    buf[len] = '\0';

    if (strncasecmp(buf, "close", 5) == 0) {
        c->resp.connection_close = FLB_TRUE;
    }
    else if (strcasestr(buf, "keep-alive")) {
        c->resp.connection_close = FLB_FALSE;
    }
    flb_free(buf);
    return FLB_HTTP_OK;

}

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline void http_client_response_reset(struct flb_http_client *c)
{
    c->resp.data_len = 0;
    c->resp.status = 0;
    c->resp.content_length = -1;
    c->resp.chunked_encoding = FLB_FALSE;
    c->resp.connection_close = -1;
    c->resp.headers_end = NULL;
    c->resp.payload = NULL;
    c->resp.payload_size = 0;
    c->resp.chunk_processed_end = NULL;
}

static int process_chunked_data(struct flb_http_client *c)
{
    long len;
    long drop;
    long val;
    char *p;
    char tmp[32];
    int found_full_chunk = FLB_FALSE;
    struct flb_http_client_response *r = &c->resp;


 chunk_start:
    p = strstr(r->chunk_processed_end, "\r\n");
    if (!p) {
        return FLB_HTTP_MORE;
    }

    /* Hexa string length */
    len = (p - r->chunk_processed_end);
    if ((len > sizeof(tmp) - 1) || len == 0) {
        return FLB_HTTP_ERROR;
    }
    p += 2;

    /* Copy hexa string to temporary buffer */
    memcpy(tmp, r->chunk_processed_end, len);
    tmp[len] = '\0';

    /* Convert hexa string to decimal */
    errno = 0;
    val = strtol(tmp, NULL, 16);
    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
        || (errno != 0 && val == 0)) {
        flb_errno();
        return FLB_HTTP_ERROR;
    }
    if (val < 0) {
        return FLB_HTTP_ERROR;
    }
    /*
     * 'val' contains the expected number of bytes, check current lengths
     * and do buffer adjustments.
     *
     * we do val + 2 because the chunk always ends with \r\n
     */
    val += 2;

    /* Number of bytes after the Chunk header */
    len = r->data_len - (p - r->data);
    if (len < val) {
        return FLB_HTTP_MORE;
    }

    /* From the current chunk we expect it ends with \r\n */
    if (p[val -2] != '\r' || p[val - 1] != '\n') {
        return FLB_HTTP_ERROR;
    }

    /*
     * At this point we are just fine, the chunk is valid, next steps:
     *
     * 1. check possible last chunk
     * 2. drop chunk header from the buffer
     * 3. remove chunk ending \r\n
     */

    found_full_chunk = FLB_TRUE;
    /* 1. Validate ending chunk */
    if (val - 2 == 0) {
        /*
         * For an ending chunk we expect:
         *
         * 0\r\n
         * \r\n
         *
         * so at least we need 5 bytes in the buffer
         */
        len = r->data_len - (r->chunk_processed_end - r->data);
        if (len < 5) {
            return FLB_HTTP_MORE;
        }

        if (r->chunk_processed_end[3] != '\r' ||
            r->chunk_processed_end[4] != '\n') {
            return FLB_HTTP_ERROR;
        }
    }

    /* 2. Drop chunk header */
    drop = (p - r->chunk_processed_end);
    len =  r->data_len - (r->chunk_processed_end - r->data);
    consume_bytes(r->chunk_processed_end, drop, len);
    r->data_len -= drop;
    r->data[r->data_len] = '\0';

    /* 3. Remove chunk ending \r\n */
    drop = 2;
    r->chunk_processed_end += labs(val - 2);
    len = r->data_len - (r->chunk_processed_end - r->data);
    consume_bytes(r->chunk_processed_end, drop, len);
    r->data_len -= drop;

    /* Always append a NULL byte */
    r->data[r->data_len] = '\0';

    /* Always update payload size after full chunk */
    r->payload_size = r->data_len - (r->headers_end - r->data);

    /* Is this the last chunk ? */
    if ((val - 2 == 0)) {
        /* Update payload size */
        return FLB_HTTP_OK;
    }

    /* If we have some remaining bytes, start over */
    len = r->data_len - (r->chunk_processed_end - r->data);
    if (len > 0) {
        goto chunk_start;
    }

    if (found_full_chunk == FLB_TRUE) {
        return FLB_HTTP_CHUNK_AVAILABLE;
    }

    return FLB_HTTP_MORE;
}

static int process_data(struct flb_http_client *c)
{
    int ret;
    char code[4];
    char *tmp;

    if (c->resp.data_len < 15) {
        /* we need more data */
        return FLB_HTTP_MORE;
    }

    /* HTTP response status */
    if (c->resp.status <= 0) {
        memcpy(code, c->resp.data + 9, 3);
        code[3] = '\0';
        c->resp.status = atoi(code);
        if (c->resp.status < 100 || c->resp.status > 599) {
            return FLB_HTTP_ERROR;
        }
    }

    /* Try to lookup content length */
    if (c->resp.content_length == -1 && c->resp.chunked_encoding == FLB_FALSE) {
        ret = check_content_length(c);
        if (ret == FLB_HTTP_ERROR) {
            return FLB_HTTP_ERROR;
        }
    }

    /* Chunked encoding for HTTP/1.1 (no content length of course) */
    if ((c->flags & FLB_HTTP_11) && c->resp.content_length == -1) {
        if (c->resp.chunked_encoding == FLB_FALSE) {
            ret = check_chunked_encoding(c);
            if (ret == FLB_HTTP_ERROR) {
                return FLB_HTTP_ERROR;
            }
        }
    }

    if (!c->resp.headers_end) {
        tmp = strstr(c->resp.data, "\r\n\r\n");
        if (tmp) {
            c->resp.headers_end = tmp + 4;
            if (c->resp.chunked_encoding == FLB_TRUE) {
                c->resp.chunk_processed_end = c->resp.headers_end;
            }

            /* Mark the payload */
            if ((tmp - c->resp.data + 4) < c->resp.data_len) {
                c->resp.payload = tmp += 4;
                c->resp.payload_size = (c->resp.data_len - (tmp - c->resp.data));
            }
        }
        else {
            return FLB_HTTP_MORE;
        }
    }

    /* Re-check if an ending exists, if so process payload if required */
    if (c->resp.headers_end) {
        /* Mark the payload */
        if (!c->resp.payload &&
            c->resp.headers_end - c->resp.data < c->resp.data_len) {
            c->resp.payload = c->resp.headers_end;
            c->resp.payload_size = (c->resp.data_len - (c->resp.headers_end - c->resp.data));
        }

        if (c->resp.content_length >= 0) {
            c->resp.payload_size = c->resp.data_len;
            c->resp.payload_size -= (c->resp.headers_end - c->resp.data);
            if (c->resp.payload_size >= c->resp.content_length) {
                return FLB_HTTP_OK;
            }
        }
        else if (c->resp.chunked_encoding == FLB_TRUE) {
            ret = process_chunked_data(c);
            if (ret == FLB_HTTP_ERROR) {
                return FLB_HTTP_ERROR;
            }
            else if (ret == FLB_HTTP_OK || ret == FLB_HTTP_CHUNK_AVAILABLE) {
                return ret;
            }
        }
        else {
            return FLB_HTTP_OK;
        }
    }
    else if (c->resp.headers_end && c->resp.content_length <= 0) {
        return FLB_HTTP_OK;
    }

    return FLB_HTTP_MORE;
}

#if defined FLB_HAVE_TESTS_OSSFUZZ
int fuzz_process_data(struct flb_http_client *c);
int fuzz_process_data(struct flb_http_client *c) {
	return process_data(c);
}

int fuzz_check_connection(struct flb_http_client *c);
int fuzz_check_connection(struct flb_http_client *c) {
    return check_connection(c);
}

#endif

static int proxy_parse(const char *proxy, struct flb_http_client *c)
{
    int len;
    int port;
    int off = 0;
    const char *s;
    const char *e;
    const char *host;

    len = strlen(proxy);
    if (len < 7) {
        return -1;
    }

    /* Protocol lookup */
    if (strncmp(proxy, "http://", 7) == 0) {
        port = 80;
        off = 7;
        c->proxy.type = FLB_HTTP_PROXY_HTTP;
    }
    else if (strncmp(proxy, "https://", 8) == 0) {
        port = 443;
        off = 8;
        c->proxy.type = FLB_HTTP_PROXY_HTTPS;
    }
    else {
        return -1;
    }

    /* Separate host/ip from port if any */
    s = proxy + off;
    if (*s == '[') {
        /* IPv6 address (RFC 3986) */
        e = strchr(++s, ']');
        if (!e) {
            return -1;
        }
        host = strndup(s, e - s);
        s = e + 1;
    } else {
        e = s;
        while (!(*e == '\0' || *e == ':' || *e == '/')) {
            ++e;
        }
        if (e == s) {
            return -1;
        }
        host = strndup(s, e - s);
        s = e;
    }
    if (*s == ':') {
        port = atoi(++s);
    }

    flb_trace("[http_client] proxy type=%i host=%s port=%i",
              c->proxy.type, host, port);

    c->proxy.host = host;
    c->proxy.port = port;

    return 0;
}

static int add_host_and_content_length(struct flb_http_client *c)
{
    int len;
    flb_sds_t tmp;
    flb_sds_t host;
    char *out_host;
    int out_port;
    size_t size;
    struct flb_upstream *u = c->u_conn->upstream;

    if (!c->host) {
        if (u->proxied_host) {
            out_host = u->proxied_host;
        }
        else {
            out_host = u->tcp_host;
        }
    }
    else {
        out_host = (char *) c->host;
    }

    len = strlen(out_host);
    host = flb_sds_create_size(len + 32);
    if (!host) {
        flb_error("[http_client] cannot create temporal buffer");
        return -1;
    }

    if (c->port == 0) {
        if (u->proxied_port != 0 ) {
            out_port = u->proxied_port;
        }
        else {
            out_port = u->tcp_port;
        }
    }
    else {
        out_port = c->port;
    }

    if (c->flags & FLB_IO_TLS && out_port == 443) {
        tmp = flb_sds_copy(host, out_host, strlen(out_host));
    }
    else {
        tmp = flb_sds_printf(&host, "%s:%i", out_host, out_port);
    }

    if (!tmp) {
        flb_sds_destroy(host);
        flb_error("[http_client] cannot compose temporary host header");
        return -1;
    }
    host = tmp;
    tmp = NULL;

    flb_http_add_header(c, "Host", 4, host, flb_sds_len(host));
    flb_sds_destroy(host);

    /* Content-Length */
    if (c->body_len >= 0) {
        size = 32;
        tmp = flb_malloc(size);
        if (!tmp) {
            flb_errno();
            return -1;
        }
        len = snprintf(tmp, size - 1, "%i", c->body_len);
        flb_http_add_header(c, "Content-Length", 14, tmp, len);
        flb_free(tmp);
    }

    return 0;
}

struct flb_http_client *create_http_client(struct flb_connection *u_conn,
                                        int method, const char *uri,
                                        const char *body, size_t body_len,
                                        const char *host, int port,
                                        const char *proxy, int flags)
{
    int ret;
    char *p;
    char *buf = NULL;
    char *str_method = NULL;
    char *fmt_plain =                           \
        "%s %s HTTP/1.%i\r\n";
    char *fmt_proxy =                           \
        "%s http://%s:%i%s HTTP/1.%i\r\n"
        "Proxy-Connection: KeepAlive\r\n";
    // TODO: IPv6 should have the format of [ip]:port
    char *fmt_connect =                           \
        "%s %s:%i HTTP/1.%i\r\n"
        "Proxy-Connection: KeepAlive\r\n";

    struct flb_http_client *c;

    switch (method) {
    case FLB_HTTP_GET:
        str_method = "GET";
        break;
    case FLB_HTTP_POST:
        str_method = "POST";
        break;
    case FLB_HTTP_PUT:
        str_method = "PUT";
        break;
    case FLB_HTTP_DELETE:
        str_method = "DELETE";
        break;
    case FLB_HTTP_HEAD:
        str_method = "HEAD";
        break;
    case FLB_HTTP_CONNECT:
        str_method = "CONNECT";
        break;
    case FLB_HTTP_PATCH:
        str_method = "PATCH";
        break;
    };

    buf = flb_calloc(1, FLB_HTTP_BUF_SIZE);
    if (!buf) {
        flb_errno();
        return NULL;
    }

    /* FIXME: handler for HTTPS proxy */
    if (proxy) {
        flb_debug("[http_client] using http_proxy %s for header", proxy);
        ret = snprintf(buf, FLB_HTTP_BUF_SIZE,
                       fmt_proxy,
                       str_method,
                       host,
                       port,
                       uri,
                       flags & FLB_HTTP_10 ? 0 : 1);
    }
    else if (method == FLB_HTTP_CONNECT) {
        flb_debug("[http_client] using HTTP CONNECT for proxy: proxy host %s, proxy port %i", host, port);
        ret = snprintf(buf, FLB_HTTP_BUF_SIZE,
                       fmt_connect,
                       str_method,
                       host,
                       port,
                       flags & FLB_HTTP_10 ? 0 : 1);
    }
    else {
        flb_debug("[http_client] not using http_proxy for header");
        ret = snprintf(buf, FLB_HTTP_BUF_SIZE,
                       fmt_plain,
                       str_method,
                       uri,
                       flags & FLB_HTTP_10 ? 0 : 1);
    }

    if (ret == -1) {
        flb_errno();
        flb_free(buf);
        return NULL;
    }

    c = flb_calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        flb_free(buf);
        return NULL;
    }

    c->u_conn      = u_conn;
    c->method      = method;
    c->uri         = uri;
    c->host        = host;
    c->port        = port;
    c->header_buf  = buf;
    c->header_size = FLB_HTTP_BUF_SIZE;
    c->header_len  = ret;
    c->base_header_len = ret;
    c->flags       = flags;
    c->allow_dup_headers = FLB_TRUE;
    mk_list_init(&c->headers);

    /* Check if we have a query string */
    p = strchr(uri, '?');
    if (p) {
        p++;
        c->query_string = p;
    }

    /* Response */
    c->resp.content_length = -1;
    c->resp.connection_close = -1;

    if (body && body_len > 0) {
        c->body_buf = body;
        c->body_len = body_len;
    }

    /* 'Read' buffer size */
    c->resp.data = flb_malloc(FLB_HTTP_DATA_SIZE_MAX);
    if (!c->resp.data) {
        flb_errno();
        flb_http_client_destroy(c);
        return NULL;
    }
    c->resp.data[0] = '\0';
    c->resp.data_len  = 0;
    c->resp.data_size = FLB_HTTP_DATA_SIZE_MAX;
    c->resp.data_size_max = FLB_HTTP_DATA_SIZE_MAX;

    /* Tests */
    c->test_mode = FLB_FALSE;
    c->test_response.callback = NULL;

    return c;
}

struct flb_http_client *flb_http_dummy_client(struct flb_connection *u_conn,
                                              int method, const char *uri,
                                              const char *body, size_t body_len,
                                              const char *host, int port,
                                              const char *proxy, int flags)
{
    struct flb_http_client *c;

    c = create_http_client(u_conn, method, uri,
                           body, body_len,
                           host, port,
                           proxy, flags);

    if (!c) {
        return NULL;
    }

    return c;
}

struct flb_http_client *flb_http_client(struct flb_connection *u_conn,
                                        int method, const char *uri,
                                        const char *body, size_t body_len,
                                        const char *host, int port,
                                        const char *proxy, int flags)
{
    int ret;
    struct flb_http_client *c;

    c = create_http_client(u_conn, method, uri,
                           body, body_len,
                           host, port,
                           proxy, flags);

    if (!c) {
        return NULL;
    }

    /* Is Upstream connection using keepalive mode ? */
    if (flb_stream_get_flag_status(&u_conn->upstream->base, FLB_IO_TCP_KA)) {
        c->flags |= FLB_HTTP_KA;
    }

    if ((flags & FLB_HTTP_10) == 0) {
        c->flags |= FLB_HTTP_11;
    }

    ret = add_host_and_content_length(c);
    if (ret != 0) {
        flb_http_client_destroy(c);
        return NULL;
    }

    /* Check proxy data */
    if (proxy) {
        flb_debug("[http_client] Using http_proxy: %s", proxy);
        ret = proxy_parse(proxy, c);
        if (ret != 0) {
            flb_debug("[http_client] Something wrong with the http_proxy parsing");
            flb_http_client_destroy(c);
            return NULL;
        }
    }

    return c;
}

/*
 * By default the HTTP client have a fixed buffer to read a response for a
 * simple request. But in certain situations the caller might expect a
 * larger response that exceed the buffer limit.
 *
 * This function allows to set a maximum buffer size for the client
 * response where:
 *
 *   1. size =  0  no limit, read as much as possible.
 *   2. size =  N: specific limit, upon reach limit discard data (default: 4KB)
 */
int flb_http_buffer_size(struct flb_http_client *c, size_t size)
{
    if (size < c->resp.data_size_max && size != 0) {
        flb_error("[http] requested buffer size %lu (bytes) needs to be greater than "
                  "minimum size allowed %lu (bytes)",
                  size, c->resp.data_size_max);
        return -1;
    }

    c->resp.data_size_max = size;
    return 0;
}

size_t flb_http_buffer_available(struct flb_http_client *c)
{
    return (c->resp.data_size - c->resp.data_len);
}

/*
 * Increase the read buffer size based on the limits set by default or manually
 * through the flb_http_buffer_size() function.
 *
 * The parameter 'size' is the amount of extra memory requested.
 */
int flb_http_buffer_increase(struct flb_http_client *c, size_t size,
                             size_t *out_size)
{
    int off_payload = 0;
    int off_headers_end = 0;
    int off_chunk_processed_end = 0;
    char *tmp;
    size_t new_size;
    size_t allocated;

    *out_size = 0;
    new_size = c->resp.data_size + size;

    /* Limit exceeded, adjust */
    if (c->resp.data_size_max != 0) {
        if (new_size > c->resp.data_size_max) {
            new_size = c->resp.data_size_max;
            if (new_size <= c->resp.data_size) {
                /* Can't expand the buffer any further. */
                return -1;
            }
        }
    }


    if (c->resp.headers_end) {
        off_headers_end = c->resp.headers_end - c->resp.data;
    }
    if (c->resp.chunk_processed_end) {
        off_chunk_processed_end = c->resp.chunk_processed_end - c->resp.data;
    }

    /*
     * The payload is a reference to a position of 'data' buffer,
     * we need to adjust the pointer after a memory buffer size change.
     */
    if (c->resp.payload_size > 0) {
        off_payload = c->resp.payload - c->resp.data;
    }

    tmp = flb_realloc(c->resp.data, new_size);
    if (!tmp) {
        flb_errno();
        return -1;
    }
    else {
        allocated = new_size - c->resp.data_size;
        c->resp.data = tmp;
        c->resp.data_size = new_size;

        if (off_headers_end > 0) {
            c->resp.headers_end = c->resp.data + off_headers_end;
        }
        if (off_chunk_processed_end > 0) {
            c->resp.chunk_processed_end = c->resp.data + off_chunk_processed_end;
        }
        if (off_payload > 0) {
            c->resp.payload = c->resp.data + off_payload;
        }
    }

    *out_size = allocated;
    return 0;
}


/* Append a custom HTTP header to the request */
int flb_http_add_header(struct flb_http_client *c,
                        const char *key, size_t key_len,
                        const char *val, size_t val_len)
{
    struct flb_kv *kv;
    struct mk_list *tmp;
    struct mk_list *head;

    if (key_len < 1 || val_len < 1) {
        return -1;
    }

    /* Check any previous header to avoid duplicates */
    if (c->allow_dup_headers == FLB_FALSE) {
        mk_list_foreach_safe(head, tmp, &c->headers) {
            kv = mk_list_entry(head, struct flb_kv, _head);
            if (flb_sds_casecmp(kv->key, key, key_len) == 0) {
                /* the header already exists, remove it */
                flb_kv_item_destroy(kv);
                break;
            }
        }
    }

    /* register new header in the temporal kv list */
    kv = flb_kv_item_create_len(&c->headers,
                                (char *) key, key_len, (char *) val, val_len);
    if (!kv) {
        return -1;
    }

    return 0;
}

int flb_http_remove_header(struct flb_http_client *c,
                          const char *key, size_t key_len)
{
    int removed = 0;
    struct flb_kv *kv;
    struct mk_list *tmp;
    struct mk_list *head;

    mk_list_foreach_safe(head, tmp, &c->headers) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (flb_sds_casecmp(kv->key, key, key_len) == 0) {
            flb_kv_item_destroy(kv);
            removed++;
        }
    }

    return removed;
}

/*
 * flb_http_get_header looks up a first value of request header.
 * The return value should be destroyed after using.
 * The return value is NULL, if the value is not found.
 */
flb_sds_t flb_http_get_header(struct flb_http_client *c,
                              const char *key, size_t key_len)
{
    flb_sds_t ret_str;
    struct flb_kv *kv;
    struct mk_list *head = NULL;
    struct mk_list *tmp  = NULL;

    mk_list_foreach_safe(head, tmp, &c->headers) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (flb_sds_casecmp(kv->key, key, key_len) == 0) {
            ret_str = flb_sds_create(kv->val);
            return ret_str;
        }
    }

    return NULL;
}

static int http_header_push(struct flb_http_client *c, struct flb_kv *header)
{
    char *tmp;
    const char *key;
    const char *val;
    size_t key_len;
    size_t val_len;
    size_t required;
    size_t new_size;

    key = header->key;
    key_len = flb_sds_len(header->key);
    val = header->val;
    val_len = flb_sds_len(header->val);

    /*
     * The new header will need enough space in the buffer:
     *
     * key      : length of the key
     * separator: ': ' (2 bytes)
     * val      : length of the key value
     * CRLF     : '\r\n' (2 bytes)
     */
    required = key_len + 2 + val_len + 2;

    if (header_available(c, required) != 0) {
        if (required < 512) {
            new_size = c->header_size + 512;
        }
        else {
            new_size = c->header_size + required;
        }
        tmp = flb_realloc(c->header_buf, new_size);
        if (!tmp) {
            flb_errno();
            return -1;
        }
        c->header_buf  = tmp;
        c->header_size = new_size;
    }

    /* append the header key */
    memcpy(c->header_buf + c->header_len,
           key, key_len);
    c->header_len += key_len;

    /* append the separator */
    c->header_buf[c->header_len++] = ':';
    c->header_buf[c->header_len++] = ' ';

    /* append the header value */
    memcpy(c->header_buf + c->header_len,
           val, val_len);
    c->header_len += val_len;

    /* Append the ending header CRLF */
    c->header_buf[c->header_len++] = '\r';
    c->header_buf[c->header_len++] = '\n';

    return 0;
}

static int http_headers_compose(struct flb_http_client *c)
{
    int ret;
    struct mk_list *head;
    struct flb_kv *header;

    /* Push header list to one buffer */
    mk_list_foreach(head, &c->headers) {
        header = mk_list_entry(head, struct flb_kv, _head);
        ret = http_header_push(c, header);
        if (ret != 0) {
            flb_error("[http_client] cannot compose request headers");
            return -1;
        }
    }

    return 0;
}

static void http_headers_destroy(struct flb_http_client *c)
{
    flb_kv_release(&c->headers);
}

int flb_http_set_keepalive(struct flb_http_client *c)
{
    /* check if 'keepalive' mode is enabled in the Upstream connection */
    if (flb_stream_is_keepalive(c->u_conn->stream) == FLB_FALSE) {
        return -1;
    }

    /* append header */
    return flb_http_add_header(c,
                               FLB_HTTP_HEADER_CONNECTION,
                               sizeof(FLB_HTTP_HEADER_CONNECTION) - 1,
                               FLB_HTTP_HEADER_KA,
                               sizeof(FLB_HTTP_HEADER_KA) - 1);
}

/* Adds a header specifying that the payload is compressed with gzip */
int flb_http_set_content_encoding_gzip(struct flb_http_client *c)
{
    int ret;

    ret = flb_http_add_header(c,
                              FLB_HTTP_HEADER_CONTENT_ENCODING,
                              sizeof(FLB_HTTP_HEADER_CONTENT_ENCODING) - 1,
                              "gzip", 4);
    return ret;
}

int flb_http_set_content_encoding_zstd(struct flb_http_client *c)
{
    int ret;

    ret = flb_http_add_header(c,
                              FLB_HTTP_HEADER_CONTENT_ENCODING,
                              sizeof(FLB_HTTP_HEADER_CONTENT_ENCODING) - 1,
                              "zstd", 4);
    return ret;
}

int flb_http_set_content_encoding_snappy(struct flb_http_client *c)
{
    int ret;

    ret = flb_http_add_header(c,
                              FLB_HTTP_HEADER_CONTENT_ENCODING,
                              sizeof(FLB_HTTP_HEADER_CONTENT_ENCODING) - 1,
                              "snappy", 6);
    return ret;
}

int flb_http_set_read_idle_timeout(struct flb_http_client *c, int timeout)
{
    c->read_idle_timeout = timeout;
    return 0;
}

int flb_http_set_response_timeout(struct flb_http_client *c, int timeout)
{
    c->response_timeout = timeout;
    return 0;
}

int flb_http_set_callback_context(struct flb_http_client *c,
                                  struct flb_callback *cb_ctx)
{
    c->cb_ctx = cb_ctx;
    return 0;
}

int flb_http_set_response_test(struct flb_http_client *c, char *test_name,
                               const void *data, size_t len,
                               int status,
                               void (*resp_callback) (void *, int, void *, size_t, void *),
                               void *resp_callback_data)
{
    if (!c) {
        return -1;
    }

    /*
     * Enabling a test, set the http_client instance in 'test' mode, so no real
     * http request is invoked, only the desired implemented test.
     */

    /* Response test */
    if (strcmp(test_name, "response") == 0) {
        c->test_mode = FLB_TRUE;
        c->test_response.rt_ctx = c;
        c->test_response.rt_status = status;
        c->test_response.rt_resp_callback = resp_callback;
        c->test_response.rt_data = resp_callback_data;
        if (data != NULL && len > 0) {
            c->resp.payload = (char *)data;
            c->resp.payload_size = len;
            c->resp.status = status;
        }
    }
    else {
        return -1;
    }

    return 0;
}

static int flb_http_run_response_test(struct flb_http_client *c,
                                      const void *data, size_t len)
{
    int ret = 0;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_test_http_response  *htr;

    if (!c) {
        return -1;
    }

    htr = &c->test_response;

    /* Invoke the output plugin formatter test callback */
    ret = htr->callback(c,
                        data, len,
                        &out_buf, &out_size);

    /* Call the runtime test callback checker */
    if (htr->rt_resp_callback) {
        htr->rt_resp_callback(htr->rt_ctx,
                              ret,
                              out_buf, out_size,
                              htr->rt_data);
    }
    else {
        flb_free(out_buf);
    }

    return 0;
}

/* Push some response into the http client */
static int flb_http_stub_response(struct flb_http_client *c)
{
    int ret = 0;

    if (!c) {
        return -1;
    }

    /* If http client's test_responses is registered, run the stub. */
    if (c->test_response.callback != NULL && c->resp.payload != NULL) {
        ret = flb_http_run_response_test(c, c->resp.payload, c->resp.payload_size);
    }

    return ret;
}

int flb_http_add_auth_header(struct flb_http_client *c,
                             const char *user, const char *passwd, const char *header) {
    int ret;
    int len_u;
    int len_p;
    int len_h;
    int len_out;
    char tmp[1024];
    char *p;
    size_t b64_len;

    /*
     * We allow a max of 255 bytes for user and password (255 each), meaning
     * we need at least:
     *
     * 'Basic base64(user : passwd)' => ~688 bytes
     *
     */

    len_u = strlen(user);

    if (passwd) {
        len_p = strlen(passwd);
    }
    else {
        len_p = 0;
    }

    p = flb_malloc(len_u + len_p + 2);
    if (!p) {
        flb_errno();
        return -1;
    }

    memcpy(p, user, len_u);
    p[len_u] = ':';
    len_out = len_u + 1;

    if (passwd) {
        memcpy(p + len_out, passwd, len_p);
        len_out += len_p;
    }
    p[len_out] = '\0';

    memcpy(tmp, "Basic ", 6);
    ret = flb_base64_encode((unsigned char *) tmp + 6, sizeof(tmp) - 7, &b64_len,
                                (unsigned char *) p, len_out);
    if (ret != 0) {
        flb_free(p);
        return -1;
    }

    flb_free(p);
    b64_len += 6;

    len_h = strlen(header);
    ret = flb_http_add_header(c,
                              header,
                              len_h,
                              tmp, b64_len);
    return ret;
}

int flb_http_basic_auth(struct flb_http_client *c,
                        const char *user, const char *passwd)
{
    return flb_http_add_auth_header(c, user, passwd, FLB_HTTP_HEADER_AUTH);
}

int flb_http_proxy_auth(struct flb_http_client *c,
                        const char *user, const char *passwd)
{
    return flb_http_add_auth_header(c, user, passwd, FLB_HTTP_HEADER_PROXY_AUTH);
}

int flb_http_bearer_auth(struct flb_http_client *c, const char *token)
{
    flb_sds_t header_buffer;
    flb_sds_t header_line;
    int       result;

    result = -1;

    if (token == NULL) {
        token = "";

        /* Shouldn't we log this and return instead of sending
         * a malformed value?
         */
    }

    header_buffer = flb_sds_create_size(strlen(token) + 64);

    if (header_buffer == NULL) {
        return -1;
    }

    header_line = flb_sds_printf(&header_buffer, "Bearer %s", token);

    if (header_line != NULL) {
        result = flb_http_add_header(c,
                                     FLB_HTTP_HEADER_AUTH,
                                     strlen(FLB_HTTP_HEADER_AUTH),
                                     header_line,
                                     flb_sds_len(header_line));
    }

    flb_sds_destroy(header_buffer);

    return result;
}

/* flb_http_do_request only sends the http request the data.
*  This is useful for processing the chunked responses on your own.
*  If you do not want to process the response on your own or expect
*  all response data before you process data, use flb_http_do instead.
*/
int flb_http_do_request(struct flb_http_client *c, size_t *bytes)
{
    int ret;
    int crlf = 2;
    int new_size;
    size_t bytes_header = 0;
    size_t bytes_body = 0;
    char *tmp;

    c->header_len = c->base_header_len;

    /* Try to add keep alive header */
    flb_http_set_keepalive(c);

    /* Append pending headers */
    ret = http_headers_compose(c);
    if (ret == -1) {
        return FLB_HTTP_ERROR;
    }

    /* check enough space for the ending CRLF */
    if (header_available(c, crlf) != 0) {
        new_size = c->header_size + 2;
        tmp = flb_realloc(c->header_buf, new_size);
        if (!tmp) {
            flb_errno();
            return FLB_HTTP_ERROR;
        }
        c->header_buf  = tmp;
        c->header_size = new_size;
    }

    /* Append the ending header CRLF */
    c->header_buf[c->header_len++] = '\r';
    c->header_buf[c->header_len++] = '\n';

#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    /* debug: request_headers callback */
    flb_http_client_debug_cb(c, "_debug.http.request_headers");

    /* debug: request_payload callback */
    if (c->body_len > 0) {
        flb_http_client_debug_cb(c, "_debug.http.request_payload");
    }
#endif

    /* Write the header */
    ret = flb_io_net_write(c->u_conn,
                           c->header_buf, c->header_len,
                           &bytes_header);
    if (ret == -1) {
        /* errno might be changed from the original call */
        if (errno != 0) {
            flb_errno();
        }
        return FLB_HTTP_ERROR;
    }

    if (c->body_len > 0) {
        ret = flb_io_net_write(c->u_conn,
                               c->body_buf, c->body_len,
                               &bytes_body);
        if (ret == -1) {
            flb_errno();
            return FLB_HTTP_ERROR;
        }
    }

    /* number of sent bytes */
    *bytes = (bytes_header + bytes_body);

    /* Initialize timeout tracking */
    c->ts_start = time(NULL);
    c->last_read_ts = c->ts_start;

    /* prep c->resp for incoming data */
    http_client_response_reset(c);

    /* at this point we've sent our request so we expect more data in response*/
    return FLB_HTTP_MORE;
}

int flb_http_get_response_data(struct flb_http_client *c, size_t bytes_consumed)
{
    /* returns
     *  FLB_HTTP_MORE - if we are waiting for more data to be received
     *  FLB_HTTP_CHUNK_AVAILABLE - if this is a chunked transfer and one or more chunks
     *                 have been received and it is not the end of the stream
     *  FLB_HTTP_OK - if we have collected all response data and no errors were thrown
     *                (in chunked transfers this means we've received the end chunk
     *                and any remaining data to process from the end of stream, will be
     *                contained in the response payload)
     *  FLB_HTTP_ERROR - for any error
     */
    int ret = FLB_HTTP_MORE;
    int r_bytes;
    ssize_t available;
    size_t out_size;
    time_t now;

    /* If the caller has consumed some of the payload (via bytes_consumed)
     * we consume those bytes off the payload
     */
    if( bytes_consumed > 0 ) {
        if(bytes_consumed > c->resp.payload_size) {
            flb_error("[http_client] attempting to consume more bytes than "
                      "available. Attempted bytes_consumed=%zu payload_size=%zu ",
                        bytes_consumed,
                        c->resp.payload_size);
            return FLB_HTTP_ERROR;
        }

        c->resp.payload_size -= bytes_consumed;
        c->resp.data_len -= bytes_consumed;
        memmove(c->resp.payload, c->resp.payload+bytes_consumed, c->resp.payload_size);
        c->resp.chunk_processed_end = c->resp.payload+c->resp.payload_size;
        c->resp.data[c->resp.data_len] = '\0';
    }

    while (ret == FLB_HTTP_MORE) {
        available = flb_http_buffer_available(c) - 1;
        if (available <= 1) {
            /*
             * If there is no more space available on our buffer, try to
             * increase it.
             */
            ret = flb_http_buffer_increase(c, FLB_HTTP_DATA_CHUNK,
                                           &out_size);
            if (ret == -1) {
                /*
                 * We could not allocate more space, let the caller handle
                 * this.
                 */
                flb_warn("[http_client] cannot increase buffer: current=%zu "
                         "requested=%zu max=%zu", c->resp.data_size,
                         c->resp.data_size + FLB_HTTP_DATA_CHUNK,
                         c->resp.data_size_max);
                flb_upstream_conn_recycle(c->u_conn, FLB_FALSE);
                return FLB_HTTP_ERROR;
            }
            available = flb_http_buffer_available(c) - 1;
        }
        now = time(NULL);

        if (c->response_timeout > 0 && (now - c->ts_start) > c->response_timeout) {
            flb_error("[http_client] response timeout reached (elapsed=%lds, limit=%ds)",
                      (long)(now - c->ts_start), c->response_timeout);
            flb_upstream_conn_recycle(c->u_conn, FLB_FALSE);
            return FLB_HTTP_ERROR;
        }

        if (c->read_idle_timeout > 0 &&  (now - c->last_read_ts) > c->read_idle_timeout) {
            flb_error("[http_client] read idle timeout reached (idle=%lds, limit=%ds)",
                      (long)(now - c->last_read_ts), c->read_idle_timeout);
            flb_upstream_conn_recycle(c->u_conn, FLB_FALSE);
            return FLB_HTTP_ERROR;
        }

        r_bytes = flb_io_net_read(c->u_conn,
                                  c->resp.data + c->resp.data_len,
                                  available);
        if (r_bytes <= 0) {
            if (c->flags & FLB_HTTP_10) {
                return FLB_HTTP_OK;
            }
        }

        /* Always append a NULL byte */
        if (r_bytes >= 0) {
            c->resp.data_len += r_bytes;
            c->resp.data[c->resp.data_len] = '\0';

            if (r_bytes > 0) {
                c->last_read_ts = now;
            }

            ret = process_data(c);
            if (ret == FLB_HTTP_ERROR) {
                flb_warn("[http_client] malformed HTTP response from %s:%i on "
                         "connection #%i",
                         c->u_conn->upstream->tcp_host,
                         c->u_conn->upstream->tcp_port,
                         c->u_conn->fd);
                return FLB_HTTP_ERROR;
            }
        }
        else {
            flb_error("[http_client] broken connection to %s:%i ?",
                      c->u_conn->upstream->tcp_host,
                      c->u_conn->upstream->tcp_port);
            return FLB_HTTP_ERROR;
        }
    }

    return ret;
}

int flb_http_do(struct flb_http_client *c, size_t *bytes)
{
    int ret;

    if (c->test_mode == FLB_TRUE) {
        return flb_http_stub_response(c);
    }

    ret = flb_http_do_request(c, bytes);
    if (ret != 0) {
        return ret;
    }

    /* Read the server response, we need at least 19 bytes */
    while (ret == FLB_HTTP_MORE || ret == FLB_HTTP_CHUNK_AVAILABLE) {
        /*
         * flb_http_do does not consume any bytes during processing
         * so we always pass 0 consumed_bytes because we fetch until
         * the end chunk before returning to the caller
         */
        ret = flb_http_get_response_data(c, 0);
    }


    if (ret != FLB_HTTP_OK) {
        return ret;
    }

    /* Check 'Connection' response header */
    ret = check_connection(c);
    if (ret == FLB_HTTP_ERROR) {
        return ret;
    }
    else if (ret == FLB_HTTP_OK) {
        /*
         * If the server replied that the connection will be closed
         * and our Upstream connection is in keepalive mode, we must
         * inactivate the connection.
         */
        if (c->resp.connection_close == FLB_TRUE) {
            /* Do not recycle the connection (no more keepalive) */
            flb_upstream_conn_recycle(c->u_conn, FLB_FALSE);
            flb_debug("[http_client] server %s:%i will close connection #%i",
                      c->u_conn->upstream->tcp_host,
                      c->u_conn->upstream->tcp_port,
                      c->u_conn->fd);
        }
    }
    else if (ret == FLB_HTTP_NOT_FOUND) {
        /* Connection header not found, continue normally */
    }

#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    flb_http_client_debug_cb(c, "_debug.http.response_headers");
    if (c->resp.payload_size > 0) {
        flb_http_client_debug_cb(c, "_debug.http.response_payload");
    }
#endif

    return 0;
}

int flb_http_do_with_oauth2(struct flb_http_client *c, size_t *bytes,
                            struct flb_oauth2 *oauth2)
{
    int ret;
    flb_sds_t token = NULL;

    if (!oauth2 || oauth2->cfg.enabled == FLB_FALSE) {
        return flb_http_do(c, bytes);
    }

    flb_http_allow_duplicated_headers(c, FLB_FALSE);

    ret = flb_oauth2_get_access_token(oauth2, &token, FLB_FALSE);
    if (ret != 0 || token == NULL) {
        return -1;
    }

    flb_http_remove_header(c, FLB_HTTP_HEADER_AUTH, strlen(FLB_HTTP_HEADER_AUTH));
    ret = flb_http_bearer_auth(c, token);
    if (ret != 0) {
        return ret;
    }

    ret = flb_http_do(c, bytes);
    if (ret != 0) {
        return ret;
    }

    if (c->resp.status == 401) {
        flb_info("[http_client] 401 received; refreshing OAuth2 token and retrying once");
        flb_oauth2_invalidate_token(oauth2);

        /* If connection was closed, get a new one */
        if (c->resp.connection_close == FLB_TRUE && c->u_conn) {
            flb_upstream_conn_release(c->u_conn);
            c->u_conn = flb_upstream_conn_get(c->u_conn->upstream);
            if (!c->u_conn) {
                return -1;
            }
        }

        ret = flb_oauth2_get_access_token(oauth2, &token, FLB_TRUE);
        if (ret != 0 || token == NULL) {
            return -1;
        }

        flb_http_remove_header(c, FLB_HTTP_HEADER_AUTH, strlen(FLB_HTTP_HEADER_AUTH));
        ret = flb_http_bearer_auth(c, token);
        if (ret != 0) {
            return ret;
        }

        ret = flb_http_do(c, bytes);
    }

    return ret;
}

/*
 * flb_http_client_proxy_connect opens a tunnel to a proxy server via
 * http `CONNECT` method. This is needed for https traffic through a
 * http proxy.
 * More: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT
 */
int flb_http_client_proxy_connect(struct flb_connection *u_conn)
{
    struct flb_upstream *u = u_conn->upstream;
    struct flb_http_client *c;
    size_t b_sent;
    int ret = -1;

    /* Don't pass proxy when using FLB_HTTP_CONNECT */
    flb_debug("[upstream] establishing http tunneling to proxy: host %s port %d", u->tcp_host, u->tcp_port);
    c = flb_http_client(u_conn, FLB_HTTP_CONNECT, "", NULL,
                        0, u->proxied_host, u->proxied_port, NULL, 0);

    /* Setup proxy's username and password */
    if (u->proxy_username && u->proxy_password) {
        flb_debug("[upstream] proxy uses username %s password %s", u->proxy_username, u->proxy_password);
        flb_http_proxy_auth(c, u->proxy_username, u->proxy_password);
    }

    flb_http_buffer_size(c, 4192);

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Validate HTTP response */
    if (ret != 0) {
        flb_error("[upstream] error in flb_establish_proxy: %d", ret);
        ret = -1;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_debug("[upstream] proxy returned %d", c->resp.status);
        if (c->resp.status == 200) {
            ret = 0;
        }
        else {
            flb_error("flb_establish_proxy error: %s", c->resp.payload);
            ret = -1;
        }
    }

    /* Cleanup */
    flb_http_client_destroy(c);

    return ret;
}

void flb_http_client_destroy(struct flb_http_client *c)
{
    http_headers_destroy(c);
    flb_free(c->resp.data);
    flb_free(c->header_buf);
    flb_free((void *)c->proxy.host);
    flb_free(c);
}


















static int flb_http_client_session_read(struct flb_http_client_session *session);
static int flb_http_client_session_write(struct flb_http_client_session *session);










int flb_http_client_ng_init(struct flb_http_client_ng *client,
                            struct flb_upstream_ha *upstream_ha,
                            struct flb_upstream *upstream,
                            int protocol_version,
                            uint64_t flags)
{
    memset(client, 0, sizeof(struct flb_http_client_ng));

    client->temporary_buffer = cfl_sds_create_size(HTTP_CLIENT_TEMPORARY_BUFFER_SIZE);

    if (client->temporary_buffer == NULL) {
        return -1;
    }

    client->protocol_version = protocol_version;
    client->upstream_ha = upstream_ha;
    client->upstream = upstream;
    client->flags = flags;

    cfl_list_init(&client->sessions);

    if (protocol_version == HTTP_PROTOCOL_VERSION_AUTODETECT) {
        if (upstream->base.tls_context != NULL) {
            flb_tls_set_alpn(upstream->base.tls_context, "h2,http/1.1,http/1.0");
        }
    }
    else if (protocol_version == HTTP_PROTOCOL_VERSION_20) {
        if (upstream->base.tls_context != NULL) {
            flb_tls_set_alpn(upstream->base.tls_context, "h2");
        }
    }
    else if (protocol_version == HTTP_PROTOCOL_VERSION_11) {
        if (upstream->base.tls_context != NULL) {
            flb_tls_set_alpn(upstream->base.tls_context, "http/1.1,http/1.0");
        }
    }
    else if (protocol_version <= HTTP_PROTOCOL_VERSION_10) {
        if (upstream->base.tls_context != NULL) {
            flb_tls_set_alpn(upstream->base.tls_context, "http/1.0");
        }
    }

    flb_lock_init(&client->lock);

    return 0;
}

struct flb_http_client_ng *flb_http_client_ng_create(
                                struct flb_upstream_ha *upstream_ha,
                                struct flb_upstream *upstream,
                                int protocol_version,
                                uint64_t flags)
{
    struct flb_http_client_ng *client;
    int                        result;

    client = flb_calloc(1, sizeof(struct flb_http_client_ng));

    if (client != NULL) {
        result = flb_http_client_ng_init(client,
                                         upstream_ha,
                                         upstream,
                                         protocol_version,
                                         flags);

        client->releasable = FLB_TRUE;

        if (result != 0) {
            flb_http_client_ng_destroy(client);

            client = NULL;
        }
    }

    return client;
}

void flb_http_client_ng_destroy(struct flb_http_client_ng *client)
{
    struct cfl_list                *iterator_backup;
    struct cfl_list                *iterator;
    struct flb_http_client_session *session;

    flb_lock_acquire(&client->lock,
                     FLB_LOCK_INFINITE_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);

    if (client->temporary_buffer != NULL) {
        cfl_sds_destroy(client->temporary_buffer);

        client->temporary_buffer = NULL;
    }

    cfl_list_foreach_safe(iterator,
                          iterator_backup,
                          &client->sessions) {
        session = cfl_list_entry(iterator,
                                 struct flb_http_client_session,
                                 _head);

        flb_http_client_session_destroy(session);
    }

    flb_lock_release(&client->lock,
                     FLB_LOCK_INFINITE_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);

    flb_lock_destroy(&client->lock);
}

int flb_http_client_session_init(struct flb_http_client_session *session,
                                 struct flb_http_client_ng *client,
                                 int protocol_version,
                                 struct flb_connection  *connection)
{
    int result;

    memset(session, 0, sizeof(struct flb_http_client_session));

    session->parent = client;
    session->protocol_version = protocol_version;
    session->connection = connection;
    session->stream_sequence_number = 1;

    cfl_list_init(&session->streams);
    cfl_list_init(&session->response_queue);

    cfl_list_entry_init(&session->_head);

    session->incoming_data = cfl_sds_create_size(1);

    if (session->incoming_data == NULL) {
        return -1;
    }

    session->outgoing_data = cfl_sds_create_size(1);

    if (session->outgoing_data == NULL) {
        return -1;
    }

    if (session->protocol_version == HTTP_PROTOCOL_VERSION_11 ||
        session->protocol_version == HTTP_PROTOCOL_VERSION_10) {
        session->http1.parent = session;

        result = flb_http1_client_session_init(&session->http1);

        if (result != 0) {
            return result;
        }
    }
    else if (session->protocol_version == HTTP_PROTOCOL_VERSION_20) {
        session->http2.parent = session;

        result = flb_http2_client_session_init(&session->http2);

        if (result != 0) {
            return result;
        }
    }
    else {
        return -1;
    }

    return 0;
}

struct flb_http_client_session *flb_http_client_session_create(struct flb_http_client_ng *client,
                                                               int protocol_version,
                                                               struct flb_connection  *connection)
{
    struct flb_http_client_session *session;
    int                             result;

    session = flb_calloc(1, sizeof(struct flb_http_client_session));

    if (session != NULL) {
        if (client != NULL) {
            flb_lock_acquire(&client->lock,
                            FLB_LOCK_INFINITE_RETRY_LIMIT,
                            FLB_LOCK_DEFAULT_RETRY_DELAY);
        }

        result = flb_http_client_session_init(session,
                                              client,
                                              protocol_version,
                                              connection);

        if (client != NULL) {
            flb_lock_release(&client->lock,
                            FLB_LOCK_INFINITE_RETRY_LIMIT,
                            FLB_LOCK_DEFAULT_RETRY_DELAY);
        }

        session->releasable = FLB_TRUE;

        if (result != 0) {
            flb_http_client_session_destroy(session);

            session = NULL;
        }
    }

    return session;
}

struct flb_http_client_session *flb_http_client_session_begin(struct flb_http_client_ng *client)
{
    int                             protocol_version;
    struct flb_upstream_node       *upstream_node;
    struct flb_connection          *connection;
    struct flb_upstream            *upstream;
    struct flb_http_client_session *session;
    const char                     *alpn;

    if (client->upstream_ha != NULL) {
        upstream_node = flb_upstream_ha_node_get(client->upstream_ha);

        if (upstream_node == NULL) {
            return NULL;
        }

        upstream = upstream_node->u;

        connection = flb_upstream_conn_get(upstream_node->u);
    }
    else {
        upstream_node = NULL;

        upstream = client->upstream;

        connection = flb_upstream_conn_get(client->upstream);
    }

    if (connection == NULL) {
        return NULL;
    }

    protocol_version = client->protocol_version;

    if (protocol_version == HTTP_PROTOCOL_VERSION_AUTODETECT) {
        if (connection->tls_session != NULL) {
            alpn = flb_tls_session_get_alpn(connection->tls_session);

            if (alpn != NULL) {
                if (strcasecmp(alpn, "h2") == 0) {
                    protocol_version = HTTP_PROTOCOL_VERSION_20;
                }
                else if (strcasecmp(alpn, "http/1.1") == 0) {
                    protocol_version = HTTP_PROTOCOL_VERSION_11;
                }
                else if (strcasecmp(alpn, "http/1.0") == 0) {
                    protocol_version = HTTP_PROTOCOL_VERSION_10;
                }
            }
        }
    }

    if (protocol_version == HTTP_PROTOCOL_VERSION_AUTODETECT) {
        protocol_version = HTTP_PROTOCOL_VERSION_11;
    }

    if (protocol_version == HTTP_PROTOCOL_VERSION_20) {
        flb_stream_disable_keepalive(&upstream->base);
    }

    session = flb_http_client_session_create(client, protocol_version, connection);

    if (session == NULL) {
        flb_upstream_conn_release(connection);
    }

    session->upstream_node = upstream_node;

    return session;
}

void flb_http_client_session_destroy(struct flb_http_client_session *session)
{
    struct cfl_list         *iterator_backup;
    struct cfl_list         *iterator;
    struct flb_http_stream  *stream;

    if (session != NULL) {
        cfl_list_foreach_safe(iterator,
                              iterator_backup,
                              &session->streams) {
            stream = cfl_list_entry(iterator, struct flb_http_stream, _head);

            flb_http_stream_destroy(stream);
        }

        if (session->connection != NULL) {
            flb_upstream_conn_release(session->connection);
        }

        if (!cfl_list_entry_is_orphan(&session->_head)) {
            cfl_list_del(&session->_head);
        }

        if (session->incoming_data != NULL) {
            cfl_sds_destroy(session->incoming_data);
        }

        if (session->outgoing_data != NULL) {
            cfl_sds_destroy(session->outgoing_data);
        }

        flb_http1_client_session_destroy(&session->http1);
        flb_http2_client_session_destroy(&session->http2);

        if (session->releasable) {
            flb_free(session);
        }
    }
}

struct flb_http_request *flb_http_client_request_begin(struct flb_http_client_session *session)
{
    int                     stream_id;
    struct flb_http_stream *stream;
    int                     result;

    stream_id = session->stream_sequence_number;
    session->stream_sequence_number += 2;

    stream = flb_http_stream_create(session,
                                    stream_id,
                                    HTTP_STREAM_ROLE_CLIENT,
                                    session);

    if (stream == NULL) {
        return NULL;
    }

    stream->request.protocol_version = session->protocol_version;

    if (stream->request.protocol_version == HTTP_PROTOCOL_VERSION_20) {
        result = flb_http2_request_begin(&stream->request);
    }
    else if (stream->request.protocol_version == HTTP_PROTOCOL_VERSION_11 ||
             stream->request.protocol_version == HTTP_PROTOCOL_VERSION_10) {
        result = flb_http1_request_begin(&stream->request);
    }
    else {
        result = -1;
    }

    if (result != 0) {
        flb_http_stream_destroy(stream);

        return NULL;
    }

    cfl_list_add(&stream->_head, &session->streams);

    return &stream->request;
}

struct flb_http_response *flb_http_client_request_execute_step(
                            struct flb_http_request *request)
{
    struct flb_http_response       *response;
    struct flb_http_client_session *session;
    int                             result;

    session = (struct flb_http_client_session *) request->stream->parent;
    response = &request->stream->response;

    /* We allow this to enable request mocking, there is no
     * other legitimate use for it.
     */
    if (session->connection == NULL) {
        return response;
    }

    if (session->outgoing_data != NULL &&
        cfl_sds_len(session->outgoing_data) > 0)
    {
        result = flb_http_client_session_write(session);

        if (result != 0) {
            return NULL;
        }

        result = flb_http_client_session_read(session);

        if (result != 0) {
            return NULL;
        }
    }

    if (request->stream->status == HTTP_STREAM_STATUS_SENDING_HEADERS) {
        result = flb_http_request_commit(request);

        if (result != 0) {
            return NULL;
        }

        result = flb_http_client_session_write(session);

        if (result != 0) {
            return NULL;
        }

        request->stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;
    }
    else if (request->stream->status == HTTP_STREAM_STATUS_RECEIVING_HEADERS ||
             request->stream->status == HTTP_STREAM_STATUS_RECEIVING_DATA ) {
        result = flb_http_client_session_read(session);

        if (result != 0) {
            return NULL;
        }

        if (session->outgoing_data != NULL &&
            cfl_sds_len(session->outgoing_data) > 0)
        {
            result = flb_http_client_session_write(session);

            if (result != 0) {
                return NULL;
            }
        }
    }

    if (request->stream->status != HTTP_STREAM_STATUS_RECEIVING_HEADERS &&
        request->stream->status != HTTP_STREAM_STATUS_RECEIVING_DATA &&
        request->stream->status != HTTP_STREAM_STATUS_CLOSED &&
        request->stream->status != HTTP_STREAM_STATUS_READY ) {
        return NULL;
    }

    return response;
}

struct flb_http_response *flb_http_client_request_execute(struct flb_http_request *request)
{
    struct flb_http_response *response;

    do {
        response = flb_http_client_request_execute_step(request);
    } while (response != NULL &&
             request->stream->status != HTTP_STREAM_STATUS_READY &&
             request->stream->status != HTTP_STREAM_STATUS_CLOSED);

    return response;
}

static int flb_http_client_session_read(struct flb_http_client_session *session)
{
    ssize_t result;

    result = flb_io_net_read(session->connection,
                             (void *) session->parent->temporary_buffer,
                             cfl_sds_avail(session->parent->temporary_buffer));

    if (result <= 0) {
        return -1;
    }

    result = (ssize_t) flb_http_client_session_ingest(
                            session,
                            (unsigned char *) session->parent->temporary_buffer,
                            result);

    if (result < 0) {
        return -2;
    }

    return 0;
}


void flb_http_client_request_destroy(struct flb_http_request *request,
                                     int destroy_session)
{
    if (destroy_session == FLB_TRUE) {
        flb_http_client_session_destroy((struct flb_http_client_session *)
                                         request->stream->parent);
    }
    else {
        flb_http_request_destroy(request);
    }
}


static int flb_http_client_session_write(struct flb_http_client_session *session)
{
    size_t data_length;
    size_t data_sent;
    int    result;

    if (session == NULL) {
        return -1;
    }

    if (session->outgoing_data == NULL) {
        return 0;
    }

    data_length = cfl_sds_len(session->outgoing_data);

    if (data_length > 0) {
        result = flb_io_net_write(session->connection,
                                  (void *) session->outgoing_data,
                                  data_length,
                                  &data_sent);

        if (result == -1) {
            return -2;
        }


        if (data_sent < data_length) {
            memmove(session->outgoing_data,
                    &session->outgoing_data[data_sent],
                    data_length - data_sent);

            cfl_sds_set_len(session->outgoing_data,
                            data_length - data_sent);
        }
        else {
            cfl_sds_set_len(session->outgoing_data, 0);
        }
    }

    return 0;
}

int flb_http_client_session_ingest(struct flb_http_client_session *session,
                                   unsigned char *buffer,
                                   size_t length)
{
    if (session->protocol_version == HTTP_PROTOCOL_VERSION_11 ||
        session->protocol_version == HTTP_PROTOCOL_VERSION_10) {
        return flb_http1_client_session_ingest(&session->http1,
                                               buffer,
                                               length);
    }
    else if (session->protocol_version == HTTP_PROTOCOL_VERSION_20) {
        return flb_http2_client_session_ingest(&session->http2,
                                               buffer,
                                               length);
    }

    return -20;
}

static int flb_http_encode_basic_auth_value(cfl_sds_t *output_buffer,
                                            char *username,
                                            char *password)
{
    size_t    encoded_value_length;
    cfl_sds_t encoded_value;
    cfl_sds_t sds_result;
    cfl_sds_t raw_value;
    int       result;

    *output_buffer = NULL;

    raw_value = cfl_sds_create_size(strlen(username) +
                                    strlen(password) + 2);

    if (raw_value == NULL) {
        return -1;
    }

    sds_result = cfl_sds_printf(&raw_value,
                                "%s:%s",
                                username,
                                password);

    if (sds_result == NULL) {
        cfl_sds_destroy(raw_value);

        return -1;
    }

    encoded_value = cfl_sds_create_size(cfl_sds_len(raw_value) * 2 + 1);

    if (encoded_value == NULL) {
        cfl_sds_destroy(raw_value);

        return -1;
    }

    result = flb_base64_encode((unsigned char *) encoded_value,
                                cfl_sds_alloc(encoded_value),
                                &encoded_value_length,
                                (unsigned char *) raw_value,
                                cfl_sds_len(raw_value));

    if (result == 0) {
        *output_buffer = cfl_sds_create_size(cfl_sds_len(encoded_value) + 6);

        if (*output_buffer != NULL) {
            sds_result = cfl_sds_printf(output_buffer, "Basic %s", encoded_value);

            if (sds_result != NULL) {
                *output_buffer = sds_result;
            }
            else {
                result = -1;
            }
        }
        else {
            result = -1;
        }
    }
    else {
        result = -1;
    }

    cfl_sds_destroy(encoded_value);
    cfl_sds_destroy(raw_value);

    return 0;
}

static int flb_http_encode_bearer_auth_value(cfl_sds_t *output_buffer,
                                             char *token)
{
    cfl_sds_t sds_result;

    *output_buffer = NULL;

    *output_buffer = cfl_sds_create_size(strlen(token) + 9);

    if (*output_buffer == NULL) {
        return -1;
    }

    sds_result = cfl_sds_printf(output_buffer,
                                "Bearer %s",
                                token);

    if (sds_result == NULL) {
        cfl_sds_destroy(*output_buffer);
        *output_buffer = NULL;

        return -1;
    }

    *output_buffer = sds_result;

    return 0;
}


int flb_http_request_set_authorization(struct flb_http_request *request,
                                       int type, ...)
{
    cfl_sds_t   header_value;
    const char *header_name;
    va_list     arguments;
    char       *username;
    char       *password;
    int         result;
    char       *token;

    va_start(arguments, type);

    if (type == HTTP_WWW_AUTHORIZATION_SCHEME_BASIC) {
        header_name = "authorization";

        username = va_arg(arguments, char *);
        password = va_arg(arguments, char *);

        result = flb_http_encode_basic_auth_value(&header_value,
                                                  username,
                                                  password);

        if (result != 0) {
            va_end(arguments);

            return -1;
        }
    }
    else if (type == HTTP_WWW_AUTHORIZATION_SCHEME_BEARER) {
        header_name = "authorization";

        token = va_arg(arguments, char *);

        result = flb_http_encode_bearer_auth_value(&header_value,
                                                   token);

        if (result != 0) {
            va_end(arguments);

            return -1;
        }
    }
    else if (type == HTTP_PROXY_AUTHORIZATION_SCHEME_BASIC) {
        header_name = "proxy-authorization";

        username = va_arg(arguments, char *);
        password = va_arg(arguments, char *);

        result = flb_http_encode_basic_auth_value(&header_value,
                                                  username,
                                                  password);

        if (result != 0) {
            va_end(arguments);

            return -1;
        }
    }
    else if (type == HTTP_PROXY_AUTHORIZATION_SCHEME_BEARER) {
        header_name = "proxy-authorization";

        token = va_arg(arguments, char *);

        result = flb_http_encode_bearer_auth_value(&header_value,
                                                   token);

        if (result != 0) {
            va_end(arguments);

            return -1;
        }
    }
    else {
        va_end(arguments);

        return -1;
    }

    va_end(arguments);

    result = flb_http_request_set_header(request,
                                         (char *) header_name, 0,
                                         (char *) header_value, 0);

    cfl_sds_destroy(header_value);

    if (result != 0) {
        result = -1;
    }

    return result;
}




int flb_http_request_set_parameters_internal(
    struct flb_http_request *request,
    va_list arguments)
{
    char                           *compression_algorithm;
    struct flb_config_map_val      *config_map_list_entry;
    int                             failure_detected;
    size_t                          header_data_type;
    char                           *content_type;
    char                           *bearer_token;
    struct flb_aws_provider        *aws_provider;
    struct flb_slist_entry         *header_value;
    char                          **header_array;
    char                           *aws_service;
    struct mk_list                 *header_list;
    struct flb_slist_entry         *header_name;
    char                           *aws_region;
    size_t                          value_type;
    char                           *user_agent;
    struct mk_list                 *iterator;
    size_t                          body_len;
    char                           *username;
    char                           *password;
    int                             result;
    size_t                          index;
    size_t                          method;
    char                           *host;
    unsigned char                  *body;
    char                           *uri;
    char                           *url;

    failure_detected = FLB_FALSE;

    do {
        value_type = va_arg(arguments, size_t);

        if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_METHOD) {
            method = va_arg(arguments, size_t);

            flb_http_request_set_method(request, (int) method);
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_HOST) {
            host = va_arg(arguments, char *);

            flb_http_request_set_host(request, host);
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_URL) {
            url = va_arg(arguments, char *);

            flb_http_request_set_url(request, url);
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_URI) {
            uri = va_arg(arguments, char *);

            flb_http_request_set_uri(request, uri);
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_USER_AGENT) {
            user_agent = va_arg(arguments, char *);

            flb_http_request_set_user_agent(request, user_agent);
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_CONTENT_TYPE) {
            content_type = va_arg(arguments, char *);

            result = flb_http_request_set_content_type(request, content_type);

            if (request == NULL) {
                flb_debug("http request : error setting content type");

                failure_detected = FLB_TRUE;
            }
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_BODY) {
            body = va_arg(arguments, unsigned char *);
            body_len = va_arg(arguments, size_t);
            compression_algorithm = va_arg(arguments, char *);

            result = flb_http_request_set_body(request,
                                               body,
                                               body_len,
                                               compression_algorithm);

            if (request == NULL) {
                flb_debug("http request creation error");

                failure_detected = FLB_TRUE;
            }
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_HEADERS) {
            header_data_type = va_arg(arguments, size_t);

            if (header_data_type == FLB_HTTP_CLIENT_HEADER_ARRAY) {
                header_array = va_arg(arguments, char **);
                if (header_array != NULL) {
                    for (index = 0 ;
                        header_array[index+0] != NULL &&
                        header_array[index+1] != NULL;
                        index += 2) {
                        result = flb_http_request_set_header(request,
                                                             header_array[index+0], 0,
                                                             header_array[index+1], 0);

                        if (result != 0) {
                            flb_debug("http request header addition error");

                            failure_detected = FLB_TRUE;

                            break;
                        }
                    }
                }
            }
            else if (header_data_type == FLB_HTTP_CLIENT_HEADER_CONFIG_MAP_LIST) {
                header_list = va_arg(arguments, struct mk_list *);

                flb_config_map_foreach(iterator, config_map_list_entry, header_list) {
                    header_name = mk_list_entry_first(config_map_list_entry->val.list,
                                                      struct flb_slist_entry,
                                                      _head);

                    header_value = mk_list_entry_last(config_map_list_entry->val.list,
                                                      struct flb_slist_entry,
                                                      _head);

                    result = flb_http_request_set_header(request,
                                                         header_name->str, 0,
                                                         header_value->str, 0);

                    if (result != 0) {
                        flb_debug("http request header addition error");

                        failure_detected = FLB_TRUE;

                        break;
                    }
                }
            }
            else {
                failure_detected = FLB_TRUE;
            }
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_AUTH_BASIC) {
            username = va_arg(arguments, char *);
            password = va_arg(arguments, char *);

            flb_http_request_set_authorization(request,
                                            HTTP_WWW_AUTHORIZATION_SCHEME_BASIC,
                                            username,
                                            password);
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_AUTH_BEARER_TOKEN) {
            bearer_token = va_arg(arguments, char *);

            flb_http_request_set_authorization(request,
                                            HTTP_WWW_AUTHORIZATION_SCHEME_BEARER,
                                            bearer_token);
        }
        else if (value_type == FLB_HTTP_CLIENT_ARGUMENT_TYPE_AUTH_SIGNV4) {
            aws_region = va_arg(arguments, char *);
            aws_service = va_arg(arguments, char *);
            aws_provider = va_arg(arguments, struct flb_aws_provider *);

            result = flb_http_request_perform_signv4_signature(request,
                                                               aws_region,
                                                               aws_service,
                                                               aws_provider);
        }
    } while (!failure_detected &&
             value_type != FLB_HTTP_CLIENT_ARGUMENT_TYPE_TERMINATOR);

    if (failure_detected) {
        return -1;
    }

    return 0;
}

int flb_http_request_set_parameters_unsafe(
    struct flb_http_request *request,
    ...)
{
    va_list arguments;
    int     result;

    va_start(arguments, request);

    result = flb_http_request_set_parameters_internal(request, arguments);

    va_end(arguments);

    return result;
}

struct flb_http_request *flb_http_client_request_builder_unsafe(
    struct flb_http_client_ng *client,
    ...)
{
    va_list                         arguments;
    struct flb_http_request        *request;
    struct flb_http_client_session *session;
    int                             result;

    session = flb_http_client_session_begin(client);

    if (session == NULL) {
        flb_debug("http session creation error");

        return NULL;
    }

    request = flb_http_client_request_begin(session);

    if (request == NULL) {
        flb_debug("http request creation error");

        flb_http_client_session_destroy(session);

        return NULL;
    }

    flb_http_request_set_port(request, client->upstream->tcp_port);

    va_start(arguments, client);

    result = flb_http_request_set_parameters_internal(request, arguments);

    va_end(arguments);

    if (result != 0) {
        flb_http_client_session_destroy(session);

        /*
         * The request instance is recursively disposed of
         */
        request = NULL;
    }

    return request;
}
