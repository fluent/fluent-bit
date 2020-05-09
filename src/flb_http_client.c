/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_http_client_debug.h>
#include <fluent-bit/flb_utils.h>

#include <mbedtls/base64.h>

/*
 * Removes the port from the host header
 */
int flb_http_strip_port_from_host(struct flb_http_client *c)
{
    struct mk_list *head;
    struct flb_kv *kv;
    char *out_host;
    struct flb_upstream *u = c->u_conn->u;

    if (!c->host) {
        out_host = u->tcp_host;
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

    buf = flb_malloc(len + 1);
    if (!buf) {
        flb_errno();
        return -1;
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

static int process_chunked_data(struct flb_http_client *c)
{
    long len;
    long drop;
    long val;
    char *p;
    char tmp[32];
    struct flb_http_response *r = &c->resp;

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

    /* Is this the last chunk ? */
    if ((val - 2 == 0)) {
        /* Update payload size */
        r->payload_size = r->data_len - (r->headers_end - r->data);
        return FLB_HTTP_OK;
    }

    /* If we have some remaining bytes, start over */
    len = r->data_len - (r->chunk_processed_end - r->data);
    if (len > 0) {
        goto chunk_start;
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
            else if (ret == FLB_HTTP_OK) {
                return FLB_HTTP_OK;
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
    struct flb_upstream *u = c->u_conn->u;

    if (!c->host) {
        out_host = u->tcp_host;
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
        out_port = u->tcp_port;
    }
    else {
        out_port = c->port;
    }

    tmp = flb_sds_printf(&host, "%s:%i", out_host, out_port);
    if (!tmp) {
        flb_sds_destroy(host);
        flb_error("[http_client] cannot compose temporary host header");
        return -1;
    }

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

struct flb_http_client *flb_http_client(struct flb_upstream_conn *u_conn,
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
    case FLB_HTTP_HEAD:
        str_method = "HEAD";
        break;
    };

    buf = flb_calloc(1, FLB_HTTP_BUF_SIZE);
    if (!buf) {
        flb_errno();
        return NULL;
    }

    /* FIXME: handler for HTTPS proxy */
    if (!proxy) {
        ret = snprintf(buf, FLB_HTTP_BUF_SIZE,
                       fmt_plain,
                       str_method,
                       uri,
                       flags & FLB_HTTP_10 ? 0 : 1,
                       body_len);
    }
    else {
        ret = snprintf(buf, FLB_HTTP_BUF_SIZE,
                       fmt_proxy,
                       str_method,
                       host,
                       port,
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
    c->flags       = flags;
    mk_list_init(&c->headers);

    /* Check if we have a query string */
    p = strchr(uri, '?');
    if (p) {
        p++;
        c->query_string = p;
    }

    /* Is Upstream connection using keepalive mode ? */
    if (u_conn->u->flags & FLB_IO_TCP_KA) {
        c->flags |= FLB_HTTP_KA;
    }

    /* Response */
    c->resp.content_length = -1;
    c->resp.connection_close = -1;

    if ((flags & FLB_HTTP_10) == 0) {
        c->flags |= FLB_HTTP_11;
    }

    if (body && body_len > 0) {
        c->body_buf = body;
        c->body_len = body_len;
    }

    add_host_and_content_length(c);

    /* Check proxy data */
    if (proxy) {
        ret = proxy_parse(proxy, c);
        if (ret != 0) {
            flb_free(buf);
            flb_free(c);
            return NULL;
        }
    }

    /* 'Read' buffer size */
    c->resp.data = flb_malloc(FLB_HTTP_DATA_SIZE_MAX);
    if (!c->resp.data) {
        flb_errno();
        flb_free(buf);
        flb_free(c);
        return NULL;
    }
    c->resp.data_len  = 0;
    c->resp.data_size = FLB_HTTP_DATA_SIZE_MAX;
    c->resp.data_size_max = FLB_HTTP_DATA_SIZE_MAX;

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

    if (key_len < 1 || val_len < 1) {
        return -1;
    }

    /* register new header in the temporal kv list */
    kv = flb_kv_item_create_len(&c->headers,
                                (char *) key, key_len, (char *) val, val_len);
    if (!kv) {
        return -1;
    }

    return 0;
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
    if (c->u_conn->u->net.keepalive == FLB_FALSE) {
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

int flb_http_set_callback_context(struct flb_http_client *c,
                                  struct flb_callback *cb_ctx)
{
    c->cb_ctx = cb_ctx;
    return 0;
}

int flb_http_basic_auth(struct flb_http_client *c,
                        const char *user, const char *passwd)
{
    int ret;
    int len_u;
    int len_p;
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
    ret = mbedtls_base64_encode((unsigned char *) tmp + 6, sizeof(tmp) - 7, &b64_len,
                                (unsigned char *) p, len_out);
    if (ret != 0) {
        flb_free(p);
        return -1;
    }

    flb_free(p);
    b64_len += 6;

    ret = flb_http_add_header(c,
                              FLB_HTTP_HEADER_AUTH,
                              sizeof(FLB_HTTP_HEADER_AUTH) - 1,
                              tmp, b64_len);
    return ret;
}

int flb_http_do(struct flb_http_client *c, size_t *bytes)
{
    int ret;
    int r_bytes;
    int crlf = 2;
    int new_size;
    ssize_t available;
    size_t out_size;
    size_t bytes_header = 0;
    size_t bytes_body = 0;
    char *tmp;

    /* Append pending headers */
    ret = http_headers_compose(c);
    if (ret == -1) {
        return -1;
    }

    /* check enough space for the ending CRLF */
    if (header_available(c, crlf) != 0) {
        new_size = c->header_size + 2;
        tmp = flb_realloc(c->header_buf, new_size);
        if (!tmp) {
            return -1;
        }
        c->header_buf = tmp;
        c->header_len = new_size;
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
        flb_errno();
        return -1;
    }

    if (c->body_len > 0) {
        ret = flb_io_net_write(c->u_conn,
                               c->body_buf, c->body_len,
                               &bytes_body);
        if (ret == -1) {
            flb_errno();
            return -1;
        }
    }

    /* number of sent bytes */
    *bytes = (bytes_header + bytes_body);

    /* Read the server response, we need at least 19 bytes */
    c->resp.data_len = 0;
    while (1) {
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
                return 0;
            }
            available = flb_http_buffer_available(c) - 1;
        }

        r_bytes = flb_io_net_read(c->u_conn,
                                  c->resp.data + c->resp.data_len,
                                  available);
        if (r_bytes <= 0) {
            if (c->flags & FLB_HTTP_10) {
                break;
            }
        }

        /* Always append a NULL byte */
        if (r_bytes >= 0) {
            c->resp.data_len += r_bytes;
            c->resp.data[c->resp.data_len] = '\0';

            ret = process_data(c);
            if (ret == FLB_HTTP_ERROR) {
                return -1;
            }
            else if (ret == FLB_HTTP_OK) {
                break;
            }
            else if (ret == FLB_HTTP_MORE) {
                continue;
            }
        }
        else {
            flb_error("[http_client] broken connection to %s:%i ?",
                      c->u_conn->u->tcp_host, c->u_conn->u->tcp_port);
            return -1;
        }
    }

    /* Check 'Connection' response header */
    ret = check_connection(c);
    if (ret == FLB_HTTP_OK) {
        /*
         * If the server replied that the connection will be closed
         * and our Upstream connection is in keepalive mode, we must
         * inactivate the connection.
         */
        if (c->resp.connection_close == FLB_TRUE) {
            /* Do not recycle the connection (no more keepalive) */
            flb_upstream_conn_recycle(c->u_conn, FLB_FALSE);
            flb_debug("[http_client] server %s:%i will close connection #%i",
                      c->u_conn->u->tcp_host, c->u_conn->u->tcp_port,
                      c->u_conn->fd);
        }
    }

#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    flb_http_client_debug_cb(c, "_debug.http.response_headers");
    if (c->resp.payload_size > 0) {
        flb_http_client_debug_cb(c, "_debug.http.response_payload");
    }
#endif

    return 0;
}

void flb_http_client_destroy(struct flb_http_client *c)
{
    http_headers_destroy(c);
    flb_free(c->resp.data);
    flb_free(c->header_buf);
    flb_free((void *)c->proxy.host);
    flb_free(c);
}
