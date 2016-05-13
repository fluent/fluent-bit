/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
 */

#include <fluent-bit/flb_http_client.h>

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

static int process_response(struct flb_http_client *c)
{
    char *tmp;

    tmp = mk_string_copy_substr(c->resp.data, 9, 12);
    c->resp.status = atoi(tmp);
    free(tmp);

    return 0;
}

struct flb_http_client *flb_http_client(struct flb_upstream_conn *u_conn,
                                        int method, char *uri,
                                        char *body, size_t body_len)
{
    int ret;
    char *buf;
    char *str_method = NULL;
    char *fmt =                                 \
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%i\r\n"
        "Connection: KeepAlive\r\n"
        "Content-Length: %i\r\n";

    struct flb_http_client *c;
    struct flb_upstream *u = u_conn->u;

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

    buf = malloc(FLB_HTTP_BUF_SIZE);
    if (!buf) {
        perror("malloc");
        return NULL;
    }

    ret = snprintf(buf, FLB_HTTP_BUF_SIZE,
                   fmt,
                   str_method,
                   uri,
                   u->tcp_host,
                   u->tcp_port,
                   body_len);
    if (ret == -1) {
        perror("snprintf");
        free(buf);
        return NULL;
    }

    c = calloc(1, sizeof(struct flb_http_client));
    if (!c) {
        free(buf);
        return NULL;
    }

    c->u_conn      = u_conn;
    c->method      = method;
    c->header_buf  = buf;
    c->header_size = FLB_HTTP_BUF_SIZE;
    c->header_len  = ret;

    if (body && body_len > 0) {
        c->body_buf = body;
        c->body_len = body_len;
    }

    return c;
}

/* Append a custom HTTP header to the request */
int flb_http_add_header(struct flb_http_client *c,
                        char *key, size_t key_len,
                        char *val, size_t val_len)
{
    int required;
    int new_size;
    char *tmp;

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
        tmp = realloc(c->header_buf, new_size);
        if (!tmp) {
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

int flb_http_do(struct flb_http_client *c, size_t *bytes)
{
    int ret;
    int r_bytes;
    int available;
    int crlf = 2;
    int new_size;
    size_t bytes_header = 0;
    size_t bytes_body = 0;
    char *tmp;

    /* check enough space for the ending CRLF */
    if (header_available(c, crlf) != 0) {
        new_size = c->header_size + 2;
        tmp = realloc(c->header_buf, new_size);
        if (!tmp) {
            return -1;
        }
        c->header_buf = tmp;
        c->header_len = new_size;
    }

    /* Append the ending header CRLF */
    c->header_buf[c->header_len++] = '\r';
    c->header_buf[c->header_len++] = '\n';

    /* Write the header */
    ret = flb_io_net_write(c->u_conn,
                           c->header_buf, c->header_len,
                           &bytes_header);
    if (ret == -1) {
        perror("write");
        return -1;
    }

    if (c->body_len > 0) {
        ret = flb_io_net_write(c->u_conn,
                               c->body_buf, c->body_len,
                               &bytes_body);
        if (ret == -1) {
            perror("write");
            return -1;
        }
    }

    /* number of sent bytes */
    *bytes = (bytes_header + bytes_body);

    /* Read the server response, we need at least 19 bytes */
    c->resp.data_len = 0;
    while (c->resp.data_len < 19) {
        available = ((sizeof(c->resp.data) - 1) - c->resp.data_len);
        if (available < 1) {
            return -1;
        }

        r_bytes = flb_io_net_read(c->u_conn,
                                  c->resp.data + c->resp.data_len,
                                  available);
        if (r_bytes <= 0) {
            return -1;
        }

        c->resp.data_len += r_bytes;
        c->resp.data[c->resp.data_len] = '\0';
    }

    process_response(c);
    return 0;
}

void flb_http_client_destroy(struct flb_http_client *c)
{
    free(c->header_buf);
    free(c);
}
