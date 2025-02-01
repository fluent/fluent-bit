/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>

#include <monkey/mk_http.h>
#include <monkey/mk_http_parser.h>
#include <monkey/mk_http_status.h>

#define mark_end()                              \
    p->end = p->i;                              \
    p->chars = -1;

#define start_next()                            \
    p->start = p->i + 1;                        \
    continue

#define field_len()   (p->end - p->start)
#define header_scope_eq(p, x) p->header_min = p->header_max = x

struct row_entry {
    int len;
    const char name[32];
};

struct row_entry mk_methods_table[] = {
    { 3, "GET"     },
    { 4, "POST"    },
    { 4, "HEAD"    },
    { 3, "PUT"     },
    { 6, "DELETE"  },
    { 7, "OPTIONS" }
};

struct row_entry mk_headers_table[] = {
    {  6, "accept"              },
    { 14, "accept-charset"      },
    { 15, "accept-encoding"     },
    { 15, "accept-language"     },
    { 13, "authorization"       },
    { 13, "cache-control"       },
    {  6, "cookie"              },
    { 10, "connection"          },
    { 14, "content-length"      },
    { 13, "content-range"       },
    { 12, "content-type"        },
    {  4, "host"                },
    { 14, "http2-settings"      },
    { 17, "if-modified-since"   },
    { 13, "last-modified"       },
    { 19, "last-modified-since" },
    {  5, "range"               },
    {  7, "referer"             },
    { 17, "transfer-encoding"   },
    {  7, "upgrade"             },
    { 10, "user-agent"          },
};

static inline void reverse_char_lookup(char *buf, char c, int len, struct mk_http_parser *p)
{
    int x = 0;
    int y = 0;

    x = p->i;
    do {
        if (buf[x - y] == c) {
            p->i = x - y;
            return;
        }
        y++;
    } while (y < len);
}

static inline void char_lookup(char *buf, char c, int len, struct mk_http_parser *p)
{
    int x = 0;

    x = p->i;
    do {
        if (buf[x] == c) {
            p->i = x;
            return;
        }
        x++;
    } while (x < len);
}

static inline int str_searchr(char *buf, char c, int len)
{
    int i;

    for (i = len - 1; i >= 0; i--) {
        if (buf[i] == c) {
            return i;
        }
    }

    return -1;
}

static inline int method_lookup(struct mk_http_request *req,
                                struct mk_http_parser *p, char *buffer)
{
    int i = 0;
    int len;

    /* Method lenght */
    len = field_len();

    /* Point the buffer */
    req->method = MK_METHOD_UNKNOWN;
    req->method_p.data = buffer + p->start;
    req->method_p.len  = len;

    if (p->method >= 0) {
        if (strncmp(buffer + p->start + 1,
                    mk_methods_table[p->method].name + 1,
                    len - 1) == 0) {
            req->method = p->method;
            return req->method;
        }
    }

    for (i = 0; i < MK_METHOD_SIZEOF; i++) {
        if (len != mk_methods_table[i].len) {
            continue;
        }

        if (strncmp(buffer + p->start, mk_methods_table[i].name, len) == 0) {
            req->method = i;
            return i;
        }
    }
    return MK_METHOD_UNKNOWN;
}

static inline void request_set(mk_ptr_t *ptr, struct mk_http_parser *p, char *buffer)
{
    ptr->data = buffer + p->start;
    ptr->len  = field_len();
}

/*
 * expected: a known & expected value in lowercase
 * value   : the expected string value in the header
 * len     : the value string length.
 *
 * If it matches it return zero. Otherwise -1.
 */
static inline int header_cmp(const char *expected, char *value, int len)
{
    int i = 0;

    if (len >= 8) {
        if (expected[0] != tolower(value[0])) return -1;
        if (expected[1] != tolower(value[1])) return -1;
        if (expected[2] != tolower(value[2])) return -1;
        if (expected[3] != tolower(value[3])) return -1;
        if (expected[4] != tolower(value[4])) return -1;
        if (expected[5] != tolower(value[5])) return -1;
        if (expected[6] != tolower(value[6])) return -1;
        if (expected[7] != tolower(value[7])) return -1;
        i = 8;
    }

    for (; i < len; i++) {
        if (expected[i] != tolower(value[i])) {
            return -1;
        }
    }

    return 0;
}

static inline int header_lookup(struct mk_http_parser *p, char *buffer)
{
    int i;
    int len;
    int pos;
    long val;
    char *endptr;
    char *tmp;

    struct mk_http_header *header;
    struct mk_http_header *header_extra;
    struct row_entry *h;

    len = (p->header_sep - p->header_key);
    for (i = p->header_min; i <= p->header_max && i >= 0; i++) {
        h = &mk_headers_table[i];
        /* Check string length first */
        if (h->len != len) {
            continue;
        }

        if (header_cmp(h->name + 1, buffer + p->header_key + 1, len - 1) == 0) {
            /* We got a header match, register the header index */
            header = &p->headers[i];
            header->type = i;
            header->key.data = buffer + p->header_key;
            header->key.len  = len;
            header->val.data = buffer + p->header_val;
            header->val.len  = p->end - p->header_val;
            p->header_count++;

            if (!mk_list_entry_is_orphan(&header->_head)) {
                mk_list_del(&header->_head);
            }

            mk_list_add(&header->_head, &p->header_list);

            if (i == MK_HEADER_HOST) {
                /* Handle a possible port number in the Host header */
                int sep = str_searchr(header->val.data, ':', header->val.len);
                if (sep > 0) {
                    int plen;
                    short int port_size = 6;
                    char port[6]; /* Can't use port_size to declare a stack allocated array in vc++ */

                    plen = header->val.len - sep - 1;
                    if (plen <= 0 || plen >= port_size) {
                        return -MK_CLIENT_BAD_REQUEST;
                    }
                    memcpy(&port, header->val.data + sep + 1, plen);
                    port[plen] = '\0';

                    errno = 0;
                    val = strtol(port, &endptr, 10);
                    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
                        || (errno != 0 && val == 0)) {
                        return -MK_CLIENT_BAD_REQUEST;
                    }

                    if (endptr == port || *endptr != '\0') {
                        return -MK_CLIENT_BAD_REQUEST;
                    }

                    p->header_host_port = val;

                    /* Re-set the Host header value without port */
                    header->val.len = sep;
                }
            }
            else if (i == MK_HEADER_CONTENT_LENGTH) {
                errno = 0;
                val = strtol(header->val.data, &endptr, 10);
                if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
                    || (errno != 0 && val == 0)) {
                    return -MK_CLIENT_REQUEST_ENTITY_TOO_LARGE;
                }
                if (endptr == header->val.data) {
                    return -1;
                }
                if (val < 0) {
                    return -1;
                }

                p->header_content_length = val;
            }
            else if (i == MK_HEADER_CONNECTION) {
                /* Check Connection: Keep-Alive */
                if (header->val.len == sizeof(MK_CONN_KEEP_ALIVE) - 1) {
                    if (header_cmp(MK_CONN_KEEP_ALIVE,
                                   header->val.data,
                                   header->val.len ) == 0) {
                        p->header_connection = MK_HTTP_PARSER_CONN_KA;
                    }
                }
                /* Check Connection: Close */
                else if (header->val.len == sizeof(MK_CONN_CLOSE) -1) {
                    if (header_cmp(MK_CONN_CLOSE,
                                   header->val.data, header->val.len) == 0) {
                        p->header_connection = MK_HTTP_PARSER_CONN_CLOSE;
                    }
                }
                else {
                    p->header_connection = MK_HTTP_PARSER_CONN_UNKNOWN;

                    /* Try to find some known values */

                    /* Connection: upgrade */
                    pos = mk_string_search_n(header->val.data,
                                             "Upgrade",
                                             MK_STR_INSENSITIVE,
                                             header->val.len);
                    if (pos >= 0) {
                        p->header_connection = MK_HTTP_PARSER_CONN_UPGRADE;
                    }

                    /* Connection: HTTP2-Settings */
                    pos = mk_string_search_n(header->val.data,
                                             "HTTP2-Settings",
                                             MK_STR_INSENSITIVE,
                                             header->val.len);
                    if (pos >= 0) {
                        p->header_connection |= MK_HTTP_PARSER_CONN_HTTP2_SE;
                    }
                }
            }
            else if (i == MK_HEADER_TRANSFER_ENCODING) {
                /* Check Transfer-Encoding: chunked */
                pos = mk_string_search_n(header->val.data,
                                         "chunked",
                                         MK_STR_INSENSITIVE,
                                         header->val.len);
                if (pos >= 0) {
                    p->header_transfer_encoding |= MK_HTTP_PARSER_TRANSFER_ENCODING_CHUNKED;
                }

                /* Check Transfer-Encoding: gzip */
                pos = mk_string_search_n(header->val.data,
                                         "gzip",
                                         MK_STR_INSENSITIVE,
                                         header->val.len);
                if (pos >= 0) {
                    p->header_transfer_encoding |= MK_HTTP_PARSER_TRANSFER_ENCODING_GZIP;
                }

                /* Check Transfer-Encoding: compress */
                pos = mk_string_search_n(header->val.data,
                                         "compress",
                                         MK_STR_INSENSITIVE,
                                         header->val.len);
                if (pos >= 0) {
                    p->header_transfer_encoding |= MK_HTTP_PARSER_TRANSFER_ENCODING_COMPRESS;
                }

                /* Check Transfer-Encoding: deflate */
                pos = mk_string_search_n(header->val.data,
                                         "deflate",
                                         MK_STR_INSENSITIVE,
                                         header->val.len);
                if (pos >= 0) {
                    p->header_transfer_encoding |= MK_HTTP_PARSER_TRANSFER_ENCODING_DEFLATE;
                }

                /* Check Transfer-Encoding: identity */
                pos = mk_string_search_n(header->val.data,
                                         "identity",
                                         MK_STR_INSENSITIVE,
                                         header->val.len);
                if (pos >= 0) {
                    p->header_transfer_encoding |= MK_HTTP_PARSER_TRANSFER_ENCODING_IDENTITY;
                }
            }
            else if (i == MK_HEADER_UPGRADE) {
                    if (header_cmp(MK_UPGRADE_H2C,
                                   header->val.data, header->val.len) == 0) {
                        p->header_upgrade = MK_HTTP_PARSER_UPGRADE_H2C;
                    }
            }

            return 0;
        }
    }

    /*
     * The header_lookup did not match any known header, so we register this
     * entry into the headers_extra array.
     */
    if (p->headers_extra_count < MK_HEADER_EXTRA_SIZE) {
        header_extra = &p->headers_extra[p->headers_extra_count];
        header_extra->key.data = tmp = (buffer + p->header_key);
        header_extra->key.len  = len;

        /* Transform the header key string to lowercase */
        for (i = 0; i < len; i++) {
            tmp[i] = tolower(tmp[i]);
        }

        header_extra->val.data = buffer + p->header_val;
        header_extra->val.len  = p->end - p->header_val;
        p->headers_extra_count++;
        p->header_count++;
        mk_list_add(&header_extra->_head, &p->header_list);
        return 0;
    }

    /*
     * Header is unknown and we cannot store it on our extra headers
     * list as it's already full. Request is too large.
     */
    return -MK_CLIENT_REQUEST_ENTITY_TOO_LARGE;
}


/* check if the HTTP content is chunked so it contain hexa string length headers */
int mk_http_parser_is_content_chunked(struct mk_http_parser *p)
{
    return p->header_transfer_encoding & MK_HTTP_PARSER_TRANSFER_ENCODING_CHUNKED;
}

size_t mk_http_parser_content_length(struct mk_http_parser *p)
{
    /*
     * returns the content length of the payload. If the content-length header was
     * set, it will return the value of the header. If the content-length header was
     * not set and instead the transfer-encoding header was set to chunked, it will
     * return the length of the payload withouto counting the chunked headers.
     */

    if (!mk_http_parser_is_content_chunked(p)) {
        return p->header_content_length;
    }
    else {
        return p->chunk_total_size_received;
    }

    return 0;
}


int cb_debug_chunk_complete(char *in, size_t in_len, char *out, size_t out_len, size_t *out_len_processed)
{
    (void) out;
    (void) out_len;
    char *buf;

    /* copy the chunked content into the buffer */
    buf = mk_mem_alloc(in_len + 1);
    if (!buf) {
        return -1;
    }

    memcpy(buf, in, in_len);
    buf[in_len] = '\0';

    printf("==CHUNK DETECTED CONTENT (length=%zu)==\n'%s'\n---\n", in_len, buf);
    mk_mem_free(buf);

    *out_len_processed = in_len;

    return 0;
}

/*
 * Check if the request body is complete, incomplete or if it has an error while processing
 * the chunks for a chunked transfer encoded payload
 */
static int http_parser_transfer_encoding_chunked(struct mk_http_parser *p,
                                                 char *buf_request, size_t buf_request_len,
                                                 int (*cb_chunk_complete)(char *in, size_t in_len, char *out, size_t out_len, size_t *out_len_processed),
                                                 char *out_buf, size_t out_buf_size, size_t *out_buf_len)
{
    int64_t len;
    int64_t chunk_len;
    int64_t pos;
    char tmp[32];
    char *ptr;
    char *content_start;
    size_t available_bytes;

    p->level = REQ_LEVEL_BODY;

parse_more:

    /* read the payload and check if the request has finished based on the logic of transfer encoding chunked */
    if (!p->chunk_processed_start) {
        /*
         * if p->chunk_processed_start is not set, it means we are parsing from the beginning. Note that
         * p->chunk_expected_start is set, it means the content was already processed before, so we just
         * adjust the pointer, otherwise we use the parser iterator index (p->i) for it.
         */
        if (p->chunk_expected_start) {
            p->chunk_processed_start = p->chunk_expected_start;
        }
        else {
            p->chunk_processed_start = buf_request + p->i;

            /* Mark the very first chunk */
            p->chunk_expected_start = p->chunk_processed_start;
        }

        len = buf_request_len - p->i;
        if (len == 0) {
            return MK_HTTP_PARSER_PENDING;
        }

        if (p->chunk_processed_start[0] != '\n') {
            return MK_HTTP_PARSER_ERROR;
        }

        /* we are at the beginning of a chunk, we need to find the end */
        p->chunk_processed_start++;
        len--;

    }
    else {
        len = buf_request_len - (p->chunk_processed_end - buf_request);
    }

    /* find the end of the 'chunk header' (e.g: ffae\r\n\r\n) */
    pos = mk_string_search_n(p->chunk_processed_start, "\r\n", MK_STR_SENSITIVE, len);
    if (pos < 0) {
        return MK_HTTP_PARSER_PENDING;
    }

    /* length of the hex string */
    len = (p->chunk_processed_start + pos) - p->chunk_processed_start;
    if (((unsigned long) len > sizeof(tmp) - 1) || len == 0) {
        return MK_HTTP_PARSER_ERROR;
    }

    /* copy the hex string to a temporary buffer */
    memcpy(tmp, p->chunk_processed_start, len);
    tmp[len] = '\0';

    /* convert the hex string to a number */
    errno = 0;
    chunk_len = strtol(tmp, &ptr, 16);
    if ((errno == ERANGE && (chunk_len == LONG_MAX || chunk_len == LONG_MIN)) ||
        (errno != 0)) {
        return MK_HTTP_PARSER_ERROR;
    }

    if (chunk_len < 0) {
        return MK_HTTP_PARSER_ERROR;
    }
    else if (chunk_len == 0) {
        /* we have reached the end of the request, validate the last \r\n\r\n exists */
        len = buf_request_len - (p->chunk_processed_start - buf_request);

        if (len < 5) {
            return MK_HTTP_PARSER_PENDING;
        }

        /* all or nothing */
        if (strncmp(p->chunk_processed_start, "0\r\n\r\n", 5) != 0) {
            return MK_HTTP_PARSER_ERROR;
        }

        return MK_HTTP_PARSER_OK;
    }
    else {
        /* set the new markers: required size and start position after the hex string length */
        p->chunk_expected_size = chunk_len;

        /* the content starts after the hex_str_length\r\n */
        content_start = p->chunk_processed_start + pos + 2;

        /* calculate the amount of available bytes 'after' content_start */
        available_bytes = buf_request_len - (content_start - buf_request);

        /* do we have all the remaining data needed in our buffer ? */
        if (available_bytes >= p->chunk_expected_size + 2 /* \r\n */) {
            /* we have all the data needed */
            p->chunk_processed_end = content_start + p->chunk_expected_size;

            /* check for delimiter \r\n */
            if (p->chunk_processed_end[0] != '\r' || p->chunk_processed_end[1] != '\n') {
                return MK_HTTP_PARSER_ERROR;
            }

            /*
             * If the callback function has been set, invoke it: this callback might be useful for
             * debugging and/or provide a way to copy the chunked content into a buffer
             */
            if (cb_chunk_complete) {
                cb_chunk_complete(content_start, chunk_len, out_buf, out_buf_size, out_buf_len);
            }

            /* set the new start for the new chunk */
            p->chunk_processed_start = p->chunk_processed_end + 2;
            p->chunk_total_size_received += chunk_len;
            goto parse_more;
        }
        else {
            /* we need more data */
            return MK_HTTP_PARSER_PENDING;
        }

    }
    /* is our chunk complete ? */
    return MK_HTTP_PARSER_PENDING;

}

/* Read the chunked content and invoke callback if it has been set */
int mk_http_parser_read_chunked_content(struct mk_http_parser *p,
                                        char *buf_request, size_t buf_request_len,
                                        int (*cb_chunk_complete)(char *in, size_t in_len, char *out, size_t out_size, size_t *out_len),
                                        char *out_buf, size_t out_buf_size, size_t *out_buf_len)
{
    p->chunk_processed_start = NULL;
    p->chunk_processed_end = NULL;

    return http_parser_transfer_encoding_chunked(p,
                                                 buf_request, buf_request_len,
                                                 cb_chunk_complete,
                                                 out_buf, out_buf_size, out_buf_len);
}

/*
 * Callback function used by mk_http_parser_chunked_decode to provide a new buffer with the content
 * of the payload decoded
 */
static int cb_copy_chunk(char *in, size_t in_len, char *out, size_t out_size, size_t *out_len_processed)
{
    (void) out_size;

    /* check we don't overflow the buffer */
    if (*out_len_processed + in_len > out_size) {
        return -1;
    }

    /* copy the chunk */
    memcpy(out + *out_len_processed, in, in_len);
    *out_len_processed += in_len;

    return 0;
}

/*
 * This function assumes that the output buffer size has enough space to copy the desired
 * chunked content. We do some sanity checks but if the buffer is smaller the data will
 * be truncated.
 */
int mk_http_parser_chunked_decode_buf(struct mk_http_parser *p,
                                      char *buf_request, size_t buf_request_len,
                                      char *out_buf, size_t out_buf_size, size_t *out_buf_len)
{
    int ret;
    size_t written_bytes = 0;

    ret = mk_http_parser_read_chunked_content(p,
                                              buf_request, buf_request_len,
                                              cb_copy_chunk,
                                              out_buf, out_buf_size, &written_bytes);
    if (ret == MK_HTTP_PARSER_OK) {
        *out_buf_len = written_bytes;
        return 0;
    }

    return -1;
}

int mk_http_parser_chunked_decode(struct mk_http_parser *p,
                                    char *buf_request, size_t buf_request_len,
                                    char **out_buf, size_t *out_buf_size)
{
    int ret;
    char *tmp_buf;
    size_t tmp_buf_size = 0;
    size_t tmp_written_bytes = 0;

    tmp_buf_size = mk_http_parser_content_length(p);
    if (tmp_buf_size == 0) {
        return -1;
    }

    tmp_buf = mk_mem_alloc(tmp_buf_size);
    if (!tmp_buf) {
        return -1;
    }

    ret = mk_http_parser_chunked_decode_buf(p,
                                            buf_request, buf_request_len,
                                            tmp_buf, tmp_buf_size, &tmp_written_bytes);
    if (ret == -1) {
        mk_mem_free(tmp_buf);
        return -1;
    }

    *out_buf = tmp_buf;
    *out_buf_size = tmp_written_bytes;

    return 0;
}

/*
 * This function is invoked everytime the parser evaluate the request is
 * OK. Here we perform some extra validations mostly based on some logic
 * and protocol requirements according to the data received.
 */
static inline int mk_http_parser_ok(struct mk_http_request *req,
                                    struct mk_http_parser *p,
                                    char *buf_request, size_t buf_request_len,
                                    struct mk_server *server)
{
    int ret;

    /* Validate HTTP Version */
    if (req->protocol == MK_HTTP_PROTOCOL_UNKNOWN) {
        mk_http_error(MK_SERVER_HTTP_VERSION_UNSUP, req->session, req, server);
        return MK_HTTP_PARSER_ERROR;
    }

    /* POST checks */
    if (req->method == MK_METHOD_POST || req->method == MK_METHOD_PUT) {
        /* validate Content-Length exists for non-chunked requests */
        if (mk_http_parser_is_content_chunked(p)) {
            p->level = REQ_LEVEL_BODY;

            ret = http_parser_transfer_encoding_chunked(p,
                                                        buf_request, buf_request_len,
                                                        NULL, NULL, 0, NULL);
            return ret;
        }
        else {
            if (p->headers[MK_HEADER_CONTENT_LENGTH].type == 0) {
                mk_http_error(MK_CLIENT_LENGTH_REQUIRED, req->session, req, server);
                return MK_HTTP_PARSER_ERROR;
            }
        }
    }

    return MK_HTTP_PARSER_OK;
}

/*
 * Parse the protocol and point relevant fields, don't take logic decisions
 * based on this, just parse to locate things.
 */
int mk_http_parser(struct mk_http_request *req, struct mk_http_parser *p,
                   char *buffer, int buf_len, struct mk_server *server)
{
    int s;
    int tmp;
    int ret;
    int len;

    /* lazy test
    printf("p->i=%i buf_len=%i\n",
           p->i, buf_len);

    for (s = p->i; s < buf_len; s++) {
        if (buffer[s] == '\r') {
            printf("CR");
        }
        else if (buffer[s] == '\n') {
            printf("LF");
        }
        else {
            printf("%c", buffer[s]);
        }
    }
    printf("\n");
    */

    len = buf_len;
    for (; p->i < len; p->i++, p->chars++) {
        /* FIRST LINE LEVEL: Method, URI & Protocol */
        if (p->level == REQ_LEVEL_FIRST) {
            switch (p->status) {
            case MK_ST_REQ_METHOD:                      /* HTTP Method */
                if (p->chars == -1) {
                    switch (buffer[p->i]) {
                    case 'G':
                        p->method = MK_METHOD_GET;
                        break;
                    case 'P':
                        p->method = MK_METHOD_POST;
                        break;
                    case 'H':
                        p->method = MK_METHOD_HEAD;
                        break;
                    case 'D':
                        p->method = MK_METHOD_DELETE;
                        break;
                    case 'O':
                        p->method = MK_METHOD_OPTIONS;
                        break;
                    }
                    continue;
                }

                if (buffer[p->i] == ' ') {
                    mark_end();
                    p->status = MK_ST_REQ_URI;
                    if (p->end < 2) {
                        return MK_HTTP_PARSER_ERROR;
                    }
                    method_lookup(req, p, buffer);
                    start_next();
                }
                else {
                    if ((p->i - p->start) > 10) {
                        return MK_HTTP_PARSER_ERROR;
                    }
                }
                break;
            case MK_ST_REQ_URI:                         /* URI */
                if (buffer[p->i] == ' ') {
                    mark_end();
                    p->status = MK_ST_REQ_PROT_VERSION;
                    if (field_len() < 1) {
                        return MK_HTTP_PARSER_ERROR;
                    }
                    request_set(&req->uri, p, buffer);
                    start_next();
                }
                else if (buffer[p->i] == '?') {
                    mark_end();
                    request_set(&req->uri, p, buffer);
                    p->status = MK_ST_REQ_QUERY_STRING;
                    start_next();
                }
                else if (buffer[p->i] == '\r' || buffer[p->i] == '\n') {
                    mk_http_error(MK_CLIENT_BAD_REQUEST, req->session,
                                  req, server);
                    return MK_HTTP_PARSER_ERROR;
                }
                break;
            case MK_ST_REQ_QUERY_STRING:                /* Query string */
                char_lookup(buffer, '\n', len, p);

                if (buffer[p->i] == '\n') {
                    reverse_char_lookup(buffer, ' ', p->i, p);
                }

                if (buffer[p->i] == ' ') {
                    mark_end();
                    request_set(&req->query_string, p, buffer);
                    p->status = MK_ST_REQ_PROT_VERSION;
                    start_next();
                }
                else if (buffer[p->i] == '\r' || buffer[p->i] == '\n') {
                    mk_http_error(MK_CLIENT_BAD_REQUEST, req->session,
                                  req, server);
                    return MK_HTTP_PARSER_ERROR;
                }
                break;
            case MK_ST_REQ_PROT_VERSION:                /* Protocol Version */
                /*
                 * Most of the time we already have the string version in our
                 * buffer, for that case try to match the version and avoid
                 * loop rounds.
                 */
                if (p->start + 6 >= p->i) {
                    continue;
                }

                tmp = p->start;
                if (buffer[tmp] == 'H' &&
                    buffer[tmp + 1] == 'T' &&
                    buffer[tmp + 2] == 'T' &&
                    buffer[tmp + 3] == 'P' &&
                    buffer[tmp + 4] == '/' &&
                    buffer[tmp + 5] == '1' &&
                    buffer[tmp + 6] == '.') {

                    request_set(&req->protocol_p, p, buffer);
                    req->protocol_p.len = 8;
                    mk_http_set_minor_version(buffer[tmp + 7]);
                }
                else {
                    mk_http_error(MK_SERVER_HTTP_VERSION_UNSUP,
                                  req->session, req, server);
                    return MK_HTTP_PARSER_ERROR;
                }
                p->status = MK_ST_FIRST_CONTINUE;
                break;
            case MK_ST_FIRST_CONTINUE:
                if (buffer[p->i] == '\r') {
                    p->status = MK_ST_FIRST_FINALIZING;
                }
                else {
                    return MK_HTTP_PARSER_ERROR;
                }
                break;
            case MK_ST_FIRST_FINALIZING:                  /* New Line */
                if (buffer[p->i] == '\n') {
                    p->level = REQ_LEVEL_CONTINUE;
                    start_next();
                }
                else {
                    return MK_HTTP_PARSER_ERROR;
                }
                break;
            case MK_ST_BLOCK_END:
                if (buffer[p->i] == '\n') {
                    return mk_http_parser_ok(req, p, buffer, buf_len, server);
                }
                else {
                    return MK_HTTP_PARSER_ERROR;
                }
                break;
            };
        }
        else if (p->level == REQ_LEVEL_CONTINUE) {
            if (buffer[p->i] == '\r') {
                p->level  = REQ_LEVEL_FIRST;
                p->status = MK_ST_BLOCK_END;
            }
            else {
                p->level  = REQ_LEVEL_HEADERS;
                p->status = MK_ST_HEADER_KEY;
                p->chars  = 0;
            }
        }
        /* HEADERS: all headers stuff */
        if (p->level == REQ_LEVEL_HEADERS) {
            /* Expect a Header key */
            if (p->status == MK_ST_HEADER_KEY) {
                if (buffer[p->i] == '\r') {
                    if (p->chars == 0) {
                        p->level = REQ_LEVEL_END;
                        start_next();
                    }
                    else {
                        return MK_HTTP_PARSER_ERROR;
                    }
                }

                if (p->chars == 0) {
                    /*
                     * We reach the start of a Header row, lets catch the most
                     * probable header.
                     *
                     * The goal of this 'first row character lookup', is to define a
                     * small range set of probable headers comparison once we catch
                     * a header end.
                     */
                    s = tolower(buffer[p->i]);
                    switch (s) {
                    case 'a':
                        p->header_min = MK_HEADER_ACCEPT;
                        p->header_max = MK_HEADER_AUTHORIZATION;
                        break;
                    case 'c':
                        p->header_min = MK_HEADER_CACHE_CONTROL;
                        p->header_max = MK_HEADER_CONTENT_TYPE;
                        break;
                    case 'h':
                        p->header_min = MK_HEADER_HOST;
                        p->header_max = MK_HEADER_HTTP2_SETTINGS;
                        break;
                    case 'i':
                        header_scope_eq(p, MK_HEADER_IF_MODIFIED_SINCE);
                        break;
                    case 'l':
                        p->header_min = MK_HEADER_LAST_MODIFIED;
                        p->header_max = MK_HEADER_LAST_MODIFIED_SINCE;
                        break;
                    case 'r':
                        p->header_min = MK_HEADER_RANGE;
                        p->header_max = MK_HEADER_REFERER;
                        break;
                    case 'u':
                        p->header_min = MK_HEADER_UPGRADE;
                        p->header_max = MK_HEADER_USER_AGENT;
                        break;
                    case 't':
                        header_scope_eq(p, MK_HEADER_TRANSFER_ENCODING);
                        break;
                    default:
                        p->header_key = -1;
                        p->header_sep = -1;
                        p->header_min = -1;
                        p->header_max = -1;
                    };
                    p->header_key = p->i;
                    continue;
                }

                /* Found key/value separator */
                char_lookup(buffer, ':', len, p);
                if (buffer[p->i] == ':') {
                    /* Set the key/value middle point */
                    p->header_sep = p->i;

                    /* validate length */
                    mark_end();
                    if (field_len() < 1) {
                        return MK_HTTP_PARSER_ERROR;
                    }

                    /* Wait for a value */
                    p->status = MK_ST_HEADER_VALUE;
                    start_next();
                }
            }
            /* Parsing the header value */
            else if (p->status == MK_ST_HEADER_VALUE) {
                /* Trim left, set starts only when found something != ' ' */
                if (buffer[p->i] == '\r' || buffer[p->i] == '\n') {
                    return MK_HTTP_PARSER_ERROR;
                }
                else if (buffer[p->i] != ' ') {
                    p->status = MK_ST_HEADER_VAL_STARTS;
                    p->start = p->header_val = p->i;
                }
                continue;
            }
            /* New header row starts */
            else if (p->status == MK_ST_HEADER_VAL_STARTS) {
                /* Maybe there is no more headers and we reach the end ? */
                if (buffer[p->i] == '\r') {
                    mark_end();
                    if (field_len() <= 0) {
                        return MK_HTTP_PARSER_ERROR;
                    }

                    /*
                     * A header row has ended, lets lookup the header and populate
                     * our headers table index.
                     */
                    ret = header_lookup(p, buffer);
                    if (ret != 0) {
                        if (ret < -1) {
                            mk_http_error(-ret, req->session, req, server);
                        }
                        return MK_HTTP_PARSER_ERROR;
                    }

                    /* Try to catch next LF */
                    if (p->i + 1 < len) {
                        if (buffer[p->i + 1] == '\n') {
                            p->i++;
                            p->status = MK_ST_HEADER_KEY;
                            p->chars = -1;
                            start_next();
                        }
                    }

                    p->status = MK_ST_HEADER_END;
                    start_next();
                }
                else if (buffer[p->i] == '\n' && buffer[p->i - 1] != '\r') {
                    return MK_HTTP_PARSER_ERROR;
                }
            }
            else if (p->status == MK_ST_HEADER_END) {
                if (buffer[p->i] == '\n') {
                    p->status = MK_ST_HEADER_KEY;
                    p->chars = -1;
                    start_next();
                }
                else {
                    return MK_HTTP_PARSER_ERROR;
                }
            }
        }
        else if (p->level == REQ_LEVEL_END) {
            if (buffer[p->i] == '\n') {
                if (p->header_content_length > 0) {
                    p->level = REQ_LEVEL_BODY;
                    p->chars = -1;
                    start_next();
                }
                else {
                    return mk_http_parser_ok(req, p, buffer, buf_len, server);
                }
            }
            else {
                return MK_HTTP_PARSER_ERROR;
            }
        }
        else if (p->level == REQ_LEVEL_BODY) {
            /*
             * Reaching this level can means two things:
             *
             * - A Pipeline Request
             * - A Body content (POST/PUT methods)
             */
            if (p->header_content_length > 0) {

                p->body_received = len - p->start;
                if ((len - p->start) < p->header_content_length) {
                    return MK_HTTP_PARSER_PENDING;
                }

                /* Cut off */
                p->i += p->body_received;
                req->data.len  = p->body_received;
                req->data.data = (buffer + p->start);
            }
            return mk_http_parser_ok(req, p, buffer, buf_len, server);
        }
    }

    return MK_HTTP_PARSER_PENDING;
}
