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

#include <monkey/mk_api.h>
#include <monkey/mk_net.h>
#include <monkey/mk_stream.h>

#include "fastcgi.h"
#include "fcgi_handler.h"

#define FCGI_BUF(h)           (char *) h->buf_data + h->buf_len
#define FCGI_PARAM_DYN(str)   str, strlen(str), MK_FALSE
#define FCGI_PARAM_CONST(str) str, sizeof(str) -1, MK_FALSE
#define FCGI_PARAM_PTR(ptr)   ptr.data, ptr.len, MK_FALSE
#define FCGI_PARAM_DUP(str)   mk_api->str_dup(str), strlen(str), MK_TRUE

int fcgi_pad[256] = {0};

static inline void fcgi_build_header(struct fcgi_record_header *rec,
                                     uint8_t type, uint16_t request_id,
                                     uint16_t content_length)
{
    rec->version         = FCGI_VERSION_1;
    rec->type            = type;
    fcgi_encode16(&rec->request_id, request_id);
    fcgi_encode16(&rec->content_length, content_length);
    rec->padding_length  = 0;
    rec->reserved        = 0;
}

static inline void fcgi_build_request_body(struct fcgi_begin_request_body *body)
{
    fcgi_encode16(&body->role, FCGI_RESPONDER);
    body->flags       = 0;
    memset(body->reserved, '\0', sizeof(body->reserved));
}

static inline size_t fcgi_write_length(char *p, size_t len)
{
    if (len < 127) {
		*p++ = len;
		return 1;
    }
    else{
		*p++  = (len >> 24) | 0x80;
		*p++  = (len >> 16) & 0xff;
		*p++  = (len >>  8) & 0xff;
		*p++  = (len)       & 0xff;
		return 4;
	}
}

static inline int fcgi_add_param_empty(struct fcgi_handler *handler)
{
    char *p;

    p = FCGI_BUF(handler);
    fcgi_build_header((struct fcgi_record_header *) p, FCGI_PARAMS, 1, 0);
    mk_api->iov_add(handler->iov, p,
                    sizeof(struct fcgi_record_header), MK_FALSE);
    handler->buf_len += sizeof(struct fcgi_record_header);
    return 0;
}

static inline int fcgi_add_param(struct fcgi_handler *handler,
                                 char *key, int key_len, int key_free,
                                 char *val, int val_len, int val_free)
{
    int ret;
    int len;
    int diff;
    int padding;
    char *p;
    char *buf;
    struct fcgi_record_header *h;

    buf = p = (char * ) handler->buf_data + handler->buf_len;

	len  = key_len + val_len;
	len += key_len > 127 ? 4 : 1;
	len += val_len > 127 ? 4 : 1;

    fcgi_build_header((struct fcgi_record_header *) p, FCGI_PARAMS, 1, len);
    padding = ~(len - 1) & 7;
    if (padding) {
        h = (struct fcgi_record_header *) p;
        h->padding_length = padding;
    }

    p += sizeof(struct fcgi_record_header);
    p += fcgi_write_length(p, key_len);
    p += fcgi_write_length(p, val_len);

    diff = (p - buf);
    handler->buf_len += diff;
    ret = mk_api->iov_add(handler->iov, buf, diff, MK_FALSE);
    if (ret == -1) {
        return -1;
    }

    mk_api->iov_add(handler->iov, key, key_len, key_free);
    mk_api->iov_add(handler->iov, val, val_len, val_free);

    if (padding) {
        mk_api->iov_add(handler->iov, fcgi_pad, h->padding_length, MK_FALSE);
    }

    return 0;
}

static inline int fcgi_add_param_http_header(struct fcgi_handler *handler,
                                             struct mk_http_header *header)
{
    unsigned int i;
    int avail;
    int req;
    int diff;
    char *p;
    char *buf;

    avail = (sizeof(handler->buf_data) - handler->buf_len);
    req   = sizeof(struct fcgi_record_header) + 8;
    req  += header->key.len + 5;

    if (avail < req) {
        return -1;
    }

    buf = p = (handler->buf_data + handler->buf_len);
    *p++ = 'H';
    *p++ = 'T';
    *p++ = 'T';
    *p++ = 'P';
    *p++ = '_';

    for (i = 0; i < header->key.len; i++) {
        if (header->key.data[i] == '-') {
            *p++ = '_';
        }
        else {
            *p++ = toupper(header->key.data[i]);
        }
    }

    diff = (p - buf);
    handler->buf_len += diff;
    fcgi_add_param(handler,
                   buf, diff, MK_FALSE,
                   header->val.data, header->val.len, MK_FALSE);

    return 0;
}

static inline int fcgi_add_param_net(struct fcgi_handler *handler)
{
    int ret;
    const char *p;
    char buffer[256];

    /* This is to identify whether its IPV4 or IPV6 */
    struct sockaddr_storage addr;
    int port = 0;
	socklen_t addr_len = sizeof(struct sockaddr_in);

    ret = getsockname(handler->cs->socket, (struct sockaddr *)&addr, &addr_len);
    if (ret == -1) {
#ifdef TRACE
        perror("getsockname");
#endif
        if (errno == EBADF) {
            MK_TRACE("[fastcgi=%i] network connection broken",
                     handler->cs->socket);
        }
        return -1;
    }

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        port = ntohs(s->sin_port);
        p = inet_ntop(AF_INET, &s->sin_addr, buffer, sizeof(buffer));
        if (!p) {
            perror("inet_ntop");
            return -1;
        }
    } else { /* AF_INET6 */
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        port = ntohs(s->sin6_port);
        p = inet_ntop(AF_INET6, &s->sin6_addr, buffer, sizeof(buffer));
        if (!p) {
            perror("inet_ntop");
            return -1;
        }
    }

    /* Server Address */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SERVER_ADDR"),
                   FCGI_PARAM_DUP(buffer));

    /* Server Port */
    snprintf(buffer, 256, "%d", port);
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SERVER_PORT"),
                   FCGI_PARAM_DUP(buffer));


    ret = getpeername(handler->cs->socket, (struct sockaddr *)&addr, &addr_len);
    if (ret == -1) {
        perror("getpeername");
        return -1;
    }

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        port = ntohs(s->sin_port);
        p = inet_ntop(AF_INET, &s->sin_addr, buffer, sizeof(buffer));
        if (!p) {
            perror("inet_ntop");
            return -1;
        }
    } else { /* AF_INET6 */
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        port = ntohs(s->sin6_port);

        if (IN6_IS_ADDR_V4MAPPED(&s->sin6_addr)) {
            /* This is V4-Mapped-V6 - Lets convert it to plain IPV4 address.
             * E.g. we would have received like this ::ffff:10.106.146.73.
             * This would be converted to 10.106.146.73.
             */
            struct sockaddr_in addr4;
            struct sockaddr_in *s4 = (struct sockaddr_in *)&addr4;
            memset(&addr4, 0, sizeof(addr4));
            addr4.sin_family = AF_INET;
            addr4.sin_port = &s->sin6_port;
            memcpy(&addr4.sin_addr.s_addr,
                   s->sin6_addr.s6_addr + 12,
                   sizeof(addr4.sin_addr.s_addr));
            p = inet_ntop(AF_INET, &s4->sin_addr, buffer, sizeof(buffer));
            if (!p) {
                perror("inet_ntop");
                return -1;
            }
        } else {
            p = inet_ntop(AF_INET6, &s->sin6_addr, buffer, sizeof(buffer));
            if (!p) {
                perror("inet_ntop");
                return -1;
            }
        }
    }

    /* Remote Addr */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("REMOTE_ADDR"),
                   FCGI_PARAM_DUP(buffer));

    /* Remote Port */
    snprintf(buffer, 256, "%d", port);
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("REMOTE_PORT"),
                   FCGI_PARAM_DUP(buffer));

    return 0;
}

static inline int fcgi_stdin_chunk(struct fcgi_handler *handler)
{
    int padding = 0;
    uint16_t max = 65535;
    uint16_t chunk;
    uint64_t total;
    char *p;
    char *eof;
    struct fcgi_record_header *h;

    total = handler->stdin_length - handler->stdin_offset;
    if (total > max) {
        chunk = max;
    }
    else {
        chunk = total;
    }

    p = FCGI_BUF(handler);
    h = (struct fcgi_record_header *) p;
    fcgi_build_header(h, FCGI_STDIN, 1, chunk);
    h->padding_length = ~(chunk - 1) & 7;

    MK_TRACE("[fastcgi] STDIN: length=%i", chunk);

    mk_api->iov_add(handler->iov, p, FCGI_RECORD_HEADER_SIZE, MK_FALSE);
    handler->buf_len += FCGI_RECORD_HEADER_SIZE;


    if (chunk > 0) {
        mk_api->iov_add(handler->iov,
                        handler->stdin_buffer + handler->stdin_offset,
                        chunk,
                        MK_FALSE);
    }

    if (h->padding_length > 0) {
        mk_api->iov_add(handler->iov,
                        fcgi_pad, h->padding_length,
                        MK_FALSE);
    }

    if (handler->stdin_offset + chunk == handler->stdin_length) {
        eof = FCGI_BUF(handler);
        fcgi_build_header((struct fcgi_record_header *) eof, FCGI_STDIN, 1, 0);
        mk_api->iov_add(handler->iov, eof, FCGI_RECORD_HEADER_SIZE, MK_FALSE);
        handler->buf_len += FCGI_RECORD_HEADER_SIZE + padding;
    }

    handler->stdin_offset += chunk;
    return 0;
}

static inline int fcgi_add_stdin(struct fcgi_handler *handler)
{
    uint64_t bytes = handler->sr->data.len;

    if (bytes <= 0) {
        return -1;
    }

    handler->stdin_length = bytes;
    handler->stdin_offset = 0;
    handler->stdin_buffer = handler->sr->data.data;
    fcgi_stdin_chunk(handler);

    return 0;
}

static int fcgi_encode_request(struct fcgi_handler *handler)
{
    int ret;
    struct mk_http_header *header;
    struct fcgi_begin_request_record *request;

    MK_TRACE("ENCODE REQUEST");

    request = &handler->header_request;
    fcgi_build_header(&request->header, FCGI_BEGIN_REQUEST, 1,
                      FCGI_BEGIN_REQUEST_BODY_SIZE);

    fcgi_build_request_body(&request->body);

    /* BEGIN_REQUEST */
    mk_api->iov_add(handler->iov,
                    &handler->header_request,
                    sizeof(handler->header_request),
                    MK_FALSE);

    /* Server Software */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("GATEWAY_INTERFACE"),
                   FCGI_PARAM_CONST("CGI/1.1"));

    /* Server Software */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("REDIRECT_STATUS"),
                   FCGI_PARAM_CONST("200"));

    /* Server Software */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SERVER_SOFTWARE"),
                   FCGI_PARAM_DYN(mk_api->config->server_signature));

    /* Server Name */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SERVER_PROTOCOL"),
                   FCGI_PARAM_CONST("HTTP/1.1"));

    /* Server Name */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SERVER_NAME"),
                   handler->sr->host_alias->name,
                   handler->sr->host_alias->len,
                   MK_FALSE);

    /* Document Root */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("DOCUMENT_ROOT"),
                   FCGI_PARAM_PTR(handler->sr->host_conf->documentroot));

    /* Network params: SERVER_ADDR, SERVER_PORT, REMOTE_ADDR & REMOTE_PORT */
    ret = fcgi_add_param_net(handler);
    if (ret == -1) {
        return -1;
    }

    /* Script Filename */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SCRIPT_FILENAME"),
                   FCGI_PARAM_PTR(handler->sr->real_path));

    /* Script Filename */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SCRIPT_NAME"),
                   FCGI_PARAM_PTR(handler->sr->uri_processed));

    /* Request Method */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("REQUEST_METHOD"),
                   FCGI_PARAM_PTR(handler->sr->method_p));


    /* Request URI */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("REQUEST_URI"),
                   FCGI_PARAM_PTR(handler->sr->uri));

    /* Query String */
    if (handler->sr->query_string.len > 0) {
        fcgi_add_param(handler,
                       FCGI_PARAM_CONST("QUERY_STRING"),
                       FCGI_PARAM_PTR(handler->sr->query_string));
    }

    /* HTTPS */
    if (MK_SCHED_CONN_PROP(handler->cs->conn) & MK_CAP_SOCK_TLS) {
        fcgi_add_param(handler,
                       FCGI_PARAM_CONST("HTTPS"),
                       FCGI_PARAM_CONST("on"));
    }

    /* Content Length */
    if (handler->sr->_content_length.data) {
        fcgi_add_param(handler,
                       FCGI_PARAM_CONST("CONTENT_LENGTH"),
                       FCGI_PARAM_PTR(handler->sr->_content_length));
    }

    /* Content Length */
    header = &handler->cs->parser.headers[MK_HEADER_CONTENT_TYPE];
    if (header->type == MK_HEADER_CONTENT_TYPE) {
        fcgi_add_param(handler,
                       FCGI_PARAM_CONST("CONTENT_TYPE"),
                       FCGI_PARAM_PTR(header->val));

    }

    /* Append HTTP request headers */
    struct mk_list *head;
    struct mk_http_header *http_header;
    mk_list_foreach(head, &handler->cs->parser.header_list) {
        http_header = mk_list_entry(head, struct mk_http_header, _head);
        fcgi_add_param_http_header(handler, http_header);
    }

    /* Append the empty params record */
    fcgi_add_param_empty(handler);

    /* Data for FCGI_STDIN */
    fcgi_add_stdin(handler);

    return 0;
}

size_t fcgi_read_header(void *p, struct fcgi_record_header *h)
{
    memcpy(h, p, sizeof(struct fcgi_record_header));
    h->request_id     = htons(h->request_id);
    h->content_length = htons(h->content_length);

	return sizeof(*h);
}

static inline int fcgi_buffer_consume(struct fcgi_handler *handler, size_t bytes)
{
    if (bytes >= handler->buf_len) {
        handler->buf_len = 0;
        return 0;
    }

    memmove(handler->buf_data, handler->buf_data + bytes,
            handler->buf_len - bytes);
    handler->buf_len -= bytes;
    return 0;
}

static char *getearliestbreak(const char buf[], const unsigned bufsize,
                              unsigned char * const advance)
{
    char *crend;
    char *lfend;

    crend = memmem(buf, bufsize, "\r\n\r\n", 4);
    lfend = memmem(buf, bufsize, "\n\n", 2);

    if (!crend && !lfend)
        return NULL;

    /* If only one found, return that one */
    if (!crend) {
        *advance = 2;
        return lfend;
    }
    if (!lfend)
        return crend;

    /* Both found, return the earlier one - the latter one is part of content */
    if (lfend < crend) {
        *advance = 2;
        return lfend;
    }
    return crend;
}

static int fcgi_write(struct fcgi_handler *handler, char *buf, size_t len)
{
    mk_stream_in_raw(handler->stream,
                      NULL,
                      buf, len,
                      NULL, NULL);

    if (handler->headers_set == MK_TRUE) {
        mk_stream_in_raw(handler->stream,
                          NULL,
                          "\r\n", 2,
                          NULL, NULL);
    }
    return 0;
}

void fcgi_stream_eof(struct mk_stream_input *in)
{
    (void) in;
    // FIXME
    //struct fcgi_handler *handler;

    //handler = stream->data;
    //if (handler->hangup == MK_FALSE) {
    //    fcgi_exit(handler);
    //}
}

int fcgi_exit(struct fcgi_handler *handler)
{
    /* Always disable any backend notification first */
    if (handler->server_fd > 0) {
        mk_api->ev_del(mk_api->sched_loop(), &handler->event);
        close(handler->server_fd);
        handler->server_fd = -1;
    }

    /*
     * Before to exit our handler, we need to verify that our parent
     * channel have sent the whole information, otherwise we may face
     * some corruption. If there is still some data enqueued, just
     * defer the exit process.
     */
    if (mk_channel_is_empty(handler->cs->channel) != 0 &&
        handler->eof == MK_FALSE &&
        handler->active == MK_TRUE) {
        MK_TRACE("[fastcgi=%i] deferring exit, EOF stream",
                 handler->server_fd);

        /* Now set an EOF stream/callback to resume the exiting process */
        mk_stream_in_eof(handler->stream,
                         NULL,
                         fcgi_stream_eof);
        handler->eof = MK_TRUE;
        return 1;
    }

    MK_TRACE("[fastcgi] exiting");

    if (handler->iov) {
        mk_api->iov_free(handler->iov);
        mk_api->sched_event_free((struct mk_event *) handler);
        handler->iov = NULL;
    }

    if (handler->active == MK_TRUE) {
        handler->active = MK_FALSE;
        mk_api->http_request_end(handler->plugin, handler->cs, handler->hangup);
    }

    return 1;
}

int fcgi_error(struct fcgi_handler *handler)
{
    fcgi_exit(handler);
    mk_api->http_request_error(500, handler->cs, handler->sr, handler->plugin);
    return 0;
}

static int fcgi_response(struct fcgi_handler *handler, char *buf, size_t len)
{
    int status;
    int diff;
    int xlen;
    char tmp[16];
    char *p;
    char *end;
    size_t p_len;
    unsigned char advance;

    MK_TRACE("[fastcgi=%i] process response len=%lu",
             handler->server_fd, len);

    p = buf;
    p_len = len;

    if (len == 0 && handler->chunked && handler->headers_set == MK_TRUE) {
        MK_TRACE("[fastcgi=%i] sending EOF", handler->server_fd);
        mk_stream_in_raw(handler->stream,
                          NULL,
                          "0\r\n\r\n", 5,
                          NULL, NULL);
        mk_api->channel_flush(handler->cs->channel);
        return 0;
    }

    if (handler->headers_set == MK_FALSE) {
        advance = 4;

        if (!buf) {
            return -1;
        }

        end = getearliestbreak(buf, len, &advance);
        if (!end) {
            /* we need more data */
            return -1;
        }

        handler->sr->headers.cgi = MK_TRUE;
        if (strncasecmp(buf, "Status: ", 8) == 0) {
            sscanf(buf + 8, "%d", &status);
            MK_TRACE("FastCGI status %i", status);
            mk_api->header_set_http_status(handler->sr, status);
        }
        else {
            mk_api->header_set_http_status(handler->sr, 200);
        }

        /* Set transfer encoding */
        if (handler->sr->protocol >= MK_HTTP_PROTOCOL_11) {
            handler->sr->headers.transfer_encoding = MK_HEADER_TE_TYPE_CHUNKED;
            handler->chunked = MK_TRUE;
        }

        mk_api->header_prepare(handler->plugin, handler->cs, handler->sr);

        diff = (end - buf) + advance;
        fcgi_write(handler, buf, diff);

        p = buf + diff;
        p_len -= diff;
        handler->write_rounds++;
        handler->headers_set = MK_TRUE;
    }

    if (p_len > 0) {
        xlen = snprintf(tmp, 16, "%x\r\n", (unsigned int) p_len);
        mk_stream_in_raw(handler->stream,
                          NULL,
                          tmp, xlen,
                          NULL, NULL);
        fcgi_write(handler, p, p_len);
    }

    return 0;
}

int cb_fastcgi_on_read(void *data)
{
    int n;
    int ret = 0;
    int avail;
    char *body;
    size_t offset;
    struct fcgi_handler *handler = data;
    struct fcgi_record_header header;

    if (handler->active == MK_FALSE) {
        fcgi_exit(handler);
        return -1;
    }

    avail = FCGI_BUF_SIZE - handler->buf_len;
    n = read(handler->server_fd, handler->buf_data + handler->buf_len, avail);
    MK_TRACE("[fastcgi=%i] read()=%i", handler->server_fd, n);
    if (n <= 0) {
        MK_TRACE("[fastcgi=%i] FastCGI server ended", handler->server_fd);
        fcgi_exit(handler);
        return -1;
    }
    else {
        handler->buf_len += n;
    }

    if ((unsigned) handler->buf_len < FCGI_RECORD_HEADER_SIZE) {
        /* wait for more data */
        return n;
    }

    while (1) {
        /* decode the header */
        fcgi_read_header(&handler->buf_data, &header);

        if (header.type != FCGI_STDOUT && header.type != FCGI_STDERR &&
            header.type != FCGI_END_REQUEST) {
            fcgi_exit(handler);
            return -1;
        }

        /* Check if the package is complete */
        if (handler->buf_len < (FCGI_RECORD_HEADER_SIZE + header.content_length)) {
            /* we need more data */
            return n;
        }

        body = handler->buf_data + FCGI_RECORD_HEADER_SIZE;
        switch (header.type) {
        case FCGI_STDOUT:
            MK_TRACE("[fastcgi=%i] FCGI_STDOUT content_length=%i",
                     handler->server_fd, header.content_length);
            /*
             * Issue seen with Chrome & Firefox browsers:
             * Sometimes content length is coming as ZERO and we are encoding a
             * HTTP response packet with ZERO size data. This makes Chrome & Firefox
             * browsers fail to proceed furhter and subsequent content loading fails.
             * However, IE/Safari discards the packets with ZERO size data.
             */
            if (0 != header.content_length) {
                ret = fcgi_response(handler, body, header.content_length);
            }
            else {
                MK_TRACE("[fastcgi=%i] ZERO byte content length in FCGI_STDOUT, discard!!",
                         handler->server_fd);
                ret = 0;
            }
            break;
        case FCGI_STDERR:
            MK_TRACE("[fastcgi=%i] FCGI_STDERR content_length=%i",
                     handler->server_fd, header.content_length);
            break;
        case FCGI_END_REQUEST:
            MK_TRACE("[fastcgi=%i] FCGI_END_REQUEST content_length=%i",
                     handler->server_fd, header.content_length);
            ret = fcgi_response(handler, NULL, 0);
            break;
        default:
            //fcgi_exit(handler);
            return -1;
        }

        if (ret == -1) {
            /* Missing header breaklines ? */
            return n;
        }

        /* adjust buffer content */
        offset = FCGI_RECORD_HEADER_SIZE +
            header.content_length + header.padding_length;

        fcgi_buffer_consume(handler, offset);
    }
    return n;
}

int cb_fastcgi_request_flush(void *data)
{
    int ret;
    size_t count = 0;
    struct fcgi_handler *handler = data;

    ret = mk_api->channel_write(&handler->fcgi_channel, &count);

    MK_TRACE("[fastcgi=%i] %lu bytes, ret=%i",
             handler->server_fd, count, ret);

    if (ret == MK_CHANNEL_DONE || ret == MK_CHANNEL_EMPTY) {
        /* Do we have more data for the stdin ? */
        if (handler->stdin_length - handler->stdin_offset > 0) {
            mk_api->iov_free(handler->iov);
            handler->iov = mk_api->iov_create(64, 0);
            fcgi_stdin_chunk(handler);

            mk_api->stream_set(&handler->fcgi_stream,
                               MK_STREAM_IOV,
                               &handler->fcgi_channel,
                               handler->iov,
                               -1,
                               handler,
                               NULL, NULL, NULL);
            return MK_CHANNEL_FLUSH;
        }

        /* Request done, switch the event side to receive the FCGI response */
        handler->buf_len = 0;
        handler->event.handler = cb_fastcgi_on_read;
        ret = mk_api->ev_add(mk_api->sched_loop(),
                             handler->server_fd,
                             MK_EVENT_CUSTOM, MK_EVENT_READ, handler);
        if (ret == -1) {
            goto error;
        }
    }
    else if (ret == MK_CHANNEL_ERROR) {
        fcgi_exit(handler);
    }
    else if (ret == MK_CHANNEL_BUSY) {
        return -1;
    }

    return ret;

 error:
    return -1;
}

/* Callback: on connect to the backend server */
static int fastcgi_on_connect(struct fcgi_handler *handler)
{
    int ret;
    int s_err;
    size_t count;
    socklen_t s_len = sizeof(s_err);
    struct mk_list *head;
    struct mk_plugin *pio;
    struct mk_channel *channel;

    /* Convert the original request to FCGI format */
    ret = fcgi_encode_request(handler);
    if (ret == -1) {
        goto error;
    }

    /* Prepare the channel */
    channel = &handler->fcgi_channel;
    channel->type = MK_CHANNEL_SOCKET;
    channel->fd   = handler->server_fd;

    /* FIXME: Discovery process needs to be fast */
    mk_list_foreach(head, &mk_api->config->plugins) {
        pio = mk_list_entry(head, struct mk_plugin, _head);
        if (strncmp(pio->shortname, "liana", 5) == 0) {
            break;
        }
        pio = NULL;
    }
    channel->io   = pio->network;

    mk_list_init(&channel->streams);
    mk_api->stream_set(&handler->fcgi_stream,
                       MK_STREAM_IOV,
                       &handler->fcgi_channel,
                       handler->iov,
                       -1,
                       handler,
                       NULL, NULL, NULL);

    handler->event.handler = cb_fastcgi_request_flush;
    handler->event.data = handler;

    return 0;

 error:
    fcgi_error(handler);
    mk_api->channel_write(handler->cs->channel, &count);
    return 0;
}

struct fcgi_handler *fcgi_handler_new(struct mk_plugin *plugin,
                                      struct mk_http_session *cs,
                                      struct mk_http_request *sr)
{
    int ret;
    int entries;
    struct fcgi_handler *h = NULL;
    struct mk_net_connection *conn = NULL;

    /* Allocate handler instance and set fields */
    h = mk_api->mem_alloc_z(sizeof(struct fcgi_handler));
    if (!h) {
        return NULL;
    }

    stream = mk_stream_set(NULL, cs->channel, h,
                           NULL, NULL, NULL);
    if (!stream) {
        mk_api->mem_free(h);
        return NULL;
    }

    h->stream = stream;
    h->plugin = plugin;
    h->cs = cs;
    h->sr = sr;
    h->write_rounds = 0;
    h->active = MK_TRUE;
    h->server_fd = -1;
    h->eof = MK_FALSE;
    h->stdin_length = 0;
    h->stdin_offset = 0;
    h->stdin_buffer = NULL;
    h->conn         = NULL;

    /* Allocate enough space for our data */
    entries = 128 + (cs->parser.header_count * 3);
    h->iov = mk_api->iov_create(entries, 0);

    /* Associate the handler with the Session Request */
    sr->handler_data = h;

    if (sr->protocol >= MK_HTTP_PROTOCOL_11) {
        h->hangup = MK_FALSE;
    }
    else {
        h->hangup = MK_TRUE;
    }

    /* Params buffer set an offset to include the header */
    h->buf_len = FCGI_RECORD_HEADER_SIZE;

    /* Request and async connection to the server */
    if (fcgi_conf.server_addr) {
        conn = mk_api->net_conn_create(fcgi_conf.server_addr,
                                       atoi(fcgi_conf.server_port));
        if (!conn) {
            goto error;
        }
        h->conn      = conn;
        h->server_fd = conn->fd;
    }
    else if (fcgi_conf.server_path) {
        /* FIXME: unix socket connection NOT FUNCTIONAL for now */
        h->server_fd = mk_api->socket_open(fcgi_conf.server_path, MK_TRUE);
    }

    if (h->server_fd == -1) {
        goto error;
    }

    fastcgi_on_connect(h);
    return h;

 error:
    mk_api->iov_free(h->iov);
    mk_api->mem_free(h);
    sr->handler_data = NULL;
    mk_api->http_request_error(500, cs, sr, plugin);

    return NULL;
}
