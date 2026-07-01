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

#ifndef MK_HEADER_H
#define MK_HEADER_H

#include "mk_http.h"
#include "mk_http_status.h"

#define MK_HEADER_BREAKLINE 1

/*
 * header response: We handle this as static global data in order
 * to save some process time when building the response header.
 */

/* Informational */
#define MK_RH_INFO_CONTINUE "HTTP/1.1 100 Continue\r\n"
#define MK_RH_INFO_SWITCH_PROTOCOL "HTTP/1.1 101 Switching Protocols\r\n"

/* Successfull */
#define MK_RH_HTTP_OK "HTTP/1.1 200 OK\r\n"
#define MK_RH_HTTP_CREATED "HTTP/1.1 201 Created\r\n"
#define MK_RH_HTTP_ACCEPTED "HTTP/1.1 202 Accepted\r\n"
#define MK_RH_HTTP_NON_AUTH_INFO "HTTP/1.1 203 Non-Authoritative Information\r\n"
#define MK_RH_HTTP_NOCONTENT "HTTP/1.1 204 No Content\r\n"
#define MK_RH_HTTP_RESET "HTTP/1.1 205 Reset Content\r\n"
#define MK_RH_HTTP_PARTIAL "HTTP/1.1 206 Partial Content\r\n"

/* Redirections */
#define MK_RH_REDIR_MULTIPLE "HTTP/1.1 300 Multiple Choices\r\n"
#define MK_RH_REDIR_MOVED "HTTP/1.1 301 Moved Permanently\r\n"
#define MK_RH_REDIR_MOVED_T "HTTP/1.1 302 Found\r\n"
#define	MK_RH_REDIR_SEE_OTHER "HTTP/1.1 303 See Other\r\n"
#define MK_RH_NOT_MODIFIED "HTTP/1.1 304 Not Modified\r\n"
#define MK_RH_REDIR_USE_PROXY "HTTP/1.1 305 Use Proxy\r\n"

/* Client side errors */
#define MK_RH_CLIENT_BAD_REQUEST "HTTP/1.1 400 Bad Request\r\n"
#define MK_RH_CLIENT_UNAUTH "HTTP/1.1 401 Unauthorized\r\n"
#define MK_RH_CLIENT_PAYMENT_REQ "HTTP/1.1 402 Payment Required\r\n"
#define MK_RH_CLIENT_FORBIDDEN "HTTP/1.1 403 Forbidden\r\n"
#define MK_RH_CLIENT_NOT_FOUND "HTTP/1.1 404 Not Found\r\n"
#define MK_RH_CLIENT_METHOD_NOT_ALLOWED "HTTP/1.1 405 Method Not Allowed\r\n"
#define MK_RH_CLIENT_NOT_ACCEPTABLE "HTTP/1.1 406 Not Acceptable\r\n"
#define MK_RH_CLIENT_PROXY_AUTH "HTTP/1.1 407 Proxy Authentication Required\r\n"
#define MK_RH_CLIENT_REQUEST_TIMEOUT "HTTP/1.1 408 Request Timeout\r\n"
#define MK_RH_CLIENT_CONFLICT "HTTP/1.1 409 Conflict\r\n"
#define MK_RH_CLIENT_GONE "HTTP/1.1 410 Gone\r\n"
#define MK_RH_CLIENT_LENGTH_REQUIRED "HTTP/1.1 411 Length Required\r\n"
#define MK_RH_CLIENT_PRECOND_FAILED "HTTP/1.1 412 Precondition Failed\r\n"
#define MK_RH_CLIENT_REQUEST_ENTITY_TOO_LARGE   \
    "HTTP/1.1 413 Request Entity Too Large\r\n"
#define MK_RH_CLIENT_REQUEST_URI_TOO_LONG "HTTP/1.1 414 Request-URI Too Long\r\n"
#define MK_RH_CLIENT_UNSUPPORTED_MEDIA  "HTTP/1.1 415 Unsupported Media Type\r\n"
#define MK_RH_CLIENT_REQUESTED_RANGE_NOT_SATISF \
    "HTTP/1.1 416 Requested Range Not Satisfiable\r\n"

/* Server side errors */
#define MK_RH_SERVER_INTERNAL_ERROR "HTTP/1.1 500 Internal Server Error\r\n"
#define MK_RH_SERVER_NOT_IMPLEMENTED "HTTP/1.1 501 Not Implemented\r\n"
#define MK_RH_SERVER_BAD_GATEWAY "HTTP/1.1 502 Bad Gateway\r\n"
#define MK_RH_SERVER_SERVICE_UNAV "HTTP/1.1 503 Service Unavailable\r\n"
#define MK_RH_SERVER_GATEWAY_TIMEOUT "HTTP/1.1 504 Gateway Timeout\r\n"
#define MK_RH_SERVER_HTTP_VERSION_UNSUP "HTTP/1.1 505 HTTP Version Not Supported\r\n"

struct header_status_response {
    int   status;
    int   length;
    char *response;
};

#define MK_HEADER_TE_TYPE_CHUNKED   0
#define MK_HEADER_CONN_UPGRADED    11
#define MK_HEADER_UPGRADED_H2C     20

extern const mk_ptr_t mk_header_short_date;
extern const mk_ptr_t mk_header_short_location;
extern const mk_ptr_t mk_header_short_ct;

/* mk pointers with response server headers */
extern const mk_ptr_t mk_header_conn_ka;
extern const mk_ptr_t mk_header_conn_close;
extern const mk_ptr_t mk_header_content_length;
extern const mk_ptr_t mk_header_content_encoding;
extern const mk_ptr_t mk_header_accept_ranges;
extern const mk_ptr_t mk_header_te_chunked;
extern const mk_ptr_t mk_header_last_modified;

int mk_header_prepare(struct mk_http_session *cs, struct mk_http_request *sr,
                      struct mk_server *server);

void mk_header_response_reset(struct response_headers *header);
void mk_header_set_http_status(struct mk_http_request *sr, int status);
void mk_header_set_content_length(struct mk_http_request *sr, long len);

#endif
