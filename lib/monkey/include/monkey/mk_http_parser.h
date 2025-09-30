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

#ifndef MK_HTTP_PARSER_H
#define MK_HTTP_PARSER_H

#define _GNU_SOURCE
#include <ctype.h>

#include <monkey/mk_core.h>
#include <monkey/mk_http.h>
#include <monkey/mk_http_internal.h>

/* General status */
#define MK_HTTP_PARSER_PENDING -10  /* cannot complete until more data arrives */
#define MK_HTTP_PARSER_ERROR    -1  /* found an error when parsing the string  */
#define MK_HTTP_PARSER_OK        0  /* parser OK, ready to go                  */

/* Connection header values */
#define MK_HTTP_PARSER_CONN_EMPTY    0
#define MK_HTTP_PARSER_CONN_UNKNOWN -1
#define MK_HTTP_PARSER_CONN_KA       1
#define MK_HTTP_PARSER_CONN_CLOSE    2
#define MK_HTTP_PARSER_CONN_UPGRADE  4
#define MK_HTTP_PARSER_CONN_HTTP2_SE 8

/* Upgrades supported */
#define MK_HTTP_PARSER_UPGRADE_NONE  0
#define MK_HTTP_PARSER_UPGRADE_H2    1
#define MK_HTTP_PARSER_UPGRADE_H2C   2

/* Transfer encoding */
#define MK_HTTP_PARSER_TRANSFER_ENCODING_NONE      (0)
#define MK_HTTP_PARSER_TRANSFER_ENCODING_CHUNKED   (1 << 0)
#define MK_HTTP_PARSER_TRANSFER_ENCODING_GZIP      (1 << 1)

/* Transfer encoding (almost not used) */
#define MK_HTTP_PARSER_TRANSFER_ENCODING_COMPRESS  (1 << 2)
#define MK_HTTP_PARSER_TRANSFER_ENCODING_DEFLATE   (1 << 3)
#define MK_HTTP_PARSER_TRANSFER_ENCODING_IDENTITY  (1 << 4)

#define MK_HEADER_EXTRA_SIZE        50

/* Request levels
 * ==============
 *
 * 1. FIRST_LINE         : Method, URI (+ QS) + Protocol version + CRLF
 * 2. HEADERS (optional) : KEY, SEP, VALUE + CRLF
 * 3. BODY (option)      : data based on Content-Length or Chunked transfer encoding
 */

enum {
    REQ_LEVEL_FIRST    = 1,
    REQ_LEVEL_CONTINUE ,
    REQ_LEVEL_HEADERS  ,
    REQ_LEVEL_END      ,
    REQ_LEVEL_BODY
};

/* Statuses per levels */
enum {
    /* REQ_LEVEL_FIRST */
    MK_ST_REQ_METHOD        = 1,
    MK_ST_REQ_URI           ,
    MK_ST_REQ_QUERY_STRING  ,
    MK_ST_REQ_PROT_VERSION  ,
    MK_ST_FIRST_CONTINUE    ,
    MK_ST_FIRST_FINALIZING  ,    /* LEVEL_FIRST finalize the request */
    MK_ST_FIRST_COMPLETE    ,

    /* REQ_HEADERS */
    MK_ST_HEADER_KEY        ,
    MK_ST_HEADER_SEP        ,
    MK_ST_HEADER_VAL_STARTS ,
    MK_ST_HEADER_VALUE      ,
    MK_ST_HEADER_END        ,
    MK_ST_BLOCK_END
};

/* Known HTTP Methods */
enum mk_request_methods {
    MK_METHOD_GET     = 0,
    MK_METHOD_POST       ,
    MK_METHOD_HEAD       ,
    MK_METHOD_PUT        ,
    MK_METHOD_DELETE     ,
    MK_METHOD_OPTIONS    ,
    MK_METHOD_SIZEOF     ,
    MK_METHOD_UNKNOWN
};

/*
 * Define a list of known headers, they are used to perform headers
 * lookups in the parser and further Monkey core.
 */
enum mk_request_headers {
    MK_HEADER_ACCEPT             = 0,
    MK_HEADER_ACCEPT_CHARSET        ,
    MK_HEADER_ACCEPT_ENCODING       ,
    MK_HEADER_ACCEPT_LANGUAGE       ,
    MK_HEADER_AUTHORIZATION         ,
    MK_HEADER_CACHE_CONTROL         ,
    MK_HEADER_COOKIE                ,
    MK_HEADER_CONNECTION            ,
    MK_HEADER_CONTENT_LENGTH        ,
    MK_HEADER_CONTENT_RANGE         ,
    MK_HEADER_CONTENT_TYPE          ,
    MK_HEADER_HOST                  ,
    MK_HEADER_HTTP2_SETTINGS        ,
    MK_HEADER_IF_MODIFIED_SINCE     ,
    MK_HEADER_LAST_MODIFIED         ,
    MK_HEADER_LAST_MODIFIED_SINCE   ,
    MK_HEADER_RANGE                 ,
    MK_HEADER_REFERER               ,
    MK_HEADER_TRANSFER_ENCODING     ,
    MK_HEADER_UPGRADE               ,
    MK_HEADER_USER_AGENT            ,
    MK_HEADER_SIZEOF                ,

    /* used by the core for custom headers */
    MK_HEADER_OTHER
};

/*
 * Expected Header values that are used to take logic
 * decision.
 */
#define MK_CONN_KEEP_ALIVE     "keep-alive"
#define MK_CONN_CLOSE          "close"
#define MK_CONN_UPGRADE        "upgrade"

/* HTTP Upgrade options available */
#define MK_UPGRADE_H2          "h2"
#define MK_UPGRADE_H2C         "h2c"

struct mk_http_header {
    /* The header type/name, e.g: MK_HEADER_CONTENT_LENGTH */
    int type;

    /* Reference the header Key name, e.g: 'Content-Lentth' */
    mk_ptr_t key;

    /* Reference the header Value, e/g: '123456' */
    mk_ptr_t val;

    /*
     * Link to head list, it's used to reference this node and
     * iterate it as a linked list
     */
    struct mk_list _head;
};

/* This structure is the 'Parser Context' */
struct mk_http_parser {
    int                        i;
    int                        level;   /* request level */
    int                        status;  /* level status  */
    int                        next;    /* something next after status ? */
    int                        length;
    int                        method;

    /* lookup fields */
    int                        start;
    int                        end;
    int                        chars;

    /* it stores the numeric value of Content-Length header */
    int                        header_host_port;

    long int                   body_received;
    long int                   header_content_length;

    /*
     * connection header value discovered: it can be set with
     * values:
     *
     * MK_HTTP_PARSER_CONN_EMPTY  : header not set
     * MK_HTTP_PARSER_CONN_UNKNOWN: unexpected value
     * MK_HTTP_PARSER_CONN_KA     : keep-alive
     * MK_HTTP_PARSER_CONN_CLOSE  : close
     */
    int                        header_connection;

    /* upgrade request: we suppport the following values:
     *
     * MK_HTTP_PARSER_UPGRADE_H2  : HTTP/2.0 over TLS
     * MK_HTTP_PARSER_UPGRADE_H2C : HTTP/2.0 (plain TCP)
     */
    int                        header_upgrade;


    /*
     * Transfer-Encoding
     * ------------------
     *  we support the following values (bitwise):
     *
     *  - MK_HTTP_PARSER_TRANSFER_ENCODING_NONE
     *  - MK_HTTP_PARSER_TRANSFER_ENCODING_CHUNKED
     *  - MK_HTTP_PARSER_TRANSFER_ENCODING_GZIP
     *  - MK_HTTP_PARSER_TRANSFER_ENCODING_COMPRESS
     *  - MK_HTTP_PARSER_TRANSFER_ENCODING_DEFLATE
     *  - MK_HTTP_PARSER_TRANSFER_ENCODING_IDENTITY
    */
    int                       header_transfer_encoding;

    /* probable current header, fly parsing */
    int                        header_key;
    int                        header_sep;
    int                        header_val;
    int                        header_min;
    int                        header_max;
    int                        headers_extra_count;

    /* Known headers */
    struct mk_http_header      headers[MK_HEADER_SIZEOF];

    /* Head of linked list for all headers found in the request */
    int                        header_count;
    struct mk_list             header_list;

    /* Extra headers */
    struct mk_http_header      headers_extra[MK_HEADER_EXTRA_SIZE];


    /*
     * total size of bytes received as chunked data; this don't count the
     * hex strings
     */
    size_t chunk_total_size_received;

    /* Transfer chunked encoding: state for active chunk being processed */
    char *chunk_expected_start;  /* pointer to the expected very first chunk in the payload */

    size_t chunk_expected_size;  /* expected size of a chunk being read */
    char *chunk_processed_start; /* beginning of a chunk being read */
    char *chunk_processed_end;   /* last position of a chunk that is complete */
};


#ifdef HTTP_STANDALONE

/* ANSI Colors */

#define ANSI_RESET "\033[0m"
#define ANSI_BOLD  "\033[1m"

#define ANSI_CYAN          "\033[36m"
#define ANSI_BOLD_CYAN     ANSI_BOLD ANSI_CYAN
#define ANSI_MAGENTA       "\033[35m"
#define ANSI_BOLD_MAGENTA  ANSI_BOLD ANSI_MAGENTA
#define ANSI_RED           "\033[31m"
#define ANSI_BOLD_RED      ANSI_BOLD ANSI_RED
#define ANSI_YELLOW        "\033[33m"
#define ANSI_BOLD_YELLOW   ANSI_BOLD ANSI_YELLOW
#define ANSI_BLUE          "\033[34m"
#define ANSI_BOLD_BLUE     ANSI_BOLD ANSI_BLUE
#define ANSI_GREEN         "\033[32m"
#define ANSI_BOLD_GREEN    ANSI_BOLD ANSI_GREEN
#define ANSI_WHITE         "\033[37m"
#define ANSI_BOLD_WHITE    ANSI_BOLD ANSI_WHITE

#define TEST_OK      0
#define TEST_FAIL    1


static inline void p_field(struct mk_http_parser *req, char *buffer)
{
    int i;

    printf("'");
    for (i = req->start; i < req->end; i++) {
        printf("%c", buffer[i]);
    }
    printf("'");

}

static inline int eval_field(struct mk_http_parser *req, char *buffer)
{
    if (req->level == REQ_LEVEL_FIRST) {
        printf("[ \033[35mfirst level\033[0m ] ");
    }
    else {
        printf("[   \033[36mheaders\033[0m   ] ");
    }

    printf(" ");
    switch (req->status) {
    case MK_ST_REQ_METHOD:
        printf("MK_ST_REQ_METHOD       : ");
        break;
    case MK_ST_REQ_URI:
        printf("MK_ST_REQ_URI          : ");
        break;
    case MK_ST_REQ_QUERY_STRING:
        printf("MK_ST_REQ_QUERY_STRING : ");
        break;
    case MK_ST_REQ_PROT_VERSION:
        printf("MK_ST_REQ_PROT_VERSION : ");
        break;
    case MK_ST_HEADER_KEY:
        printf("MK_ST_HEADER_KEY       : ");
        break;
    case MK_ST_HEADER_VAL_STARTS:
        printf("MK_ST_HEADER_VAL_STARTS: ");
        break;
    case MK_ST_HEADER_VALUE:
        printf("MK_ST_HEADER_VALUE     : ");
        break;
    case MK_ST_HEADER_END:
        printf("MK_ST_HEADER_END       : ");
        break;
    default:
        printf("\033[31mUNKNOWN STATUS (%i)\033[0m     : ", req->status);
        break;
    };


    p_field(req, buffer);
    printf("\n");

    return 0;
}
#endif /* HTTP_STANDALONE */

#define mk_http_set_minor_version(c)                \
    if (c == '1') {                                 \
        req->protocol = MK_HTTP_PROTOCOL_11;        \
    }                                               \
    else if (c == '0') {                            \
        req->protocol = MK_HTTP_PROTOCOL_10;        \
    }                                               \
    else {                                          \
        req->protocol = MK_HTTP_PROTOCOL_UNKNOWN;   \
    }


static inline void mk_http_parser_init(struct mk_http_parser *p)
{
    memset(p, '\0', sizeof(struct mk_http_parser));

    p->level  = REQ_LEVEL_FIRST;
    p->status = MK_ST_REQ_METHOD;
    p->chars  = -1;
    p->method = -1;

    /* init headers */
    p->header_key = -1;
    p->header_sep = -1;
    p->header_val = -1;
    p->header_min = -1;
    p->header_max = -1;
    p->header_content_length = -1;

    /* init list header */
    p->header_count = 0;
    mk_list_init(&p->header_list);
}

int mk_http_parser(struct mk_http_request *req, struct mk_http_parser *p,
                   char *buffer, int buf_len, struct mk_server *server);

size_t mk_http_parser_content_length(struct mk_http_parser *p);
int mk_http_parser_is_content_chunked(struct mk_http_parser *p);

int mk_http_parser_chunked_decode(struct mk_http_parser *p,
                                  char *buf_request, size_t buf_request_len,
                                  char **out_buf, size_t *out_buf_size);

int mk_http_parser_chunked_decode_buf(struct mk_http_parser *p,
                                      char *buf_request, size_t buf_request_len,
                                      char *out_buf, size_t out_buf_size, size_t *out_buf_len);

static inline int mk_http_parser_more(struct mk_http_parser *p, int len)
{
    if (abs(len - p->i) - 1 > 0) {
        return MK_TRUE;
    }

    return MK_FALSE;
}

/* Returns the full size of the HTTP request in bytes "If" mk_http_parser() has returned MK_HTTP_PARSER_OK */
static inline size_t mk_http_parser_request_size(struct mk_http_parser *p, char *buf_request, size_t buf_request_len)
{
    size_t bytes;

    /*
     * if the request is chunked encoded, p->i points to the beginning of the last chunk
     * found, so we need to check if the last chunk is complete, if so we can return the
     * size of the request
     */
    if (mk_http_parser_is_content_chunked(p)) {
        if (p->chunk_processed_start < buf_request) {
            return -1;
        }

        /* Look at the last chunk processed (0\r\n\r\n) */
        bytes = p->chunk_processed_start - buf_request + 5;
        if (bytes > buf_request_len) {
            return -1;
        }
        return bytes;
    }
    else if (p->header_content_length > 0) {
        /* p->i points to the last byte after the content body */
        return p->i;
    }

    return -1;
}

#endif /* MK_HTTP_H */
