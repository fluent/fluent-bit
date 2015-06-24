/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#ifndef MK_HTTP_INTERNAL_H
#define MK_HTTP_INTERNAL_H

#include <monkey/mk_stream.h>

struct response_headers
{
    int status;

    /* Connection flag, if equal -1, the connection header is ommited */
    int connection;

    /*
     * If some plugins wants to set a customized HTTP status, here
     * is the 'how and where'
     */
    mk_ptr_t custom_status;

    /* Length of the content to send */
    long content_length;

    /* Private value, real length of the file requested */
    long real_length;

    int cgi;
    int pconnections_left;
    int breakline;

    int transfer_encoding;

    int ranges[2];

    time_t last_modified;
    mk_ptr_t allow_methods;
    mk_ptr_t content_type;
    mk_ptr_t content_encoding;
    char *location;

    /*
     * This field allow plugins to add their own response
     * headers
     */
    struct mk_iov *_extra_rows;

    /* Flag to track if the response headers were sent */
    int sent;

};

struct mk_http_request
{
    int status;
    int protocol;

    /* is it serving a user's home directory ? */
    int user_home;

    /*-Connection-*/
    long port;
    /*------------*/

    /* Streams handling: headers and static file */
    struct mk_stream headers_stream;
    struct mk_stream headers_extra_stream;
    struct mk_stream file_stream;
    struct mk_stream page_stream;

    int headers_len;

    /*----First header of client request--*/
    int method;
    mk_ptr_t method_p;
    mk_ptr_t uri;                  /* original request */
    mk_ptr_t uri_processed;        /* processed request (decoded) */

    mk_ptr_t protocol_p;

    mk_ptr_t body;

    /*---Request headers--*/
    int content_length;

    mk_ptr_t _content_length;
    mk_ptr_t content_type;
    mk_ptr_t connection;

    mk_ptr_t host;
    mk_ptr_t host_port;
    mk_ptr_t if_modified_since;
    mk_ptr_t last_modified_since;
    mk_ptr_t range;

    /*---------------------*/

    /* POST/PUT data */
    mk_ptr_t data;
    /*-----------------*/

    /*-Internal-*/
    mk_ptr_t real_path;        /* Absolute real path */

    /*
     * If a full URL length is less than MAX_PATH_BASE (defined in limits.h),
     * it will be stored here and real_path will point this buffer
     */
    char real_path_static[MK_PATH_BASE];

    /* Query string: ?.... */
    mk_ptr_t query_string;


    /*
     * STAGE_30 block flag: in mk_http_init() when the file is not found, it
     * triggers the plugin STAGE_30 to look for a plugin handler. In some
     * cases the plugin would overwrite the real path of the requested file
     * and make Monkey handle the new path for the static file. At this point
     * we need to block STAGE_30 calls from mk_http_init().
     *
     * For short.. if a plugin overwrites the real_path, let Monkey handle that
     * and do not trigger more STAGE_30's.
     */
    int stage30_blocked;

    /* Static file information */
    struct file_info file_info;

    /* Vhost */
    int vhost_fdt_id;
    unsigned int vhost_fdt_hash;
    int vhost_fdt_enabled;

    struct host       *host_conf;     /* root vhost config */
    struct host_alias *host_alias;    /* specific vhost matched */

    /* Parent Session */
    struct mk_http_session *session;

    /* Response headers */
    struct response_headers headers;

    struct mk_list _head;
};

#endif
