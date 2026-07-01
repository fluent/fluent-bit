/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
 *  Copyright (C) 2012-2013, Lauri Kasanen
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

#include "cgi.h"

/*
 * The reason for this function is that some CGI apps
 *
 *	use LFLF and some use CRLFCRLF.
 *
 * 	If that app then sends content that has the other break
 *	in the beginning, monkey can accidentally send part of the
 *	content as headers.
 */

static char *getearliestbreak(const char buf[], const unsigned bufsize,
                              unsigned char * const advance)
															{
    char * const crend = memmem(buf, bufsize, MK_IOV_CRLFCRLF,
				sizeof(MK_IOV_CRLFCRLF) - 1);
    char * const lfend = memmem(buf, bufsize, MK_IOV_LFLF,
				sizeof(MK_IOV_LFLF) - 1);

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

int process_cgi_data(struct cgi_request *r)
{
    int ret;
    int len;
    int status;
    char *buf = r->in_buf;
    char *outptr = r->in_buf;
    char *end;
    char *endl;
    unsigned char advance;

    mk_api->socket_cork_flag(r->cs->socket, TCP_CORK_OFF);
    if (!r->status_done && r->in_len >= 8) {
        if (memcmp(buf, "Status: ", 8) == 0) {
            status = atoi(buf + 8);
            mk_api->header_set_http_status(r->sr, status);
            endl = memchr(buf + 8, '\n', r->in_len - 8);
            if (!endl) {
                return MK_PLUGIN_RET_EVENT_OWNED;
            }
            else {
                endl++;
                outptr = endl;
                r->in_len -= endl - buf;
            }
        }
        else if (memcmp(buf, "HTTP", 4) == 0) {
            status = atoi(buf + 9);
            mk_api->header_set_http_status(r->sr, status);

            endl = memchr(buf + 8, '\n', r->in_len - 8);
            if (!endl) {
                return MK_PLUGIN_RET_EVENT_OWNED;
            }
            else {
                endl++;
                outptr = endl;
                r->in_len -= endl - buf;
            }
        }
        mk_api->header_prepare(r->plugin, r->cs, r->sr);
        r->status_done = 1;
    }

    if (!r->all_headers_done) {
        advance = 4;

        /* Write the rest of the headers without chunking */
        end = getearliestbreak(outptr, r->in_len, &advance);
        if (!end) {
            /* Let's return until we have the headers break */
            return MK_PLUGIN_RET_EVENT_OWNED;
        }
        end += advance;
        len = end - outptr;
        channel_write(r, outptr, len);
        outptr += len;
        r->in_len -= len;

        r->all_headers_done = 1;
        if (r->in_len == 0) {
            return MK_PLUGIN_RET_EVENT_OWNED;
        }
    }

    if (r->chunked) {
        char tmp[16];
        len = snprintf(tmp, 16, "%x\r\n", r->in_len);
        ret = channel_write(r, tmp, len);
        if (ret < 0)
            return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    ret = channel_write(r, outptr, r->in_len);
    if (ret < 0) {
        return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    r->in_len = 0;
    if (r->chunked) {
        channel_write(r, MK_CRLF, 2);
    }
    return MK_PLUGIN_RET_EVENT_OWNED;
}

int cb_cgi_read(void *data)
{
    int n;
    struct cgi_request *r = data;

    if (r->active == MK_FALSE) {
        return -1;
    }

    if ((BUFLEN - r->in_len) < 1) {
        PLUGIN_TRACE("CLOSE BY SIZE");
        cgi_finish(r);
        return -1;
    }

    n = read(r->fd, r->in_buf + r->in_len, BUFLEN - r->in_len);
    PLUGIN_TRACE("FD=%i CGI READ=%d", r->fd, n);
    if (n <= 0) {
        /* It most of cases this means the child process finished */
        cgi_finish(r);
        return MK_PLUGIN_RET_EVENT_CLOSE;
    }
    r->in_len += n;
    process_cgi_data(r);
    return 0;
}
