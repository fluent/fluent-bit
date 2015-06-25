/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright (C) 2012, Lauri Kasanen
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

/* Get the earliest break between headers and content.

   The reason for this function is that some CGI apps
   use LFLF and some use CRLFCRLF.

   If that app then sends content that has the other break
   in the beginning, monkey can accidentally send part of the
   content as headers.
*/
static char *getearliestbreak(const char buf[], const unsigned bufsize,
				unsigned char * const advance) {

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

static void cgi_done(struct cgi_request *r)
{
    mk_api->ev_del(mk_api->sched_loop(), (struct mk_event *) r);
    if (r->chunked) {
        channel_write(r->sr->session, "0\r\n\r\n", 5);
    }

    /* XXX Fixme: this needs to be atomic */
    requests_by_socket[r->socket] = NULL;

    /* Note: Must make sure we ignore the close event caused by this line */
    mk_api->http_session_end(r->cs);
    //mk_api->socket_close(r->fd);
    cgi_req_del(r);
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
        mk_api->header_prepare(r->cs, r->sr);
        r->status_done = 1;
    }

    if (!r->all_headers_done) {
        advance = 4;

        /* Write the rest of the headers without chunking */
        end = getearliestbreak(outptr, r->in_len, &advance);
        if (!end) {
            channel_write(r->cs, outptr, r->in_len);
            r->in_len = 0;
            return MK_PLUGIN_RET_EVENT_OWNED;
        }
        end += advance;
        len = end - outptr;
        channel_write(r->cs, outptr, len);
        outptr += len;
        r->in_len -= len;

        r->all_headers_done = 1;
        if (r->in_len == 0) {
            return MK_PLUGIN_RET_EVENT_OWNED;
        }
    }

    if (r->chunked) {
        char tmp[16];
        len = snprintf(tmp, 16, "%x%s", r->in_len, MK_CRLF);
        ret = channel_write(r->cs, tmp, len);
        if (ret < 0)
            return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    ret = channel_write(r->cs, outptr, r->in_len);
    if (ret < 0) {
        return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    r->in_len = 0;
    if (r->chunked) {
        channel_write(r->sr->session, MK_CRLF, 2);
    }
    return MK_PLUGIN_RET_EVENT_OWNED;
}

int cb_cgi_read(void *data)
{
    int n;
    struct cgi_request *r = data;

    /* Read data from the CGI process */
    n = read(r->fd, r->in_buf, BUFLEN);
    PLUGIN_TRACE("CGI returned %lu bytes", n);
    if (n <= 0) {
        cgi_done(r);
        return MK_PLUGIN_RET_EVENT_CLOSE;
    }
    r->in_len = n;

    process_cgi_data(r);
    return 0;
}
