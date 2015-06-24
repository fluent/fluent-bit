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
#include <fcntl.h>

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

static void done(struct cgi_request * const r) {

    if (!r)
        return;

    /* If the CGI app is fast, we might get a hangup event before
     * a write event. Try to write things out first. */
    _mkp_event_write(r->socket);

    mk_api->event_del(r->fd);

    if (r->chunked)
    {
        swrite(r->socket, "0\r\n\r\n", 5);
    }

    /* XXX Fixme: this needs to be atomic */
    requests_by_socket[r->socket] = NULL;

    /* Note: Must make sure we ignore the close event caused by this line */
    mk_api->http_request_end(r->socket);
    mk_api->socket_close(r->fd);


    cgi_req_del(r);
}

static int hangup(const int socket)
{
    struct cgi_request *r = cgi_req_get_by_fd(socket);

    if (r) {

        /* This kind of sucks, but epoll can give a hangup while
           we still have a lot of data to read.

           At this point we must turn the socket to blocking, otherwise
           the data won't get across fully.
        */

        fcntl(r->socket, F_SETFL, fcntl(r->socket, F_GETFL, 0) & ~O_NONBLOCK);
        while (1) {
            int ret = _mkp_event_read(socket);
            if (ret == MK_PLUGIN_RET_EVENT_CLOSE) {
                done(r);
                break;
            }

            ret = _mkp_event_write(r->socket);
            if (ret == MK_PLUGIN_RET_EVENT_CLOSE) {
                done(r);
                break;
            }
        }

        return MK_PLUGIN_RET_EVENT_OWNED;

    } else if ((r = cgi_req_get(socket))) {

        /* If this was closed by us, do nothing */
        if (!requests_by_socket[r->socket])
            return MK_PLUGIN_RET_EVENT_OWNED;

        mk_api->event_del(r->fd);
        mk_api->socket_close(r->fd);

        /* XXX Fixme: this needs to be atomic */
        requests_by_socket[r->socket] = NULL;

        cgi_req_del(r);

        return MK_PLUGIN_RET_EVENT_OWNED;
    }

    return MK_PLUGIN_RET_EVENT_CONTINUE;
}

int _mkp_event_write(int socket)
{
    struct cgi_request *r = cgi_req_get(socket);
    if (!r) return MK_PLUGIN_RET_EVENT_NEXT;

    if (r->in_len > 0) {

        mk_api->socket_cork_flag(socket, TCP_CORK_ON);

        const char * const buf = r->in_buf, *outptr = r->in_buf;

        if (!r->status_done && r->in_len >= 8) {
            if (memcmp(buf, "Status: ", 8) == 0) {
                int status = atoi(buf + 8);
                mk_api->header_set_http_status(r->sr, status);

                char *endl = memchr(buf + 8, '\n', r->in_len - 8);
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
                int status = atoi(buf + 9);
                mk_api->header_set_http_status(r->sr, status);

                char *endl = memchr(buf + 8, '\n', r->in_len - 8);
                if (!endl) {
                    return MK_PLUGIN_RET_EVENT_OWNED;
                }
                else {
                    endl++;
                    outptr = endl;
                    r->in_len -= endl - buf;
                }
            }

            mk_api->header_send(socket, r->cs, r->sr);

            r->status_done = 1;
        }

        if (!r->all_headers_done)
        {
            unsigned char advance = 4;

            // Write the rest of the headers without chunking
            char *end = getearliestbreak(outptr, r->in_len, &advance);
            if (!end)
            {
                swrite(socket, outptr, r->in_len);
                r->in_len = 0;
                mk_api->event_socket_change_mode(socket, MK_EVENT_SLEEP, -1);
                return MK_PLUGIN_RET_EVENT_OWNED;
            }

            end += advance;

            int len = end - outptr;

            swrite(socket, outptr, len);
            outptr += len;
            r->in_len -= len;

            r->all_headers_done = 1;

            if (r->in_len == 0)
            {
                mk_api->event_socket_change_mode(socket, MK_EVENT_SLEEP, -1);
                return MK_PLUGIN_RET_EVENT_OWNED;
            }
        }

        int ret;

        if (r->chunked)
        {
            char tmp[16];
            int len = snprintf(tmp, 16, "%x%s", r->in_len, MK_CRLF);
            ret = swrite(socket, tmp, len);
            if (ret < 0)
                return MK_PLUGIN_RET_EVENT_CLOSE;
        }

        ret = swrite(socket, outptr, r->in_len);
        if (ret < 0)
            return MK_PLUGIN_RET_EVENT_CLOSE;

        r->in_len = 0;
        mk_api->event_socket_change_mode(socket, MK_EVENT_SLEEP, -1);
        mk_api->event_socket_change_mode(r->fd, MK_EVENT_READ, -1);

        if (r->chunked)
        {
            swrite(socket, MK_CRLF, 2);
        }

        mk_api->socket_cork_flag(socket, TCP_CORK_OFF);
    }

    return MK_PLUGIN_RET_EVENT_OWNED;
}

int _mkp_event_read(int fd)
{
    struct cgi_request *r = cgi_req_get_by_fd(fd);
    if (!r) return MK_PLUGIN_RET_EVENT_NEXT;

    size_t count = PATHLEN - r->in_len;

    /* Too much to read? Start writing. */
    if (count < 1)
    {
        mk_api->event_socket_change_mode(r->fd, MK_EVENT_SLEEP, -1);
        goto out;
    }

    int n = read(r->fd, r->in_buf + r->in_len, count);

    if (n <=0)
        return MK_PLUGIN_RET_EVENT_CLOSE;

    r->in_len += n;

out:
    /* Now we do have something to write */
    mk_api->event_socket_change_mode(r->socket, MK_EVENT_WRITE, -1);

    return MK_PLUGIN_RET_EVENT_OWNED;
}

int _mkp_event_close(int socket)
{
    return hangup(socket);
}

int _mkp_event_error(int socket)
{
    return hangup(socket);
}
