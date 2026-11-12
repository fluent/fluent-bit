/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/http_server/flb_http_server.h>

/*
 * HTTP server lifecycle for the browser. A browser cannot listen on a
 * socket, so the only server that can run is one whose requests are supplied
 * by the host program (input property 'source.mode external') and processed
 * by flb_http_server_ingest().
 */

int flb_http_server_start(struct flb_http_server *session)
{
    int result;

    if (session->host_driven != FLB_TRUE) {
        flb_error("[http_server] listeners are not available in the browser, "
                  "set 'source.mode' to 'external'");
        return -1;
    }

    if (session->cb_worker_init != NULL) {
        result = session->cb_worker_init(session, session->user_data);
        if (result != 0) {
            return result;
        }
    }

    session->status = HTTP_SERVER_RUNNING;

    return 0;
}

int flb_http_server_stop(struct flb_http_server *server)
{
    if (server->status == HTTP_SERVER_RUNNING) {
        if (server->cb_worker_exit != NULL) {
            server->cb_worker_exit(server, server->user_data);
        }

        server->status = HTTP_SERVER_STOPPED;
    }

    return 0;
}

int flb_http_server_destroy(struct flb_http_server *server)
{
    return flb_http_server_stop(server);
}

/* There are no connections to hold back: the input queue keeps the requests */
int flb_http_server_pause(struct flb_http_server *server)
{
    (void) server;

    return 0;
}

int flb_http_server_resume(struct flb_http_server *server)
{
    (void) server;

    return 0;
}
