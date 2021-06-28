/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>

#include "udp.h"
#include "udp_conf.h"
#include "udp_conn.h"
#include "udp_prot.h"


int udp_conn_del(struct udp_conn *conn)
{
    /* Unregister the file descriptior from the event-loop */
    mk_event_del(conn->ctx->evl, &conn->event);

    /* Release resources */
    mk_list_del(&conn->_head);
    close(conn->fd);
    flb_free(conn->buf_data);
    flb_free(conn);

    return 0;
}

int udp_conn_exit(struct flb_udp *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct udp_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct udp_conn, _head);
        udp_conn_del(conn);
    }

    return 0;
}
