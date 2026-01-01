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

#ifndef FLB_DOWNSTREAM_CONN_H
#define FLB_DOWNSTREAM_CONN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_connection.h>

int flb_downstream_conn_release(struct flb_connection *connection);
int flb_downstream_conn_timeouts(struct mk_list *list);
int flb_downstream_conn_pending_destroy(struct flb_downstream *downstream);
struct flb_connection *flb_downstream_conn_get(struct flb_downstream *stream);

#endif
