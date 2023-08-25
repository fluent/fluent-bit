/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#ifndef FLB_PROMETHEUS_EXPORTER_HTTP_CONN_H
#define FLB_PROMETHEUS_EXPORTER_HTTP_CONN_H

#include <fluent-bit/flb_output_plugin.h>
#include <monkey/mk_lib.h>

#include "prom.h"

struct prom_http_conn {
  /* Buffer */
  char *buf_data; /* Buffer data                       */
  int buf_len;    /* Data length                       */
  int buf_size;   /* Buffer size                       */

  /*
   * Parser context: we only held one parser per connection
   * which is re-used everytime we have a new request.
   */
  struct mk_http_parser parser;
  struct mk_http_request request;
  struct mk_http_session session;
  struct flb_connection *connection;

  struct prom_exporter *ctx; /* Plugin parent context             */
  struct mk_list _head;      /* link to flb_http->connections     */
};

// Downstream connection management
struct prom_http_conn *prom_http_conn_create(struct flb_connection *conn,
                                             struct prom_exporter *ctx);
int prom_http_conn_destroy(struct prom_http_conn *conn);
void prom_http_conn_release_all(struct prom_exporter *ctx);

#endif