/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef MK_TLS_TRANSPORT_H
#define MK_TLS_TRANSPORT_H

#include <monkey/mk_plugin_net.h>
#include <monkey/mk_server.h>

int mk_tls_enabled(void);
int mk_tls_init(struct mk_server *server);
void mk_tls_thread_init(struct mk_server *server);
void mk_tls_exit(struct mk_server *server);
struct mk_plugin_network *mk_tls_transport(void);

#endif
