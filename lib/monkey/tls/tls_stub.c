/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <monkey/mk_tls_transport.h>

int mk_tls_enabled(void)
{
    return 0;
}

int mk_tls_init(struct mk_server *server)
{
    (void) server;
    return 0;
}

void mk_tls_thread_init(struct mk_server *server)
{
    (void) server;
}

void mk_tls_exit(struct mk_server *server)
{
    (void) server;
}

struct mk_plugin_network *mk_tls_transport(void)
{
    return NULL;
}
