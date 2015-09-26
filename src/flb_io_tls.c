/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <unistd.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_tls.h>
#include <fluent-bit/flb_stats.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>

#define FLB_TLS_CLIENT   "Fluent Bit"
#define io_tls_error(ret) _io_tls_error(ret, __FILE__, __LINE__)

static inline void _io_tls_error(int ret, char *file, int line)
{
    char err_buf[72];

    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    flb_error("[io_tls] flb_io_tls.c:%i %s", line, err_buf);
}

static inline int io_tls_event_switch(struct flb_io_upstream *u, int mask)
{
    int ret;
    struct mk_event *event;

    event = &u->event;
    if (event->mask & ~mask) {
        ret = mk_event_add(u->evl,
                           event->fd,
                           FLB_ENGINE_EV_THREAD,
                           mask, &u->event);
        if (ret == -1) {
            flb_error("[io_tls] error changing mask to %i", mask);
            return -1;
        }
    }

    return 0;
}

struct flb_tls_context *flb_tls_context_new()
{
    int ret;
    struct flb_tls_context *tls;

    tls = malloc(sizeof(struct flb_tls_context));
    if (!tls) {
        perror("malloc");
        return NULL;
    }

    mbedtls_entropy_init(&tls->entropy);
    mbedtls_ctr_drbg_init(&tls->ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&tls->ctr_drbg,
                                mbedtls_entropy_func,
                                &tls->entropy,
                                (const unsigned char *) FLB_TLS_CLIENT,
                                sizeof(FLB_TLS_CLIENT) -1);
    if (ret == -1) {
        io_tls_error(ret);
        goto error;
    }

    return tls;

 error:
    free(tls);
    return NULL;
}

struct flb_tls_session *flb_tls_session_new(struct flb_tls_context *tls)
{
    int ret;
    struct flb_tls_session *session;

    session = malloc(sizeof(struct flb_tls_session));
    if (!session) {
        return NULL;
    }

    session->tls_context = tls;
    mbedtls_ssl_init(&session->ssl);
    mbedtls_ssl_config_init(&session->conf);

    ret = mbedtls_ssl_config_defaults(&session->conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        io_tls_error(ret);
    }

    mbedtls_ssl_conf_rng(&session->conf,
                         mbedtls_ctr_drbg_random,
                         &tls->ctr_drbg);
    mbedtls_ssl_conf_authmode(&session->conf, MBEDTLS_SSL_VERIFY_NONE);

    ret = mbedtls_ssl_setup(&session->ssl, &session->conf);
    if (ret == -1) {
        flb_error("[tls] ssl_setup");
        goto error;
    }


    return session;

 error:
    free(session);
    return NULL;
}

int tls_session_destroy(struct flb_tls_session *session)
{
    if (session) {
        mbedtls_ssl_free(&session->ssl);
        mbedtls_ssl_config_free(&session->conf);
        free(session);
    }

    return 0;
}


FLB_INLINE int io_tls_read(struct flb_thread *th, struct flb_output_plugin *out,
                               void *buf, size_t len)
{
    int ret;
    struct flb_io_upstream *u;

    u = out->upstream;
    ret = mbedtls_ssl_read(&u->tls_session->ssl, buf, len);
    if (ret <= 0) {
        tls_session_destroy(u->tls_session);
        u->tls_session = NULL;
    }

    return -1;
}

int io_tls_write(struct flb_thread *th, struct flb_output_plugin *out,
                 void *data, size_t len, size_t *out_len)
{
    int ret;
    size_t total = 0;
    struct flb_io_upstream *u;

    u = out->upstream;
    if (!u->tls_session) {
        u->tls_session = flb_tls_session_new(out->tls_context);
        if (!u->tls_session) {
            flb_error("[io_tls] could not create tls session");
            return -1;
        }

        ret = flb_io_tls_connect(out, th, u);
        if (ret == -1) {
            flb_error("[io_tls] could not connect/initiate TLS session");
            return -1;
        }
    }

 retry_write:
    ret = mbedtls_ssl_write(&u->tls_session->ssl,
                            data + total,
                            len - total);
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        io_tls_event_switch(u, MK_EVENT_WRITE);
        flb_thread_yield(th, FLB_FALSE);
        goto retry_write;
    }
    else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        io_tls_event_switch(u, MK_EVENT_READ);
        flb_thread_yield(th, FLB_FALSE);
        goto retry_write;
    }
    else if (ret < 0) {
        /* There was an error transmitting data */
        mk_event_del(u->evl, &u->event);
        tls_session_destroy(u->tls_session);
        u->tls_session = NULL;
        return -1;
    }

    /* Update statistics */
    flb_stats_update(ret, 0, &out->stats);

    /* Update counter and check if we need to continue writing */
    total += ret;
    if (total < len) {
        io_tls_event_switch(u, MK_EVENT_WRITE);
        flb_thread_yield(th, FLB_FALSE);
        goto retry_write;
    }

    mk_event_del(u->evl, &u->event);
    return 0;
}

/*
 * This routine perform a TCP connection and the required TLS/SSL
 * handshake,
 */
FLB_INLINE int flb_io_tls_connect(struct flb_output_plugin *out,
                                  struct flb_thread *th,
                                  struct flb_io_upstream *u)
{
    int fd;
    int ret;
    int error = 0;
    int flag;
    socklen_t len = sizeof(error);
    struct flb_tls_session *session;

    if (u->fd > 0) {
        close(u->fd);
    }

    /* Create the socket */
    fd = flb_net_socket_create(AF_INET, FLB_TRUE);
    if (fd == -1) {
        flb_error("[io] could not create socket");
        return -1;
    }
    u->fd = fd;

    /* Make the socket non-blocking */
    flb_net_socket_nonblocking(u->fd);

    /* Start the connection */
    ret = flb_net_tcp_fd_connect(fd, u->tcp_host, u->tcp_port);
    if (ret == -1) {
        if (errno == EINPROGRESS) {
            flb_debug("[upstream] connection in process");
        }
        else {
            close(u->fd);
            if (u->tls_session) {
                tls_session_destroy(u->tls_session);
                u->tls_session = NULL;
            }
            return -1;
        }

        u->event.mask = MK_EVENT_EMPTY;
        u->event.status = MK_EVENT_NONE;
        u->thread = th;

        ret = mk_event_add(u->evl,
                           fd,
                           FLB_ENGINE_EV_THREAD,
                           MK_EVENT_WRITE, &u->event);
        if (ret == -1) {
            /*
             * If we failed here there no much that we can do, just
             * let the caller we failed
             */
            flb_error("[io_tls] connect failed registering event");
            close(fd);
            return -1;
        }

        /*
         * Return the control to the parent caller, we need to wait for
         * the event loop to get back to us.
         */
        flb_thread_yield(th, FLB_FALSE);

        /* Check the connection status */
        if (u->event.mask & MK_EVENT_WRITE) {
            ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (error != 0) {
                /* Connection is broken, not much to do here */
                flb_error("[io_tls] connection failed");
                goto error;
            }
        }
        else {
            return -1;
        }
    }

    /* Configure TLS and prepare handshake */
    session = u->tls_session;
    mbedtls_ssl_set_bio(&session->ssl,
                        u,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

 retry_handshake:
    ret = mbedtls_ssl_handshake(&session->ssl);
    if (ret != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret !=  MBEDTLS_ERR_SSL_WANT_WRITE) {
            io_tls_error(ret);
            goto error;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            flag = MK_EVENT_WRITE;
        }
        else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            flag = MK_EVENT_READ;
        }
        else {

        }

        /*
         * FIXME: if we need multiple reads we are invoking the same
         * system call multiple times.
         */
        mk_event_add(u->evl,
                     u->event.fd,
                     FLB_ENGINE_EV_THREAD,
                     flag, &u->event);
        flb_thread_yield(th, FLB_FALSE);
        goto retry_handshake;
    }
    else {
        flb_debug("[io_tls] Handshake OK");
    }

    if (u->event.status == MK_EVENT_REGISTERED) {
        mk_event_del(u->evl, &u->event);
        u->event.status = MK_EVENT_NONE;
    }
    flb_debug("[io_tls] connection OK");
    return 0;

 error:
    if (u->event.status == MK_EVENT_REGISTERED) {
        mk_event_del(u->evl, &u->event);
    }
    return -1;
}
