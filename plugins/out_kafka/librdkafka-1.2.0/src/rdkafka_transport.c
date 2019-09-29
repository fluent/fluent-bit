/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2015, Magnus Edenhill
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met: 
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#define __need_IOV_MAX

#define _DARWIN_C_SOURCE  /* MSG_DONTWAIT */

#include "rdkafka_int.h"
#include "rdaddr.h"
#include "rdkafka_transport.h"
#include "rdkafka_transport_int.h"
#include "rdkafka_broker.h"
#include "rdkafka_interceptor.h"

#include <errno.h>

/* AIX doesn't have MSG_DONTWAIT */
#ifndef MSG_DONTWAIT
#  define MSG_DONTWAIT MSG_NONBLOCK
#endif

#if WITH_SSL
#include "rdkafka_ssl.h"
#endif

/**< Current thread's rd_kafka_transport_t instance.
 *   This pointer is set up when calling any OpenSSL APIs that might
 *   trigger SSL callbacks, and is used to retrieve the SSL object's
 *   corresponding rd_kafka_transport_t instance.
 *   There is an set/get_ex_data() API in OpenSSL, but it requires storing
 *   a unique index somewhere, which we can't do without having a singleton
 *   object, so instead we cut out the middle man and store the
 *   rd_kafka_transport_t pointer directly in the thread-local memory. */
RD_TLS rd_kafka_transport_t *rd_kafka_curr_transport;



/**
 * Low-level socket close
 */
static void rd_kafka_transport_close0 (rd_kafka_t *rk, int s) {
        if (rk->rk_conf.closesocket_cb)
                rk->rk_conf.closesocket_cb(s, rk->rk_conf.opaque);
        else {
#ifndef _MSC_VER
		close(s);
#else
		closesocket(s);
#endif
        }

}

/**
 * Close and destroy a transport handle
 */
void rd_kafka_transport_close (rd_kafka_transport_t *rktrans) {
#if WITH_SSL
        rd_kafka_curr_transport = rktrans;
        if (rktrans->rktrans_ssl)
                rd_kafka_transport_ssl_close(rktrans);
#endif

        rd_kafka_sasl_close(rktrans);

	if (rktrans->rktrans_recv_buf)
		rd_kafka_buf_destroy(rktrans->rktrans_recv_buf);

	if (rktrans->rktrans_s != -1)
                rd_kafka_transport_close0(rktrans->rktrans_rkb->rkb_rk,
                                          rktrans->rktrans_s);

	rd_free(rktrans);
}


static const char *socket_strerror(int err) {
#ifdef _MSC_VER
	static RD_TLS char buf[256];
        rd_strerror_w32(err, buf, sizeof(buf));
	return buf;
#else
	return rd_strerror(err);
#endif
}




#ifndef _MSC_VER
/**
 * @brief sendmsg() abstraction, converting a list of segments to iovecs.
 * @remark should only be called if the number of segments is > 1.
 */
static ssize_t
rd_kafka_transport_socket_sendmsg (rd_kafka_transport_t *rktrans,
                                   rd_slice_t *slice,
                                   char *errstr, size_t errstr_size) {
        struct iovec iov[IOV_MAX];
        struct msghdr msg = { .msg_iov = iov };
        size_t iovlen;
        ssize_t r;

        rd_slice_get_iov(slice, msg.msg_iov, &iovlen, IOV_MAX,
                         /* FIXME: Measure the effects of this */
                         rktrans->rktrans_sndbuf_size);
        msg.msg_iovlen = (int)iovlen;

#ifdef __sun
        /* See recvmsg() comment. Setting it here to be safe. */
        socket_errno = EAGAIN;
#endif

        r = sendmsg(rktrans->rktrans_s, &msg, MSG_DONTWAIT
#ifdef MSG_NOSIGNAL
                    | MSG_NOSIGNAL
#endif
                );

        if (r == -1) {
                if (socket_errno == EAGAIN)
                        return 0;
                rd_snprintf(errstr, errstr_size, "%s", rd_strerror(errno));
        }

        /* Update buffer read position */
        rd_slice_read(slice, NULL, (size_t)r);

        return r;
}
#endif


/**
 * @brief Plain send() abstraction
 */
static ssize_t
rd_kafka_transport_socket_send0 (rd_kafka_transport_t *rktrans,
                                 rd_slice_t *slice,
                                 char *errstr, size_t errstr_size) {
        ssize_t sum = 0;
        const void *p;
        size_t rlen;

        while ((rlen = rd_slice_peeker(slice, &p))) {
                ssize_t r;

                r = send(rktrans->rktrans_s, p,
#ifdef _MSC_VER
                         (int)rlen, (int)0
#else
                         rlen, 0
#endif
                );

#ifdef _MSC_VER
                if (unlikely(r == SOCKET_ERROR)) {
                        if (sum > 0 || WSAGetLastError() == WSAEWOULDBLOCK)
                                return sum;
                        else {
                                rd_snprintf(errstr, errstr_size, "%s",
                                            socket_strerror(WSAGetLastError()));
                                return -1;
                        }
                }
#else
                if (unlikely(r <= 0)) {
                        if (r == 0 || errno == EAGAIN)
                                return 0;
                        rd_snprintf(errstr, errstr_size, "%s",
                                    socket_strerror(socket_errno));
                        return -1;
                }
#endif

                /* Update buffer read position */
                rd_slice_read(slice, NULL, (size_t)r);

                sum += r;

                /* FIXME: remove this and try again immediately and let
                 *        the next write() call fail instead? */
                if ((size_t)r < rlen)
                        break;
        }

        return sum;
}


static ssize_t
rd_kafka_transport_socket_send (rd_kafka_transport_t *rktrans,
                                rd_slice_t *slice,
                                char *errstr, size_t errstr_size) {
#ifndef _MSC_VER
        /* FIXME: Use sendmsg() with iovecs if there's more than one segment
         * remaining, otherwise (or if platform does not have sendmsg)
         * use plain send(). */
        return rd_kafka_transport_socket_sendmsg(rktrans, slice,
                                                 errstr, errstr_size);
#endif
        return rd_kafka_transport_socket_send0(rktrans, slice,
                                               errstr, errstr_size);
}



#ifndef _MSC_VER
/**
 * @brief recvmsg() abstraction, converting a list of segments to iovecs.
 * @remark should only be called if the number of segments is > 1.
 */
static ssize_t
rd_kafka_transport_socket_recvmsg (rd_kafka_transport_t *rktrans,
                                   rd_buf_t *rbuf,
                                   char *errstr, size_t errstr_size) {
        ssize_t r;
        struct iovec iov[IOV_MAX];
        struct msghdr msg = { .msg_iov = iov };
        size_t iovlen;

        rd_buf_get_write_iov(rbuf, msg.msg_iov, &iovlen, IOV_MAX,
                             /* FIXME: Measure the effects of this */
                             rktrans->rktrans_rcvbuf_size);
        msg.msg_iovlen = (int)iovlen;

#ifdef __sun
        /* SunOS doesn't seem to set errno when recvmsg() fails
         * due to no data and MSG_DONTWAIT is set. */
        socket_errno = EAGAIN;
#endif
        r = recvmsg(rktrans->rktrans_s, &msg, MSG_DONTWAIT);
        if (unlikely(r <= 0)) {
                if (r == -1 && socket_errno == EAGAIN)
                        return 0;
                else if (r == 0 ||
                         (r == -1 && socket_errno == ECONNRESET)) {
                        /* Receive 0 after POLLIN event means
                         * connection closed. */
                        rd_snprintf(errstr, errstr_size, "Disconnected");
                        errno = ECONNRESET;
                        return -1;
                } else if (r == -1) {
                        int errno_save = errno;
                        rd_snprintf(errstr, errstr_size, "%s",
                                    rd_strerror(errno));
                        errno = errno_save;
                        return -1;
                }
        }

        /* Update buffer write position */
        rd_buf_write(rbuf, NULL, (size_t)r);

        return r;
}
#endif


/**
 * @brief Plain recv()
 */
static ssize_t
rd_kafka_transport_socket_recv0 (rd_kafka_transport_t *rktrans,
                                 rd_buf_t *rbuf,
                                 char *errstr, size_t errstr_size) {
        ssize_t sum = 0;
        void *p;
        size_t len;

        while ((len = rd_buf_get_writable(rbuf, &p))) {
                ssize_t r;

                r = recv(rktrans->rktrans_s, p,
#ifdef _MSC_VER
                         (int)
#endif
                         len,
                         0);

                if (unlikely(r == SOCKET_ERROR)) {
                        int errno_save = socket_errno;
                        if (errno_save == EAGAIN
#ifdef _MSC_VER
                           || errno_save == WSAEWOULDBLOCK
#endif 
                           )
                                return sum;
                        else {
                                rd_snprintf(errstr, errstr_size, "%s",
                                    socket_strerror(errno_save));
#ifndef _MSC_VER
                                errno = errno_save;
#endif
                                return -1;
                        }
                } else if (unlikely(r == 0)) {
                        /* Receive 0 after POLLIN event means
                         * connection closed. */
                        rd_snprintf(errstr, errstr_size,
                                    "Disconnected");
#ifndef _MSC_VER
                        errno = ECONNRESET;
#endif
                        return -1;
                }

                /* Update buffer write position */
                rd_buf_write(rbuf, NULL, (size_t)r);

                sum += r;

                /* FIXME: remove this and try again immediately and let
                 *        the next recv() call fail instead? */
                if ((size_t)r < len)
                        break;
        }
        return sum;
}


static ssize_t
rd_kafka_transport_socket_recv (rd_kafka_transport_t *rktrans,
                                rd_buf_t *buf,
                                char *errstr, size_t errstr_size) {
#ifndef _MSC_VER
        /* FIXME: Use recvmsg() with iovecs if there's more than one segment
         * remaining, otherwise (or if platform does not have sendmsg)
         * use plain send(). */
        return rd_kafka_transport_socket_recvmsg(rktrans, buf,
                                                 errstr, errstr_size);
#endif
        return rd_kafka_transport_socket_recv0(rktrans, buf,
                                               errstr, errstr_size);
}





/**
 * CONNECT state is failed (errstr!=NULL) or done (TCP is up, SSL is working..).
 * From this state we either hand control back to the broker code,
 * or if authentication is configured we ente the AUTH state.
 */
void rd_kafka_transport_connect_done (rd_kafka_transport_t *rktrans,
				      char *errstr) {
	rd_kafka_broker_t *rkb = rktrans->rktrans_rkb;

        rd_kafka_curr_transport = rktrans;

        rd_kafka_broker_connect_done(rkb, errstr);
}






ssize_t
rd_kafka_transport_send (rd_kafka_transport_t *rktrans,
                         rd_slice_t *slice, char *errstr, size_t errstr_size) {
        ssize_t r;
#if WITH_SSL
        if (rktrans->rktrans_ssl) {
                rd_kafka_curr_transport = rktrans;
                r = rd_kafka_transport_ssl_send(rktrans, slice,
                                                errstr, errstr_size);
        } else
#endif
                r = rd_kafka_transport_socket_send(rktrans, slice,
                                                   errstr, errstr_size);

        return r;
}


ssize_t
rd_kafka_transport_recv (rd_kafka_transport_t *rktrans, rd_buf_t *rbuf,
                         char *errstr, size_t errstr_size) {
        ssize_t r;

#if WITH_SSL
        if (rktrans->rktrans_ssl) {
                rd_kafka_curr_transport = rktrans;
                r = rd_kafka_transport_ssl_recv(rktrans, rbuf,
                                                errstr, errstr_size);
        } else
#endif
                r = rd_kafka_transport_socket_recv(rktrans, rbuf,
                                                   errstr, errstr_size);

        return r;
}



/**
 * @brief Notify transport layer of full request sent.
 */
void rd_kafka_transport_request_sent (rd_kafka_broker_t *rkb,
                                      rd_kafka_buf_t *rkbuf) {
        rd_kafka_transport_t *rktrans = rkb->rkb_transport;

        /* Call on_request_sent interceptors */
        rd_kafka_interceptors_on_request_sent(
                rkb->rkb_rk,
                rktrans->rktrans_s,
                rkb->rkb_name, rkb->rkb_nodeid,
                rkbuf->rkbuf_reqhdr.ApiKey,
                rkbuf->rkbuf_reqhdr.ApiVersion,
                rkbuf->rkbuf_corrid,
                rd_slice_size(&rkbuf->rkbuf_reader));
}




/**
 * Length framed receive handling.
 * Currently only supports a the following framing:
 *     [int32_t:big_endian_length_of_payload][payload]
 *
 * To be used on POLLIN event, will return:
 *   -1: on fatal error (errstr will be updated, *rkbufp remains unset)
 *    0: still waiting for data (*rkbufp remains unset)
 *    1: data complete, (buffer returned in *rkbufp)
 */
int rd_kafka_transport_framed_recv (rd_kafka_transport_t *rktrans,
                                    rd_kafka_buf_t **rkbufp,
                                    char *errstr, size_t errstr_size) {
	rd_kafka_buf_t *rkbuf = rktrans->rktrans_recv_buf;
	ssize_t r;
	const int log_decode_errors = LOG_ERR;

	/* States:
	 *   !rktrans_recv_buf: initial state; set up buf to receive header.
	 *    rkbuf_totlen == 0:   awaiting header
	 *    rkbuf_totlen > 0:    awaiting payload
	 */

	if (!rkbuf) {
                rkbuf = rd_kafka_buf_new(1, 4/*length field's length*/);
                /* Set up buffer reader for the length field */
                rd_buf_write_ensure(&rkbuf->rkbuf_buf, 4, 4);
		rktrans->rktrans_recv_buf = rkbuf;
	}


        r = rd_kafka_transport_recv(rktrans, &rkbuf->rkbuf_buf,
                                    errstr, errstr_size);
	if (r == 0)
		return 0;
	else if (r == -1)
		return -1;

	if (rkbuf->rkbuf_totlen == 0) {
		/* Frame length not known yet. */
		int32_t frame_len;

		if (rd_buf_write_pos(&rkbuf->rkbuf_buf) < sizeof(frame_len)) {
			/* Wait for entire frame header. */
			return 0;
		}

                /* Initialize reader */
                rd_slice_init(&rkbuf->rkbuf_reader, &rkbuf->rkbuf_buf, 0, 4);

		/* Reader header: payload length */
		rd_kafka_buf_read_i32(rkbuf, &frame_len);

		if (frame_len < 0 ||
		    frame_len > rktrans->rktrans_rkb->
		    rkb_rk->rk_conf.recv_max_msg_size) {
			rd_snprintf(errstr, errstr_size,
				    "Invalid frame size %"PRId32, frame_len);
			return -1;
		}

		rkbuf->rkbuf_totlen = 4 + frame_len;
		if (frame_len == 0) {
			/* Payload is empty, we're done. */
			rktrans->rktrans_recv_buf = NULL;
			*rkbufp = rkbuf;
			return 1;
		}

		/* Allocate memory to hold entire frame payload in contigious
		 * memory. */
                rd_buf_write_ensure_contig(&rkbuf->rkbuf_buf, frame_len);

                /* Try reading directly, there is probably more data available*/
                return rd_kafka_transport_framed_recv(rktrans, rkbufp,
                                                      errstr, errstr_size);
	}

	if (rd_buf_write_pos(&rkbuf->rkbuf_buf) == rkbuf->rkbuf_totlen) {
		/* Payload is complete. */
		rktrans->rktrans_recv_buf = NULL;
		*rkbufp = rkbuf;
		return 1;
	}

	/* Wait for more data */
	return 0;

 err_parse:
	if (rkbuf)
		rd_kafka_buf_destroy(rkbuf);
        rd_snprintf(errstr, errstr_size, "Frame header parsing failed: %s",
                    rd_kafka_err2str(rkbuf->rkbuf_err));
	return -1;
}


/**
 * TCP connection established.
 * Set up socket options, SSL, etc.
 *
 * Locality: broker thread
 */
static void rd_kafka_transport_connected (rd_kafka_transport_t *rktrans) {
	rd_kafka_broker_t *rkb = rktrans->rktrans_rkb;
        unsigned int slen;

        rd_rkb_dbg(rkb, BROKER, "CONNECT",
                   "Connected to %s",
                   rd_sockaddr2str(rkb->rkb_addr_last,
                                   RD_SOCKADDR2STR_F_PORT |
                                   RD_SOCKADDR2STR_F_FAMILY));

	/* Set socket send & receive buffer sizes if configuerd */
	if (rkb->rkb_rk->rk_conf.socket_sndbuf_size != 0) {
		if (setsockopt(rktrans->rktrans_s, SOL_SOCKET, SO_SNDBUF,
			       (void *)&rkb->rkb_rk->rk_conf.socket_sndbuf_size,
			       sizeof(rkb->rkb_rk->rk_conf.
				      socket_sndbuf_size)) == SOCKET_ERROR)
			rd_rkb_log(rkb, LOG_WARNING, "SNDBUF",
				   "Failed to set socket send "
				   "buffer size to %i: %s",
				   rkb->rkb_rk->rk_conf.socket_sndbuf_size,
				   socket_strerror(socket_errno));
	}

	if (rkb->rkb_rk->rk_conf.socket_rcvbuf_size != 0) {
		if (setsockopt(rktrans->rktrans_s, SOL_SOCKET, SO_RCVBUF,
			       (void *)&rkb->rkb_rk->rk_conf.socket_rcvbuf_size,
			       sizeof(rkb->rkb_rk->rk_conf.
				      socket_rcvbuf_size)) == SOCKET_ERROR)
			rd_rkb_log(rkb, LOG_WARNING, "RCVBUF",
				   "Failed to set socket receive "
				   "buffer size to %i: %s",
				   rkb->rkb_rk->rk_conf.socket_rcvbuf_size,
				   socket_strerror(socket_errno));
	}

        /* Get send and receive buffer sizes to allow limiting
         * the total number of bytes passed with iovecs to sendmsg()
         * and recvmsg(). */
        slen = sizeof(rktrans->rktrans_rcvbuf_size);
        if (getsockopt(rktrans->rktrans_s, SOL_SOCKET, SO_RCVBUF,
                       (void *)&rktrans->rktrans_rcvbuf_size,
                       &slen) == SOCKET_ERROR) {
                rd_rkb_log(rkb, LOG_WARNING, "RCVBUF",
                           "Failed to get socket receive "
                           "buffer size: %s: assuming 1MB",
                           socket_strerror(socket_errno));
                rktrans->rktrans_rcvbuf_size = 1024*1024;
        } else if (rktrans->rktrans_rcvbuf_size < 1024 * 64)
                rktrans->rktrans_rcvbuf_size = 1024*64; /* Use at least 64KB */

        slen = sizeof(rktrans->rktrans_sndbuf_size);
        if (getsockopt(rktrans->rktrans_s, SOL_SOCKET, SO_SNDBUF,
                       (void *)&rktrans->rktrans_sndbuf_size,
                       &slen) == SOCKET_ERROR) {
                rd_rkb_log(rkb, LOG_WARNING, "RCVBUF",
                           "Failed to get socket send "
                           "buffer size: %s: assuming 1MB",
                           socket_strerror(socket_errno));
                rktrans->rktrans_sndbuf_size = 1024*1024;
        } else if (rktrans->rktrans_sndbuf_size < 1024 * 64)
                rktrans->rktrans_sndbuf_size = 1024*64; /* Use at least 64KB */


#ifdef TCP_NODELAY
        if (rkb->rkb_rk->rk_conf.socket_nagle_disable) {
                int one = 1;
                if (setsockopt(rktrans->rktrans_s, IPPROTO_TCP, TCP_NODELAY,
                               (void *)&one, sizeof(one)) == SOCKET_ERROR)
                        rd_rkb_log(rkb, LOG_WARNING, "NAGLE",
                                   "Failed to disable Nagle (TCP_NODELAY) "
                                   "on socket: %s",
                                   socket_strerror(socket_errno));
        }
#endif


#if WITH_SSL
	if (rkb->rkb_proto == RD_KAFKA_PROTO_SSL ||
	    rkb->rkb_proto == RD_KAFKA_PROTO_SASL_SSL) {
		char errstr[512];

		/* Set up SSL connection.
		 * This is also an asynchronous operation so dont
		 * propagate to broker_connect_done() just yet. */
		if (rd_kafka_transport_ssl_connect(rkb, rktrans,
						   errstr,
						   sizeof(errstr)) == -1) {
			rd_kafka_transport_connect_done(rktrans, errstr);
			return;
		}
		return;
	}
#endif

	/* Propagate connect success */
	rd_kafka_transport_connect_done(rktrans, NULL);
}



/**
 * @brief the kernel SO_ERROR in \p errp for the given transport.
 * @returns 0 if getsockopt() was succesful (and \p and errp can be trusted),
 * else -1 in which case \p errp 's value is undefined.
 */
static int rd_kafka_transport_get_socket_error (rd_kafka_transport_t *rktrans,
						int *errp) {
	socklen_t intlen = sizeof(*errp);

	if (getsockopt(rktrans->rktrans_s, SOL_SOCKET,
		       SO_ERROR, (void *)errp, &intlen) == -1) {
		rd_rkb_dbg(rktrans->rktrans_rkb, BROKER, "SO_ERROR",
			   "Failed to get socket error: %s",
			   socket_strerror(socket_errno));
		return -1;
	}

	return 0;
}


/**
 * IO event handler.
 *
 * Locality: broker thread
 */
static void rd_kafka_transport_io_event (rd_kafka_transport_t *rktrans,
					 int events) {
	char errstr[512];
	int r;
	rd_kafka_broker_t *rkb = rktrans->rktrans_rkb;

	switch (rkb->rkb_state)
	{
	case RD_KAFKA_BROKER_STATE_CONNECT:
#if WITH_SSL
		if (rktrans->rktrans_ssl) {
			/* Currently setting up SSL connection:
			 * perform handshake. */
			rd_kafka_transport_ssl_handshake(rktrans);
			return;
		}
#endif

		/* Asynchronous connect finished, read status. */
		if (!(events & (POLLOUT|POLLERR|POLLHUP)))
			return;

		if (rd_kafka_transport_get_socket_error(rktrans, &r) == -1) {
			rd_kafka_broker_fail(
                                rkb, LOG_ERR, RD_KAFKA_RESP_ERR__TRANSPORT,
                                "Connect to %s failed: "
                                "unable to get status from "
                                "socket %d: %s",
                                rd_sockaddr2str(rkb->rkb_addr_last,
                                                RD_SOCKADDR2STR_F_PORT |
                                                RD_SOCKADDR2STR_F_FAMILY),
                                rktrans->rktrans_s,
                                rd_strerror(socket_errno));
		} else if (r != 0) {
			/* Connect failed */
                        errno = r;
			rd_snprintf(errstr, sizeof(errstr),
				    "Connect to %s failed: %s",
                                    rd_sockaddr2str(rkb->rkb_addr_last,
                                                    RD_SOCKADDR2STR_F_PORT |
                                                    RD_SOCKADDR2STR_F_FAMILY),
                                    rd_strerror(r));

			rd_kafka_transport_connect_done(rktrans, errstr);
		} else {
			/* Connect succeeded */
			rd_kafka_transport_connected(rktrans);
		}
		break;

        case RD_KAFKA_BROKER_STATE_AUTH_LEGACY:
                /* SASL authentication.
                 * Prior to broker version v1.0.0 this is performed
                 * directly on the socket without Kafka framing. */
                if (rd_kafka_sasl_io_event(rktrans, events,
                                           errstr,
                                           sizeof(errstr)) == -1) {
                        errno = EINVAL;
                        rd_kafka_broker_fail(
                                rkb, LOG_ERR,
                                RD_KAFKA_RESP_ERR__AUTHENTICATION,
                                "SASL authentication failure: %s",
                                errstr);
                        return;
                }

                if (events & POLLHUP) {
                        errno = EINVAL;
                        rd_kafka_broker_fail(
                                rkb, LOG_ERR,
                                RD_KAFKA_RESP_ERR__AUTHENTICATION,
                                "Disconnected");

                        return;
                }

                break;

	case RD_KAFKA_BROKER_STATE_APIVERSION_QUERY:
	case RD_KAFKA_BROKER_STATE_AUTH_HANDSHAKE:
                case RD_KAFKA_BROKER_STATE_AUTH_REQ:
	case RD_KAFKA_BROKER_STATE_UP:
	case RD_KAFKA_BROKER_STATE_UPDATE:

		if (events & POLLIN) {
			while (rkb->rkb_state >= RD_KAFKA_BROKER_STATE_UP &&
			       rd_kafka_recv(rkb) > 0)
				;

                        /* If connection went down: bail out early */
                        if (rkb->rkb_state == RD_KAFKA_BROKER_STATE_DOWN)
                                return;
		}

                if (events & POLLHUP) {
                        rd_kafka_broker_conn_closed(
                                rkb, RD_KAFKA_RESP_ERR__TRANSPORT,
                                "Disconnected");
                        return;
                }

		if (events & POLLOUT) {
			while (rd_kafka_send(rkb) > 0)
				;
		}
		break;

	case RD_KAFKA_BROKER_STATE_INIT:
	case RD_KAFKA_BROKER_STATE_DOWN:
        case RD_KAFKA_BROKER_STATE_TRY_CONNECT:
		rd_kafka_assert(rkb->rkb_rk, !*"bad state");
	}
}


/**
 * @brief Poll and serve IOs
 *
 * @returns 1 if at least one IO event was triggered, else 0, or -1 on error.
 *
 * @locality broker thread
 */
int rd_kafka_transport_io_serve (rd_kafka_transport_t *rktrans,
                                  int timeout_ms) {
	rd_kafka_broker_t *rkb = rktrans->rktrans_rkb;
        int events;
        int r;

        rd_kafka_curr_transport = rktrans;

        if (rkb->rkb_state == RD_KAFKA_BROKER_STATE_CONNECT ||
            (rkb->rkb_state > RD_KAFKA_BROKER_STATE_CONNECT &&
             rd_kafka_bufq_cnt(&rkb->rkb_waitresps) < rkb->rkb_max_inflight &&
             rd_kafka_bufq_cnt(&rkb->rkb_outbufs) > 0))
                rd_kafka_transport_poll_set(rkb->rkb_transport, POLLOUT);

        if ((r = rd_kafka_transport_poll(rktrans, timeout_ms)) <= 0)
                return r;

        /* Only handle events on the broker socket, the wakeup
         * socket is just for waking up the blocking boll. */
        events = rktrans->rktrans_pfd[0].revents;
        if (events) {
                rd_kafka_transport_poll_clear(rktrans, POLLOUT);

                rd_kafka_transport_io_event(rktrans, events);
        }

        return 1;
}


/**
 * Initiate asynchronous connection attempt.
 *
 * Locality: broker thread
 */
rd_kafka_transport_t *rd_kafka_transport_connect (rd_kafka_broker_t *rkb,
						  const rd_sockaddr_inx_t *sinx,
						  char *errstr,
						  size_t errstr_size) {
	rd_kafka_transport_t *rktrans;
	int s = -1;
	int on = 1;
        int r;

        rkb->rkb_addr_last = sinx;

	s = rkb->rkb_rk->rk_conf.socket_cb(sinx->in.sin_family,
					   SOCK_STREAM, IPPROTO_TCP,
					   rkb->rkb_rk->rk_conf.opaque);
	if (s == -1) {
		rd_snprintf(errstr, errstr_size, "Failed to create socket: %s",
			    socket_strerror(socket_errno));
		return NULL;
	}


#ifdef SO_NOSIGPIPE
	/* Disable SIGPIPE signalling for this socket on OSX */
	if (setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) == -1) 
		rd_rkb_dbg(rkb, BROKER, "SOCKET",
			   "Failed to set SO_NOSIGPIPE: %s",
			   socket_strerror(socket_errno));
#endif

#ifdef SO_KEEPALIVE
        /* Enable TCP keep-alives, if configured. */
        if (rkb->rkb_rk->rk_conf.socket_keepalive) {
                if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                               (void *)&on, sizeof(on)) == SOCKET_ERROR)
                        rd_rkb_dbg(rkb, BROKER, "SOCKET",
                                   "Failed to set SO_KEEPALIVE: %s",
                                   socket_strerror(socket_errno));
        }
#endif

        /* Set the socket to non-blocking */
        if ((r = rd_fd_set_nonblocking(s))) {
                rd_snprintf(errstr, errstr_size,
                            "Failed to set socket non-blocking: %s",
                            socket_strerror(r));
                goto err;
        }

	rd_rkb_dbg(rkb, BROKER, "CONNECT", "Connecting to %s (%s) "
		   "with socket %i",
		   rd_sockaddr2str(sinx, RD_SOCKADDR2STR_F_FAMILY |
				   RD_SOCKADDR2STR_F_PORT),
		   rd_kafka_secproto_names[rkb->rkb_proto], s);

	/* Connect to broker */
        if (rkb->rkb_rk->rk_conf.connect_cb) {
                rd_kafka_broker_lock(rkb); /* for rkb_nodename */
                r = rkb->rkb_rk->rk_conf.connect_cb(
                        s, (struct sockaddr *)sinx, RD_SOCKADDR_INX_LEN(sinx),
                        rkb->rkb_nodename, rkb->rkb_rk->rk_conf.opaque);
                rd_kafka_broker_unlock(rkb);
        } else {
                if (connect(s, (struct sockaddr *)sinx,
                            RD_SOCKADDR_INX_LEN(sinx)) == SOCKET_ERROR &&
                    (socket_errno != EINPROGRESS
#ifdef _MSC_VER
                     && socket_errno != WSAEWOULDBLOCK
#endif
                            ))
                        r = socket_errno;
                else
                        r = 0;
        }

        if (r != 0) {
		rd_rkb_dbg(rkb, BROKER, "CONNECT",
			   "couldn't connect to %s: %s (%i)",
			   rd_sockaddr2str(sinx,
					   RD_SOCKADDR2STR_F_PORT |
					   RD_SOCKADDR2STR_F_FAMILY),
			   socket_strerror(r), r);
		rd_snprintf(errstr, errstr_size,
			    "Failed to connect to broker at %s: %s",
			    rd_sockaddr2str(sinx, RD_SOCKADDR2STR_F_NICE),
			    socket_strerror(r));
		goto err;
	}

	/* Create transport handle */
	rktrans = rd_calloc(1, sizeof(*rktrans));
	rktrans->rktrans_rkb = rkb;
	rktrans->rktrans_s = s;
	rktrans->rktrans_pfd[rktrans->rktrans_pfd_cnt++].fd = s;
        if (rkb->rkb_wakeup_fd[0] != -1) {
                rktrans->rktrans_pfd[rktrans->rktrans_pfd_cnt].events = POLLIN;
                rktrans->rktrans_pfd[rktrans->rktrans_pfd_cnt++].fd = rkb->rkb_wakeup_fd[0];
        }


	/* Poll writability to trigger on connection success/failure. */
	rd_kafka_transport_poll_set(rktrans, POLLOUT);

	return rktrans;

 err:
	if (s != -1)
                rd_kafka_transport_close0(rkb->rkb_rk, s);

	return NULL;
}



void rd_kafka_transport_poll_set(rd_kafka_transport_t *rktrans, int event) {
	rktrans->rktrans_pfd[0].events |= event;
}

void rd_kafka_transport_poll_clear(rd_kafka_transport_t *rktrans, int event) {
	rktrans->rktrans_pfd[0].events &= ~event;
}

/**
 * @brief Poll transport fds.
 *
 * @returns 1 if an event was raised, else 0, or -1 on error.
 */
int rd_kafka_transport_poll(rd_kafka_transport_t *rktrans, int tmout) {
        int r;
#ifndef _MSC_VER
	r = poll(rktrans->rktrans_pfd, rktrans->rktrans_pfd_cnt, tmout);
	if (r <= 0)
		return r;
#else
	r = WSAPoll(rktrans->rktrans_pfd, rktrans->rktrans_pfd_cnt, tmout);
	if (r == 0) {
		/* Workaround for broken WSAPoll() while connecting:
		 * failed connection attempts are not indicated at all by WSAPoll()
		 * so we need to check the socket error when Poll returns 0.
		 * Issue #525 */
		r = ECONNRESET;
		if (unlikely(rktrans->rktrans_rkb->rkb_state ==
			     RD_KAFKA_BROKER_STATE_CONNECT &&
			     (rd_kafka_transport_get_socket_error(rktrans,
								  &r) == -1 ||
			      r != 0))) {
			char errstr[512];
			errno = r;
			rd_snprintf(errstr, sizeof(errstr),
				    "Connect to %s failed: %s",
				    rd_sockaddr2str(rktrans->rktrans_rkb->
						    rkb_addr_last,
						    RD_SOCKADDR2STR_F_PORT |
                                                    RD_SOCKADDR2STR_F_FAMILY),
                                    socket_strerror(r));
			rd_kafka_transport_connect_done(rktrans, errstr);
			return -1;
		} else
			return 0;
	} else if (r == SOCKET_ERROR)
		return -1;
#endif
        rd_atomic64_add(&rktrans->rktrans_rkb->rkb_c.wakeups, 1);

        if (rktrans->rktrans_pfd[1].revents & POLLIN) {
                /* Read wake-up fd data and throw away, just used for wake-ups*/
                char buf[1024];
                while (rd_read((int)rktrans->rktrans_pfd[1].fd,
                               buf, sizeof(buf)) > 0)
                        ; /* Read all buffered signalling bytes */
        }

        return 1;
}





#if 0
/**
 * Global cleanup.
 * This is dangerous and SHOULD NOT be called since it will rip
 * the rug from under the application if it uses any of this functionality
 * in its own code. This means we might leak some memory on exit.
 */
void rd_kafka_transport_term (void) {
#ifdef _MSC_VER
	(void)WSACleanup(); /* FIXME: dangerous */
#endif
}
#endif

void rd_kafka_transport_init (void) {
#ifdef _MSC_VER
	WSADATA d;
	(void)WSAStartup(MAKEWORD(2, 2), &d);
#endif
}
