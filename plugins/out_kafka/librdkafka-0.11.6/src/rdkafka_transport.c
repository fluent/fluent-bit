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

#if WITH_VALGRIND
/* OpenSSL relies on uninitialized memory, which Valgrind will whine about.
 * We use in-code Valgrind macros to suppress those warnings. */
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_DEFINED(A,B)
#endif


#ifdef _MSC_VER
#define socket_errno WSAGetLastError()
#else
#include <sys/socket.h>
#include <netinet/tcp.h>
#define socket_errno errno
#define SOCKET_ERROR -1
#endif

/* AIX doesn't have MSG_DONTWAIT */
#ifndef MSG_DONTWAIT
#  define MSG_DONTWAIT MSG_NONBLOCK
#endif


#if WITH_SSL
static mtx_t *rd_kafka_ssl_locks;
static int    rd_kafka_ssl_locks_cnt;
#endif



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
	if (rktrans->rktrans_ssl) {
		SSL_shutdown(rktrans->rktrans_ssl);
		SSL_free(rktrans->rktrans_ssl);
	}
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
ssize_t rd_kafka_transport_socket_sendmsg (rd_kafka_transport_t *rktrans,
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

#ifdef sun
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

#ifdef sun
        /* SunOS doesn't seem to set errno when recvmsg() fails
         * due to no data and MSG_DONTWAIT is set. */
        socket_errno = EAGAIN;
#endif
        r = recvmsg(rktrans->rktrans_s, &msg, MSG_DONTWAIT);
        if (unlikely(r <= 0)) {
                if (r == -1 && socket_errno == EAGAIN)
                        return 0;
                else if (r == 0) {
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
#ifdef _MSC_VER
                        if (WSAGetLastError() == WSAEWOULDBLOCK)
                                return sum;
                        rd_snprintf(errstr, errstr_size, "%s",
                                    socket_strerror(WSAGetLastError()));
#else
                        if (socket_errno == EAGAIN)
                                return sum;
                        else {
                                int errno_save = errno;
                                rd_snprintf(errstr, errstr_size, "%s",
                                            rd_strerror(errno));
                                errno = errno_save;
                                return -1;
                        }
#endif
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

	rd_kafka_broker_connect_done(rkb, errstr);
}



#if WITH_SSL


/**
 * @brief Clear OpenSSL error queue to get a proper error reporting in case
 *        the next SSL_*() operation fails.
 */
static RD_INLINE void
rd_kafka_transport_ssl_clear_error (rd_kafka_transport_t *rktrans) {
        ERR_clear_error();
#ifdef _MSC_VER
        WSASetLastError(0);
#else
        rd_set_errno(0);
#endif
}


/**
 * Serves the entire OpenSSL error queue and logs each error.
 * The last error is not logged but returned in 'errstr'.
 *
 * If 'rkb' is non-NULL broker-specific logging will be used,
 * else it will fall back on global 'rk' debugging.
 */
static char *rd_kafka_ssl_error (rd_kafka_t *rk, rd_kafka_broker_t *rkb,
				 char *errstr, size_t errstr_size) {
    unsigned long l;
    const char *file, *data;
    int line, flags;
    int cnt = 0;

    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
	char buf[256];

	if (cnt++ > 0) {
		/* Log last message */
		if (rkb)
			rd_rkb_log(rkb, LOG_ERR, "SSL", "%s", errstr);
		else
			rd_kafka_log(rk, LOG_ERR, "SSL", "%s", errstr);
	}
	
	ERR_error_string_n(l, buf, sizeof(buf));

	rd_snprintf(errstr, errstr_size, "%s:%d: %s: %s",
		    file, line, buf, (flags & ERR_TXT_STRING) ? data : "");

    }

    if (cnt == 0)
    	    rd_snprintf(errstr, errstr_size, "No error");
    
    return errstr;
}


static RD_UNUSED void
rd_kafka_transport_ssl_lock_cb (int mode, int i, const char *file, int line) {
	if (mode & CRYPTO_LOCK)
		mtx_lock(&rd_kafka_ssl_locks[i]);
	else
		mtx_unlock(&rd_kafka_ssl_locks[i]);
}

static RD_UNUSED unsigned long rd_kafka_transport_ssl_threadid_cb (void) {
#ifdef _MSC_VER
        /* Windows makes a distinction between thread handle
         * and thread id, which means we can't use the
         * thrd_current() API that returns the handle. */
        return (unsigned long)GetCurrentThreadId();
#else
        return (unsigned long)(intptr_t)thrd_current();
#endif
}


/**
 * Global OpenSSL cleanup.
 */
void rd_kafka_transport_ssl_term (void) {
	int i;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
        CRYPTO_cleanup_all_ex_data();

	for (i = 0 ; i < rd_kafka_ssl_locks_cnt ; i++)
		mtx_destroy(&rd_kafka_ssl_locks[i]);

	rd_free(rd_kafka_ssl_locks);

}


/**
 * Global OpenSSL init.
 */
void rd_kafka_transport_ssl_init (void) {
	int i;
	
	rd_kafka_ssl_locks_cnt = CRYPTO_num_locks();
	rd_kafka_ssl_locks = rd_malloc(rd_kafka_ssl_locks_cnt *
				       sizeof(*rd_kafka_ssl_locks));
	for (i = 0 ; i < rd_kafka_ssl_locks_cnt ; i++)
		mtx_init(&rd_kafka_ssl_locks[i], mtx_plain);

	CRYPTO_set_id_callback(rd_kafka_transport_ssl_threadid_cb);
	CRYPTO_set_locking_callback(rd_kafka_transport_ssl_lock_cb);
	
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
}


/**
 * Set transport IO event polling based on SSL error.
 *
 * Returns -1 on permanent errors.
 *
 * Locality: broker thread
 */
static RD_INLINE int
rd_kafka_transport_ssl_io_update (rd_kafka_transport_t *rktrans, int ret,
				  char *errstr, size_t errstr_size) {
	int serr = SSL_get_error(rktrans->rktrans_ssl, ret);
        int serr2;

	switch (serr)
	{
	case SSL_ERROR_WANT_READ:
		rd_kafka_transport_poll_set(rktrans, POLLIN);
		break;

	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
		rd_kafka_transport_poll_set(rktrans, POLLOUT);
		break;

        case SSL_ERROR_SYSCALL:
                serr2 = ERR_peek_error();
                if (!serr2 && !socket_errno)
                        rd_snprintf(errstr, errstr_size, "Disconnected");
                else if (serr2)
                        rd_kafka_ssl_error(NULL, rktrans->rktrans_rkb,
                                           errstr, errstr_size);
                else
                        rd_snprintf(errstr, errstr_size,
                                    "SSL transport error: %s",
                                    rd_strerror(socket_errno));
                return -1;

        case SSL_ERROR_ZERO_RETURN:
                rd_snprintf(errstr, errstr_size, "Disconnected");
                return -1;

	default:
		rd_kafka_ssl_error(NULL, rktrans->rktrans_rkb,
				   errstr, errstr_size);
		return -1;
	}

	return 0;
}

static ssize_t
rd_kafka_transport_ssl_send (rd_kafka_transport_t *rktrans,
                             rd_slice_t *slice,
                             char *errstr, size_t errstr_size) {
	ssize_t sum = 0;
        const void *p;
        size_t rlen;

        rd_kafka_transport_ssl_clear_error(rktrans);

        while ((rlen = rd_slice_peeker(slice, &p))) {
                int r;

                r = SSL_write(rktrans->rktrans_ssl, p, (int)rlen);

		if (unlikely(r <= 0)) {
			if (rd_kafka_transport_ssl_io_update(rktrans, r,
							     errstr,
							     errstr_size) == -1)
				return -1;
			else
				return sum;
		}

                /* Update buffer read position */
                rd_slice_read(slice, NULL, (size_t)r);

		sum += r;
                 /* FIXME: remove this and try again immediately and let
                  *        the next SSL_write() call fail instead? */
                if ((size_t)r < rlen)
                        break;

	}
	return sum;
}

static ssize_t
rd_kafka_transport_ssl_recv (rd_kafka_transport_t *rktrans,
                             rd_buf_t *rbuf, char *errstr, size_t errstr_size) {
	ssize_t sum = 0;
        void *p;
        size_t len;

        while ((len = rd_buf_get_writable(rbuf, &p))) {
		int r;

                rd_kafka_transport_ssl_clear_error(rktrans);

                r = SSL_read(rktrans->rktrans_ssl, p, (int)len);

		if (unlikely(r <= 0)) {
			if (rd_kafka_transport_ssl_io_update(rktrans, r,
							     errstr,
							     errstr_size) == -1)
				return -1;
			else
				return sum;
		}

                VALGRIND_MAKE_MEM_DEFINED(p, r);

                /* Update buffer write position */
                rd_buf_write(rbuf, NULL, (size_t)r);

		sum += r;

                 /* FIXME: remove this and try again immediately and let
                  *        the next SSL_read() call fail instead? */
                if ((size_t)r < len)
                        break;

	}
	return sum;

}


/**
 * OpenSSL password query callback
 *
 * Locality: application thread
 */
static int rd_kafka_transport_ssl_passwd_cb (char *buf, int size, int rwflag,
					     void *userdata) {
	rd_kafka_t *rk = userdata;
	int pwlen;

	rd_kafka_dbg(rk, SECURITY, "SSLPASSWD",
		     "Private key file \"%s\" requires password",
		     rk->rk_conf.ssl.key_location);

	if (!rk->rk_conf.ssl.key_password) {
		rd_kafka_log(rk, LOG_WARNING, "SSLPASSWD",
			     "Private key file \"%s\" requires password but "
			     "no password configured (ssl.key.password)",
			     rk->rk_conf.ssl.key_location);
		return -1;
	}


	pwlen = (int) strlen(rk->rk_conf.ssl.key_password);
	memcpy(buf, rk->rk_conf.ssl.key_password, RD_MIN(pwlen, size));

	return pwlen;
}

/**
 * Set up SSL for a newly connected connection
 *
 * Returns -1 on failure, else 0.
 */
static int rd_kafka_transport_ssl_connect (rd_kafka_broker_t *rkb,
					   rd_kafka_transport_t *rktrans,
					   char *errstr, size_t errstr_size) {
	int r;
	char name[RD_KAFKA_NODENAME_SIZE];
	char *t;

	rktrans->rktrans_ssl = SSL_new(rkb->rkb_rk->rk_conf.ssl.ctx);
	if (!rktrans->rktrans_ssl)
		goto fail;

	if (!SSL_set_fd(rktrans->rktrans_ssl, rktrans->rktrans_s))
		goto fail;

#if (OPENSSL_VERSION_NUMBER >= 0x0090806fL) && !defined(OPENSSL_NO_TLSEXT)
	/* If non-numerical hostname, send it for SNI */
	rd_snprintf(name, sizeof(name), "%s", rkb->rkb_nodename);
	if ((t = strrchr(name, ':')))
		*t = '\0';
	if (!(/*ipv6*/(strchr(name, ':') &&
		       strspn(name, "0123456789abcdefABCDEF:.[]%") == strlen(name)) ||
	      /*ipv4*/strspn(name, "0123456789.") == strlen(name)) &&
	    !SSL_set_tlsext_host_name(rktrans->rktrans_ssl, name))
		goto fail;
#endif

        rd_kafka_transport_ssl_clear_error(rktrans);

	r = SSL_connect(rktrans->rktrans_ssl);
	if (r == 1) {
		/* Connected, highly unlikely since this is a
		 * non-blocking operation. */
		rd_kafka_transport_connect_done(rktrans, NULL);
		return 0;
	}

		
	if (rd_kafka_transport_ssl_io_update(rktrans, r,
					     errstr, errstr_size) == -1)
		return -1;
	
	return 0;

 fail:
	rd_kafka_ssl_error(NULL, rkb, errstr, errstr_size);
	return -1;
}


static RD_UNUSED int
rd_kafka_transport_ssl_io_event (rd_kafka_transport_t *rktrans, int events) {
	int r;
	char errstr[512];

	if (events & POLLOUT) {
                rd_kafka_transport_ssl_clear_error(rktrans);

		r = SSL_write(rktrans->rktrans_ssl, NULL, 0);
		if (rd_kafka_transport_ssl_io_update(rktrans, r,
						     errstr,
						     sizeof(errstr)) == -1)
			goto fail;
	}

	return 0;

 fail:
	/* Permanent error */
	rd_kafka_broker_fail(rktrans->rktrans_rkb, LOG_ERR,
                             RD_KAFKA_RESP_ERR__TRANSPORT,
			     "%s", errstr);
	return -1;
}


/**
 * Verify SSL handshake was valid.
 */
static int rd_kafka_transport_ssl_verify (rd_kafka_transport_t *rktrans) {
	long int rl;
	X509 *cert;

	cert = SSL_get_peer_certificate(rktrans->rktrans_ssl);
	X509_free(cert);
	if (!cert) {
		rd_kafka_broker_fail(rktrans->rktrans_rkb, LOG_ERR,
				     RD_KAFKA_RESP_ERR__SSL,
				     "Broker did not provide a certificate");
		return -1;
	}

	if ((rl = SSL_get_verify_result(rktrans->rktrans_ssl)) != X509_V_OK) {
		rd_kafka_broker_fail(rktrans->rktrans_rkb, LOG_ERR,
				     RD_KAFKA_RESP_ERR__SSL,
				     "Failed to verify broker certificate: %s",
				     X509_verify_cert_error_string(rl));
		return -1;
	}

	rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "SSLVERIFY",
		   "Broker SSL certificate verified");
	return 0;
}

/**
 * SSL handshake handling.
 * Call repeatedly (based on IO events) until handshake is done.
 *
 * Returns -1 on error, 0 if handshake is still in progress, or 1 on completion.
 */
static int rd_kafka_transport_ssl_handshake (rd_kafka_transport_t *rktrans) {
	rd_kafka_broker_t *rkb = rktrans->rktrans_rkb;
	char errstr[512];
	int r;

	r = SSL_do_handshake(rktrans->rktrans_ssl);
	if (r == 1) {
		/* SSL handshake done. Verify. */
		if (rd_kafka_transport_ssl_verify(rktrans) == -1)
			return -1;

		rd_kafka_transport_connect_done(rktrans, NULL);
		return 1;

	} else if (rd_kafka_transport_ssl_io_update(rktrans, r,
						    errstr,
						    sizeof(errstr)) == -1) {
		rd_kafka_broker_fail(rkb, LOG_ERR, RD_KAFKA_RESP_ERR__SSL,
				     "SSL handshake failed: %s%s", errstr,
				     strstr(errstr, "unexpected message") ?
				     ": client authentication might be "
				     "required (see broker log)" : "");
		return -1;
	}

	return 0;
}


/**
 * Once per rd_kafka_t handle cleanup of OpenSSL
 *
 * Locality: any thread
 *
 * NOTE: rd_kafka_wrlock() MUST be held
 */
void rd_kafka_transport_ssl_ctx_term (rd_kafka_t *rk) {
	SSL_CTX_free(rk->rk_conf.ssl.ctx);
	rk->rk_conf.ssl.ctx = NULL;
}

/**
 * Once per rd_kafka_t handle initialization of OpenSSL
 *
 * Locality: application thread
 *
 * NOTE: rd_kafka_wrlock() MUST be held
 */
int rd_kafka_transport_ssl_ctx_init (rd_kafka_t *rk,
				     char *errstr, size_t errstr_size) {
	int r;
	SSL_CTX *ctx;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        rd_kafka_dbg(rk, SECURITY, "OPENSSL", "Using OpenSSL version %s "
                     "(0x%lx, librdkafka built with 0x%lx)",
                     OpenSSL_version(OPENSSL_VERSION),
                     OpenSSL_version_num(),
                     OPENSSL_VERSION_NUMBER);
#else
        rd_kafka_dbg(rk, SECURITY, "OPENSSL", "librdkafka built with OpenSSL "
                     "version 0x%lx", OPENSSL_VERSION_NUMBER);
#endif

        if (errstr_size > 0)
                errstr[0] = '\0';

	ctx = SSL_CTX_new(SSLv23_client_method());
        if (!ctx) {
                rd_snprintf(errstr, errstr_size,
                            "SSLv23_client_method() failed: ");
                goto fail;
        }

#ifdef SSL_OP_NO_SSLv3
	/* Disable SSLv3 (unsafe) */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#endif

	/* Key file password callback */
	SSL_CTX_set_default_passwd_cb(ctx, rd_kafka_transport_ssl_passwd_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, rk);

	/* Ciphers */
	if (rk->rk_conf.ssl.cipher_suites) {
		rd_kafka_dbg(rk, SECURITY, "SSL",
			     "Setting cipher list: %s",
			     rk->rk_conf.ssl.cipher_suites);
		if (!SSL_CTX_set_cipher_list(ctx,
					     rk->rk_conf.ssl.cipher_suites)) {
                        /* Set a string that will prefix the
                         * the OpenSSL error message (which is lousy)
                         * to make it more meaningful. */
                        rd_snprintf(errstr, errstr_size,
                                    "ssl.cipher.suites failed: ");
                        goto fail;
		}
	}

#if OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined(LIBRESSL_VERSION_NUMBER)
	/* Curves */
	if (rk->rk_conf.ssl.curves_list) {
		rd_kafka_dbg(rk, SECURITY, "SSL",
			     "Setting curves list: %s",
			     rk->rk_conf.ssl.curves_list);
		if (!SSL_CTX_set1_curves_list(ctx,
					      rk->rk_conf.ssl.curves_list)) {
                        rd_snprintf(errstr, errstr_size,
                                    "ssl.curves.list failed: ");
                        goto fail;
		}
	}

	/* Certificate signature algorithms */
	if (rk->rk_conf.ssl.sigalgs_list) {
		rd_kafka_dbg(rk, SECURITY, "SSL",
			     "Setting signature algorithms list: %s",
			     rk->rk_conf.ssl.sigalgs_list);
		if (!SSL_CTX_set1_sigalgs_list(ctx,
					       rk->rk_conf.ssl.sigalgs_list)) {
                        rd_snprintf(errstr, errstr_size,
                                    "ssl.sigalgs.list failed: ");
                        goto fail;
		}
	}
#endif

	if (rk->rk_conf.ssl.ca_location) {
		/* CA certificate location, either file or directory. */
		int is_dir = rd_kafka_path_is_dir(rk->rk_conf.ssl.ca_location);

		rd_kafka_dbg(rk, SECURITY, "SSL",
			     "Loading CA certificate(s) from %s %s",
			     is_dir ? "directory":"file",
			     rk->rk_conf.ssl.ca_location);
		
		r = SSL_CTX_load_verify_locations(ctx,
						  !is_dir ?
						  rk->rk_conf.ssl.
						  ca_location : NULL,
						  is_dir ?
						  rk->rk_conf.ssl.
						  ca_location : NULL);

                if (r != 1) {
                        rd_snprintf(errstr, errstr_size,
                                    "ssl.ca.location failed: ");
                        goto fail;
                }
        } else {
                /* Use default CA certificate paths: ignore failures. */
                r = SSL_CTX_set_default_verify_paths(ctx);
                if (r != 1)
                        rd_kafka_dbg(rk, SECURITY, "SSL",
                                     "SSL_CTX_set_default_verify_paths() "
                                     "failed: ignoring");
        }

	if (rk->rk_conf.ssl.crl_location) {
		rd_kafka_dbg(rk, SECURITY, "SSL",
			     "Loading CRL from file %s",
			     rk->rk_conf.ssl.crl_location);

		r = SSL_CTX_load_verify_locations(ctx,
						  rk->rk_conf.ssl.crl_location,
						  NULL);

                if (r != 1) {
                        rd_snprintf(errstr, errstr_size,
                                    "ssl.crl.location failed: ");
                        goto fail;
                }


		rd_kafka_dbg(rk, SECURITY, "SSL",
			     "Enabling CRL checks");

		X509_STORE_set_flags(SSL_CTX_get_cert_store(ctx),
				     X509_V_FLAG_CRL_CHECK);
	}

	if (rk->rk_conf.ssl.cert_location) {
		rd_kafka_dbg(rk, SECURITY, "SSL",
			     "Loading certificate from file %s",
			     rk->rk_conf.ssl.cert_location);

		r = SSL_CTX_use_certificate_chain_file(ctx,
						       rk->rk_conf.ssl.cert_location);

                if (r != 1) {
                        rd_snprintf(errstr, errstr_size,
                                    "ssl.certificate.location failed: ");
                        goto fail;
                }
	}

	if (rk->rk_conf.ssl.key_location) {
		rd_kafka_dbg(rk, SECURITY, "SSL",
			     "Loading private key file from %s",
			     rk->rk_conf.ssl.key_location);

		r = SSL_CTX_use_PrivateKey_file(ctx,
						rk->rk_conf.ssl.key_location,
						SSL_FILETYPE_PEM);
                if (r != 1) {
                        rd_snprintf(errstr, errstr_size,
                                    "ssl.key.location failed: ");
                        goto fail;
                }
	}

	if (rk->rk_conf.ssl.keystore_location) {
		FILE *fp;
		EVP_PKEY *pkey;
		X509 *cert;
		STACK_OF(X509) *ca = NULL;
		PKCS12 *p12;

		rd_kafka_dbg(rk, SECURITY, "SSL",
			     "Loading client's keystore file from %s",
			     rk->rk_conf.ssl.keystore_location);

		if (!(fp = fopen(rk->rk_conf.ssl.keystore_location, "rb"))) {
			rd_snprintf(errstr, errstr_size,
				    "Failed to open ssl.keystore.location: %s: %s", 
				    rk->rk_conf.ssl.keystore_location, 
				    rd_strerror(errno));
			goto fail;
		}

		p12 = d2i_PKCS12_fp(fp, NULL);
		fclose(fp);
		if (!p12) {
			rd_snprintf(errstr, errstr_size,
				    "Error reading PKCS#12 file: ");
			goto fail;
		}

		pkey = EVP_PKEY_new();
		cert = X509_new();
		if (!PKCS12_parse(p12, rk->rk_conf.ssl.keystore_password, &pkey, &cert, &ca)) {
			EVP_PKEY_free(pkey);
			X509_free(cert);
			PKCS12_free(p12);
			if (ca != NULL)
				sk_X509_pop_free(ca, X509_free);
			rd_snprintf(errstr, errstr_size,
				    "Failed to parse PKCS#12 file: %s: ",
				    rk->rk_conf.ssl.keystore_location);
			goto fail;
		}

		if (ca != NULL)
			sk_X509_pop_free(ca, X509_free);

		PKCS12_free(p12);

		r = SSL_CTX_use_certificate(ctx, cert);
		X509_free(cert);
		if (r != 1) {
			EVP_PKEY_free(pkey);
			rd_snprintf(errstr, errstr_size,
				    "Failed to use ssl.keystore.location certificate: ");
			goto fail;
		}

		r = SSL_CTX_use_PrivateKey(ctx, pkey);
		EVP_PKEY_free(pkey);
		if (r != 1) {
			rd_snprintf(errstr, errstr_size,
				    "Failed to use ssl.keystore.location private key: ");
			goto fail;
		}
	}

	SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

	rk->rk_conf.ssl.ctx = ctx;
	return 0;

 fail:
        r = (int)strlen(errstr);
        rd_kafka_ssl_error(rk, NULL, errstr+r,
                           (int)errstr_size > r ? (int)errstr_size - r : 0);
	SSL_CTX_free(ctx);

	return -1;
}


#endif /* WITH_SSL */


ssize_t
rd_kafka_transport_send (rd_kafka_transport_t *rktrans,
                         rd_slice_t *slice, char *errstr, size_t errstr_size) {

#if WITH_SSL
        if (rktrans->rktrans_ssl)
                return rd_kafka_transport_ssl_send(rktrans, slice,
                                                   errstr, errstr_size);
        else
#endif
                return rd_kafka_transport_socket_send(rktrans, slice,
                                                      errstr, errstr_size);
}


ssize_t
rd_kafka_transport_recv (rd_kafka_transport_t *rktrans, rd_buf_t *rbuf,
                         char *errstr, size_t errstr_size) {
#if WITH_SSL
	if (rktrans->rktrans_ssl)
                return rd_kafka_transport_ssl_recv(rktrans, rbuf,
                                                   errstr, errstr_size);
	else
#endif
                return rd_kafka_transport_socket_recv(rktrans, rbuf,
                                                      errstr, errstr_size);
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

	case RD_KAFKA_BROKER_STATE_AUTH:
		/* SASL handshake */
		if (rd_kafka_sasl_io_event(rktrans, events,
					   errstr, sizeof(errstr)) == -1) {
			errno = EINVAL;
			rd_kafka_broker_fail(rkb, LOG_ERR,
					     RD_KAFKA_RESP_ERR__AUTHENTICATION,
					     "SASL authentication failure: %s",
					     errstr);
			return;
		}

		if (events & POLLHUP) {
			errno = EINVAL;
			rd_kafka_broker_fail(rkb, LOG_ERR,
					     RD_KAFKA_RESP_ERR__AUTHENTICATION,
					     "Disconnected");

			return;
		}

		break;

	case RD_KAFKA_BROKER_STATE_APIVERSION_QUERY:
	case RD_KAFKA_BROKER_STATE_AUTH_HANDSHAKE:
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
		rd_kafka_assert(rkb->rkb_rk, !*"bad state");
	}
}


/**
 * Poll and serve IOs
 *
 * Locality: broker thread 
 */
void rd_kafka_transport_io_serve (rd_kafka_transport_t *rktrans,
                                  int timeout_ms) {
	rd_kafka_broker_t *rkb = rktrans->rktrans_rkb;
	int events;

	if (rd_kafka_bufq_cnt(&rkb->rkb_waitresps) < rkb->rkb_max_inflight &&
	    rd_kafka_bufq_cnt(&rkb->rkb_outbufs) > 0)
		rd_kafka_transport_poll_set(rkb->rkb_transport, POLLOUT);

	if ((events = rd_kafka_transport_poll(rktrans, timeout_ms)) <= 0)
                return;

        rd_kafka_transport_poll_clear(rktrans, POLLOUT);

	rd_kafka_transport_io_event(rktrans, events);
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
                r = rkb->rkb_rk->rk_conf.connect_cb(
                        s, (struct sockaddr *)sinx, RD_SOCKADDR_INX_LEN(sinx),
                        rkb->rkb_name, rkb->rkb_rk->rk_conf.opaque);
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
                char buf[512];
                if (rd_read((int)rktrans->rktrans_pfd[1].fd,
                            buf, sizeof(buf)) == -1) {
                        /* Ignore warning */
                }
        }

        return rktrans->rktrans_pfd[0].revents;
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
 
void rd_kafka_transport_init(void) {
#ifdef _MSC_VER
	WSADATA d;
	(void)WSAStartup(MAKEWORD(2, 2), &d);
#endif
}
