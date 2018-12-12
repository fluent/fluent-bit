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

#ifndef _RDKAFKA_TRANSPORT_H_
#define _RDKAFKA_TRANSPORT_H_

#ifndef _MSC_VER
#include <poll.h>
#endif

#include "rdbuf.h"
#include "rdaddr.h"

typedef struct rd_kafka_transport_s rd_kafka_transport_t;

void rd_kafka_transport_io_serve (rd_kafka_transport_t *rktrans,
                                  int timeout_ms);

ssize_t rd_kafka_transport_send (rd_kafka_transport_t *rktrans,
                                 rd_slice_t *slice,
                                 char *errstr, size_t errstr_size);
ssize_t rd_kafka_transport_recv (rd_kafka_transport_t *rktrans,
                                 rd_buf_t *rbuf,
                                 char *errstr, size_t errstr_size);

void rd_kafka_transport_request_sent (rd_kafka_broker_t *rkb,
                                      rd_kafka_buf_t *rkbuf);

int rd_kafka_transport_framed_recv (rd_kafka_transport_t *rktrans,
                                    rd_kafka_buf_t **rkbufp,
                                    char *errstr, size_t errstr_size);
struct rd_kafka_broker_s;
rd_kafka_transport_t *rd_kafka_transport_connect(struct rd_kafka_broker_s *rkb, const rd_sockaddr_inx_t *sinx,
                                                 char *errstr, size_t errstr_size);
void rd_kafka_transport_connect_done (rd_kafka_transport_t *rktrans,
				      char *errstr);

void rd_kafka_transport_close(rd_kafka_transport_t *rktrans);
void rd_kafka_transport_poll_set(rd_kafka_transport_t *rktrans, int event);
void rd_kafka_transport_poll_clear(rd_kafka_transport_t *rktrans, int event);
int rd_kafka_transport_poll(rd_kafka_transport_t *rktrans, int tmout);

#if WITH_SSL
void rd_kafka_transport_ssl_ctx_term (rd_kafka_t *rk);
int rd_kafka_transport_ssl_ctx_init (rd_kafka_t *rk,
				     char *errstr, size_t errstr_size);

void rd_kafka_transport_ssl_term (void);
void rd_kafka_transport_ssl_init (void);
#endif
void rd_kafka_transport_term (void);
void rd_kafka_transport_init(void);

#endif /* _RDKAFKA_TRANSPORT_H_ */
