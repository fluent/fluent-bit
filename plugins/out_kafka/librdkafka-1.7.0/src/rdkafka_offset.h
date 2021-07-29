/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012,2013 Magnus Edenhill
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

#ifndef _RDKAFKA_OFFSET_H_
#define _RDKAFKA_OFFSET_H_

#include "rdkafka_partition.h"


const char *rd_kafka_offset2str (int64_t offset);


/**
 * Stores the offset for the toppar 'rktp'.
 * The actual commit of the offset to backing store is usually
 * performed at a later time (time or threshold based).
 *
 * See head of rdkafka_offset.c for more information.
 */
static RD_INLINE RD_UNUSED
void rd_kafka_offset_store0 (rd_kafka_toppar_t *rktp, int64_t offset,
			     int lock) {
	if (lock)
		rd_kafka_toppar_lock(rktp);
	rktp->rktp_stored_offset = offset;
	if (lock)
		rd_kafka_toppar_unlock(rktp);
}

rd_kafka_resp_err_t rd_kafka_offset_store (rd_kafka_topic_t *rkt,
					   int32_t partition, int64_t offset);

rd_kafka_resp_err_t rd_kafka_offset_sync (rd_kafka_toppar_t *rktp);

void rd_kafka_offset_store_term (rd_kafka_toppar_t *rktp,
                                 rd_kafka_resp_err_t err);
rd_kafka_resp_err_t rd_kafka_offset_store_stop (rd_kafka_toppar_t *rktp);
void rd_kafka_offset_store_init (rd_kafka_toppar_t *rktp);

void rd_kafka_offset_reset (rd_kafka_toppar_t *rktp, int64_t err_offset,
			    rd_kafka_resp_err_t err, const char *reason);

void rd_kafka_offset_query_tmr_cb (rd_kafka_timers_t *rkts, void *arg);

#endif /* _RDKAFKA_OFFSET_H_ */
