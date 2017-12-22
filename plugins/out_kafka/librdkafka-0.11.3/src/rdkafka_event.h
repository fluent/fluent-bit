/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2016 Magnus Edenhill
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


/**
 * @brief Converts op type to event type.
 * @returns the event type, or 0 if the op cannot be mapped to an event.
 */
static RD_UNUSED RD_INLINE
rd_kafka_event_type_t rd_kafka_op2event (rd_kafka_op_type_t optype) {
	static const rd_kafka_event_type_t map[RD_KAFKA_OP__END] = {
		[RD_KAFKA_OP_DR] = RD_KAFKA_EVENT_DR,
		[RD_KAFKA_OP_FETCH] = RD_KAFKA_EVENT_FETCH,
		[RD_KAFKA_OP_ERR] = RD_KAFKA_EVENT_ERROR,
		[RD_KAFKA_OP_CONSUMER_ERR] = RD_KAFKA_EVENT_ERROR,
		[RD_KAFKA_OP_REBALANCE] = RD_KAFKA_EVENT_REBALANCE,
		[RD_KAFKA_OP_OFFSET_COMMIT] = RD_KAFKA_EVENT_OFFSET_COMMIT,
                [RD_KAFKA_OP_LOG] = RD_KAFKA_EVENT_LOG,
		[RD_KAFKA_OP_STATS] = RD_KAFKA_EVENT_STATS
	};

	return map[(int)optype & ~RD_KAFKA_OP_FLAGMASK];
}


/**
 * @brief Attempt to set up an event based on rko.
 * @returns 1 if op is event:able and set up, else 0.
 */
static RD_UNUSED RD_INLINE
int rd_kafka_event_setup (rd_kafka_t *rk, rd_kafka_op_t *rko) {
	rko->rko_evtype = rd_kafka_op2event(rko->rko_type);
	switch (rko->rko_evtype)
	{
	case RD_KAFKA_EVENT_NONE:
		return 0;

	case RD_KAFKA_EVENT_DR:
		rko->rko_rk = rk;
		rd_dassert(!rko->rko_u.dr.do_purge2);
		rd_kafka_msgq_init(&rko->rko_u.dr.msgq2);
		rko->rko_u.dr.do_purge2 = 1;
		return 1;

	case RD_KAFKA_EVENT_REBALANCE:
	case RD_KAFKA_EVENT_ERROR:
        case RD_KAFKA_EVENT_LOG:
        case RD_KAFKA_EVENT_OFFSET_COMMIT:
        case RD_KAFKA_EVENT_STATS:
		return 1;

	default:
		return 0;
		
	}
}
