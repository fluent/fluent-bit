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

#include "rdkafka_int.h"
#include "rdkafka_event.h"
#include "rd.h"

rd_kafka_event_type_t rd_kafka_event_type (const rd_kafka_event_t *rkev) {
	return rkev ? rkev->rko_evtype : RD_KAFKA_EVENT_NONE;
}

const char *rd_kafka_event_name (const rd_kafka_event_t *rkev) {
	switch (rkev ? rkev->rko_evtype : RD_KAFKA_EVENT_NONE)
	{
	case RD_KAFKA_EVENT_NONE:
		return "(NONE)";
	case RD_KAFKA_EVENT_DR:
		return "DeliveryReport";
	case RD_KAFKA_EVENT_FETCH:
		return "Fetch";
	case RD_KAFKA_EVENT_LOG:
		return "Log";
	case RD_KAFKA_EVENT_ERROR:
		return "Error";
	case RD_KAFKA_EVENT_REBALANCE:
		return "Rebalance";
	case RD_KAFKA_EVENT_OFFSET_COMMIT:
		return "OffsetCommit";
	case RD_KAFKA_EVENT_STATS:
		return "Stats";
        case RD_KAFKA_EVENT_CREATETOPICS_RESULT:
                return "CreateTopicsResult";
        case RD_KAFKA_EVENT_DELETETOPICS_RESULT:
                return "DeleteTopicsResult";
        case RD_KAFKA_EVENT_CREATEPARTITIONS_RESULT:
                return "CreatePartitionsResult";
        case RD_KAFKA_EVENT_ALTERCONFIGS_RESULT:
                return "AlterConfigsResult";
        case RD_KAFKA_EVENT_DESCRIBECONFIGS_RESULT:
                return "DescribeConfigsResult";
        case RD_KAFKA_EVENT_OAUTHBEARER_TOKEN_REFRESH:
                return "SaslOAuthBearerTokenRefresh";
	default:
		return "?unknown?";
	}
}




void rd_kafka_event_destroy (rd_kafka_event_t *rkev) {
	if (unlikely(!rkev))
		return;
	rd_kafka_op_destroy(rkev);
}


/**
 * @returns the next message from the event's message queue.
 * @remark messages will be freed automatically when event is destroyed,
 *         application MUST NOT call rd_kafka_message_destroy()
 */
const rd_kafka_message_t *
rd_kafka_event_message_next (rd_kafka_event_t *rkev) {
	rd_kafka_op_t *rko = rkev;
	rd_kafka_msg_t *rkm;
	rd_kafka_msgq_t *rkmq, *rkmq2;
	rd_kafka_message_t *rkmessage;

	switch (rkev->rko_type)
	{
	case RD_KAFKA_OP_DR:
		rkmq = &rko->rko_u.dr.msgq;
		rkmq2 = &rko->rko_u.dr.msgq2;
		break;

	case RD_KAFKA_OP_FETCH:
		/* Just one message */
		if (rko->rko_u.fetch.evidx++ > 0)
			return NULL;

		rkmessage = rd_kafka_message_get(rko);
		if (unlikely(!rkmessage))
			return NULL;

		/* Store offset */
		rd_kafka_op_offset_store(NULL, rko, rkmessage);

		return rkmessage;


	default:
		return NULL;
	}

	if (unlikely(!(rkm = TAILQ_FIRST(&rkmq->rkmq_msgs))))
		return NULL;

	rd_kafka_msgq_deq(rkmq, rkm, 1);

	/* Put rkm on secondary message queue which will be purged later. */
	rd_kafka_msgq_enq(rkmq2, rkm);

	return rd_kafka_message_get_from_rkm(rko, rkm);
}


size_t rd_kafka_event_message_array (rd_kafka_event_t *rkev,
				     const rd_kafka_message_t **rkmessages, size_t size) {
	size_t cnt = 0;
	const rd_kafka_message_t *rkmessage;

	while ((rkmessage = rd_kafka_event_message_next(rkev)))
		rkmessages[cnt++] = rkmessage;

	return cnt;
}


size_t rd_kafka_event_message_count (rd_kafka_event_t *rkev) {
	switch (rkev->rko_evtype)
	{
	case RD_KAFKA_EVENT_DR:
                return (size_t)rkev->rko_u.dr.msgq.rkmq_msg_cnt;
	case RD_KAFKA_EVENT_FETCH:
		return 1;
	default:
		return 0;
	}
}


const char *rd_kafka_event_config_string (rd_kafka_event_t *rkev) {
        switch (rkev->rko_evtype)
        {
#if WITH_SASL_OAUTHBEARER
        case RD_KAFKA_EVENT_OAUTHBEARER_TOKEN_REFRESH:
                return rkev->rko_rk->rk_conf.sasl.oauthbearer_config;
#endif
        default:
                return NULL;
        }
}

rd_kafka_resp_err_t rd_kafka_event_error (rd_kafka_event_t *rkev) {
	return rkev->rko_err;
}

const char *rd_kafka_event_error_string (rd_kafka_event_t *rkev) {
	switch (rkev->rko_type)
	{
	case RD_KAFKA_OP_ERR:
	case RD_KAFKA_OP_CONSUMER_ERR:
		if (rkev->rko_u.err.errstr)
			return rkev->rko_u.err.errstr;
                break;
        case RD_KAFKA_OP_ADMIN_RESULT:
                if (rkev->rko_u.admin_result.errstr)
                        return rkev->rko_u.admin_result.errstr;
                break;
        default:
                break;
        }

        return rd_kafka_err2str(rkev->rko_err);
}

int rd_kafka_event_error_is_fatal (rd_kafka_event_t *rkev) {
        return rkev->rko_u.err.fatal;
}


void *rd_kafka_event_opaque (rd_kafka_event_t *rkev) {
	switch (rkev->rko_type & ~RD_KAFKA_OP_FLAGMASK)
	{
	case RD_KAFKA_OP_OFFSET_COMMIT:
		return rkev->rko_u.offset_commit.opaque;
        case RD_KAFKA_OP_ADMIN_RESULT:
                return rkev->rko_u.admin_result.opaque;
	default:
		return NULL;
	}
}


int rd_kafka_event_log (rd_kafka_event_t *rkev, const char **fac,
			const char **str, int *level) {
	if (unlikely(rkev->rko_evtype != RD_KAFKA_EVENT_LOG))
		return -1;

	if (likely(fac != NULL))
                *fac = rkev->rko_u.log.fac;
	if (likely(str != NULL))
		*str = rkev->rko_u.log.str;
	if (likely(level != NULL))
		*level = rkev->rko_u.log.level;

	return 0;
}

const char *rd_kafka_event_stats (rd_kafka_event_t *rkev) {
	return rkev->rko_u.stats.json;
}

rd_kafka_topic_partition_list_t *
rd_kafka_event_topic_partition_list (rd_kafka_event_t *rkev) {
	switch (rkev->rko_evtype)
	{
	case RD_KAFKA_EVENT_REBALANCE:
		return rkev->rko_u.rebalance.partitions;
	case RD_KAFKA_EVENT_OFFSET_COMMIT:
		return rkev->rko_u.offset_commit.partitions;
	default:
		return NULL;
	}
}


rd_kafka_topic_partition_t *
rd_kafka_event_topic_partition (rd_kafka_event_t *rkev) {
	rd_kafka_topic_partition_t *rktpar;

	if (unlikely(!rkev->rko_rktp))
		return NULL;

	rktpar = rd_kafka_topic_partition_new_from_rktp(
		rd_kafka_toppar_s2i(rkev->rko_rktp));

	switch (rkev->rko_type)
	{
	case RD_KAFKA_OP_ERR:
	case RD_KAFKA_OP_CONSUMER_ERR:
		rktpar->offset = rkev->rko_u.err.offset;
		break;
	default:
		break;
	}

	rktpar->err = rkev->rko_err;

	return rktpar;

}



const rd_kafka_CreateTopics_result_t *
rd_kafka_event_CreateTopics_result (rd_kafka_event_t *rkev) {
        if (!rkev || rkev->rko_evtype != RD_KAFKA_EVENT_CREATETOPICS_RESULT)
                return NULL;
        else
                return (const rd_kafka_CreateTopics_result_t *)rkev;
}


const rd_kafka_DeleteTopics_result_t *
rd_kafka_event_DeleteTopics_result (rd_kafka_event_t *rkev) {
        if (!rkev || rkev->rko_evtype != RD_KAFKA_EVENT_DELETETOPICS_RESULT)
                return NULL;
        else
                return (const rd_kafka_DeleteTopics_result_t *)rkev;
}


const rd_kafka_CreatePartitions_result_t *
rd_kafka_event_CreatePartitions_result (rd_kafka_event_t *rkev) {
        if (!rkev || rkev->rko_evtype != RD_KAFKA_EVENT_CREATEPARTITIONS_RESULT)
                return NULL;
        else
                return (const rd_kafka_CreatePartitions_result_t *)rkev;
}


const rd_kafka_AlterConfigs_result_t *
rd_kafka_event_AlterConfigs_result (rd_kafka_event_t *rkev) {
        if (!rkev || rkev->rko_evtype != RD_KAFKA_EVENT_ALTERCONFIGS_RESULT)
                return NULL;
        else
                return (const rd_kafka_AlterConfigs_result_t *)rkev;
}


const rd_kafka_DescribeConfigs_result_t *
rd_kafka_event_DescribeConfigs_result (rd_kafka_event_t *rkev) {
        if (!rkev || rkev->rko_evtype != RD_KAFKA_EVENT_DESCRIBECONFIGS_RESULT)
                return NULL;
        else
                return (const rd_kafka_DescribeConfigs_result_t *)rkev;
}
