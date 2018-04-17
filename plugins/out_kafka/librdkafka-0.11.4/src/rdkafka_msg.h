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

#ifndef _RDKAFKA_MSG_H_
#define _RDKAFKA_MSG_H_

#include "rdsysqueue.h"

#include "rdkafka_proto.h"
#include "rdkafka_header.h"


/**
 * @brief Internal RD_KAFKA_MSG_F_.. flags
 */
#define RD_KAFKA_MSG_F_RKT_RDLOCKED    0x100000 /* rkt is rdlock():ed */


/**
 * @brief Message.MsgAttributes for MsgVersion v0..v1,
 *        also used for MessageSet.Attributes for MsgVersion v2.
 */
#define RD_KAFKA_MSG_ATTR_GZIP             (1 << 0)
#define RD_KAFKA_MSG_ATTR_SNAPPY           (1 << 1)
#define RD_KAFKA_MSG_ATTR_LZ4              (3)
#define RD_KAFKA_MSG_ATTR_COMPRESSION_MASK 0x3
#define RD_KAFKA_MSG_ATTR_CREATE_TIME      (0 << 3)
#define RD_KAFKA_MSG_ATTR_LOG_APPEND_TIME  (1 << 3)


/**
 * @brief MessageSet.Attributes for MsgVersion v2
 *
 * Attributes:
 *  -------------------------------------------------------------------------------------------------
 *  | Unused (6-15) | Control (5) | Transactional (4) | Timestamp Type (3) | Compression Type (0-2) |
 *  -------------------------------------------------------------------------------------------------
 */
/* Compression types same as MsgVersion 0 above */
/* Timestamp type same as MsgVersion 0 above */
#define RD_KAFKA_MSGSET_V2_ATTR_TRANSACTIONAL (1 << 4)
#define RD_KAFKA_MSGSET_V2_ATTR_CONTROL       (1 << 5)


typedef struct rd_kafka_msg_s {
	rd_kafka_message_t rkm_rkmessage;  /* MUST be first field */
#define rkm_len               rkm_rkmessage.len
#define rkm_payload           rkm_rkmessage.payload
#define rkm_opaque            rkm_rkmessage._private
#define rkm_partition         rkm_rkmessage.partition
#define rkm_offset            rkm_rkmessage.offset
#define rkm_key               rkm_rkmessage.key
#define rkm_key_len           rkm_rkmessage.key_len
#define rkm_err               rkm_rkmessage.err

	TAILQ_ENTRY(rd_kafka_msg_s)  rkm_link;

	int        rkm_flags;
	/* @remark These additional flags must not collide with
	 *         the RD_KAFKA_MSG_F_* flags in rdkafka.h */
#define RD_KAFKA_MSG_F_FREE_RKM     0x10000 /* msg_t is allocated */
#define RD_KAFKA_MSG_F_ACCOUNT      0x20000 /* accounted for in curr_msgs */
#define RD_KAFKA_MSG_F_PRODUCER     0x40000 /* Producer message */

	int64_t    rkm_timestamp;  /* Message format V1.
				    * Meaning of timestamp depends on
				    * message Attribute LogAppendtime (broker)
				    * or CreateTime (producer).
				    * Unit is milliseconds since epoch (UTC).*/
	rd_kafka_timestamp_type_t rkm_tstype; /* rkm_timestamp type */

        rd_kafka_headers_t *rkm_headers; /**< Parsed headers list, if any. */

        union {
                struct {
                        rd_ts_t ts_timeout; /* Message timeout */
                        rd_ts_t ts_enq;     /* Enqueue/Produce time */
                        rd_ts_t ts_backoff; /* Backoff next Produce until
                                             * this time. */
                        uint64_t msgseq;    /* Message sequence number,
                                             * used to maintain ordering. */
                        int     retries;    /* Number of retries so far */
                } producer;
#define rkm_ts_timeout rkm_u.producer.ts_timeout
#define rkm_ts_enq     rkm_u.producer.ts_enq

                struct {
                        rd_kafkap_bytes_t binhdrs; /**< Unparsed
                                                    *   binary headers in
                                                    *   protocol msg */
                } consumer;
        } rkm_u;
} rd_kafka_msg_t;

TAILQ_HEAD(rd_kafka_msg_head_s, rd_kafka_msg_s);


/** @returns the absolute time a message was enqueued (producer) */
#define rd_kafka_msg_enq_time(rkm) ((rkm)->rkm_ts_enq)

/**
 * @returns the message's total maximum on-wire size.
 * @remark Depending on message version (MagicByte) the actual size
 *         may be smaller.
 */
static RD_INLINE RD_UNUSED
size_t rd_kafka_msg_wire_size (const rd_kafka_msg_t *rkm, int MsgVersion) {
        static const size_t overheads[] = {
                [0] = RD_KAFKAP_MESSAGE_V0_OVERHEAD,
                [1] = RD_KAFKAP_MESSAGE_V1_OVERHEAD,
                [2] = RD_KAFKAP_MESSAGE_V2_OVERHEAD
        };
        size_t size;
        rd_dassert(MsgVersion >= 0 && MsgVersion <= 2);

        size = overheads[MsgVersion] + rkm->rkm_len + rkm->rkm_key_len;
        if (MsgVersion == 2 && rkm->rkm_headers)
                size += rd_kafka_headers_serialized_size(rkm->rkm_headers);

        return size;
}


/**
 * @returns the enveloping rd_kafka_msg_t pointer for a rd_kafka_msg_t
 *          wrapped rd_kafka_message_t.
 */
static RD_INLINE RD_UNUSED
rd_kafka_msg_t *rd_kafka_message2msg (rd_kafka_message_t *rkmessage) {
	return (rd_kafka_msg_t *)rkmessage;
}





/**
 * @brief Message queue with message and byte counters.
 */
TAILQ_HEAD(rd_kafka_msgs_head_s, rd_kafka_msg_s);
typedef struct rd_kafka_msgq_s {
        struct rd_kafka_msgs_head_s rkmq_msgs;  /* TAILQ_HEAD */
        int32_t rkmq_msg_cnt;
        int64_t rkmq_msg_bytes;
} rd_kafka_msgq_t;

#define RD_KAFKA_MSGQ_INITIALIZER(rkmq) \
	{ .rkmq_msgs = TAILQ_HEAD_INITIALIZER((rkmq).rkmq_msgs) }

#define RD_KAFKA_MSGQ_FOREACH(elm,head) \
	TAILQ_FOREACH(elm, &(head)->rkmq_msgs, rkm_link)

/* @brief Check if queue is empty. Proper locks must be held. */
#define RD_KAFKA_MSGQ_EMPTY(rkmq) TAILQ_EMPTY(&(rkmq)->rkmq_msgs)

/**
 * Returns the number of messages in the specified queue.
 */
static RD_INLINE RD_UNUSED int rd_kafka_msgq_len (rd_kafka_msgq_t *rkmq) {
        return (int)rkmq->rkmq_msg_cnt;
}

/**
 * Returns the total number of bytes in the specified queue.
 */
static RD_INLINE RD_UNUSED size_t rd_kafka_msgq_size (rd_kafka_msgq_t *rkmq) {
        return (size_t)rkmq->rkmq_msg_bytes;
}


void rd_kafka_msg_destroy (rd_kafka_t *rk, rd_kafka_msg_t *rkm);

int rd_kafka_msg_new (rd_kafka_itopic_t *rkt, int32_t force_partition,
		      int msgflags,
		      char *payload, size_t len,
		      const void *keydata, size_t keylen,
		      void *msg_opaque);

static RD_INLINE RD_UNUSED void rd_kafka_msgq_init (rd_kafka_msgq_t *rkmq) {
        TAILQ_INIT(&rkmq->rkmq_msgs);
        rkmq->rkmq_msg_cnt   = 0;
        rkmq->rkmq_msg_bytes = 0;
}

/**
 * Concat all elements of 'src' onto tail of 'dst'.
 * 'src' will be cleared.
 * Proper locks for 'src' and 'dst' must be held.
 */
static RD_INLINE RD_UNUSED void rd_kafka_msgq_concat (rd_kafka_msgq_t *dst,
						   rd_kafka_msgq_t *src) {
	TAILQ_CONCAT(&dst->rkmq_msgs, &src->rkmq_msgs, rkm_link);
        dst->rkmq_msg_cnt   += src->rkmq_msg_cnt;
        dst->rkmq_msg_bytes += src->rkmq_msg_bytes;
	rd_kafka_msgq_init(src);
}

/**
 * Move queue 'src' to 'dst' (overwrites dst)
 * Source will be cleared.
 */
static RD_INLINE RD_UNUSED void rd_kafka_msgq_move (rd_kafka_msgq_t *dst,
						 rd_kafka_msgq_t *src) {
	TAILQ_MOVE(&dst->rkmq_msgs, &src->rkmq_msgs, rkm_link);
        dst->rkmq_msg_cnt   = src->rkmq_msg_cnt;
        dst->rkmq_msg_bytes = src->rkmq_msg_bytes;
	rd_kafka_msgq_init(src);
}


/**
 * rd_free all msgs in msgq and reinitialize the msgq.
 */
static RD_INLINE RD_UNUSED void rd_kafka_msgq_purge (rd_kafka_t *rk,
                                                    rd_kafka_msgq_t *rkmq) {
	rd_kafka_msg_t *rkm, *next;

	next = TAILQ_FIRST(&rkmq->rkmq_msgs);
	while (next) {
		rkm = next;
		next = TAILQ_NEXT(next, rkm_link);

		rd_kafka_msg_destroy(rk, rkm);
	}

	rd_kafka_msgq_init(rkmq);
}


/**
 * Remove message from message queue
 */
static RD_INLINE RD_UNUSED 
rd_kafka_msg_t *rd_kafka_msgq_deq (rd_kafka_msgq_t *rkmq,
				   rd_kafka_msg_t *rkm,
				   int do_count) {
	if (likely(do_count)) {
		rd_kafka_assert(NULL, rkmq->rkmq_msg_cnt > 0);
                rd_kafka_assert(NULL, rkmq->rkmq_msg_bytes >=
                                (int64_t)(rkm->rkm_len+rkm->rkm_key_len));
                rkmq->rkmq_msg_cnt--;
                rkmq->rkmq_msg_bytes -= rkm->rkm_len+rkm->rkm_key_len;
	}

	TAILQ_REMOVE(&rkmq->rkmq_msgs, rkm, rkm_link);

	return rkm;
}

static RD_INLINE RD_UNUSED
rd_kafka_msg_t *rd_kafka_msgq_pop (rd_kafka_msgq_t *rkmq) {
	rd_kafka_msg_t *rkm;

	if (((rkm = TAILQ_FIRST(&rkmq->rkmq_msgs))))
		rd_kafka_msgq_deq(rkmq, rkm, 1);

	return rkm;
}


/**
 * @brief Message ordering comparator using the message sequence
 *        number to order messages in ascending order (FIFO).
 */
static RD_INLINE
int rd_kafka_msg_cmp_msgseq (const void *_a, const void *_b) {
        const rd_kafka_msg_t *a = _a, *b = _b;

        rd_dassert(a->rkm_u.producer.msgseq);

        if (a->rkm_u.producer.msgseq > b->rkm_u.producer.msgseq)
                return 1;
        else if (a->rkm_u.producer.msgseq < b->rkm_u.producer.msgseq)
                return -1;
        else
                return 0;
}

/**
 * @brief Message ordering comparator using the message sequence
 *        number to order messages in descending order (LIFO).
 */
static RD_INLINE
int rd_kafka_msg_cmp_msgseq_lifo (const void *_a, const void *_b) {
        const rd_kafka_msg_t *a = _a, *b = _b;

        rd_dassert(a->rkm_u.producer.msgseq);

        if (a->rkm_u.producer.msgseq < b->rkm_u.producer.msgseq)
                return 1;
        else if (a->rkm_u.producer.msgseq > b->rkm_u.producer.msgseq)
                return -1;
        else
                return 0;
}

/**
 * @brief Insert message at its sorted position using the msgseq.
 * @remark This is an O(n) operation.
 * @warning The message must have a msgseq set.
 * @returns the message count of the queue after enqueuing the message.
 */
int rd_kafka_msgq_enq_sorted (const rd_kafka_itopic_t *rkt,
                               rd_kafka_msgq_t *rkmq,
                               rd_kafka_msg_t *rkm);

/**
 * Insert message at head of message queue.
 */
static RD_INLINE RD_UNUSED void rd_kafka_msgq_insert (rd_kafka_msgq_t *rkmq,
						   rd_kafka_msg_t *rkm) {
	TAILQ_INSERT_HEAD(&rkmq->rkmq_msgs, rkm, rkm_link);
        rkmq->rkmq_msg_cnt++;
        rkmq->rkmq_msg_bytes += rkm->rkm_len+rkm->rkm_key_len;
}

/**
 * Append message to tail of message queue.
 */
static RD_INLINE RD_UNUSED int rd_kafka_msgq_enq (rd_kafka_msgq_t *rkmq,
                                                rd_kafka_msg_t *rkm) {
        TAILQ_INSERT_TAIL(&rkmq->rkmq_msgs, rkm, rkm_link);
        rkmq->rkmq_msg_bytes += rkm->rkm_len+rkm->rkm_key_len;
        return (int)++rkmq->rkmq_msg_cnt;
}


/**
 * Scans a message queue for timed out messages and removes them from
 * 'rkmq' and adds them to 'timedout', returning the number of timed out
 * messages.
 * 'timedout' must be initialized.
 */
int rd_kafka_msgq_age_scan (rd_kafka_msgq_t *rkmq,
			    rd_kafka_msgq_t *timedout,
			    rd_ts_t now);

rd_kafka_msg_t *rd_kafka_msgq_find_pos (const rd_kafka_msgq_t *rkmq,
                                        const rd_kafka_msg_t *rkm,
                                        int (*cmp) (const void *,
                                                    const void *));

int rd_kafka_msg_partitioner (rd_kafka_itopic_t *rkt, rd_kafka_msg_t *rkm,
                              int do_lock);


rd_kafka_message_t *rd_kafka_message_get (struct rd_kafka_op_s *rko);
rd_kafka_message_t *rd_kafka_message_get_from_rkm (struct rd_kafka_op_s *rko,
                                                   rd_kafka_msg_t *rkm);
rd_kafka_message_t *rd_kafka_message_new (void);

void rd_kafka_msgq_dump (FILE *fp, const char *what, rd_kafka_msgq_t *rkmq);

int unittest_msg (void);

#endif /* _RDKAFKA_MSG_H_ */
