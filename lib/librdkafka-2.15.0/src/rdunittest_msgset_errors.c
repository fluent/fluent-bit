/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2025, Confluent Inc.
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
 * @name Unit tests for Share Consumer MessageSet error handling
 * @{
 *
 * Tests cover per-offset error handling for:
 *   - CRC errors → REJECT ack_type
 *   - Decompression errors → RELEASE ack_type
 *   - Unsupported MagicByte → REJECT ack_type
 *
 * These tests craft binary MessageSet v2 buffers with intentional corruption
 * and verify that the msgset reader creates one error op per offset with
 * correct ack_types for share consumers.
 */

#include "rd.h"
#include "rdunittest.h"
#include "rdkafka_int.h"
#include "rdkafka_queue.h"
#include "rdkafka_partition.h"
#include "rdkafka_share_acknowledgement.h"
#include "rdkafka_buf.h"
#include "rdkafka_msgset.h"
#include "crc32c.h"

#if WITH_ZSTD
#include "rdkafka_zstd.h"
#endif


/**
 * @brief Alignment-safe big-endian writers.
 *
 * The msgset crafting helpers below write into a char buffer at arbitrary
 * offsets. Casting `char *` to `int{16,32,64}_t *` triggers -Wcast-align
 * on stricter targets (and is undefined behaviour even on x86 strictly
 * speaking). Use memcpy() — the compiler lowers it to a single move on
 * supported architectures.
 */
static RD_INLINE void ut_put_be16(void *p, int16_t v) {
        int16_t be = htobe16(v);
        memcpy(p, &be, sizeof(be));
}
static RD_INLINE void ut_put_be32(void *p, int32_t v) {
        int32_t be = htobe32(v);
        memcpy(p, &be, sizeof(be));
}
static RD_INLINE void ut_put_be64(void *p, int64_t v) {
        int64_t be = htobe64(v);
        memcpy(p, &be, sizeof(be));
}


/**
 * @name Test helpers
 * @{
 */

/**
 * @brief Create a minimal share consumer for testing
 */
static rd_kafka_share_t *ut_create_test_share_consumer(void) {
        rd_kafka_conf_t *conf = rd_kafka_conf_new();
        rd_kafka_share_t *rkshare;
        char errstr[512];

        if (rd_kafka_conf_set(conf, "group.id", "ut-msgset-errors", errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                rd_kafka_conf_destroy(conf);
                return NULL;
        }

        /* Enable CRC checking for tests */
        if (rd_kafka_conf_set(conf, "check.crcs", "true", errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                rd_kafka_conf_destroy(conf);
                return NULL;
        }

        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        return rkshare;
}

static void ut_destroy_share_consumer(rd_kafka_share_t *rkshare) {
        if (!rkshare)
                return;
        rd_kafka_share_consumer_close(rkshare);
        rd_kafka_share_destroy(rkshare);
}

/**
 * @brief Create a mock topic partition
 */
static rd_kafka_toppar_t *
ut_create_mock_toppar(rd_kafka_t *rk, const char *topic, int32_t partition) {
        rd_kafka_topic_t *rkt = rd_kafka_topic_new(rk, topic, NULL);
        if (!rkt)
                return NULL;
        return rd_kafka_toppar_new(rkt, partition);
}

/**
 * @brief Helper to write MessageSet v2 header fields in big-endian
 */
static void ut_write_msgset_v2_header(char *buf,
                                      int64_t BaseOffset,
                                      int32_t Length,
                                      int32_t PartitionLeaderEpoch,
                                      int8_t MagicByte,
                                      int32_t Crc,
                                      int16_t Attributes,
                                      int32_t LastOffsetDelta,
                                      int64_t BaseTimestamp,
                                      int64_t MaxTimestamp,
                                      int64_t ProducerId,
                                      int16_t ProducerEpoch,
                                      int32_t BaseSequence,
                                      int32_t RecordCount) {
        size_t offset = 0;

        /* BaseOffset (int64) */
        ut_put_be64(buf + offset, BaseOffset);
        offset += 8;

        /* Length (int32) */
        ut_put_be32(buf + offset, Length);
        offset += 4;

        /* PartitionLeaderEpoch (int32) */
        ut_put_be32(buf + offset, PartitionLeaderEpoch);
        offset += 4;

        /* MagicByte (int8) */
        *(int8_t *)(buf + offset) = MagicByte;
        offset += 1;

        /* Crc (int32) */
        ut_put_be32(buf + offset, Crc);
        offset += 4;

        /* Attributes (int16) */
        ut_put_be16(buf + offset, Attributes);
        offset += 2;

        /* LastOffsetDelta (int32) */
        ut_put_be32(buf + offset, LastOffsetDelta);
        offset += 4;

        /* BaseTimestamp (int64) */
        ut_put_be64(buf + offset, BaseTimestamp);
        offset += 8;

        /* MaxTimestamp (int64) */
        ut_put_be64(buf + offset, MaxTimestamp);
        offset += 8;

        /* ProducerId (int64) */
        ut_put_be64(buf + offset, ProducerId);
        offset += 8;

        /* ProducerEpoch (int16) */
        ut_put_be16(buf + offset, ProducerEpoch);
        offset += 2;

        /* BaseSequence (int32) */
        ut_put_be32(buf + offset, BaseSequence);
        offset += 4;

        /* RecordCount (int32) */
        ut_put_be32(buf + offset, RecordCount);
        offset += 4;
}

#if WITH_ZSTD
/**
 * @brief Calculate correct CRC32C for MessageSet v2
 *        CRC covers from Attributes to end of records
 */
static uint32_t ut_calc_msgset_crc(const char *buf,
                                   size_t offset_to_attributes,
                                   size_t total_len) {
        /* CRC starts after MagicByte and Crc field itself */
        const void *data = buf + offset_to_attributes;
        size_t data_len  = total_len - offset_to_attributes;
        return rd_crc32c(0, data, data_len);
}
#endif /* WITH_ZSTD */

/**
 * @brief Write a varint (used in Record format)
 * @returns number of bytes written
 */
static size_t ut_write_varint(char *buf, int64_t value) {
        uint64_t uval = (value << 1) ^ (value >> 63); /* Zigzag encoding */
        size_t i      = 0;

        while (uval >= 0x80) {
                buf[i++] = (char)((uval & 0x7F) | 0x80);
                uval >>= 7;
        }
        buf[i++] = (char)(uval & 0x7F);
        return i;
}

/**
 * @brief Build a minimal valid Record v2
 * @returns size of record written
 */
static size_t ut_build_record_v2(char *buf,
                                 int32_t offset_delta,
                                 int64_t timestamp_delta,
                                 const char *key,
                                 size_t key_len,
                                 const char *value,
                                 size_t value_len) {
        size_t offset = 0;
        size_t len_offset;
        int32_t key_len_varint = key ? (int32_t)key_len : -1;
        int32_t val_len_varint = value ? (int32_t)value_len : -1;

        /* Reserve space for Length (varint) - we'll fill this in later */
        len_offset = offset;
        offset += 5; /* Max varint size for record length */

        /* Attributes (int8) */
        buf[offset++] = 0;

        /* TimestampDelta (varint) */
        offset += ut_write_varint(buf + offset, timestamp_delta);

        /* OffsetDelta (varint) */
        offset += ut_write_varint(buf + offset, offset_delta);

        /* KeyLen (varint) */
        offset += ut_write_varint(buf + offset, key_len_varint);

        /* Key bytes */
        if (key) {
                memcpy(buf + offset, key, key_len);
                offset += key_len;
        }

        /* ValueLen (varint) */
        offset += ut_write_varint(buf + offset, val_len_varint);

        /* Value bytes */
        if (value) {
                memcpy(buf + offset, value, value_len);
                offset += value_len;
        }

        /* Headers count (varint) - 0 headers */
        offset += ut_write_varint(buf + offset, 0);

        /* Calculate record length (everything after Length field) */
        size_t record_body_len = offset - len_offset - 5;

        /* Write actual Length at the beginning */
        size_t len_size = ut_write_varint(buf + len_offset, record_body_len);

        /* Compact the record if varint was smaller than 5 bytes */
        if (len_size < 5) {
                memmove(buf + len_offset + len_size, buf + len_offset + 5,
                        record_body_len);
                offset = len_offset + len_size + record_body_len;
        }

        return offset;
}

/**
 * @brief Build a complete valid MessageSet v2 with records
 * @returns total size of MessageSet
 */
static size_t ut_build_valid_msgset_v2(char *buf,
                                       int64_t base_offset,
                                       int32_t record_count,
                                       const char **values,
                                       size_t *value_lens) {
        size_t offset       = 0;
        size_t len_offset   = 8;
        size_t records_size = 0;
        int32_t i;
        char *records_buf;
        uint32_t crc;
        int32_t last_offset_delta = record_count > 0 ? record_count - 1 : 0;

        /* Build all records first to know total size */
        records_buf = rd_calloc(1, 8192);
        for (i = 0; i < record_count; i++) {
                records_size += ut_build_record_v2(
                    records_buf + records_size, i, /* offsetDelta */
                    0,                             /* timestampDelta */
                    NULL, 0,                       /* no key */
                    values ? values[i] : NULL,
                    values && value_lens ? value_lens[i] : 0);
        }

        /* BaseOffset */
        ut_put_be64(buf + offset, base_offset);
        offset += 8;

        /* Length - will update later */
        len_offset = offset;
        offset += 4;

        /* PartitionLeaderEpoch */
        ut_put_be32(buf + offset, -1);
        offset += 4;

        /* MagicByte */
        buf[offset++] = 2;

        /* CRC - placeholder, will calculate later */
        size_t crc_offset = offset;
        offset += 4;

        /* Attributes (no compression) */
        ut_put_be16(buf + offset, 0);
        offset += 2;

        /* LastOffsetDelta */
        ut_put_be32(buf + offset, last_offset_delta);
        offset += 4;

        /* BaseTimestamp */
        ut_put_be64(buf + offset, 0);
        offset += 8;

        /* MaxTimestamp */
        ut_put_be64(buf + offset, 0);
        offset += 8;

        /* ProducerId */
        ut_put_be64(buf + offset, -1);
        offset += 8;

        /* ProducerEpoch */
        ut_put_be16(buf + offset, -1);
        offset += 2;

        /* BaseSequence */
        ut_put_be32(buf + offset, -1);
        offset += 4;

        /* RecordCount */
        ut_put_be32(buf + offset, record_count);
        offset += 4;

        /* Copy records */
        memcpy(buf + offset, records_buf, records_size);
        offset += records_size;
        rd_free(records_buf);

        /* Calculate and write Length */
        int32_t length = (int32_t)(offset - len_offset - 4);
        ut_put_be32(buf + len_offset, length);

        /* Calculate and write CRC (covers Attributes to end) */
        crc = rd_crc32c(0, buf + crc_offset + 4, offset - crc_offset - 4);
        ut_put_be32(buf + crc_offset, crc);

        return offset;
}

/**@}*/


/**
 * @brief Test CRC error generates per-offset error ops with REJECT ack_type
 *
 * Creates a MessageSet v2 with intentionally wrong CRC and verifies:
 * - One error op per offset in range [BaseOffset, LastOffset]
 * - Each error op has REJECT ack_type
 * - Error code is RD_KAFKA_RESP_ERR__BAD_MSG
 */
static int unittest_msgset_crc_error_share_consumer(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_q_t *response_q;
        char *msgset_data;
        size_t msgset_size;
        int64_t BaseOffset = 100;
        int32_t LastOffsetDelta =
            4; /* Offsets 100-104 inclusive = 5 messages */
        int expected_err_ops = 5;
        int i;
        struct rd_kafka_toppar_ver tver = {.version = 11};

        RD_UT_BEGIN();

        rkshare = ut_create_test_share_consumer();
        RD_UT_ASSERT(rkshare, "Failed to create share consumer");

        rktp = ut_create_mock_toppar(rkshare->rkshare_rk, "test-topic-crc", 0);
        RD_UT_ASSERT(rktp, "Failed to create toppar");

        response_q = rd_kafka_q_new(rkshare->rkshare_rk);

        /* Craft MessageSet v2 with wrong CRC */
        /* MessageSet v2 structure:
         * - BaseOffset (8) + Length (4) = 12 bytes before "Length" data starts
         * - Length field contains size of: PartitionLeaderEpoch (4) + MagicByte
         * (1)
         *   + Crc (4) + Attributes (2) + LastOffsetDelta (4) + BaseTimestamp
         * (8)
         *   + MaxTimestamp (8) + ProducerId (8) + ProducerEpoch (2)
         *   + BaseSequence (4) + RecordCount (4) + Records
         * - Minimum Length = 49 (just the header fields after Length)
         * - For this test, we need enough space for CRC validation
         */

        /* CRC validation needs: crc_len = Length - 4 - 1 - 4 bytes available
         * after reading up to Crc field (21 bytes read so far) */
        int32_t Length = 61 - 12;     /* Minimum: just the header, no records */
        msgset_size    = 12 + Length; /* BaseOffset + Length + data */
        msgset_data    = rd_calloc(1, msgset_size);

        ut_write_msgset_v2_header(
            msgset_data, BaseOffset,
            Length,     /* Length of data after BaseOffset+Length fields */
            -1,         /* PartitionLeaderEpoch */
            2,          /* MagicByte v2 */
            0xDEADBEEF, /* WRONG CRC - will trigger error */
            0,          /* Attributes: no compression */
            LastOffsetDelta, 0, /* BaseTimestamp */
            0,                  /* MaxTimestamp */
            -1,                 /* ProducerId */
            -1,                 /* ProducerEpoch */
            -1,                 /* BaseSequence */
            5 /* RecordCount */);

        /* Create shadow buffer from raw data */
        rkbuf = rd_kafka_buf_new_shadow(msgset_data, msgset_size, rd_free);
        rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkshare->rkshare_rk);

        /* Parse the MessageSet - should detect CRC error */
        rd_kafka_resp_err_t parse_err =
            rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver, response_q);

        RD_UT_ASSERT(parse_err == RD_KAFKA_RESP_ERR_NO_ERROR ||
                         parse_err == RD_KAFKA_RESP_ERR__BAD_MSG,
                     "Unexpected parse error: %s", rd_kafka_err2str(parse_err));

        /* Verify we got expected number of error ops */
        for (i = 0; i < expected_err_ops; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL,
                             "Expected error op %d of %d, got timeout", i + 1,
                             expected_err_ops);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_MSG,
                             "Expected BAD_MSG error, got %s",
                             rd_kafka_err2str(rko->rko_err));
                RD_UT_ASSERT(rko->rko_u.err.offset == BaseOffset + i,
                             "Expected offset %" PRId64 ", got %" PRId64,
                             BaseOffset + i, rko->rko_u.err.offset);
                RD_UT_ASSERT(rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                                 RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                             "Expected REJECT ack_type for CRC error, got %d",
                             rko->rko_u.err.rkm.rkm_u.consumer.ack_type);
                rd_kafka_op_destroy(rko);
        }

        /* Verify no extra ops */
        {
                rd_kafka_op_t *rko;
                rko = rd_kafka_q_pop(response_q, 100, 0);
                RD_UT_ASSERT(rko == NULL, "Got unexpected extra op");
        }

        rd_kafka_buf_destroy(rkbuf);
        rd_kafka_q_destroy_owner(response_q);
        rd_kafka_toppar_destroy(rktp);
        ut_destroy_share_consumer(rkshare);

        RD_UT_PASS();
}


#if WITH_ZSTD
/**
 * @brief Test decompression error generates per-offset error ops with RELEASE
 *
 * Creates a MessageSet v2 with ZSTD compression but corrupted compressed data.
 * Verifies:
 * - One error op per offset in range [BaseOffset, LastOffset]
 * - Each error op has RELEASE ack_type (retryable error)
 * - Error code is RD_KAFKA_RESP_ERR__BAD_COMPRESSION
 */
static int unittest_msgset_decompression_error_share_consumer(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_q_t *response_q;
        char *msgset_data;
        size_t msgset_size;
        int64_t BaseOffset = 200;
        int32_t LastOffsetDelta =
            2; /* Offsets 200-202 inclusive = 3 messages */
        int expected_err_ops = 3;
        int i;
        uint32_t correct_crc;
        size_t crc_offset = 17; /* Offset to CRC field in header */
        size_t attr_offset =
            21; /* Offset to Attributes field (where CRC starts) */
        struct rd_kafka_toppar_ver tver = {.version = 11};

        RD_UT_BEGIN();

        rkshare = ut_create_test_share_consumer();
        RD_UT_ASSERT(rkshare, "Failed to create share consumer");

        rktp = ut_create_mock_toppar(rkshare->rkshare_rk,
                                     "test-topic-decompress", 0);
        RD_UT_ASSERT(rktp, "Failed to create toppar");

        response_q = rd_kafka_q_new(rkshare->rkshare_rk);

        /* Craft MessageSet v2 with ZSTD compression but corrupted data */
        msgset_size = 200;
        msgset_data = rd_calloc(1, msgset_size);

        int32_t Length = msgset_size - 12;

        ut_write_msgset_v2_header(
            msgset_data, BaseOffset,
            Length, /* Length of data after BaseOffset+Length fields */
            -1,     /* PartitionLeaderEpoch */
            2,      /* MagicByte v2 */
            0,      /* CRC - will calculate correct one below */
            4,      /* Attributes: ZSTD compression (codec=4) */
            LastOffsetDelta, 0, /* BaseTimestamp */
            0,                  /* MaxTimestamp */
            -1,                 /* ProducerId */
            -1,                 /* ProducerEpoch */
            -1,                 /* BaseSequence */
            3 /* RecordCount */);

        /* Fill records section with garbage (corrupted ZSTD data) */
        memset(msgset_data + 61, 0xAB, msgset_size - 61);

        /* Calculate CORRECT CRC so we pass CRC check but fail decompression */
        correct_crc = ut_calc_msgset_crc(msgset_data, attr_offset, msgset_size);
        ut_put_be32(msgset_data + crc_offset, correct_crc);

        /* Create shadow buffer from raw data */
        rkbuf = rd_kafka_buf_new_shadow(msgset_data, msgset_size, rd_free);
        rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkshare->rkshare_rk);

        /* Parse the MessageSet - should detect decompression error */
        rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver, response_q);

        /* Verify we got expected number of error ops */
        for (i = 0; i < expected_err_ops; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL,
                             "Expected error op %d of %d, got timeout", i + 1,
                             expected_err_ops);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_COMPRESSION,
                             "Expected BAD_COMPRESSION error, got %s",
                             rd_kafka_err2str(rko->rko_err));
                RD_UT_ASSERT(rko->rko_u.err.offset == BaseOffset + i,
                             "Expected offset %" PRId64 ", got %" PRId64,
                             BaseOffset + i, rko->rko_u.err.offset);
                RD_UT_ASSERT(
                    rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                        RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
                    "Expected RELEASE ack_type for decompression error, got %d",
                    rko->rko_u.err.rkm.rkm_u.consumer.ack_type);
                rd_kafka_op_destroy(rko);
        }

        /* Verify no extra ops */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 100, 0);
                RD_UT_ASSERT(rko == NULL, "Unexpected extra op");
        }

        rd_kafka_buf_destroy(rkbuf);
        rd_kafka_q_destroy_owner(response_q);
        rd_kafka_toppar_destroy(rktp);
        ut_destroy_share_consumer(rkshare);

        RD_UT_PASS();
}
#endif /* WITH_ZSTD */


/**
 * @brief Test unsupported MagicByte generates per-offset error ops with REJECT
 *
 * Creates a MessageSet with MagicByte=99 (unsupported future version).
 * Verifies:
 * - One error op per offset in range [BaseOffset, LastOffset]
 * - Each error op has REJECT ack_type (permanent error)
 * - Error code is RD_KAFKA_RESP_ERR__NOT_IMPLEMENTED
 */
static int unittest_msgset_unsupported_magic_share_consumer(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_q_t *response_q;
        char *msgset_data;
        size_t msgset_size;
        int64_t BaseOffset = 300;
        int32_t LastOffsetDelta =
            9; /* Offsets 300-309 inclusive = 10 messages */
        int expected_err_ops = 10;
        int i;
        struct rd_kafka_toppar_ver tver = {.version = 11};

        RD_UT_BEGIN();

        rkshare = ut_create_test_share_consumer();
        RD_UT_ASSERT(rkshare, "Failed to create share consumer");

        rktp =
            ut_create_mock_toppar(rkshare->rkshare_rk, "test-topic-magic", 0);
        RD_UT_ASSERT(rktp, "Failed to create toppar");

        response_q = rd_kafka_q_new(rkshare->rkshare_rk);

        /* Craft MessageSet with unsupported MagicByte */
        msgset_size = 200;
        msgset_data = rd_calloc(1, msgset_size);

        int32_t Length = msgset_size - 12;

        ut_write_msgset_v2_header(
            msgset_data, BaseOffset,
            Length, /* Length of data after BaseOffset+Length fields */
            -1,     /* PartitionLeaderEpoch */
            99,     /* UNSUPPORTED MagicByte - will trigger error */
            0,      /* CRC - doesn't matter, won't get that far */
            0,      /* Attributes */
            LastOffsetDelta, 0, /* BaseTimestamp */
            0,                  /* MaxTimestamp */
            -1,                 /* ProducerId */
            -1,                 /* ProducerEpoch */
            -1,                 /* BaseSequence */
            10 /* RecordCount */);

        /* Create shadow buffer from raw data */
        rkbuf = rd_kafka_buf_new_shadow(msgset_data, msgset_size, rd_free);
        rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkshare->rkshare_rk);

        /* Parse the MessageSet - should detect unsupported MagicByte */
        rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver, response_q);

        /* Verify we got expected number of error ops */
        for (i = 0; i < expected_err_ops; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL,
                             "Expected error op %d of %d, got timeout", i + 1,
                             expected_err_ops);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__NOT_IMPLEMENTED,
                             "Expected NOT_IMPLEMENTED error, got %s",
                             rd_kafka_err2str(rko->rko_err));
                RD_UT_ASSERT(rko->rko_u.err.offset == BaseOffset + i,
                             "Expected offset %" PRId64 ", got %" PRId64,
                             BaseOffset + i, rko->rko_u.err.offset);
                RD_UT_ASSERT(
                    rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                        RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                    "Expected REJECT ack_type for unsupported MagicByte, got "
                    "%d",
                    rko->rko_u.err.rkm.rkm_u.consumer.ack_type);
                rd_kafka_op_destroy(rko);
        }

        /* Verify no extra ops */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 100, 0);
                RD_UT_ASSERT(rko == NULL, "Unexpected extra op");
        }

        rd_kafka_buf_destroy(rkbuf);
        rd_kafka_q_destroy_owner(response_q);
        rd_kafka_toppar_destroy(rktp);
        ut_destroy_share_consumer(rkshare);

        RD_UT_PASS();
}


/**
 * @brief Test mixed scenario: Success → CRC Error → Success
 *
 * Verifies parser correctly handles:
 * - MessageSet 1: 3 successful messages (offsets 100-102)
 * - MessageSet 2: CRC error covering 5 messages (offsets 103-107)
 * - MessageSet 3: 2 successful messages (offsets 108-109)
 */
static int unittest_msgset_mixed_success_crc_success(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_q_t *response_q;
        char *buffer;
        size_t buffer_size              = 4096;
        size_t offset                   = 0;
        struct rd_kafka_toppar_ver tver = {.version = 11};
        const char *values[] = {"msg1", "msg2", "msg3", "msg4", "msg5"};
        size_t value_lens[]  = {4, 4, 4, 4, 4};
        int i;

        RD_UT_BEGIN();

        rkshare = ut_create_test_share_consumer();
        RD_UT_ASSERT(rkshare, "Failed to create share consumer");

        rktp =
            ut_create_mock_toppar(rkshare->rkshare_rk, "test-topic-mixed", 0);
        RD_UT_ASSERT(rktp, "Failed to create toppar");

        response_q = rd_kafka_q_new(rkshare->rkshare_rk);
        buffer     = rd_calloc(1, buffer_size);

        /* MessageSet 1: Valid with 3 messages (offsets 100-102) */
        offset += ut_build_valid_msgset_v2(buffer + offset, 100, 3, values,
                                           value_lens);

        /* MessageSet 2: CRC error with 5 messages (offsets 103-107) */
        int64_t BaseOffset2      = 103;
        int32_t LastOffsetDelta2 = 4;
        int32_t Length2          = 61 - 12; /* Just header */
        ut_write_msgset_v2_header(buffer + offset, BaseOffset2, Length2, -1, 2,
                                  0xBADC0C, /* Wrong CRC */
                                  0, LastOffsetDelta2, 0, 0, -1, -1, -1, 5);
        offset += 12 + Length2;

        /* MessageSet 3: Valid with 2 messages (offsets 108-109) */
        const char *values3[] = {"msg6", "msg7"};
        size_t value_lens3[]  = {4, 4};
        offset += ut_build_valid_msgset_v2(buffer + offset, 108, 2, values3,
                                           value_lens3);

        /* Parse all MessageSets */
        rkbuf            = rd_kafka_buf_new_shadow(buffer, offset, rd_free);
        rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkshare->rkshare_rk);

        rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver, response_q);

        /* Verify MessageSet 1: 3 FETCH ops with offsets 100-102 */
        for (i = 0; i < 3; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected FETCH op %d, got timeout",
                             i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_FETCH,
                             "Expected FETCH op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_u.fetch.rkm.rkm_offset == 100 + i,
                             "Expected offset %d, got %" PRId64, 100 + i,
                             rko->rko_u.fetch.rkm.rkm_offset);
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 2: 5 CONSUMER_ERR ops with offsets 103-107 */
        for (i = 0; i < 5; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL,
                             "Expected CRC error op %d, got timeout", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_MSG,
                             "Expected BAD_MSG error, got %s",
                             rd_kafka_err2str(rko->rko_err));
                RD_UT_ASSERT(rko->rko_u.err.offset == 103 + i,
                             "Expected offset %d, got %" PRId64, 103 + i,
                             rko->rko_u.err.offset);
                RD_UT_ASSERT(rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                                 RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                             "Expected REJECT ack_type");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 3: 2 FETCH ops with offsets 108-109 */
        for (i = 0; i < 2; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected FETCH op %d, got timeout",
                             i + 3);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_FETCH,
                             "Expected FETCH op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_u.fetch.rkm.rkm_offset == 108 + i,
                             "Expected offset %d, got %" PRId64, 108 + i,
                             rko->rko_u.fetch.rkm.rkm_offset);
                rd_kafka_op_destroy(rko);
        }

        /* Verify no extra ops */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 100, 0);
                RD_UT_ASSERT(rko == NULL, "Unexpected extra op");
        }

        rd_kafka_buf_destroy(rkbuf);
        rd_kafka_q_destroy_owner(response_q);
        rd_kafka_toppar_destroy(rktp);
        ut_destroy_share_consumer(rkshare);

        RD_UT_PASS();
}


#if WITH_ZSTD
/**
 * @brief Test mixed scenario: CRC Error → Success → Decompression Error
 *
 * Verifies parser correctly handles:
 * - MessageSet 1: CRC error covering 2 messages (offsets 200-201)
 * - MessageSet 2: 4 successful messages (offsets 202-205)
 * - MessageSet 3: Decompression error covering 3 messages (offsets 206-208)
 */
static int unittest_msgset_mixed_crc_success_decomp(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_q_t *response_q;
        char *buffer;
        size_t buffer_size              = 4096;
        size_t offset                   = 0;
        struct rd_kafka_toppar_ver tver = {.version = 11};
        const char *values[]            = {"a", "b", "c", "d"};
        size_t value_lens[]             = {1, 1, 1, 1};
        int i;

        RD_UT_BEGIN();

        rkshare = ut_create_test_share_consumer();
        RD_UT_ASSERT(rkshare, "Failed to create share consumer");

        rktp =
            ut_create_mock_toppar(rkshare->rkshare_rk, "test-topic-mixed2", 0);
        RD_UT_ASSERT(rktp, "Failed to create toppar");

        response_q = rd_kafka_q_new(rkshare->rkshare_rk);
        buffer     = rd_calloc(1, buffer_size);

        /* MessageSet 1: CRC error with 2 messages (offsets 200-201) */
        ut_write_msgset_v2_header(buffer + offset, 200, 61 - 12, -1, 2,
                                  0xDEADC0C, 0, 1, 0, 0, -1, -1, -1, 2);
        offset += 12 + (61 - 12);

        /* MessageSet 2: Valid with 4 messages (offsets 202-205) */
        offset += ut_build_valid_msgset_v2(buffer + offset, 202, 4, values,
                                           value_lens);

        /* MessageSet 3: Decompression error with 3 messages (offsets 206-208)
         */
        char corrupted_data[16] = {0xDE, 0xAD, 0xBE, 0xEF}; /* Garbage */
        size_t decomp_start     = offset;
        ut_write_msgset_v2_header(buffer + offset, 206,
                                  49 + sizeof(corrupted_data), -1, 2, 0,
                                  4, /* ZSTD compression */
                                  2, 0, 0, -1, -1, -1, 3);
        offset += 61;
        memcpy(buffer + offset, corrupted_data, sizeof(corrupted_data));
        offset += sizeof(corrupted_data);
        /* Fix CRC for decompression error (CRC is valid, data is corrupt) */
        uint32_t crc = rd_crc32c(0, buffer + decomp_start + 21,
                                 49 + sizeof(corrupted_data) - 4 - 1 - 4);
        ut_put_be32(buffer + decomp_start + 17, crc);

        /* Parse all MessageSets */
        rkbuf            = rd_kafka_buf_new_shadow(buffer, offset, rd_free);
        rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkshare->rkshare_rk);

        rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver, response_q);

        /* Verify MessageSet 1: 2 CRC error ops (offsets 200-201) */
        for (i = 0; i < 2; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected CRC error op %d", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR");
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_MSG,
                             "Expected BAD_MSG");
                RD_UT_ASSERT(rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                                 RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                             "Expected REJECT");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 2: 4 successful FETCH ops (offsets 202-205) */
        for (i = 0; i < 4; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected FETCH op %d", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_FETCH,
                             "Expected FETCH op");
                RD_UT_ASSERT(rko->rko_u.fetch.rkm.rkm_offset == 202 + i,
                             "Expected offset %d", 202 + i);
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 3: 3 decompression error ops (offsets 206-208) */
        for (i = 0; i < 3; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected decomp error op %d", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR");
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_COMPRESSION,
                             "Expected BAD_COMPRESSION");
                RD_UT_ASSERT(rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                                 RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
                             "Expected RELEASE");
                rd_kafka_op_destroy(rko);
        }

        /* Verify no extra ops */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 100, 0);
                RD_UT_ASSERT(rko == NULL, "Unexpected extra op");
        }

        rd_kafka_buf_destroy(rkbuf);
        rd_kafka_q_destroy_owner(response_q);
        rd_kafka_toppar_destroy(rktp);
        ut_destroy_share_consumer(rkshare);

        RD_UT_PASS();
}
#endif /* WITH_ZSTD */


/**
 * @brief Test mixed scenario: Unsupported Magic → Success → CRC Error → Success
 *
 * Verifies parser correctly handles:
 * - MessageSet 1: Unsupported MagicByte covering 3 messages (offsets 300-302)
 * - MessageSet 2: 1 successful message (offset 303)
 * - MessageSet 3: CRC error covering 2 messages (offsets 304-305)
 * - MessageSet 4: 5 successful messages (offsets 306-310)
 */
static int unittest_msgset_mixed_magic_success_crc_success(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_q_t *response_q;
        char *buffer;
        size_t buffer_size              = 4096;
        size_t offset                   = 0;
        struct rd_kafka_toppar_ver tver = {.version = 11};
        const char *value1              = "x";
        size_t value_len1               = 1;
        const char *values5[]           = {"a", "b", "c", "d", "e"};
        size_t value_lens5[]            = {1, 1, 1, 1, 1};
        int i;

        RD_UT_BEGIN();

        rkshare = ut_create_test_share_consumer();
        RD_UT_ASSERT(rkshare, "Failed to create share consumer");

        rktp =
            ut_create_mock_toppar(rkshare->rkshare_rk, "test-topic-mixed3", 0);
        RD_UT_ASSERT(rktp, "Failed to create toppar");

        response_q = rd_kafka_q_new(rkshare->rkshare_rk);
        buffer     = rd_calloc(1, buffer_size);

        /* MessageSet 1: Unsupported MagicByte=99, 3 messages (offsets 300-302)
         */
        ut_write_msgset_v2_header(buffer + offset, 300, 61 - 12, -1,
                                  99, /* Unsupported */
                                  0, 0, 2, 0, 0, -1, -1, -1, 3);
        offset += 12 + (61 - 12);

        /* MessageSet 2: Valid with 1 message (offset 303) */
        offset += ut_build_valid_msgset_v2(buffer + offset, 303, 1, &value1,
                                           &value_len1);

        /* MessageSet 3: CRC error, 2 messages (offsets 304-305) */
        ut_write_msgset_v2_header(buffer + offset, 304, 61 - 12, -1, 2,
                                  0xBADBAD, 0, 1, 0, 0, -1, -1, -1, 2);
        offset += 12 + (61 - 12);

        /* MessageSet 4: Valid with 5 messages (offsets 306-310) */
        offset += ut_build_valid_msgset_v2(buffer + offset, 306, 5, values5,
                                           value_lens5);

        /* Parse all MessageSets */
        rkbuf            = rd_kafka_buf_new_shadow(buffer, offset, rd_free);
        rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkshare->rkshare_rk);

        rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver, response_q);

        /* Verify MessageSet 1: 3 unsupported magic error ops (offsets 300-302)
         */
        for (i = 0; i < 3; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected magic error op %d", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR");
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__NOT_IMPLEMENTED,
                             "Expected NOT_IMPLEMENTED");
                RD_UT_ASSERT(rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                                 RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                             "Expected REJECT");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 2: 1 successful FETCH op (offset 303) */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected FETCH op");
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_FETCH,
                             "Expected FETCH op");
                RD_UT_ASSERT(rko->rko_u.fetch.rkm.rkm_offset == 303,
                             "Expected offset 303");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 3: 2 CRC error ops (offsets 304-305) */
        for (i = 0; i < 2; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected CRC error op %d", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR");
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_MSG,
                             "Expected BAD_MSG");
                RD_UT_ASSERT(rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                                 RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                             "Expected REJECT");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 4: 5 successful FETCH ops (offsets 306-310) */
        for (i = 0; i < 5; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected FETCH op %d", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_FETCH,
                             "Expected FETCH op");
                RD_UT_ASSERT(rko->rko_u.fetch.rkm.rkm_offset == 306 + i,
                             "Expected offset %d", 306 + i);
                rd_kafka_op_destroy(rko);
        }

        /* Verify no extra ops */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 100, 0);
                RD_UT_ASSERT(rko == NULL, "Unexpected extra op");
        }

        rd_kafka_buf_destroy(rkbuf);
        rd_kafka_q_destroy_owner(response_q);
        rd_kafka_toppar_destroy(rktp);
        ut_destroy_share_consumer(rkshare);

        RD_UT_PASS();
}


/**
 * @brief Test all successful MessageSets
 *
 * Verifies parser correctly handles multiple consecutive successful
 * MessageSets:
 * - MessageSet 1: 2 messages (offsets 400-401)
 * - MessageSet 2: 3 messages (offsets 402-404)
 * - MessageSet 3: 1 message (offset 405)
 * - MessageSet 4: 4 messages (offsets 406-409)
 */
static int unittest_msgset_all_success(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_q_t *response_q;
        char *buffer;
        size_t buffer_size              = 4096;
        size_t offset                   = 0;
        struct rd_kafka_toppar_ver tver = {.version = 11};
        const char *values2[]           = {"m1", "m2"};
        size_t value_lens2[]            = {2, 2};
        const char *values3[]           = {"m3", "m4", "m5"};
        size_t value_lens3[]            = {2, 2, 2};
        const char *value1              = "m6";
        size_t value_len1               = 2;
        const char *values4[]           = {"m7", "m8", "m9", "m10"};
        size_t value_lens4[]            = {2, 2, 2, 3};
        int i;

        RD_UT_BEGIN();

        rkshare = ut_create_test_share_consumer();
        RD_UT_ASSERT(rkshare, "Failed to create share consumer");

        rktp =
            ut_create_mock_toppar(rkshare->rkshare_rk, "test-topic-success", 0);
        RD_UT_ASSERT(rktp, "Failed to create toppar");

        response_q = rd_kafka_q_new(rkshare->rkshare_rk);
        buffer     = rd_calloc(1, buffer_size);

        /* Build 4 valid MessageSets */
        offset += ut_build_valid_msgset_v2(buffer + offset, 400, 2, values2,
                                           value_lens2);
        offset += ut_build_valid_msgset_v2(buffer + offset, 402, 3, values3,
                                           value_lens3);
        offset += ut_build_valid_msgset_v2(buffer + offset, 405, 1, &value1,
                                           &value_len1);
        offset += ut_build_valid_msgset_v2(buffer + offset, 406, 4, values4,
                                           value_lens4);

        /* Parse all MessageSets */
        rkbuf            = rd_kafka_buf_new_shadow(buffer, offset, rd_free);
        rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkshare->rkshare_rk);

        rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver, response_q);

        /* Verify all 10 messages received successfully (offsets 400-409) */
        for (i = 0; i < 10; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected FETCH op %d, got timeout",
                             i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_FETCH,
                             "Expected FETCH op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_u.fetch.rkm.rkm_offset == 400 + i,
                             "Expected offset %d, got %" PRId64, 400 + i,
                             rko->rko_u.fetch.rkm.rkm_offset);
                rd_kafka_op_destroy(rko);
        }

        /* Verify no extra ops */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 100, 0);
                RD_UT_ASSERT(rko == NULL, "Unexpected extra op");
        }

        rd_kafka_buf_destroy(rkbuf);
        rd_kafka_q_destroy_owner(response_q);
        rd_kafka_toppar_destroy(rktp);
        ut_destroy_share_consumer(rkshare);

        RD_UT_PASS();
}


/**
 * @brief Test all error MessageSets in sequence
 *
 * Verifies parser correctly handles consecutive errors:
 * - MessageSet 1: CRC error, 2 messages (offsets 500-501)
 * - MessageSet 2: Unsupported MagicByte, 1 message (offset 502)
 * - MessageSet 3: CRC error, 3 messages (offsets 503-505)
 */
static int unittest_msgset_all_errors(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_q_t *response_q;
        char *buffer;
        size_t buffer_size              = 4096;
        size_t offset                   = 0;
        struct rd_kafka_toppar_ver tver = {.version = 11};
        int i;

        RD_UT_BEGIN();

        rkshare = ut_create_test_share_consumer();
        RD_UT_ASSERT(rkshare, "Failed to create share consumer");

        rktp =
            ut_create_mock_toppar(rkshare->rkshare_rk, "test-topic-errors", 0);
        RD_UT_ASSERT(rktp, "Failed to create toppar");

        response_q = rd_kafka_q_new(rkshare->rkshare_rk);
        buffer     = rd_calloc(1, buffer_size);

        /* MessageSet 1: CRC error, 2 messages (offsets 500-501) */
        ut_write_msgset_v2_header(buffer + offset, 500, 61 - 12, -1, 2,
                                  0xBADC001, 0, 1, 0, 0, -1, -1, -1, 2);
        offset += 61;

        /* MessageSet 2: Unsupported MagicByte, 1 message (offset 502) */
        ut_write_msgset_v2_header(buffer + offset, 502, 61 - 12, -1, 99, 0, 0,
                                  0, 0, 0, -1, -1, -1, 1);
        offset += 61;

        /* MessageSet 3: CRC error, 3 messages (offsets 503-505) */
        ut_write_msgset_v2_header(buffer + offset, 503, 61 - 12, -1, 2,
                                  0xBADC002, 0, 2, 0, 0, -1, -1, -1, 3);
        offset += 61;

        RD_UT_SAY("Buffer size: %zu bytes", offset);

        /* Parse all MessageSets */
        rkbuf            = rd_kafka_buf_new_shadow(buffer, offset, rd_free);
        rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkshare->rkshare_rk);

        rd_kafka_resp_err_t parse_err =
            rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver, response_q);

        RD_UT_SAY("Parse returned: %s", rd_kafka_err2str(parse_err));

        /* Verify MessageSet 1: 2 CRC error ops (offsets 500-501) */
        for (i = 0; i < 2; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected CRC error op %d", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR");
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_MSG,
                             "Expected BAD_MSG");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 2: 1 unsupported magic error op (offset 502) */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected magic error op");
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR");
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__NOT_IMPLEMENTED,
                             "Expected NOT_IMPLEMENTED");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 3: 3 CRC error ops (offsets 503-505) */
        for (i = 0; i < 3; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected CRC error op %d", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR");
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_MSG,
                             "Expected BAD_MSG");
                rd_kafka_op_destroy(rko);
        }

        /* Verify no extra ops */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 100, 0);
                RD_UT_ASSERT(rko == NULL, "Unexpected extra op");
        }

        rd_kafka_buf_destroy(rkbuf);
        rd_kafka_q_destroy_owner(response_q);
        rd_kafka_toppar_destroy(rktp);
        ut_destroy_share_consumer(rkshare);

        RD_UT_PASS();
}


#if WITH_ZSTD
/**
 * @brief Test all 3 error types interleaved with valid messages
 *
 * Verifies parser continues through all error types:
 * - MessageSet 1: CRC error (10 messages, offsets 0-9)
 * - MessageSet 2: Valid (10 messages, offsets 10-19)
 * - MessageSet 3: Decompression error (10 messages, offsets 20-29)
 * - MessageSet 4: Valid (10 messages, offsets 30-39)
 * - MessageSet 5: Unsupported MagicByte (10 messages, offsets 40-49)
 * - MessageSet 6: Valid (10 messages, offsets 50-59)
 *
 * This is the critical test case: all batches must be processed,
 * with valid messages delivered even after errors.
 */
static int unittest_msgset_all_error_types_with_valid(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_q_t *response_q;
        char *buffer;
        size_t buffer_size              = 8192;
        size_t offset                   = 0;
        struct rd_kafka_toppar_ver tver = {.version = 11};
        const char *values[]            = {"a", "b", "c", "d", "e",
                                           "f", "g", "h", "i", "j"};
        size_t value_lens[]             = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        int i;

        RD_UT_BEGIN();

        rkshare = ut_create_test_share_consumer();
        RD_UT_ASSERT(rkshare, "Failed to create share consumer");

        rktp = ut_create_mock_toppar(rkshare->rkshare_rk,
                                     "test-topic-all-errors", 0);
        RD_UT_ASSERT(rktp, "Failed to create toppar");

        response_q = rd_kafka_q_new(rkshare->rkshare_rk);
        buffer     = rd_calloc(1, buffer_size);

        /* MessageSet 1: CRC error with 10 messages (offsets 0-9) */
        ut_write_msgset_v2_header(buffer + offset, 0, 100, -1, 2, 0xBADC0001, 0,
                                  9, 0, 0, -1, -1, -1, 10);
        offset += 112;

        /* MessageSet 2: Valid with 10 messages (offsets 10-19) */
        offset += ut_build_valid_msgset_v2(buffer + offset, 10, 10, values,
                                           value_lens);

        /* MessageSet 3: Decompression error with 10 messages (offsets 20-29) */
        char corrupted_data[32];
        memset(corrupted_data, 0xDE, sizeof(corrupted_data));
        size_t decomp_start = offset;
        ut_write_msgset_v2_header(buffer + offset, 20,
                                  49 + sizeof(corrupted_data), -1, 2, 0,
                                  4, /* ZSTD compression */
                                  9, 0, 0, -1, -1, -1, 10);
        offset += 61;
        memcpy(buffer + offset, corrupted_data, sizeof(corrupted_data));
        offset += sizeof(corrupted_data);
        /* Fix CRC for decompression error (CRC valid, data corrupt) */
        uint32_t crc = rd_crc32c(0, buffer + decomp_start + 21,
                                 49 + sizeof(corrupted_data) - 4 - 1 - 4);
        ut_put_be32(buffer + decomp_start + 17, crc);

        /* MessageSet 4: Valid with 10 messages (offsets 30-39) */
        offset += ut_build_valid_msgset_v2(buffer + offset, 30, 10, values,
                                           value_lens);

        /* MessageSet 5: Unsupported MagicByte with 10 messages (offsets 40-49)
         */
        ut_write_msgset_v2_header(buffer + offset, 40, 100, -1,
                                  99, /* Bad magic */
                                  0, 0, 9, 0, 0, -1, -1, -1, 10);
        offset += 112;

        /* MessageSet 6: Valid with 10 messages (offsets 50-59) */
        offset += ut_build_valid_msgset_v2(buffer + offset, 50, 10, values,
                                           value_lens);

        RD_UT_SAY("Total buffer size: %zu bytes, 6 MessageSets", offset);

        /* Parse all MessageSets */
        rkbuf            = rd_kafka_buf_new_shadow(buffer, offset, rd_free);
        rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkshare->rkshare_rk);

        rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver, response_q);

        /* Verify MessageSet 1: 10 CRC error ops (offsets 0-9) */
        RD_UT_SAY("Verifying MessageSet 1: CRC errors");
        for (i = 0; i < 10; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL,
                             "Expected CRC error op %d of 10, got timeout", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_MSG,
                             "Expected BAD_MSG, got %s",
                             rd_kafka_err2str(rko->rko_err));
                RD_UT_ASSERT(rko->rko_u.err.offset == 0 + i,
                             "Expected offset %d, got %" PRId64, i,
                             rko->rko_u.err.offset);
                RD_UT_ASSERT(rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                                 RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                             "Expected REJECT ack_type for CRC error");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 2: 10 successful FETCH ops (offsets 10-19) */
        RD_UT_SAY("Verifying MessageSet 2: Valid messages");
        for (i = 0; i < 10; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected FETCH op %d of 10", i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_FETCH,
                             "Expected FETCH op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_u.fetch.rkm.rkm_offset == 10 + i,
                             "Expected offset %d, got %" PRId64, 10 + i,
                             rko->rko_u.fetch.rkm.rkm_offset);
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 3: 10 decompression error ops (offsets 20-29) */
        RD_UT_SAY("Verifying MessageSet 3: Decompression errors");
        for (i = 0; i < 10; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected decomp error op %d of 10",
                             i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__BAD_COMPRESSION,
                             "Expected BAD_COMPRESSION, got %s",
                             rd_kafka_err2str(rko->rko_err));
                RD_UT_ASSERT(rko->rko_u.err.offset == 20 + i,
                             "Expected offset %d, got %" PRId64, 20 + i,
                             rko->rko_u.err.offset);
                RD_UT_ASSERT(
                    rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                        RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
                    "Expected RELEASE ack_type for decompression error");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 4: 10 successful FETCH ops (offsets 30-39) */
        RD_UT_SAY("Verifying MessageSet 4: Valid messages after decomp error");
        for (i = 0; i < 10; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL,
                             "Expected FETCH op %d of 10 after decomp error, "
                             "got timeout "
                             "(BUG: parser stopped!)",
                             i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_FETCH,
                             "Expected FETCH op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_u.fetch.rkm.rkm_offset == 30 + i,
                             "Expected offset %d, got %" PRId64, 30 + i,
                             rko->rko_u.fetch.rkm.rkm_offset);
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 5: 10 unsupported magic error ops (offsets 40-49)
         */
        RD_UT_SAY("Verifying MessageSet 5: Unsupported MagicByte errors");
        for (i = 0; i < 10; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(rko != NULL, "Expected magic error op %d of 10",
                             i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR,
                             "Expected CONSUMER_ERR, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_err == RD_KAFKA_RESP_ERR__NOT_IMPLEMENTED,
                             "Expected NOT_IMPLEMENTED, got %s",
                             rd_kafka_err2str(rko->rko_err));
                RD_UT_ASSERT(rko->rko_u.err.offset == 40 + i,
                             "Expected offset %d, got %" PRId64, 40 + i,
                             rko->rko_u.err.offset);
                RD_UT_ASSERT(rko->rko_u.err.rkm.rkm_u.consumer.ack_type ==
                                 RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                             "Expected REJECT ack_type for unsupported magic");
                rd_kafka_op_destroy(rko);
        }

        /* Verify MessageSet 6: 10 successful FETCH ops (offsets 50-59) */
        RD_UT_SAY("Verifying MessageSet 6: Valid messages after magic error");
        for (i = 0; i < 10; i++) {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 1000, 0);
                RD_UT_ASSERT(
                    rko != NULL,
                    "Expected FETCH op %d of 10 after magic error, got timeout "
                    "(BUG: parser stopped!)",
                    i);
                RD_UT_ASSERT(rko->rko_type == RD_KAFKA_OP_FETCH,
                             "Expected FETCH op, got %d", rko->rko_type);
                RD_UT_ASSERT(rko->rko_u.fetch.rkm.rkm_offset == 50 + i,
                             "Expected offset %d, got %" PRId64, 50 + i,
                             rko->rko_u.fetch.rkm.rkm_offset);
                rd_kafka_op_destroy(rko);
        }

        /* Verify no extra ops */
        {
                rd_kafka_op_t *rko = rd_kafka_q_pop(response_q, 100, 0);
                RD_UT_ASSERT(rko == NULL, "Unexpected extra op");
        }

        RD_UT_SAY(
            "SUCCESS: All 6 MessageSets processed correctly (60 ops total)");

        rd_kafka_buf_destroy(rkbuf);
        rd_kafka_q_destroy_owner(response_q);
        rd_kafka_toppar_destroy(rktp);
        ut_destroy_share_consumer(rkshare);

        RD_UT_PASS();
}
#endif /* WITH_ZSTD */


/**
 * @brief Run all MessageSet error handling unit tests
 */
int rd_kafka_unittest_msgset_errors(void) {
        int fails = 0;

        /* Individual error type tests */
        fails += unittest_msgset_crc_error_share_consumer();
#if WITH_ZSTD
        fails += unittest_msgset_decompression_error_share_consumer();
#endif
        fails += unittest_msgset_unsupported_magic_share_consumer();

        /* Mixed scenario tests */
        fails += unittest_msgset_mixed_success_crc_success();
#if WITH_ZSTD
        fails += unittest_msgset_mixed_crc_success_decomp();
#endif
        fails += unittest_msgset_mixed_magic_success_crc_success();
        fails += unittest_msgset_all_success();
        fails += unittest_msgset_all_errors();

        /* Comprehensive test: all error types with valid messages */
#if WITH_ZSTD
        fails += unittest_msgset_all_error_types_with_valid();
#endif

        return fails;
}
