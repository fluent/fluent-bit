/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
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

#include "test.h"
#include "rdkafka.h"

/**
 * @brief Verify handling of compacted topics.
 *
 * General idea:
 *  - create a compacted topic with a low cleanup interval to promote quick
 *    compaction.
 *  - produce messages for 3 keys and interleave with unkeyed messages.
 *    interleave tombstones for k1 and k2, but not k3.
 *  - consume before compaction - verify all messages in place
 *  - wait for compaction
 *  - consume after compaction - verify expected messages.
 */



/**
 * @brief Get low watermark in partition, we use this see if compaction
 *        has kicked in.
 */
static int64_t get_low_wmark (rd_kafka_t *rk, const char *topic,
                              int32_t partition) {
        rd_kafka_resp_err_t err;
        int64_t low, high;

        err = rd_kafka_query_watermark_offsets(rk, topic, partition,
                                               &low, &high,
                                               tmout_multip(10000));

        TEST_ASSERT(!err, "query_warmark_offsets(%s, %d) failed: %s",
                    topic, (int)partition, rd_kafka_err2str(err));

        return low;
}


/**
 * @brief Wait for compaction by checking for
 *        partition low-watermark increasing */
static void wait_compaction (rd_kafka_t *rk,
                             const char *topic, int32_t partition,
                             int64_t low_offset,
                             int timeout_ms) {
        int64_t low = -1;
        int64_t ts_start = test_clock();

        TEST_SAY("Waiting for compaction to kick in and increase the "
                 "Low watermark offset from %"PRId64" on %s [%"PRId32"]\n",
                 low_offset, topic, partition);

        while (1) {
                low = get_low_wmark(rk, topic, partition);

                TEST_SAY("Low watermark offset for %s [%"PRId32"] is "
                         "%"PRId64" (want > %"PRId64")\n",
                         topic, partition, low, low_offset);

                if (low > low_offset)
                        break;

                if (ts_start + (timeout_ms * 1000) < test_clock())
                        break;

                rd_sleep(5);
        }
}

static void produce_compactable_msgs (const char *topic, int32_t partition,
                                      uint64_t testid,
                                      int msgcnt, size_t msgsize) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        int i;
        char *val;
        char key[16];
        rd_kafka_resp_err_t err;
        int msgcounter = msgcnt;

        if (!testid)
                testid = test_id_generate();

        test_str_id_generate(key, sizeof(key));

        val = calloc(1, msgsize);

        TEST_SAY("Producing %d messages (total of %"PRIusz" bytes) of "
                 "compactable messages\n", msgcnt, (size_t)msgcnt*msgsize);

        test_conf_init(&conf, NULL, 0);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        /* Make sure batch size does not exceed segment.bytes since that
         * will make the ProduceRequest fail. */
        test_conf_set(conf, "batch.num.messages", "1");

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        for (i = 0 ; i < msgcnt-1 ; i++) {
                err = rd_kafka_producev(rk,
                                        RD_KAFKA_V_TOPIC(topic),
                                        RD_KAFKA_V_PARTITION(partition),
                                        RD_KAFKA_V_KEY(key, sizeof(key)-1),
                                        RD_KAFKA_V_VALUE(val, msgsize),
                                        RD_KAFKA_V_OPAQUE(&msgcounter),
                                        RD_KAFKA_V_END);
                TEST_ASSERT(!err, "producev(): %s", rd_kafka_err2str(err));
        }

        /* Final message is the tombstone */
        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_PARTITION(partition),
                                RD_KAFKA_V_KEY(key, sizeof(key)-1),
                                RD_KAFKA_V_OPAQUE(&msgcounter),
                                RD_KAFKA_V_END);
        TEST_ASSERT(!err, "producev(): %s", rd_kafka_err2str(err));

        test_flush(rk, tmout_multip(10000));
        TEST_ASSERT(msgcounter == 0, "%d messages unaccounted for", msgcounter);

        rd_kafka_destroy(rk);

        free(val);
}



static void do_test_compaction (int msgs_per_key, const char *compression) {
        const char *topic = test_mk_topic_name(__FILE__, 1);
#define _KEY_CNT 4
        const char *keys[_KEY_CNT] = { "k1", "k2", "k3", NULL/*generate unique*/ };
        int msgcnt = msgs_per_key * _KEY_CNT;
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        uint64_t testid;
        int32_t partition = 0;
        int cnt = 0;
        test_msgver_t mv;
        test_msgver_t mv_correct;
        int msgcounter = 0;
        const int fillcnt = 20;

        testid = test_id_generate();

        TEST_SAY(_C_MAG "Test compaction on topic %s with %s compression (%d messages)\n",
                 topic, compression ? compression : "no", msgcnt);

        test_kafka_topics("--create --topic \"%s\" "
                          "--partitions %d "
                          "--replication-factor 1 "
                          "--config cleanup.policy=compact "
                          "--config segment.ms=10000 "
                          "--config segment.bytes=10000 "
                          "--config min.cleanable.dirty.ratio=0.01 "
                          "--config delete.retention.ms=86400 "
                          "--config file.delete.delay.ms=10000",
                          topic, partition+1);

        test_conf_init(&conf, NULL, 120);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        if (compression)
                test_conf_set(conf, "compression.codec", compression);
        /* Limit max batch size below segment.bytes to avoid messages
         * to accumulate into a batch that will be rejected by the broker. */
        test_conf_set(conf, "message.max.bytes", "6000");
        test_conf_set(conf, "linger.ms", "10");
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = rd_kafka_topic_new(rk, topic, NULL);

        /* The low watermark is not updated on message deletion(compaction)
         * but on segment deletion, so fill up the first segment with
         * random messages eligible for hasty compaction. */
        produce_compactable_msgs(topic, 0, partition, fillcnt, 1000);

        /* Populate a correct msgver for later comparison after compact. */
        test_msgver_init(&mv_correct, testid);

        TEST_SAY("Producing %d messages for %d keys\n", msgcnt, _KEY_CNT);
        for (cnt = 0 ; cnt < msgcnt ; ) {
                int k;

                for (k = 0 ; k < _KEY_CNT ; k++) {
                        rd_kafka_resp_err_t err;
                        int is_last = cnt + _KEY_CNT >= msgcnt;
                        /* Let keys[0] have some tombstones */
                        int is_tombstone = (k == 0 && (is_last || !(cnt % 7)));
                        char *valp;
                        size_t valsize;
                        char rdk_msgid[256];
                        char unique_key[16];
                        const void *key;
                        size_t keysize;
                        int64_t offset = fillcnt + cnt;

                        test_msg_fmt(rdk_msgid, sizeof(rdk_msgid),
                                     testid, partition, cnt);

                        if (is_tombstone) {
                                valp = NULL;
                                valsize = 0;
                        } else {
                                valp = rdk_msgid;
                                valsize = strlen(valp);
                        }

                        if (!(key = keys[k])) {
                                rd_snprintf(unique_key, sizeof(unique_key),
                                            "%d", cnt);
                                key = unique_key;
                        }
                        keysize = strlen(key);

                        /* All unique-key messages should remain intact
                         * after compaction. */
                        if (!keys[k] || is_last) {
                                TEST_SAYL(4,
                                          "Add to correct msgvec: "
                                          "msgid: %d: %s is_last=%d, "
                                          "is_tomb=%d\n",
                                          cnt, (const char *)key,
                                          is_last, is_tombstone);
                                test_msgver_add_msg00(__FUNCTION__, __LINE__,
                                                      &mv_correct, testid,
                                                      topic, partition,
                                                      offset,  -1, 0, cnt);
                        }


                        msgcounter++;
                        err = rd_kafka_producev(
                                rk,
                                RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_PARTITION(0),
                                RD_KAFKA_V_KEY(key, keysize),
                                RD_KAFKA_V_VALUE(valp, valsize),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_HEADER("rdk_msgid", rdk_msgid, -1),
                                /* msgcounter as msg_opaque is used
                                 * by test delivery report callback to
                                 * count number of messages. */
                                RD_KAFKA_V_OPAQUE(&msgcounter),
                                RD_KAFKA_V_END);
                        TEST_ASSERT(!err, "producev(#%d) failed: %s",
                                    cnt, rd_kafka_err2str(err));

                        cnt++;
                }
        }

        TEST_ASSERT(cnt == msgcnt, "cnt %d != msgcnt %d", cnt, msgcnt);

        msgcounter = cnt;
        test_wait_delivery(rk, &msgcounter);

        /* Trigger compaction by filling up the segment with dummy messages,
         * do it in chunks to avoid too good compression which then won't
         * fill up the segments..
         * We can't reuse the existing producer instance because it
         * might be using compression which makes it hard to know how
         * much data we need to produce to trigger compaction. */
        produce_compactable_msgs(topic, 0, partition, 20, 1024);

        /* Wait for compaction:
         * this doesn't really work because the low watermark offset
         * is not updated on compaction if the first segment is not deleted.
         * But it serves as a pause to let compaction kick in
         * which is triggered by the dummy produce above. */
        wait_compaction(rk, topic, partition, 0, 20*1000);

        TEST_SAY(_C_YEL "Verify messages after compaction\n");
        /* After compaction we expect the following messages:
         * last message for each of k1, k2, k3, all messages for unkeyed. */
        test_msgver_init(&mv, testid);
        mv.msgid_hdr = "rdk_msgid";
        test_consume_msgs_easy_mv(NULL, topic, -1, testid, 1, -1, NULL, &mv);
        test_msgver_verify_compare("post-compaction", &mv, &mv_correct,
                                   TEST_MSGVER_BY_MSGID|TEST_MSGVER_BY_OFFSET);
        test_msgver_clear(&mv);

        test_msgver_clear(&mv_correct);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "Compaction test with %s compression: PASS\n",
                 compression ? compression : "no");
}

int main_0077_compaction (int argc, char **argv) {

        if (!test_can_create_topics(1))
                return 0;

        do_test_compaction(10, NULL);

        if (test_quick) {
                TEST_SAY("Skipping further compaction tests "
                         "due to quick mode\n");
                return 0;
        }

        do_test_compaction(1000, NULL);
#if WITH_SNAPPY
        do_test_compaction(10, "snappy");
#endif
#if WITH_ZSTD
        do_test_compaction(10, "zstd");
#endif
#if WITH_ZLIB
        do_test_compaction(10000, "gzip");
#endif

        return 0;
}
