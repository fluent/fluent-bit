/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2013, Magnus Edenhill
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
 * Tests messages are produced in order.
 */


#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"  /* for Kafka driver */


static int msgid_next = 0;
static int fails = 0;
static int msgcounter = 0;
static int *dr_partition_count = NULL;
static const int topic_num_partitions = 4;
static int msg_partition_wo_flag = 2;
static int msg_partition_wo_flag_success = 0;

/**
 * Delivery reported callback.
 * Called for each message once to signal its delivery status.
 */
static void dr_single_partition_cb (rd_kafka_t *rk, void *payload, size_t len,
                   rd_kafka_resp_err_t err, void *opaque, void *msg_opaque) {
        int msgid = *(int *)msg_opaque;

        free(msg_opaque);

        if (err != RD_KAFKA_RESP_ERR_NO_ERROR)
                TEST_FAIL("Message delivery failed: %s\n",
                          rd_kafka_err2str(err));

        if (msgid != msgid_next) {
                fails++;
                TEST_FAIL("Delivered msg %i, expected %i\n",
                         msgid, msgid_next);
                return;
        }

        msgid_next = msgid+1;
        msgcounter--;
}

/* Produce a batch of messages to a single partition. */
static void test_single_partition (void) {
        int partition = 0;
        int r;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *topic_conf;
        char msg[128];
        int msgcnt = test_quick ? 100 : 100000;
        int failcnt = 0;
        int i;
        rd_kafka_message_t *rkmessages;

        msgid_next = 0;

        test_conf_init(&conf, &topic_conf, 20);

        /* Set delivery report callback */
        rd_kafka_conf_set_dr_cb(conf, dr_single_partition_cb);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("test_single_partition: Created kafka instance %s\n",
                 rd_kafka_name(rk));

        rkt = rd_kafka_topic_new(rk, test_mk_topic_name("0011", 0),
                                 topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n",
                          rd_strerror(errno));

        /* Create messages */
        rkmessages = calloc(sizeof(*rkmessages), msgcnt);
        for (i = 0 ; i < msgcnt ; i++) {
                int *msgidp = malloc(sizeof(*msgidp));
                *msgidp = i;
                rd_snprintf(msg, sizeof(msg), "%s:%s test message #%i",
                         __FILE__, __FUNCTION__, i);

                rkmessages[i].payload  = rd_strdup(msg);
                rkmessages[i].len      = strlen(msg);
                rkmessages[i]._private = msgidp;
                rkmessages[i].partition = 2; /* Will be ignored since
                                              * RD_KAFKA_MSG_F_PARTITION
                                              * is not supplied. */
        }

        r = rd_kafka_produce_batch(rkt, partition, RD_KAFKA_MSG_F_FREE,
                                   rkmessages, msgcnt);

        /* Scan through messages to check for errors. */
        for (i = 0 ; i < msgcnt ; i++) {
                if (rkmessages[i].err) {
                        failcnt++;
                        if (failcnt < 100)
                                TEST_SAY("Message #%i failed: %s\n",
                                         i,
                                         rd_kafka_err2str(rkmessages[i].err));
                }
        }

        /* All messages should've been produced. */
        if (r < msgcnt) {
                TEST_SAY("Not all messages were accepted "
                         "by produce_batch(): %i < %i\n", r, msgcnt);
                if (msgcnt - r != failcnt)
                        TEST_SAY("Discrepency between failed messages (%i) "
                                 "and return value %i (%i - %i)\n",
                                 failcnt, msgcnt - r, msgcnt, r);
                TEST_FAIL("%i/%i messages failed\n", msgcnt - r, msgcnt);
        }

        free(rkmessages);
        TEST_SAY("Single partition: "
                 "Produced %i messages, waiting for deliveries\n", r);

        msgcounter = msgcnt;

        /* Wait for messages to be delivered */
        test_wait_delivery(rk, &msgcounter);

        if (fails)
                TEST_FAIL("%i failures, see previous errors", fails);

        if (msgid_next != msgcnt)
                TEST_FAIL("Still waiting for messages: next %i != end %i\n",
                          msgid_next, msgcnt);

        /* Destroy topic */
        rd_kafka_topic_destroy(rkt);

        /* Destroy rdkafka instance */
        TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
        rd_kafka_destroy(rk);

        return;
}



/**
 * Delivery reported callback.
 * Called for each message once to signal its delivery status.
 */
static void dr_partitioner_cb (rd_kafka_t *rk, void *payload, size_t len,
                   rd_kafka_resp_err_t err, void *opaque, void *msg_opaque) {
        int msgid = *(int *)msg_opaque;

        free(msg_opaque);

        if (err != RD_KAFKA_RESP_ERR_NO_ERROR)
                TEST_FAIL("Message delivery failed: %s\n",
                          rd_kafka_err2str(err));

        if (msgcounter <= 0)
                TEST_FAIL("Too many message dr_cb callback calls "
                          "(at msgid #%i)\n", msgid);
        msgcounter--;
}

/* Produce a batch of messages using random (default) partitioner */
static void test_partitioner (void) {
        int partition = RD_KAFKA_PARTITION_UA;
        int r;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *topic_conf;
        char msg[128];
        int msgcnt = test_quick ? 100 : 100000;
        int failcnt = 0;
        int i;
        rd_kafka_message_t *rkmessages;

        test_conf_init(&conf, &topic_conf, 30);

        /* Set delivery report callback */
        rd_kafka_conf_set_dr_cb(conf, dr_partitioner_cb);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("test_partitioner: Created kafka instance %s\n",
                 rd_kafka_name(rk));

        rkt = rd_kafka_topic_new(rk, test_mk_topic_name("0011", 0),
                                 topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n",
                          rd_strerror(errno));

        /* Create messages */
        rkmessages = calloc(sizeof(*rkmessages), msgcnt);
        for (i = 0 ; i < msgcnt ; i++) {
                int *msgidp = malloc(sizeof(*msgidp));
                *msgidp = i;
                rd_snprintf(msg, sizeof(msg), "%s:%s test message #%i",
                         __FILE__, __FUNCTION__, i);

                rkmessages[i].payload = rd_strdup(msg);
                rkmessages[i].len     = strlen(msg);
                rkmessages[i]._private = msgidp;
        }

        r = rd_kafka_produce_batch(rkt, partition, RD_KAFKA_MSG_F_FREE,
                                   rkmessages, msgcnt);

        /* Scan through messages to check for errors. */
        for (i = 0 ; i < msgcnt ; i++) {
                if (rkmessages[i].err) {
                        failcnt++;
                        if (failcnt < 100)
                                TEST_SAY("Message #%i failed: %s\n",
                                         i,
                                         rd_kafka_err2str(rkmessages[i].err));
                }
        }

        /* All messages should've been produced. */
        if (r < msgcnt) {
                TEST_SAY("Not all messages were accepted "
                         "by produce_batch(): %i < %i\n", r, msgcnt);
                if (msgcnt - r != failcnt)
                        TEST_SAY("Discrepency between failed messages (%i) "
                                 "and return value %i (%i - %i)\n",
                                 failcnt, msgcnt - r, msgcnt, r);
                TEST_FAIL("%i/%i messages failed\n", msgcnt - r, msgcnt);
        }

        free(rkmessages);
        TEST_SAY("Partitioner: "
                 "Produced %i messages, waiting for deliveries\n", r);

        msgcounter = msgcnt;
        /* Wait for messages to be delivered */
        test_wait_delivery(rk, &msgcounter);

        if (fails)
                TEST_FAIL("%i failures, see previous errors", fails);

        if (msgcounter != 0)
                TEST_FAIL("Still waiting for %i/%i messages\n",
                          msgcounter, msgcnt);

        /* Destroy topic */
        rd_kafka_topic_destroy(rkt);

        /* Destroy rdkafka instance */
        TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
        rd_kafka_destroy(rk);

        return;
}

static void
dr_per_message_partition_cb (rd_kafka_t *rk,
                             const rd_kafka_message_t *rkmessage,
                             void *opaque) {

        free(rkmessage->_private);

        if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR)
            TEST_FAIL("Message delivery failed: %s\n",
                      rd_kafka_err2str(rkmessage->err));

        if (msgcounter <= 0)
            TEST_FAIL("Too many message dr_cb callback calls "
                      "(at msg offset #%"PRId64")\n", rkmessage->offset);

        TEST_ASSERT(rkmessage->partition < topic_num_partitions);
        msgcounter--;

        dr_partition_count[rkmessage->partition]++;
}

/* Produce a batch of messages using with per message partition flag */
static void test_per_message_partition_flag (void) {
        int partition = 0;
        int r;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *topic_conf;
        char msg[128 + sizeof(__FILE__) + sizeof(__FUNCTION__)];
        int msgcnt = test_quick ? 100 : 1000;
        int failcnt = 0;
        int i;
        int *rkpartition_counts;
        rd_kafka_message_t *rkmessages;
        const char *topic_name;

        test_conf_init(&conf, &topic_conf, 30);

        /* Set delivery report callback */
        rd_kafka_conf_set_dr_msg_cb(conf, dr_per_message_partition_cb);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("test_per_message_partition_flag: Created kafka instance %s\n",
                 rd_kafka_name(rk));
        topic_name = test_mk_topic_name("0011_per_message_flag", 1);
        test_create_topic(rk, topic_name, topic_num_partitions, 1);

        rkt = rd_kafka_topic_new(rk, topic_name,
                                 topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n",
                          rd_strerror(errno));

        /* Create messages */
        rkpartition_counts = calloc(sizeof(int), topic_num_partitions);
        dr_partition_count = calloc(sizeof(int), topic_num_partitions);
        rkmessages = calloc(sizeof(*rkmessages), msgcnt);
        for (i = 0 ; i < msgcnt ; i++) {
                int *msgidp = malloc(sizeof(*msgidp));
                *msgidp = i;
                rd_snprintf(msg, sizeof(msg), "%s:%s test message #%i",
                            __FILE__, __FUNCTION__, i);

                rkmessages[i].payload = rd_strdup(msg);
                rkmessages[i].len     = strlen(msg);
                rkmessages[i]._private = msgidp;
                rkmessages[i].partition = jitter(0, topic_num_partitions - 1);
                rkpartition_counts[rkmessages[i].partition]++;
        }

        r = rd_kafka_produce_batch(rkt, partition,
                                   RD_KAFKA_MSG_F_PARTITION|RD_KAFKA_MSG_F_FREE,
                                   rkmessages, msgcnt);

        /* Scan through messages to check for errors. */
        for (i = 0 ; i < msgcnt ; i++) {
                if (rkmessages[i].err) {
                        failcnt++;
                        if (failcnt < 100)
                                TEST_SAY("Message #%i failed: %s\n",
                                         i,
                                         rd_kafka_err2str(rkmessages[i].err));
                }
        }

        /* All messages should've been produced. */
        if (r < msgcnt) {
                TEST_SAY("Not all messages were accepted "
                         "by produce_batch(): %i < %i\n", r, msgcnt);
                if (msgcnt - r != failcnt)
                        TEST_SAY("Discrepency between failed messages (%i) "
                                 "and return value %i (%i - %i)\n",
                                 failcnt, msgcnt - r, msgcnt, r);
                TEST_FAIL("%i/%i messages failed\n", msgcnt - r, msgcnt);
        }

        free(rkmessages);
        TEST_SAY("Per-message partition: "
                 "Produced %i messages, waiting for deliveries\n", r);

        msgcounter = msgcnt;
        /* Wait for messages to be delivered */
        test_wait_delivery(rk, &msgcounter);

        if (msgcounter != 0)
                TEST_FAIL("Still waiting for %i/%i messages\n",
                          msgcounter, msgcnt);

        for (i = 0; i < topic_num_partitions; i++) {
                if (dr_partition_count[i] != rkpartition_counts[i]) {
                        TEST_FAIL("messages were not sent to designated "
                                  "partitions expected messages %i in "
                                  "partition %i, but only "
                                  "%i messages were sent",
                                  rkpartition_counts[i],
                                  i, dr_partition_count[i]);
                }
        }

        free(rkpartition_counts);
        free(dr_partition_count);

        /* Destroy topic */
        rd_kafka_topic_destroy(rkt);

        /* Destroy rdkafka instance */
        TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
        rd_kafka_destroy(rk);

        return;
}

static void
dr_partitioner_wo_per_message_flag_cb (rd_kafka_t *rk,
                                       const rd_kafka_message_t *rkmessage,
                                       void *opaque) {
        free(rkmessage->_private);

        if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR)
                TEST_FAIL("Message delivery failed: %s\n",
                          rd_kafka_err2str(rkmessage->err));
        if (msgcounter <= 0)
                TEST_FAIL("Too many message dr_cb callback calls "
                          "(at msg offset #%"PRId64")\n", rkmessage->offset);
        if (rkmessage->partition != msg_partition_wo_flag)
                msg_partition_wo_flag_success = 1;
        msgcounter--;
}

/**
 * @brief Produce a batch of messages using partitioner
 *        without per message partition flag
 */
static void test_message_partitioner_wo_per_message_flag (void) {
        int partition = RD_KAFKA_PARTITION_UA;
        int r;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *topic_conf;
        char msg[128 + sizeof(__FILE__) + sizeof(__FUNCTION__)];
        int msgcnt = test_quick ? 100 : 1000;
        int failcnt = 0;
        int i;
        rd_kafka_message_t *rkmessages;

        test_conf_init(&conf, &topic_conf, 30);

        /* Set delivery report callback */
        rd_kafka_conf_set_dr_msg_cb(conf,
                                    dr_partitioner_wo_per_message_flag_cb);
        test_conf_set(conf, "sticky.partitioning.linger.ms", "0");

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("test_partitioner: Created kafka instance %s\n",
                 rd_kafka_name(rk));

        rkt = rd_kafka_topic_new(rk, test_mk_topic_name("0011", 0),
                                 topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n",
                        rd_strerror(errno));

        /* Create messages */
        rkmessages = calloc(sizeof(*rkmessages), msgcnt);
        for (i = 0 ; i < msgcnt ; i++) {
                int *msgidp = malloc(sizeof(*msgidp));
                *msgidp = i;
                rd_snprintf(msg, sizeof(msg), "%s:%s test message #%i",
                            __FILE__, __FUNCTION__, i);

                rkmessages[i].payload = rd_strdup(msg);
                rkmessages[i].len     = strlen(msg);
                rkmessages[i]._private = msgidp;
                rkmessages[i].partition = msg_partition_wo_flag;
        }

        r = rd_kafka_produce_batch(rkt, partition, RD_KAFKA_MSG_F_FREE,
                                   rkmessages, msgcnt);

        /* Scan through messages to check for errors. */
        for (i = 0 ; i < msgcnt ; i++) {
                if (rkmessages[i].err) {
                        failcnt++;
                        if (failcnt < 100)
                                TEST_SAY("Message #%i failed: %s\n",
                                         i,
                                         rd_kafka_err2str(rkmessages[i].err));
                }
        }

        /* All messages should've been produced. */
        if (r < msgcnt) {
                TEST_SAY("Not all messages were accepted "
                         "by produce_batch(): %i < %i\n", r, msgcnt);
                if (msgcnt - r != failcnt)
                        TEST_SAY("Discrepency between failed messages (%i) "
                                 "and return value %i (%i - %i)\n",
                                 failcnt, msgcnt - r, msgcnt, r);
                TEST_FAIL("%i/%i messages failed\n", msgcnt - r, msgcnt);
        }

        free(rkmessages);
        TEST_SAY("Partitioner: "
                 "Produced %i messages, waiting for deliveries\n", r);

        msgcounter = msgcnt;
        /* Wait for messages to be delivered */
        test_wait_delivery(rk, &msgcounter);

        if (fails)
                TEST_FAIL("%i failures, see previous errors", fails);

        if (msgcounter != 0)
                TEST_FAIL("Still waiting for %i/%i messages\n",
                          msgcounter, msgcnt);
        if (msg_partition_wo_flag_success == 0) {
                TEST_FAIL("partitioner was not used, all messages were sent to "
                          "message specified partition %i", i);
        }

        /* Destroy topic */
        rd_kafka_topic_destroy(rkt);

        /* Destroy rdkafka instance */
        TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
        rd_kafka_destroy(rk);

        return;
}


int main_0011_produce_batch (int argc, char **argv) {
        test_message_partitioner_wo_per_message_flag();
        test_single_partition();
        test_partitioner();
        if (test_can_create_topics(1))
                test_per_message_partition_flag();
        return 0;
}
