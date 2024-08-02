/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
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

#if WITH_SOCKEM
/**
 * @name Test handling of message timeouts with the idempotent producer.
 *
 * - Set message timeout low.
 * - Set low socket send buffer, promote batching, and use large messages
 *   to make sure requests are partially sent.
 * - Produce a steady flow of messages
 * - After some time, set the sockem delay higher than the message timeout.
 * - Shortly after, remove the sockem delay.
 * - Verify that all messages were succesfully produced in order.
 *
 * https://github.com/confluentinc/confluent-kafka-dotnet/issues/704
 */

/*
 * Scenario:
 *
 * MsgSets: [ 1 | 2 | 3 | 4 | 5 | 6 ]
 *
 * 1. Producer sends MsgSets 1,2,3,4,5.
 * 2. Producer receives ack for MsgSet 1.
 * 3. Connection to broker goes down.
 * 4. The messages in MsgSet 2 are timed out by producer's timeout scanner.
 * 5. Connection to broker comes back up.
 * 6. Producer choices:
 * 6a. Reset the epoch and starting producing MsgSet 3 with reset sequence 0.
 *     Pros: instant recovery.
 *     Cons: a. If MsgSet 2 was persisted by the broker we now have desynch
 *           between producer and broker: Producer thinks the message failed,
 *           while broker wrote them to the log.
 *           b. If MsgSets 3,.. was also persisted then there will be duplicates
 *           as MsgSet 3 is produced with a reset sequence of 0.
 * 6b. Try to recover within the current epoch, the broker is expecting
 *     sequence 2, 3, 4, or 5, depending on what it managed to persist
 *     before the connection went down.
 *     The producer should produce msg 2 but it no longer exists due to timed
 * out. If lucky, only 2 was persisted by the broker, which means the Producer
 *     can successfully produce 3.
 *     If 3 was persisted the producer would get a DuplicateSequence error
 *     back, indicating that it was already produced, this would get
 *     the producer back in synch.
 *     If 2+ was not persisted an OutOfOrderSeq would be returned when 3
 *     is produced. The producer should be able to bump the epoch and
 *     start with Msg 3 as reset sequence 0 without risking loss or duplication.
 * 6c. Try to recover within the current epoch by draining the toppar
 *     and then adjusting its base msgid to the head-of-line message in
 *     the producer queue (after timed out messages were removed).
 *     This avoids bumping the epoch (which grinds all partitions to a halt
 *     while draining, and requires an extra roundtrip).
 *     It is tricky to get the adjustment value correct though.
 * 6d. Drain all partitions and then bump the epoch, resetting the base
 *     sequence to the first message in the queue.
 *     Pros: simple.
 *     Cons: will grind all partitions to a halt while draining.
 *
 * We chose to go with option 6d.
 */


#include <stdarg.h>
#include <errno.h>

#include "sockem_ctrl.h"

static struct {
        int dr_ok;
        int dr_fail;
        test_msgver_t mv_delivered;
} counters;


static void my_dr_msg_cb(rd_kafka_t *rk,
                         const rd_kafka_message_t *rkmessage,
                         void *opaque) {

        if (rd_kafka_message_status(rkmessage) >=
            RD_KAFKA_MSG_STATUS_POSSIBLY_PERSISTED)
                test_msgver_add_msg(rk, &counters.mv_delivered,
                                    (rd_kafka_message_t *)rkmessage);

        if (rkmessage->err) {
                counters.dr_fail++;
        } else {
                counters.dr_ok++;
        }
}

static int
is_fatal_cb(rd_kafka_t *rk, rd_kafka_resp_err_t err, const char *reason) {
        /* Ignore connectivity errors since we'll be bringing down
         * .. connectivity.
         * SASL auther will think a connection-down even in the auth
         * state means the broker doesn't support SASL PLAIN. */
        TEST_SAY("is_fatal?: %s: %s\n", rd_kafka_err2str(err), reason);
        if (err == RD_KAFKA_RESP_ERR__TRANSPORT ||
            err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN ||
            err == RD_KAFKA_RESP_ERR__AUTHENTICATION ||
            err == RD_KAFKA_RESP_ERR__TIMED_OUT)
                return 0;
        return 1;
}


static void do_test_produce_timeout(const char *topic, const int msgrate) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        uint64_t testid;
        rd_kafka_resp_err_t err;
        const int partition = RD_KAFKA_PARTITION_UA;
        int msgcnt          = msgrate * 20;
        const int msgsize   = 100 * 1000;
        sockem_ctrl_t ctrl;
        int msgcounter = 0;
        test_msgver_t mv;

        TEST_SAY(_C_BLU
                 "Test idempotent producer "
                 "with message timeouts (%d msgs/s)\n",
                 msgrate);

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 60);
        test_msgver_init(&counters.mv_delivered, testid);
        sockem_ctrl_init(&ctrl);

        test_conf_set(conf, "enable.idempotence", "true");
        test_conf_set(conf, "linger.ms", "300");
        test_conf_set(conf, "reconnect.backoff.ms", "2000");
        test_conf_set(conf, "socket.send.buffer.bytes", "10000");
        rd_kafka_conf_set_dr_msg_cb(conf, my_dr_msg_cb);

        test_socket_enable(conf);
        test_curr->is_fatal_cb = is_fatal_cb;

        rk  = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = test_create_producer_topic(rk, topic, "message.timeout.ms",
                                         "5000", NULL);

        /* Create the topic to make sure connections are up and ready. */
        err = test_auto_create_topic_rkt(rk, rkt, tmout_multip(5000));
        TEST_ASSERT(!err, "topic creation failed: %s", rd_kafka_err2str(err));

        /* After 1 seconds, set socket delay to 2*message.timeout.ms */
        sockem_ctrl_set_delay(&ctrl, 1000, 2 * 5000);

        /* After 3*message.timeout.ms seconds, remove delay. */
        sockem_ctrl_set_delay(&ctrl, 3 * 5000, 0);

        test_produce_msgs_nowait(rk, rkt, testid, partition, 0, msgcnt, NULL,
                                 msgsize, msgrate, &msgcounter);

        test_flush(rk, 3 * 5000);

        TEST_SAY("%d/%d messages produced, %d delivered, %d failed\n",
                 msgcounter, msgcnt, counters.dr_ok, counters.dr_fail);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        sockem_ctrl_term(&ctrl);

        TEST_SAY("Verifying %d delivered messages with consumer\n",
                 counters.dr_ok);

        test_msgver_init(&mv, testid);
        test_consume_msgs_easy_mv(NULL, topic, partition, testid, 1, -1, NULL,
                                  &mv);
        test_msgver_verify_compare("delivered", &mv, &counters.mv_delivered,
                                   TEST_MSGVER_ORDER | TEST_MSGVER_DUP |
                                       TEST_MSGVER_BY_MSGID |
                                       TEST_MSGVER_SUBSET);
        test_msgver_clear(&mv);
        test_msgver_clear(&counters.mv_delivered);


        TEST_SAY(_C_GRN
                 "Test idempotent producer "
                 "with message timeouts (%d msgs/s): SUCCESS\n",
                 msgrate);
}

int main_0094_idempotence_msg_timeout(int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);

        do_test_produce_timeout(topic, 10);

        if (test_quick) {
                TEST_SAY("Skipping further tests due to quick mode\n");
                return 0;
        }

        do_test_produce_timeout(topic, 100);

        return 0;
}
#endif
