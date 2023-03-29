/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019, Magnus Edenhill
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
 * Idempotent Producer example.
 *
 * The idempotent producer provides strict ordering and
 * exactly-once producing guarantees.
 *
 * From the application developer's perspective, the only difference
 * from a standard producer is the enabling of the feature by setting
 * the `enable.idempotence` configuration property to `true`, and
 * handling fatal (RD_KAFKA_RESP_ERR__FATAL) errors which are raised when
 * the idempotent guarantees can't be satisfied.
 */

#define _DEFAULT_SOURCE /* avoid glibc deprecation warning of _BSD_SOURCE */
#define _BSD_SOURCE     /* vsnprintf() */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>


/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is builtin from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"


static volatile sig_atomic_t run = 1;

/**
 * @brief Signal termination of program
 */
static void stop(int sig) {
        run = 0;
}


static int deliveredcnt = 0;
static int msgerrcnt    = 0;

/**
 * @brief Message delivery report callback.
 *
 * This callback is called exactly once per message, indicating if
 * the message was succesfully delivered
 * (rkmessage->err == RD_KAFKA_RESP_ERR_NO_ERROR) or permanently
 * failed delivery (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR).
 *
 * The callback is triggered from rd_kafka_poll() or rd_kafka_flush() and
 * executes on the application's thread.
 */
static void
dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
        if (rkmessage->err) {
                fprintf(stderr, "%% Message delivery failed: %s\n",
                        rd_kafka_err2str(rkmessage->err));
                msgerrcnt++;
        } else {
                fprintf(stderr,
                        "%% Message delivered (%zd bytes, topic %s, "
                        "partition %" PRId32 ", offset %" PRId64 ")\n",
                        rkmessage->len, rd_kafka_topic_name(rkmessage->rkt),
                        rkmessage->partition, rkmessage->offset);
                deliveredcnt++;
        }

        /* The rkmessage is destroyed automatically by librdkafka */
}


/**
 * @brief Generic error handling callback.
 *
 * This callback is triggered by rd_kafka_poll() or rd_kafka_flush()
 * for client instance-level errors, such as broker connection failures,
 * authentication issues, etc.
 *
 * These errors should generally be considered informational as
 * the underlying client will automatically try to recover from
 * any errors encountered, the application does not need to take
 * action on them.
 *
 * But with idempotence truly fatal errors can be raised when
 * the idempotence guarantees can't be satisfied, these errors
 * are identified by a the `RD_KAFKA_RESP_ERR__FATAL` error code.
 */
static void
error_cb(rd_kafka_t *rk, int err, const char *reason, void *opaque) {
        rd_kafka_resp_err_t orig_err;
        char errstr[512];

        fprintf(stderr, "%% Error: %s: %s\n", rd_kafka_err2name(err), reason);

        if (err != RD_KAFKA_RESP_ERR__FATAL)
                return;

        /* Fatal error handling.
         *
         * When a fatal error is detected by the producer instance,
         * it will trigger an error_cb with ERR__FATAL set.
         * The application should use rd_kafka_fatal_error() to extract
         * the actual underlying error code and description, propagate it
         * to the user (for troubleshooting), and then terminate the
         * producer since it will no longer accept any new messages to
         * produce().
         *
         * Note:
         *   After a fatal error has been raised, rd_kafka_produce*() will
         *   fail with the original error code.
         *
         * Note:
         *   As an alternative to an error_cb, the application may call
         *   rd_kafka_fatal_error() at any time to check if a fatal error
         *   has occurred, typically after a failing rd_kafka_produce*() call.
         */

        orig_err = rd_kafka_fatal_error(rk, errstr, sizeof(errstr));
        fprintf(stderr, "%% FATAL ERROR: %s: %s\n", rd_kafka_err2name(orig_err),
                errstr);

        /* Clean termination to get delivery results (from rd_kafka_flush())
         * for all outstanding/in-transit/queued messages. */
        fprintf(stderr, "%% Terminating on fatal error\n");
        run = 0;
}


int main(int argc, char **argv) {
        rd_kafka_t *rk;          /* Producer instance handle */
        rd_kafka_conf_t *conf;   /* Temporary configuration object */
        char errstr[512];        /* librdkafka API error reporting buffer */
        rd_kafka_resp_err_t err; /* librdkafka API error code */
        const char *brokers;     /* Argument: broker list */
        const char *topic;       /* Argument: topic to produce to */
        int msgcnt = 0;          /* Number of messages produced */

        /*
         * Argument validation
         */
        if (argc != 3) {
                fprintf(stderr, "%% Usage: %s <broker> <topic>\n", argv[0]);
                return 1;
        }

        brokers = argv[1];
        topic   = argv[2];


        /*
         * Create Kafka client configuration place-holder
         */
        conf = rd_kafka_conf_new();

        /* Set bootstrap broker(s) as a comma-separated list of
         * host or host:port (default port 9092).
         * librdkafka will use the bootstrap brokers to acquire the full
         * set of brokers from the cluster. */
        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%s\n", errstr);
                rd_kafka_conf_destroy(conf);
                return 1;
        }

        /* Enable the idempotent producer */
        if (rd_kafka_conf_set(conf, "enable.idempotence", "true", errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%s\n", errstr);
                rd_kafka_conf_destroy(conf);
                return 1;
        }

        /* Set the delivery report callback.
         * This callback will be called once per message to inform
         * the application if delivery succeeded or failed.
         * See dr_msg_cb() above. */
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

        /* Set an error handler callback to catch generic instance-level
         * errors.
         *
         * See the `error_cb()` handler above for how to handle the
         * fatal errors.
         */
        rd_kafka_conf_set_error_cb(conf, error_cb);


        /*
         * Create producer instance.
         *
         * NOTE: rd_kafka_new() takes ownership of the conf object
         *       and the application must not reference it again after
         *       this call.
         */
        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        if (!rk) {
                fprintf(stderr, "%% Failed to create new producer: %s\n",
                        errstr);
                return 1;
        }

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        fprintf(stderr, "%% Running producer loop. Press Ctrl-C to exit\n");

        while (run) {
                char buf[64];

                snprintf(buf, sizeof(buf),
                         "Idempotent Producer example message #%d", msgcnt);

                /*
                 * Produce message.
                 * This is an asynchronous call, on success it will only
                 * enqueue the message on the internal producer queue.
                 * The actual delivery attempts to the broker are handled
                 * by background threads.
                 * The previously registered delivery report callback
                 * (dr_msg_cb) is used to signal back to the application
                 * when the message has been delivered (or failed),
                 * and is triggered when the application calls
                 * rd_kafka_poll() or rd_kafka_flush().
                 */
        retry:
                err = rd_kafka_producev(
                    rk, RD_KAFKA_V_TOPIC(topic),
                    RD_KAFKA_V_VALUE(buf, strlen(buf)),
                    /* Copy the message payload so the `buf` can
                     * be reused for the next message. */
                    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY), RD_KAFKA_V_END);

                if (err) {
                        /**
                         * Failed to *enqueue* message for producing.
                         */
                        fprintf(stderr,
                                "%% Failed to produce to topic %s: %s\n", topic,
                                rd_kafka_err2str(err));

                        if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
                                /* If the internal queue is full, wait for
                                 * messages to be delivered and then retry.
                                 * The internal queue represents both
                                 * messages to be sent and messages that have
                                 * been sent or failed, awaiting their
                                 * delivery report callback to be called.
                                 *
                                 * The internal queue is limited by the
                                 * configuration property
                                 * queue.buffering.max.messages */
                                rd_kafka_poll(rk,
                                              1000 /*block for max 1000ms*/);
                                goto retry;
                        } else {
                                /* Produce failed, most likely due to a
                                 * fatal error (will be handled by error_cb()),
                                 * bail out. */

                                /* Instead of using the error_cb(), an
                                 * application may check for fatal errors here
                                 * by calling rd_kafka_fatal_error(). */
                                break;
                        }
                }

                /* A producer application should continually serve
                 * the delivery report queue by calling rd_kafka_poll()
                 * at frequent intervals.
                 * Either put the poll call in your main loop, or in a
                 * dedicated thread, or call it after or before every
                 * rd_kafka_produce*() call.
                 * Just make sure that rd_kafka_poll() is still called
                 * during periods where you are not producing any messages
                 * to make sure previously produced messages have their
                 * delivery report callback served (and any other callbacks
                 * you register). */
                rd_kafka_poll(rk, 0 /*non-blocking*/);

                msgcnt++;

                /* Since fatal errors can't be triggered in practice,
                 * use the test API to trigger a fabricated error after
                 * some time. */
                if (msgcnt == 13)
                        rd_kafka_test_fatal_error(
                            rk, RD_KAFKA_RESP_ERR_OUT_OF_ORDER_SEQUENCE_NUMBER,
                            "This is a fabricated error to test the "
                            "fatal error handling");

                /* Short sleep to rate-limit this example.
                 * A real application should not do this. */
                usleep(500 * 1000); /* 500ms */
        }


        /* Wait for final messages to be delivered or fail.
         * rd_kafka_flush() is an abstraction over rd_kafka_poll() which
         * waits for all messages to be delivered. */
        fprintf(stderr, "%% Flushing outstanding messages..\n");
        rd_kafka_flush(rk, 10 * 1000 /* wait for max 10 seconds */);
        fprintf(stderr, "%% %d message(s) produced, %d delivered, %d failed\n",
                msgcnt, deliveredcnt, msgerrcnt);

        /* Save fatal error prior for using with exit status below. */
        err = rd_kafka_fatal_error(rk, NULL, 0);

        /* Destroy the producer instance */
        rd_kafka_destroy(rk);

        /* Exit application with an error (1) if there was a fatal error. */
        if (err)
                return 1;
        else
                return 0;
}
