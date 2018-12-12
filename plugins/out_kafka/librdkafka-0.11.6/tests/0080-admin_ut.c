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
 * @brief Admin API local dry-run unit-tests.
 */

#define MY_SOCKET_TIMEOUT_MS 1500
#define MY_SOCKET_TIMEOUT_MS_STR "1500"



static mtx_t last_event_lock;
static cnd_t last_event_cnd;
static rd_kafka_event_t *last_event = NULL;

/**
 * @brief The background event callback is called automatically
 *        by librdkafka from a background thread.
 */
static void background_event_cb (rd_kafka_t *rk, rd_kafka_event_t *rkev,
                                 void *opaque) {
        mtx_lock(&last_event_lock);
        TEST_ASSERT(!last_event, "Multiple events seen in background_event_cb "
                    "(existing %s, new %s)",
                    rd_kafka_event_name(last_event), rd_kafka_event_name(rkev));
        last_event = rkev;
        mtx_unlock(&last_event_lock);
        cnd_broadcast(&last_event_cnd);
        rd_sleep(1);
}

static rd_kafka_event_t *wait_background_event_cb (void) {
        rd_kafka_event_t *rkev;
        mtx_lock(&last_event_lock);
        while (!(rkev = last_event))
                cnd_wait(&last_event_cnd, &last_event_lock);
        last_event = NULL;
        mtx_unlock(&last_event_lock);

        return rkev;
}


/**
 * @brief CreateTopics tests
 *
 *
 *
 */
static void do_test_CreateTopics (const char *what,
                                  rd_kafka_t *rk, rd_kafka_queue_t *useq,
                                  int with_background_event_cb,
                                  int with_options) {
        rd_kafka_queue_t *q = useq ? useq : rd_kafka_queue_new(rk);
#define MY_NEW_TOPICS_CNT 6
        rd_kafka_NewTopic_t *new_topics[MY_NEW_TOPICS_CNT];
        rd_kafka_AdminOptions_t *options = NULL;
        int exp_timeout = MY_SOCKET_TIMEOUT_MS;
        int i;
        char errstr[512];
        const char *errstr2;
        rd_kafka_resp_err_t err;
        test_timing_t timing;
        rd_kafka_event_t *rkev;
        const rd_kafka_CreateTopics_result_t *res;
        const rd_kafka_topic_result_t **restopics;
        size_t restopic_cnt;
        void *my_opaque = NULL, *opaque;

        TEST_SAY(_C_MAG "[ %s CreateTopics with %s, timeout %dms ]\n",
                 rd_kafka_name(rk), what, exp_timeout);

        /**
         * Construct NewTopic array with different properties for
         * different partitions.
         */
        for (i = 0 ; i < MY_NEW_TOPICS_CNT ; i++) {
                const char *topic = test_mk_topic_name(__FUNCTION__, 1);
                int num_parts = i * 51 + 1;
                int num_replicas = jitter(1, MY_NEW_TOPICS_CNT-1);
                int set_config = (i & 2);
                int set_replicas = !(i % 1);

                new_topics[i] = rd_kafka_NewTopic_new(topic,
                                                      num_parts,
                                                      set_replicas ? -1 :
                                                      num_replicas,
                                                      NULL, 0);

                if (set_config) {
                        /*
                         * Add various (unverified) configuration properties
                         */
                        err = rd_kafka_NewTopic_set_config(new_topics[i],
                                                           "dummy.doesntexist",
                                                           "butThere'sNothing "
                                                           "to verify that");
                        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

                        err = rd_kafka_NewTopic_set_config(new_topics[i],
                                                           "try.a.null.value",
                                                           NULL);
                        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

                        err = rd_kafka_NewTopic_set_config(new_topics[i],
                                                           "or.empty", "");
                        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
                }


                if (set_replicas) {
                        int32_t p;
                        int32_t replicas[MY_NEW_TOPICS_CNT];
                        int j;

                        for (j = 0 ; j < num_replicas ; j++)
                                replicas[j] = j;

                        /*
                         * Set valid replica assignments
                         */
                        for (p = 0 ; p < num_parts ; p++) {
                                /* Try adding an existing out of order,
                                 * should fail */
                                if (p == 1) {
                                        err = rd_kafka_NewTopic_set_replica_assignment(
                                                new_topics[i], p+1,
                                                replicas, num_replicas,
                                                errstr, sizeof(errstr));
                                        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                                                    "%s", rd_kafka_err2str(err));
                                }

                                err = rd_kafka_NewTopic_set_replica_assignment(
                                        new_topics[i], p,
                                        replicas, num_replicas,
                                        errstr, sizeof(errstr));
                                TEST_ASSERT(!err, "%s", errstr);
                        }

                        /* Try to add an existing partition, should fail */
                        err = rd_kafka_NewTopic_set_replica_assignment(
                                new_topics[i], 0,
                                replicas, num_replicas, NULL, 0);
                        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                                    "%s", rd_kafka_err2str(err));

                } else {
                        int32_t dummy_replicas[1] = {1};

                        /* Test invalid partition */
                        err = rd_kafka_NewTopic_set_replica_assignment(
                                new_topics[i], num_parts+1, dummy_replicas, 1,
                                errstr, sizeof(errstr));
                        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                                    "%s: %s", rd_kafka_err2str(err),
                                    err == RD_KAFKA_RESP_ERR_NO_ERROR ?
                                    "" : errstr);

                        /* Setting replicas with with default replicas != -1
                         * is an error. */
                        err = rd_kafka_NewTopic_set_replica_assignment(
                                new_topics[i], 0, dummy_replicas, 1,
                                errstr, sizeof(errstr));
                        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                                    "%s: %s", rd_kafka_err2str(err),
                                    err == RD_KAFKA_RESP_ERR_NO_ERROR ?
                                    "" : errstr);
                }
        }

        if (with_options) {
                options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ANY);

                exp_timeout = MY_SOCKET_TIMEOUT_MS * 2;
                err = rd_kafka_AdminOptions_set_request_timeout(
                        options, exp_timeout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

                my_opaque = (void *)123;
                rd_kafka_AdminOptions_set_opaque(options, my_opaque);
        }

        TIMING_START(&timing, "CreateTopics");
        TEST_SAY("Call CreateTopics, timeout is %dms\n", exp_timeout);
        rd_kafka_CreateTopics(rk, new_topics, MY_NEW_TOPICS_CNT,
                              options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        if (with_background_event_cb) {
                /* Result event will be triggered by callback from
                 * librdkafka background queue thread. */
                TIMING_START(&timing, "CreateTopics.wait_background_event_cb");
                rkev = wait_background_event_cb();
        } else {
                /* Poll result queue */
                TIMING_START(&timing, "CreateTopics.queue_poll");
                rkev = rd_kafka_queue_poll(q, exp_timeout + 1000);
        }

        TIMING_ASSERT_LATER(&timing, exp_timeout-100, exp_timeout+100);
        TEST_ASSERT(rkev != NULL, "expected result in %dms",
                    exp_timeout);
        TEST_SAY("CreateTopics: got %s in %.3fs\n",
                 rd_kafka_event_name(rkev),
                 TIMING_DURATION(&timing) / 1000.0f);

        /* Convert event to proper result */
        res = rd_kafka_event_CreateTopics_result(rkev);
        TEST_ASSERT(res, "expected CreateTopics_result, not %s",
                    rd_kafka_event_name(rkev));

        opaque = rd_kafka_event_opaque(rkev);
        TEST_ASSERT(opaque == my_opaque, "expected opaque to be %p, not %p",
                    my_opaque, opaque);

        /* Expecting error */
        err = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "expected CreateTopics to return error %s, not %s (%s)",
                    rd_kafka_err2str(RD_KAFKA_RESP_ERR__TIMED_OUT),
                    rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        /* Attempt to extract topics anyway, should return NULL. */
        restopics = rd_kafka_CreateTopics_result_topics(res, &restopic_cnt);
        TEST_ASSERT(!restopics && restopic_cnt == 0,
                    "expected no result_topics, got %p cnt %"PRIusz,
                    restopics, restopic_cnt);

        rd_kafka_event_destroy(rkev);

        rd_kafka_NewTopic_destroy_array(new_topics, MY_NEW_TOPICS_CNT);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);
}






/**
 * @brief DeleteTopics tests
 *
 *
 *
 */
static void do_test_DeleteTopics (const char *what,
                                  rd_kafka_t *rk, rd_kafka_queue_t *useq,
                                  int with_options) {
        rd_kafka_queue_t *q = useq ? useq : rd_kafka_queue_new(rk);
#define MY_DEL_TOPICS_CNT 4
        rd_kafka_DeleteTopic_t *del_topics[MY_DEL_TOPICS_CNT];
        rd_kafka_AdminOptions_t *options = NULL;
        int exp_timeout = MY_SOCKET_TIMEOUT_MS;
        int i;
        char errstr[512];
        const char *errstr2;
        rd_kafka_resp_err_t err;
        test_timing_t timing;
        rd_kafka_event_t *rkev;
        const rd_kafka_DeleteTopics_result_t *res;
        const rd_kafka_topic_result_t **restopics;
        size_t restopic_cnt;
        void *my_opaque = NULL, *opaque;

        TEST_SAY(_C_MAG "[ %s DeleteTopics with %s, timeout %dms ]\n",
                 rd_kafka_name(rk), what, exp_timeout);

        for (i = 0 ; i < MY_DEL_TOPICS_CNT ; i++)
                del_topics[i] = rd_kafka_DeleteTopic_new(test_mk_topic_name(__FUNCTION__, 1));

        if (with_options) {
                options = rd_kafka_AdminOptions_new(
                        rk, RD_KAFKA_ADMIN_OP_DELETETOPICS);

                exp_timeout = MY_SOCKET_TIMEOUT_MS * 2;
                err = rd_kafka_AdminOptions_set_request_timeout(
                        options, exp_timeout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

                if (useq) {
                        my_opaque = (void *)456;
                        rd_kafka_AdminOptions_set_opaque(options, my_opaque);
                }
        }

        TIMING_START(&timing, "DeleteTopics");
        TEST_SAY("Call DeleteTopics, timeout is %dms\n", exp_timeout);
        rd_kafka_DeleteTopics(rk, del_topics, MY_DEL_TOPICS_CNT,
                              options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /* Poll result queue */
        TIMING_START(&timing, "DeleteTopics.queue_poll");
        rkev = rd_kafka_queue_poll(q, exp_timeout + 1000);
        TIMING_ASSERT_LATER(&timing, exp_timeout-100, exp_timeout+100);
        TEST_ASSERT(rkev != NULL, "expected result in %dms", exp_timeout);
        TEST_SAY("DeleteTopics: got %s in %.3fs\n",
                 rd_kafka_event_name(rkev), TIMING_DURATION(&timing) / 1000.0f);

        /* Convert event to proper result */
        res = rd_kafka_event_DeleteTopics_result(rkev);
        TEST_ASSERT(res, "expected DeleteTopics_result, not %s",
                    rd_kafka_event_name(rkev));

        opaque = rd_kafka_event_opaque(rkev);
        TEST_ASSERT(opaque == my_opaque, "expected opaque to be %p, not %p",
                    my_opaque, opaque);

        /* Expecting error */
        err = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "expected DeleteTopics to return error %s, not %s (%s)",
                    rd_kafka_err2str(RD_KAFKA_RESP_ERR__TIMED_OUT),
                    rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        /* Attempt to extract topics anyway, should return NULL. */
        restopics = rd_kafka_DeleteTopics_result_topics(res, &restopic_cnt);
        TEST_ASSERT(!restopics && restopic_cnt == 0,
                    "expected no result_topics, got %p cnt %"PRIusz,
                    restopics, restopic_cnt);

        rd_kafka_event_destroy(rkev);

        rd_kafka_DeleteTopic_destroy_array(del_topics, MY_DEL_TOPICS_CNT);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);
}


/**
 * @brief Test a mix of APIs using the same replyq.
 *
 *  - Create topics A,B
 *  - Delete topic B
 *  - Create topic C
 *  - Create extra partitions for topic D
 */
static void do_test_mix (rd_kafka_t *rk, rd_kafka_queue_t *rkqu) {
        char *topics[] = { "topicA", "topicB", "topicC" };
        int cnt = 0;
        struct waiting {
                rd_kafka_event_type_t evtype;
                int seen;
        };
        struct waiting id1 = {RD_KAFKA_EVENT_CREATETOPICS_RESULT};
        struct waiting id2 = {RD_KAFKA_EVENT_DELETETOPICS_RESULT};
        struct waiting id3 = {RD_KAFKA_EVENT_CREATETOPICS_RESULT};
        struct waiting id4 = {RD_KAFKA_EVENT_CREATEPARTITIONS_RESULT};

        TEST_SAY(_C_MAG "[ Mixed mode test on %s]\n", rd_kafka_name(rk));

        test_CreateTopics_simple(rk, rkqu, topics, 2, 1, &id1);
        test_DeleteTopics_simple(rk, rkqu, &topics[1], 1, &id2);
        test_CreateTopics_simple(rk, rkqu, &topics[2], 1, 1, &id3);
        test_CreatePartitions_simple(rk, rkqu, "topicD", 15, &id4);

        while (cnt < 4) {
                rd_kafka_event_t *rkev;
                struct waiting *w;

                rkev = rd_kafka_queue_poll(rkqu, -1);
                TEST_ASSERT(rkev);

                TEST_SAY("Got event %s: %s\n",
                         rd_kafka_event_name(rkev),
                         rd_kafka_event_error_string(rkev));

                w = rd_kafka_event_opaque(rkev);
                TEST_ASSERT(w);

                TEST_ASSERT(w->evtype == rd_kafka_event_type(rkev),
                            "Expected evtype %d, not %d (%s)",
                            w->evtype, rd_kafka_event_type(rkev),
                            rd_kafka_event_name(rkev));

                TEST_ASSERT(w->seen == 0, "Duplicate results");

                w->seen++;
                cnt++;

                rd_kafka_event_destroy(rkev);
        }
}


/**
 * @brief Test AlterConfigs and DescribeConfigs
 */
static void do_test_configs (rd_kafka_t *rk, rd_kafka_queue_t *rkqu) {
#define MY_CONFRES_CNT RD_KAFKA_RESOURCE__CNT + 2
        rd_kafka_ConfigResource_t *configs[MY_CONFRES_CNT];
        rd_kafka_AdminOptions_t *options;
        rd_kafka_event_t *rkev;
        rd_kafka_resp_err_t err;
        const rd_kafka_AlterConfigs_result_t *res;
        const rd_kafka_ConfigResource_t **rconfigs;
        size_t rconfig_cnt;
        char errstr[128];
        int i;

        /* Check invalids */
        configs[0] = rd_kafka_ConfigResource_new(
                (rd_kafka_ResourceType_t)-1, "something");
        TEST_ASSERT(!configs[0]);

        configs[0] = rd_kafka_ConfigResource_new(
                (rd_kafka_ResourceType_t)0, NULL);
        TEST_ASSERT(!configs[0]);


        for (i = 0 ; i < MY_CONFRES_CNT ; i++) {
                int set_config = !(i % 2);

                /* librdkafka shall not limit the use of illogical
                 * or unknown settings, they are enforced by the broker. */
                configs[i] = rd_kafka_ConfigResource_new(
                        (rd_kafka_ResourceType_t)i, "3");
                TEST_ASSERT(configs[i] != NULL);

                if (set_config) {
                        rd_kafka_ConfigResource_set_config(configs[i],
                                                           "some.conf",
                                                           "which remains "
                                                           "unchecked");
                        rd_kafka_ConfigResource_set_config(configs[i],
                                                           "some.conf.null",
                                                           NULL);
                }
        }


        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ANY);
        err = rd_kafka_AdminOptions_set_request_timeout(options, 1000, errstr,
                                                        sizeof(errstr));
        TEST_ASSERT(!err, "%s", errstr);

        /* AlterConfigs */
        rd_kafka_AlterConfigs(rk, configs, MY_CONFRES_CNT,
                              options, rkqu);

        rkev = test_wait_admin_result(rkqu, RD_KAFKA_EVENT_ALTERCONFIGS_RESULT,
                                      2000);

        TEST_ASSERT(rd_kafka_event_error(rkev) == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "Expected timeout, not %s",
                    rd_kafka_event_error_string(rkev));

        res = rd_kafka_event_AlterConfigs_result(rkev);
        TEST_ASSERT(res);

        rconfigs = rd_kafka_AlterConfigs_result_resources(res, &rconfig_cnt);
        TEST_ASSERT(!rconfigs && !rconfig_cnt,
                    "Expected no result resources, got %"PRIusz,
                    rconfig_cnt);

        rd_kafka_event_destroy(rkev);

        /* DescribeConfigs: reuse same configs and options */
        rd_kafka_DescribeConfigs(rk, configs, MY_CONFRES_CNT,
                                 options, rkqu);

        rd_kafka_AdminOptions_destroy(options);
        rd_kafka_ConfigResource_destroy_array(configs, MY_CONFRES_CNT);

        rkev = test_wait_admin_result(rkqu,
                                      RD_KAFKA_EVENT_DESCRIBECONFIGS_RESULT,
                                      2000);

        TEST_ASSERT(rd_kafka_event_error(rkev) == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "Expected timeout, not %s",
                    rd_kafka_event_error_string(rkev));

        res = rd_kafka_event_DescribeConfigs_result(rkev);
        TEST_ASSERT(res);

        rconfigs = rd_kafka_DescribeConfigs_result_resources(res, &rconfig_cnt);
        TEST_ASSERT(!rconfigs && !rconfig_cnt,
                    "Expected no result resources, got %"PRIusz,
                    rconfig_cnt);

        rd_kafka_event_destroy(rkev);
}


/**
 * @brief Verify that an unclean rd_kafka_destroy() does not hang.
 */
static void do_test_unclean_destroy (rd_kafka_type_t cltype, int with_mainq) {
        rd_kafka_t *rk;
        char errstr[512];
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *q;
        rd_kafka_event_t *rkev;
        rd_kafka_DeleteTopic_t *topic;
        test_timing_t t_destroy;

        test_conf_init(&conf, NULL, 0);
        /* Remove brokers, if any, since this is a local test and we
         * rely on the controller not being found. */
        test_conf_set(conf, "bootstrap.servers", "");
        test_conf_set(conf, "socket.timeout.ms", "60000");

        rk = rd_kafka_new(cltype, conf, errstr, sizeof(errstr));
        TEST_ASSERT(rk, "kafka_new(%d): %s", cltype, errstr);

        TEST_SAY(_C_MAG "[ Test unclean destroy for %s using %s]\n", rd_kafka_name(rk),
                 with_mainq ? "mainq" : "tempq");

        if (with_mainq)
                q = rd_kafka_queue_get_main(rk);
        else
                q = rd_kafka_queue_new(rk);

        topic = rd_kafka_DeleteTopic_new("test");
        rd_kafka_DeleteTopics(rk, &topic, 1, NULL, q);
        rd_kafka_DeleteTopic_destroy(topic);

        /* We're not expecting a result yet since DeleteTopics will attempt
         * to look up the controller for socket.timeout.ms (1 minute). */
        rkev = rd_kafka_queue_poll(q, 100);
        TEST_ASSERT(!rkev, "Did not expect result: %s", rd_kafka_event_name(rkev));

        rd_kafka_queue_destroy(q);

        TEST_SAY("Giving rd_kafka_destroy() 5s to finish, "
                 "despite Admin API request being processed\n");
        test_timeout_set(5);
        TIMING_START(&t_destroy, "rd_kafka_destroy()");
        rd_kafka_destroy(rk);
        TIMING_STOP(&t_destroy);

        /* Restore timeout */
        test_timeout_set(60);
}


/**
 * @brief Test AdminOptions
 */
static void do_test_options (rd_kafka_t *rk) {
#define _all_apis { RD_KAFKA_ADMIN_OP_CREATETOPICS, \
                    RD_KAFKA_ADMIN_OP_DELETETOPICS, \
                    RD_KAFKA_ADMIN_OP_CREATEPARTITIONS, \
                    RD_KAFKA_ADMIN_OP_ALTERCONFIGS, \
                    RD_KAFKA_ADMIN_OP_DESCRIBECONFIGS, \
                    RD_KAFKA_ADMIN_OP_ANY /* Must be last */}
        struct {
                const char *setter;
                const rd_kafka_admin_op_t valid_apis[8];
        } matrix[] = {
                { "request_timeout", _all_apis },
                { "operation_timeout", { RD_KAFKA_ADMIN_OP_CREATETOPICS,
                                         RD_KAFKA_ADMIN_OP_DELETETOPICS,
                                         RD_KAFKA_ADMIN_OP_CREATEPARTITIONS } },
                { "validate_only", { RD_KAFKA_ADMIN_OP_CREATETOPICS,
                                     RD_KAFKA_ADMIN_OP_CREATEPARTITIONS,
                                     RD_KAFKA_ADMIN_OP_ALTERCONFIGS } },
                { "broker", _all_apis },
                { "opaque", _all_apis },
                { NULL },
        };
        int i;
        rd_kafka_AdminOptions_t *options;


        for (i = 0 ; matrix[i].setter ; i++) {
                static const rd_kafka_admin_op_t all_apis[] = _all_apis;
                const rd_kafka_admin_op_t *for_api;

                for (for_api = all_apis ; ; for_api++) {
                        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
                        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
                        char errstr[512];
                        int fi;

                        options = rd_kafka_AdminOptions_new(rk, *for_api);
                        TEST_ASSERT(options,
                                    "AdminOptions_new(%d) failed", *for_api);

                        if (!strcmp(matrix[i].setter, "request_timeout"))
                                err = rd_kafka_AdminOptions_set_request_timeout(
                                        options, 1234, errstr, sizeof(errstr));
                        else if (!strcmp(matrix[i].setter, "operation_timeout"))
                                err = rd_kafka_AdminOptions_set_operation_timeout(
                                        options, 12345, errstr, sizeof(errstr));
                        else if (!strcmp(matrix[i].setter, "validate_only"))
                                err = rd_kafka_AdminOptions_set_validate_only(
                                        options, 1, errstr, sizeof(errstr));
                        else if (!strcmp(matrix[i].setter, "broker"))
                                err = rd_kafka_AdminOptions_set_broker(
                                        options, 5, errstr, sizeof(errstr));
                        else if (!strcmp(matrix[i].setter, "opaque")) {
                                rd_kafka_AdminOptions_set_opaque(
                                        options, (void *)options);
                                err = RD_KAFKA_RESP_ERR_NO_ERROR;
                        } else
                                TEST_FAIL("Invalid setter: %s",
                                          matrix[i].setter);


                        TEST_SAYL(3, "AdminOptions_set_%s on "
                                  "RD_KAFKA_ADMIN_OP_%d options "
                                  "returned %s: %s\n",
                                  matrix[i].setter,
                                  *for_api,
                                  rd_kafka_err2name(err),
                                  err ? errstr : "success");

                        /* Scan matrix valid_apis to see if this
                         * setter should be accepted or not. */
                        if (exp_err) {
                                /* An expected error is already set */
                        } else if (*for_api != RD_KAFKA_ADMIN_OP_ANY) {
                                exp_err = RD_KAFKA_RESP_ERR__INVALID_ARG;

                                for (fi = 0 ; matrix[i].valid_apis[fi] ; fi++) {
                                        if (matrix[i].valid_apis[fi] ==
                                            *for_api)
                                                exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
                                }
                        } else {
                                exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
                        }

                        if (err != exp_err)
                                TEST_FAIL_LATER("Expected AdminOptions_set_%s "
                                                "for RD_KAFKA_ADMIN_OP_%d "
                                                "options to return %s, "
                                                "not %s",
                                                matrix[i].setter,
                                                *for_api,
                                                rd_kafka_err2name(exp_err),
                                                rd_kafka_err2name(err));

                        rd_kafka_AdminOptions_destroy(options);

                        if (*for_api == RD_KAFKA_ADMIN_OP_ANY)
                                break; /* This was the last one */
                }
        }

        /* Try an invalid for_api */
        options = rd_kafka_AdminOptions_new(rk, (rd_kafka_admin_op_t)1234);
        TEST_ASSERT(!options, "Expectred AdminOptions_new() to fail "
                    "with an invalid for_api, didn't.");

        TEST_LATER_CHECK();
}


static void do_test_apis (rd_kafka_type_t cltype) {
        rd_kafka_t *rk;
        char errstr[512];
        rd_kafka_queue_t *mainq, *backgroundq;
        rd_kafka_conf_t *conf;

        mtx_init(&last_event_lock, mtx_plain);
        cnd_init(&last_event_cnd);

        do_test_unclean_destroy(cltype, 0/*tempq*/);
        do_test_unclean_destroy(cltype, 1/*mainq*/);

        test_conf_init(&conf, NULL, 0);
        /* Remove brokers, if any, since this is a local test and we
         * rely on the controller not being found. */
        test_conf_set(conf, "bootstrap.servers", "");
        test_conf_set(conf, "socket.timeout.ms", MY_SOCKET_TIMEOUT_MS_STR);
        /* For use with the background queue */
        rd_kafka_conf_set_background_event_cb(conf, background_event_cb);

        rk = rd_kafka_new(cltype, conf, errstr, sizeof(errstr));
        TEST_ASSERT(rk, "kafka_new(%d): %s", cltype, errstr);

        mainq = rd_kafka_queue_get_main(rk);
        backgroundq = rd_kafka_queue_get_background(rk);

        do_test_options(rk);

        do_test_CreateTopics("temp queue, no options", rk, NULL, 0, 0);
        do_test_CreateTopics("temp queue, no options, background_event_cb",
                             rk, backgroundq, 1, 0);
        do_test_CreateTopics("temp queue, options", rk, NULL, 0, 1);
        do_test_CreateTopics("main queue, options", rk, mainq, 0, 1);

        do_test_DeleteTopics("temp queue, no options", rk, NULL, 0);
        do_test_DeleteTopics("temp queue, options", rk, NULL, 1);
        do_test_DeleteTopics("main queue, options", rk, mainq, 1);

        do_test_mix(rk, mainq);

        do_test_configs(rk, mainq);

        rd_kafka_queue_destroy(backgroundq);
        rd_kafka_queue_destroy(mainq);

        rd_kafka_destroy(rk);

        mtx_destroy(&last_event_lock);
        cnd_destroy(&last_event_cnd);

}


int main_0080_admin_ut (int argc, char **argv) {
        do_test_apis(RD_KAFKA_PRODUCER);
        do_test_apis(RD_KAFKA_CONSUMER);
        return 0;
}
