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

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


/**
 * List consumer groups
 *
 * Runs two consumers in two different groups and lists them.
 */



/**
 * Verify that all groups in 'groups' are seen, if so returns group_cnt,
 * else returns -1.
 */
static int verify_groups(const struct rd_kafka_group_list *grplist,
                         char **groups,
                         int group_cnt) {
        int i;
        int seen = 0;

        for (i = 0; i < grplist->group_cnt; i++) {
                const struct rd_kafka_group_info *gi = &grplist->groups[i];
                int j;

                for (j = 0; j < group_cnt; j++) {
                        if (strcmp(gi->group, groups[j]))
                                continue;

                        if (gi->err)
                                TEST_SAY(
                                    "Group %s has broker-reported "
                                    "error: %s\n",
                                    gi->group, rd_kafka_err2str(gi->err));

                        seen++;
                }
        }

        TEST_SAY("Found %d/%d desired groups in list of %d groups\n", seen,
                 group_cnt, grplist->group_cnt);

        if (seen != group_cnt)
                return -1;
        else
                return seen;
}


/**
 * List groups by:
 *   - List all groups, check that the groups in 'groups' are seen.
 *   - List each group in 'groups', one by one.
 *
 * Returns 'group_cnt' if all groups in 'groups' were seen by both
 * methods, else 0, or -1 on error.
 */
static int
list_groups(rd_kafka_t *rk, char **groups, int group_cnt, const char *desc) {
        rd_kafka_resp_err_t err = 0;
        const struct rd_kafka_group_list *grplist;
        int i, r;
        int fails    = 0;
        int seen     = 0;
        int seen_all = 0;
        int retries  = 5;

        TEST_SAY("List groups (expect %d): %s\n", group_cnt, desc);

        /* FIXME: Wait for broker to come up. This should really be abstracted
         *        by librdkafka. */
        do {
                if (err) {
                        TEST_SAY("Retrying group list in 1s because of: %s\n",
                                 rd_kafka_err2str(err));
                        rd_sleep(1);
                }
                err = rd_kafka_list_groups(rk, NULL, &grplist,
                                           tmout_multip(5000));
        } while ((err == RD_KAFKA_RESP_ERR__TRANSPORT ||
                  err == RD_KAFKA_RESP_ERR_GROUP_LOAD_IN_PROGRESS) &&
                 retries-- > 0);

        if (err) {
                TEST_SAY("Failed to list all groups: %s\n",
                         rd_kafka_err2str(err));
                return -1;
        }

        seen_all = verify_groups(grplist, groups, group_cnt);
        rd_kafka_group_list_destroy(grplist);

        for (i = 0; i < group_cnt; i++) {
                err = rd_kafka_list_groups(rk, groups[i], &grplist, 5000);
                if (err) {
                        TEST_SAY("Failed to list group %s: %s\n", groups[i],
                                 rd_kafka_err2str(err));
                        fails++;
                        continue;
                }

                r = verify_groups(grplist, &groups[i], 1);
                if (r == 1)
                        seen++;
                rd_kafka_group_list_destroy(grplist);
        }


        if (seen_all != seen)
                return 0;

        return seen;
}



static void do_test_list_groups(void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
#define _CONS_CNT 2
        char *groups[_CONS_CNT];
        rd_kafka_t *rk, *rk_c[_CONS_CNT];
        rd_kafka_topic_partition_list_t *topics;
        rd_kafka_resp_err_t err;
        test_timing_t t_grps;
        int i;
        int groups_seen;
        rd_kafka_topic_t *rkt;
        const struct rd_kafka_group_list *grplist;

        SUB_TEST();

        /* Handle for group listings */
        rk = test_create_producer();

        /* Produce messages so that topic is auto created */
        rkt = test_create_topic_object(rk, topic, NULL);
        test_produce_msgs(rk, rkt, 0, 0, 0, 10, NULL, 64);
        rd_kafka_topic_destroy(rkt);

        /* Query groups before creation, should not list our groups. */
        groups_seen = list_groups(rk, NULL, 0, "should be none");
        if (groups_seen != 0)
                TEST_FAIL(
                    "Saw %d groups when there wasn't "
                    "supposed to be any\n",
                    groups_seen);

        /* Fill in topic subscription set */
        topics = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(topics, topic, -1);

        /* Create consumers and start subscription */
        for (i = 0; i < _CONS_CNT; i++) {
                groups[i] = malloc(32);
                test_str_id_generate(groups[i], 32);
                rk_c[i] = test_create_consumer(groups[i], NULL, NULL, NULL);

                err = rd_kafka_poll_set_consumer(rk_c[i]);
                if (err)
                        TEST_FAIL("poll_set_consumer: %s\n",
                                  rd_kafka_err2str(err));

                err = rd_kafka_subscribe(rk_c[i], topics);
                if (err)
                        TEST_FAIL("subscribe: %s\n", rd_kafka_err2str(err));
        }

        rd_kafka_topic_partition_list_destroy(topics);


        TIMING_START(&t_grps, "WAIT.GROUPS");
        /* Query groups again until both groups are seen. */
        while (1) {
                groups_seen = list_groups(rk, (char **)groups, _CONS_CNT,
                                          "should see my groups");
                if (groups_seen == _CONS_CNT)
                        break;
                rd_sleep(1);
        }
        TIMING_STOP(&t_grps);

        /* Try a list_groups with a low enough timeout to fail. */
        grplist = NULL;
        TIMING_START(&t_grps, "WAIT.GROUPS.TIMEOUT0");
        err = rd_kafka_list_groups(rk, NULL, &grplist, 0);
        TIMING_STOP(&t_grps);
        TEST_SAY("list_groups(timeout=0) returned %d groups and status: %s\n",
                 grplist ? grplist->group_cnt : -1, rd_kafka_err2str(err));
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "expected list_groups(timeout=0) to fail "
                    "with timeout, got %s",
                    rd_kafka_err2str(err));


        TEST_SAY("Closing remaining consumers\n");
        for (i = 0; i < _CONS_CNT; i++) {
                test_timing_t t_close;
                if (!rk_c[i])
                        continue;

                TEST_SAY("Closing %s\n", rd_kafka_name(rk_c[i]));
                TIMING_START(&t_close, "CONSUMER.CLOSE");
                err = rd_kafka_consumer_close(rk_c[i]);
                TIMING_STOP(&t_close);
                if (err)
                        TEST_FAIL("consumer_close failed: %s\n",
                                  rd_kafka_err2str(err));

                rd_kafka_destroy(rk_c[i]);
                rk_c[i] = NULL;

                free(groups[i]);
        }

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}



/**
 * @brief #3705: Verify that list_groups() doesn't hang if unable to
 *        connect to the cluster.
 */
static void do_test_list_groups_hang(void) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        const struct rd_kafka_group_list *grplist;
        rd_kafka_resp_err_t err;
        test_timing_t timing;

        SUB_TEST();
        test_conf_init(&conf, NULL, 20);

        /* An unavailable broker */
        test_conf_set(conf, "bootstrap.servers", "127.0.0.1:65531");

        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        TIMING_START(&timing, "list_groups");
        err = rd_kafka_list_groups(rk, NULL, &grplist, 5 * 1000);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "Expected ERR__TIMED_OUT, not %s", rd_kafka_err2name(err));
        TIMING_ASSERT(&timing, 5 * 1000, 7 * 1000);

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


int main_0019_list_groups(int argc, char **argv) {
        do_test_list_groups();
        do_test_list_groups_hang();
        return 0;
}
