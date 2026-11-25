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

/**
 * Makes sure all symbols in the public API actually resolves during linking.
 * This test needs to be updated manually when new symbols are added.
 */

#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


int main_0006_symbols(int argc, char **argv) {

        if (argc < 0 /* always false */) {
                rd_kafka_version();
                rd_kafka_version_str();
                rd_kafka_get_debug_contexts();
                rd_kafka_get_err_descs(NULL, NULL);
                rd_kafka_err2str(RD_KAFKA_RESP_ERR_NO_ERROR);
                rd_kafka_err2name(RD_KAFKA_RESP_ERR_NO_ERROR);
                rd_kafka_last_error();
                rd_kafka_conf_new();
                rd_kafka_conf_destroy(NULL);
                rd_kafka_conf_dup(NULL);
                rd_kafka_conf_set(NULL, NULL, NULL, NULL, 0);
                rd_kafka_conf_set_dr_cb(NULL, NULL);
                rd_kafka_conf_set_dr_msg_cb(NULL, NULL);
                rd_kafka_conf_set_error_cb(NULL, NULL);
                rd_kafka_conf_set_stats_cb(NULL, NULL);
                rd_kafka_conf_set_log_cb(NULL, NULL);
                rd_kafka_conf_set_socket_cb(NULL, NULL);
                rd_kafka_conf_set_rebalance_cb(NULL, NULL);
                rd_kafka_conf_set_offset_commit_cb(NULL, NULL);
                rd_kafka_conf_set_throttle_cb(NULL, NULL);
                rd_kafka_conf_set_default_topic_conf(NULL, NULL);
                rd_kafka_conf_get(NULL, NULL, NULL, NULL);
#ifndef _WIN32
                rd_kafka_conf_set_open_cb(NULL, NULL);
#endif
                rd_kafka_conf_set_opaque(NULL, NULL);
                rd_kafka_opaque(NULL);
                rd_kafka_conf_dump(NULL, NULL);
                rd_kafka_topic_conf_dump(NULL, NULL);
                rd_kafka_conf_dump_free(NULL, 0);
                rd_kafka_conf_properties_show(NULL);
                rd_kafka_topic_conf_new();
                rd_kafka_topic_conf_dup(NULL);
                rd_kafka_topic_conf_destroy(NULL);
                rd_kafka_topic_conf_set(NULL, NULL, NULL, NULL, 0);
                rd_kafka_topic_conf_set_opaque(NULL, NULL);
                rd_kafka_topic_conf_get(NULL, NULL, NULL, NULL);
                rd_kafka_topic_conf_set_partitioner_cb(NULL, NULL);
                rd_kafka_topic_partition_available(NULL, 0);
                rd_kafka_topic_opaque(NULL);
                rd_kafka_msg_partitioner_random(NULL, NULL, 0, 0, NULL, NULL);
                rd_kafka_msg_partitioner_consistent(NULL, NULL, 0, 0, NULL,
                                                    NULL);
                rd_kafka_msg_partitioner_consistent_random(NULL, NULL, 0, 0,
                                                           NULL, NULL);
                rd_kafka_new(0, NULL, NULL, 0);
                rd_kafka_destroy(NULL);
                rd_kafka_flush(NULL, 0);
                rd_kafka_name(NULL);
                rd_kafka_memberid(NULL);
                rd_kafka_topic_new(NULL, NULL, NULL);
                rd_kafka_topic_destroy(NULL);
                rd_kafka_topic_name(NULL);
                rd_kafka_message_destroy(NULL);
                rd_kafka_message_errstr(NULL);
                rd_kafka_message_timestamp(NULL, NULL);
                rd_kafka_consume_start(NULL, 0, 0);
                rd_kafka_consume_stop(NULL, 0);
                rd_kafka_consume(NULL, 0, 0);
                rd_kafka_consume_batch(NULL, 0, 0, NULL, 0);
                rd_kafka_consume_callback(NULL, 0, 0, NULL, NULL);
                rd_kafka_offset_store(NULL, 0, 0);
                rd_kafka_produce(NULL, 0, 0, NULL, 0, NULL, 0, NULL);
                rd_kafka_produce_batch(NULL, 0, 0, NULL, 0);
                rd_kafka_poll(NULL, 0);
                rd_kafka_brokers_add(NULL, NULL);
                /* DEPRECATED: rd_kafka_set_logger(NULL, NULL); */
                rd_kafka_set_log_level(NULL, 0);
                rd_kafka_log_print(NULL, 0, NULL, NULL);
#ifndef _WIN32
                rd_kafka_log_syslog(NULL, 0, NULL, NULL);
#endif
                rd_kafka_outq_len(NULL);
                rd_kafka_dump(NULL, NULL);
                rd_kafka_thread_cnt();
                rd_kafka_wait_destroyed(0);
                rd_kafka_metadata(NULL, 0, NULL, NULL, 0);
                rd_kafka_metadata_destroy(NULL);
                rd_kafka_queue_get_partition(NULL, NULL, 0);
                rd_kafka_queue_destroy(NULL);
                rd_kafka_consume_start_queue(NULL, 0, 0, NULL);
                rd_kafka_consume_queue(NULL, 0);
                rd_kafka_consume_batch_queue(NULL, 0, NULL, 0);
                rd_kafka_consume_callback_queue(NULL, 0, NULL, NULL);
                rd_kafka_seek(NULL, 0, 0, 0);
                rd_kafka_yield(NULL);
                rd_kafka_mem_free(NULL, NULL);
                rd_kafka_list_groups(NULL, NULL, NULL, 0);
                rd_kafka_group_list_destroy(NULL);

                /* KafkaConsumer API */
                rd_kafka_subscribe(NULL, NULL);
                rd_kafka_unsubscribe(NULL);
                rd_kafka_subscription(NULL, NULL);
                rd_kafka_consumer_poll(NULL, 0);
                rd_kafka_consumer_close(NULL);
                rd_kafka_assign(NULL, NULL);
                rd_kafka_assignment(NULL, NULL);
                rd_kafka_commit(NULL, NULL, 0);
                rd_kafka_commit_message(NULL, NULL, 0);
                rd_kafka_committed(NULL, NULL, 0);
                rd_kafka_position(NULL, NULL);

                /* TopicPartition */
                rd_kafka_topic_partition_list_new(0);
                rd_kafka_topic_partition_list_destroy(NULL);
                rd_kafka_topic_partition_list_add(NULL, NULL, 0);
                rd_kafka_topic_partition_list_add_range(NULL, NULL, 0, 0);
                rd_kafka_topic_partition_list_del(NULL, NULL, 0);
                rd_kafka_topic_partition_list_del_by_idx(NULL, 0);
                rd_kafka_topic_partition_list_copy(NULL);
                rd_kafka_topic_partition_list_set_offset(NULL, NULL, 0, 0);
                rd_kafka_topic_partition_list_find(NULL, NULL, 0);
                rd_kafka_query_watermark_offsets(NULL, NULL, 0, NULL, NULL, 0);
                rd_kafka_get_watermark_offsets(NULL, NULL, 0, NULL, NULL);
        }


        return 0;
}
