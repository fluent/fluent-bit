/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2018 Magnus Edenhill
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
#include "rdkafka_aux.h"

rd_kafka_resp_err_t
rd_kafka_topic_result_error (const rd_kafka_topic_result_t *topicres) {
        return topicres->err;
}

const char *
rd_kafka_topic_result_error_string (const rd_kafka_topic_result_t *topicres) {
        return topicres->errstr;
}

const char *
rd_kafka_topic_result_name (const rd_kafka_topic_result_t *topicres) {
        return topicres->topic;
}

/**
 * @brief Create new topic_result (single allocation).
 *
 * @param topic Topic string, if topic_size is != -1 it does not have to
 *              be nul-terminated.
 * @param topic_size Size of topic, or -1 to perform automatic strlen()
 * @param err Error code
 * @param errstr Optional error string.
 *
 * All input arguments are copied.
 */

rd_kafka_topic_result_t *
rd_kafka_topic_result_new (const char *topic, ssize_t topic_size,
                           rd_kafka_resp_err_t err,
                           const char *errstr) {
        size_t tlen = topic_size != -1 ? (size_t)topic_size : strlen(topic);
        size_t elen = errstr ? strlen(errstr) + 1 : 0;
        rd_kafka_topic_result_t *terr;

        terr = rd_malloc(sizeof(*terr) + tlen + 1 + elen);

        terr->err = err;

        terr->topic = terr->data;
        memcpy(terr->topic, topic, tlen);
        terr->topic[tlen] = '\0';

        if (errstr) {
                terr->errstr = terr->topic + tlen + 1;
                memcpy(terr->errstr, errstr, elen);
        } else {
                terr->errstr = NULL;
        }

        return terr;
}


/**
 * @brief Destroy topic_result
 */
void rd_kafka_topic_result_destroy (rd_kafka_topic_result_t *terr) {
        rd_free(terr);
}

/**
 * @brief Destroy-variant suitable for rd_list free_cb use.
 */
void rd_kafka_topic_result_free (void *ptr) {
        rd_kafka_topic_result_destroy((rd_kafka_topic_result_t *)ptr);
}
