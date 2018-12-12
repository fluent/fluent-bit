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

#ifndef _RDKAFKA_AUX_H_
#define _RDKAFKA_AUX_H_

/**
 * @name Auxiliary types
 */

#include "rdkafka_conf.h"



/**
 * @brief Topic [ + Error code + Error string ]
 *
 * @remark Public type.
 * @remark Single allocation.
 */
struct rd_kafka_topic_result_s {
        char *topic;             /**< Points to data */
        rd_kafka_resp_err_t err; /**< Error code */
        char *errstr;            /**< Points to data after topic, unless NULL */
        char  data[1];           /**< topic followed by errstr */
};

void rd_kafka_topic_result_destroy (rd_kafka_topic_result_t *terr);
void rd_kafka_topic_result_free (void *ptr);

rd_kafka_topic_result_t *
rd_kafka_topic_result_new (const char *topic, ssize_t topic_size,
                           rd_kafka_resp_err_t err,
                           const char *errstr);


/**@}*/

#endif /* _RDKAFKA_AUX_H_ */
