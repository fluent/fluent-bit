/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2015 Magnus Edenhill
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
#pragma once





typedef struct rd_kafka_group_member_s {
        rd_kafka_topic_partition_list_t *rkgm_subscription;
        rd_kafka_topic_partition_list_t *rkgm_assignment;
        rd_list_t                        rkgm_eligible;
        rd_kafkap_str_t                 *rkgm_member_id;
        rd_kafkap_bytes_t               *rkgm_userdata;
        rd_kafkap_bytes_t               *rkgm_member_metadata;
} rd_kafka_group_member_t;


int rd_kafka_group_member_cmp (const void *_a, const void *_b);

int
rd_kafka_group_member_find_subscription (rd_kafka_t *rk,
					 const rd_kafka_group_member_t *rkgm,
					 const char *topic);


/**
 * Structure to hold metadata for a single topic and all its
 * subscribing members.
 */
typedef struct rd_kafka_assignor_topic_s {
        const rd_kafka_metadata_topic_t *metadata;
        rd_list_t members;     /* rd_kafka_group_member_t * */
} rd_kafka_assignor_topic_t;


int rd_kafka_assignor_topic_cmp (const void *_a, const void *_b);


typedef struct rd_kafka_assignor_s {
        rd_kafkap_str_t   *rkas_protocol_type;
        rd_kafkap_str_t   *rkas_protocol_name;

        const void        *rkas_userdata;
        size_t             rkas_userdata_size;

	int                rkas_enabled;

        rd_kafka_resp_err_t (*rkas_assign_cb) (
                rd_kafka_t *rk,
                const char *member_id,
                const char *protocol_name,
                const rd_kafka_metadata_t *metadata,
                rd_kafka_group_member_t *members,
                size_t member_cnt,
                rd_kafka_assignor_topic_t **eligible_topics,
                size_t eligible_topic_cnt,
                char *errstr,
                size_t errstr_size,
                void *opaque);

        rd_kafkap_bytes_t *(*rkas_get_metadata_cb) (
                struct rd_kafka_assignor_s *rkpas,
		const rd_list_t *topics);


        void (*rkas_on_assignment_cb) (const char *member_id,
                                        rd_kafka_group_member_t
                                        *assignment, void *opaque);

        void *rkas_opaque;
} rd_kafka_assignor_t;


rd_kafkap_bytes_t *
rd_kafka_assignor_get_metadata (rd_kafka_assignor_t *rkpas,
				const rd_list_t *topics);


void rd_kafka_assignor_update_subscription (rd_kafka_assignor_t *rkpas,
                                            const rd_kafka_topic_partition_list_t
                                            *subscription);


rd_kafka_resp_err_t
rd_kafka_assignor_run (struct rd_kafka_cgrp_s *rkcg,
                       const char *protocol_name,
                       rd_kafka_metadata_t *metadata,
                       rd_kafka_group_member_t *members, int member_cnt,
                       char *errstr, size_t errstr_size);

rd_kafka_assignor_t *
rd_kafka_assignor_find (rd_kafka_t *rk, const char *protocol);

int rd_kafka_assignors_init (rd_kafka_t *rk, char *errstr, size_t errstr_size);
void rd_kafka_assignors_term (rd_kafka_t *rk);



void rd_kafka_group_member_clear (rd_kafka_group_member_t *rkgm);


/**
 * rd_kafka_range_assignor.c
 */
rd_kafka_resp_err_t
rd_kafka_range_assignor_assign_cb (rd_kafka_t *rk,
                                   const char *member_id,
                                   const char *protocol_name,
                                   const rd_kafka_metadata_t *metadata,
                                   rd_kafka_group_member_t *members,
                                   size_t member_cnt,
                                   rd_kafka_assignor_topic_t **eligible_topics,
                                   size_t eligible_topic_cnt,
                                   char *errstr, size_t errstr_size,
                                   void *opaque);


/**
 * rd_kafka_roundrobin_assignor.c
 */
rd_kafka_resp_err_t
rd_kafka_roundrobin_assignor_assign_cb (rd_kafka_t *rk,
					const char *member_id,
					const char *protocol_name,
					const rd_kafka_metadata_t *metadata,
					rd_kafka_group_member_t *members,
					size_t member_cnt,
					rd_kafka_assignor_topic_t
					**eligible_topics,
					size_t eligible_topic_cnt,
					char *errstr, size_t errstr_size,
					void *opaque);

