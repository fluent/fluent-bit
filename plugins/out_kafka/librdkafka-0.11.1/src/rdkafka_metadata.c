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


#include "rd.h"
#include "rdkafka_int.h"
#include "rdkafka_topic.h"
#include "rdkafka_broker.h"
#include "rdkafka_request.h"
#include "rdkafka_metadata.h"

#include <string.h>



rd_kafka_resp_err_t
rd_kafka_metadata (rd_kafka_t *rk, int all_topics,
                   rd_kafka_topic_t *only_rkt,
                   const struct rd_kafka_metadata **metadatap,
                   int timeout_ms) {
        rd_kafka_q_t *rkq;
        rd_kafka_broker_t *rkb;
        rd_kafka_op_t *rko;
	rd_ts_t ts_end = rd_timeout_init(timeout_ms);
        rd_list_t topics;

        /* Query any broker that is up, and if none are up pick the first one,
         * if we're lucky it will be up before the timeout */
	rkb = rd_kafka_broker_any_usable(rk, timeout_ms, 1);
	if (!rkb)
		return RD_KAFKA_RESP_ERR__TRANSPORT;

        rkq = rd_kafka_q_new(rk);

        rd_list_init(&topics, 0, rd_free);
        if (!all_topics) {
                if (only_rkt)
                        rd_list_add(&topics,
                                    rd_strdup(rd_kafka_topic_a2i(only_rkt)->
                                              rkt_topic->str));
                else
                        rd_kafka_local_topics_to_list(rkb->rkb_rk, &topics);
        }

        /* Async: request metadata */
        rko = rd_kafka_op_new(RD_KAFKA_OP_METADATA);
        rd_kafka_op_set_replyq(rko, rkq, 0);
        rko->rko_u.metadata.force = 1; /* Force metadata request regardless
                                        * of outstanding metadata requests. */
        rd_kafka_MetadataRequest(rkb, &topics, "application requested", rko);

        rd_list_destroy(&topics);
        rd_kafka_broker_destroy(rkb);

        /* Wait for reply (or timeout) */
        rko = rd_kafka_q_pop(rkq, rd_timeout_remains(ts_end), 0);

        rd_kafka_q_destroy(rkq);

        /* Timeout */
        if (!rko)
                return RD_KAFKA_RESP_ERR__TIMED_OUT;

        /* Error */
        if (rko->rko_err) {
                rd_kafka_resp_err_t err = rko->rko_err;
                rd_kafka_op_destroy(rko);
                return err;
        }

        /* Reply: pass metadata pointer to application who now owns it*/
        rd_kafka_assert(rk, rko->rko_u.metadata.md);
        *metadatap = rko->rko_u.metadata.md;
        rko->rko_u.metadata.md = NULL;
        rd_kafka_op_destroy(rko);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}



void rd_kafka_metadata_destroy (const struct rd_kafka_metadata *metadata) {
        rd_free((void *)metadata);
}


/**
 * @returns a newly allocated copy of metadata \p src of size \p size
 */
struct rd_kafka_metadata *
rd_kafka_metadata_copy (const struct rd_kafka_metadata *src, size_t size) {
	struct rd_kafka_metadata *md;
	rd_tmpabuf_t tbuf;
	int i;

	/* metadata is stored in one contigious buffer where structs and
	 * and pointed-to fields are layed out in a memory aligned fashion.
	 * rd_tmpabuf_t provides the infrastructure to do this.
	 * Because of this we copy all the structs verbatim but
	 * any pointer fields needs to be copied explicitly to update
	 * the pointer address. */
	rd_tmpabuf_new(&tbuf, size, 1/*assert on fail*/);
	md = rd_tmpabuf_write(&tbuf, src, sizeof(*md));

	rd_tmpabuf_write_str(&tbuf, src->orig_broker_name);


	/* Copy Brokers */
	md->brokers = rd_tmpabuf_write(&tbuf, src->brokers,
				      md->broker_cnt * sizeof(*md->brokers));

	for (i = 0 ; i < md->broker_cnt ; i++)
		md->brokers[i].host =
			rd_tmpabuf_write_str(&tbuf, src->brokers[i].host);


	/* Copy TopicMetadata */
        md->topics = rd_tmpabuf_write(&tbuf, src->topics,
				      md->topic_cnt * sizeof(*md->topics));

	for (i = 0 ; i < md->topic_cnt ; i++) {
		int j;

		md->topics[i].topic = rd_tmpabuf_write_str(&tbuf,
							   src->topics[i].topic);


		/* Copy partitions */
		md->topics[i].partitions =
			rd_tmpabuf_write(&tbuf, src->topics[i].partitions,
					 md->topics[i].partition_cnt *
					 sizeof(*md->topics[i].partitions));

		for (j = 0 ; j < md->topics[i].partition_cnt ; j++) {
			/* Copy replicas and ISRs */
			md->topics[i].partitions[j].replicas =
				rd_tmpabuf_write(&tbuf,
						 src->topics[i].partitions[j].
						 replicas,
						 md->topics[i].partitions[j].
						 replica_cnt *
						 sizeof(*md->topics[i].
							partitions[j].
							replicas));

			md->topics[i].partitions[j].isrs =
				rd_tmpabuf_write(&tbuf,
						 src->topics[i].partitions[j].
						 isrs,
						 md->topics[i].partitions[j].
						 isr_cnt *
						 sizeof(*md->topics[i].
							partitions[j].
							isrs));

		}
	}

	/* Check for tmpabuf errors */
	if (rd_tmpabuf_failed(&tbuf))
		rd_kafka_assert(NULL, !*"metadata copy failed");

	/* Delibarely not destroying the tmpabuf since we return
	 * its allocated memory. */

	return md;
}




/**
 * Handle a Metadata response message.
 *
 * @param topics are the requested topics (may be NULL)
 *
 * The metadata will be marshalled into 'struct rd_kafka_metadata*' structs.
 *
 * Returns the marshalled metadata, or NULL on parse error.
 *
 * @locality rdkafka main thread
 */
struct rd_kafka_metadata *
rd_kafka_parse_Metadata (rd_kafka_broker_t *rkb,
                         rd_kafka_buf_t *request,
                         rd_kafka_buf_t *rkbuf) {
        rd_kafka_t *rk = rkb->rkb_rk;
        int i, j, k;
        rd_tmpabuf_t tbuf;
        struct rd_kafka_metadata *md;
        size_t rkb_namelen;
        const int log_decode_errors = LOG_ERR;
        rd_list_t *missing_topics = NULL;
        const rd_list_t *requested_topics = request->rkbuf_u.Metadata.topics;
        int all_topics = request->rkbuf_u.Metadata.all_topics;
        const char *reason = request->rkbuf_u.Metadata.reason ?
                request->rkbuf_u.Metadata.reason : "(no reason)";
        int ApiVersion = request->rkbuf_reqhdr.ApiVersion;
        rd_kafkap_str_t cluster_id = RD_ZERO_INIT;
        int32_t controller_id = -1;

        rd_kafka_assert(NULL, thrd_is_current(rk->rk_thread));

        /* Remove topics from missing_topics as they are seen in Metadata. */
        if (requested_topics)
                missing_topics = rd_list_copy(requested_topics,
                                              rd_list_string_copy, NULL);

        rd_kafka_broker_lock(rkb);
        rkb_namelen = strlen(rkb->rkb_name)+1;
        /* We assume that the marshalled representation is
         * no more than 4 times larger than the wire representation. */
        rd_tmpabuf_new(&tbuf,
                       sizeof(*md) + rkb_namelen + (rkbuf->rkbuf_totlen * 4),
                       0/*dont assert on fail*/);

        if (!(md = rd_tmpabuf_alloc(&tbuf, sizeof(*md))))
                goto err;
        md->orig_broker_id = rkb->rkb_nodeid;
        md->orig_broker_name = rd_tmpabuf_write(&tbuf,
                                                rkb->rkb_name, rkb_namelen);
        rd_kafka_broker_unlock(rkb);

        /* Read Brokers */
        rd_kafka_buf_read_i32a(rkbuf, md->broker_cnt);
        if (md->broker_cnt > RD_KAFKAP_BROKERS_MAX)
                rd_kafka_buf_parse_fail(rkbuf, "Broker_cnt %i > BROKERS_MAX %i",
                                        md->broker_cnt, RD_KAFKAP_BROKERS_MAX);

        if (!(md->brokers = rd_tmpabuf_alloc(&tbuf, md->broker_cnt *
                                             sizeof(*md->brokers))))
                rd_kafka_buf_parse_fail(rkbuf,
                                        "%d brokers: tmpabuf memory shortage",
                                        md->broker_cnt);

        for (i = 0 ; i < md->broker_cnt ; i++) {
                rd_kafka_buf_read_i32a(rkbuf, md->brokers[i].id);
                rd_kafka_buf_read_str_tmpabuf(rkbuf, &tbuf, md->brokers[i].host);
                rd_kafka_buf_read_i32a(rkbuf, md->brokers[i].port);

                if (ApiVersion >= 1) {
                        rd_kafkap_str_t rack;
                        rd_kafka_buf_read_str(rkbuf, &rack);
                }
        }

        if (ApiVersion >= 2)
                rd_kafka_buf_read_str(rkbuf, &cluster_id);

        if (ApiVersion >= 1) {
                rd_kafka_buf_read_i32(rkbuf, &controller_id);
                rd_rkb_dbg(rkb, METADATA,
                           "METADATA", "ClusterId: %.*s, ControllerId: %"PRId32,
                           RD_KAFKAP_STR_PR(&cluster_id), controller_id);
        }



        /* Read TopicMetadata */
        rd_kafka_buf_read_i32a(rkbuf, md->topic_cnt);
        rd_rkb_dbg(rkb, METADATA, "METADATA", "%i brokers, %i topics",
                   md->broker_cnt, md->topic_cnt);

        if (md->topic_cnt > RD_KAFKAP_TOPICS_MAX)
                rd_kafka_buf_parse_fail(rkbuf, "TopicMetadata_cnt %"PRId32
                                        " > TOPICS_MAX %i",
                                        md->topic_cnt, RD_KAFKAP_TOPICS_MAX);

        if (!(md->topics = rd_tmpabuf_alloc(&tbuf,
                                            md->topic_cnt *
                                            sizeof(*md->topics))))
                rd_kafka_buf_parse_fail(rkbuf,
                                        "%d topics: tmpabuf memory shortage",
                                        md->topic_cnt);

        for (i = 0 ; i < md->topic_cnt ; i++) {
                rd_kafka_buf_read_i16a(rkbuf, md->topics[i].err);
                rd_kafka_buf_read_str_tmpabuf(rkbuf, &tbuf, md->topics[i].topic);
                if (ApiVersion >= 1) {
                        int8_t is_internal;
                        rd_kafka_buf_read_i8(rkbuf, &is_internal);
                }

                /* PartitionMetadata */
                rd_kafka_buf_read_i32a(rkbuf, md->topics[i].partition_cnt);
                if (md->topics[i].partition_cnt > RD_KAFKAP_PARTITIONS_MAX)
                        rd_kafka_buf_parse_fail(rkbuf,
                                                "TopicMetadata[%i]."
                                                "PartitionMetadata_cnt %i "
                                                "> PARTITIONS_MAX %i",
                                                i, md->topics[i].partition_cnt,
                                                RD_KAFKAP_PARTITIONS_MAX);

                if (!(md->topics[i].partitions =
                      rd_tmpabuf_alloc(&tbuf,
                                       md->topics[i].partition_cnt *
                                       sizeof(*md->topics[i].partitions))))
                        rd_kafka_buf_parse_fail(rkbuf,
                                                "%s: %d partitions: "
                                                "tmpabuf memory shortage",
                                                md->topics[i].topic,
                                                md->topics[i].partition_cnt);

                for (j = 0 ; j < md->topics[i].partition_cnt ; j++) {
                        rd_kafka_buf_read_i16a(rkbuf, md->topics[i].partitions[j].err);
                        rd_kafka_buf_read_i32a(rkbuf, md->topics[i].partitions[j].id);
                        rd_kafka_buf_read_i32a(rkbuf, md->topics[i].partitions[j].leader);

                        /* Replicas */
                        rd_kafka_buf_read_i32a(rkbuf, md->topics[i].partitions[j].replica_cnt);
                        if (md->topics[i].partitions[j].replica_cnt >
                            RD_KAFKAP_BROKERS_MAX)
                                rd_kafka_buf_parse_fail(rkbuf,
                                                        "TopicMetadata[%i]."
                                                        "PartitionMetadata[%i]."
                                                        "Replica_cnt "
                                                        "%i > BROKERS_MAX %i",
                                                        i, j,
                                                        md->topics[i].
                                                        partitions[j].
                                                        replica_cnt,
                                                        RD_KAFKAP_BROKERS_MAX);

                        if (!(md->topics[i].partitions[j].replicas =
                              rd_tmpabuf_alloc(&tbuf,
                                               md->topics[i].
                                               partitions[j].replica_cnt *
                                               sizeof(*md->topics[i].
                                                      partitions[j].replicas))))
                                rd_kafka_buf_parse_fail(
                                        rkbuf,
                                        "%s [%"PRId32"]: %d replicas: "
                                        "tmpabuf memory shortage",
                                        md->topics[i].topic,
                                        md->topics[i].partitions[j].id,
                                        md->topics[i].partitions[j].replica_cnt);


                        for (k = 0 ;
                             k < md->topics[i].partitions[j].replica_cnt; k++)
                                rd_kafka_buf_read_i32a(rkbuf, md->topics[i].partitions[j].
                                           replicas[k]);

                        /* Isrs */
                        rd_kafka_buf_read_i32a(rkbuf, md->topics[i].partitions[j].isr_cnt);
                        if (md->topics[i].partitions[j].isr_cnt >
                            RD_KAFKAP_BROKERS_MAX)
                                rd_kafka_buf_parse_fail(rkbuf,
                                                        "TopicMetadata[%i]."
                                                        "PartitionMetadata[%i]."
                                                        "Isr_cnt "
                                                        "%i > BROKERS_MAX %i",
                                                        i, j,
                                                        md->topics[i].
                                                        partitions[j].isr_cnt,
                                                        RD_KAFKAP_BROKERS_MAX);

                        if (!(md->topics[i].partitions[j].isrs =
                              rd_tmpabuf_alloc(&tbuf,
                                               md->topics[i].
                                               partitions[j].isr_cnt *
                                               sizeof(*md->topics[i].
                                                      partitions[j].isrs))))
                                rd_kafka_buf_parse_fail(
                                        rkbuf,
                                        "%s [%"PRId32"]: %d isrs: "
                                        "tmpabuf memory shortage",
                                        md->topics[i].topic,
                                        md->topics[i].partitions[j].id,
                                        md->topics[i].partitions[j].isr_cnt);


                        for (k = 0 ;
                             k < md->topics[i].partitions[j].isr_cnt; k++)
                                rd_kafka_buf_read_i32a(rkbuf, md->topics[i].
                                                       partitions[j].isrs[k]);

                }
        }

        /* Entire Metadata response now parsed without errors:
         * update our internal state according to the response. */

        /* Avoid metadata updates when we're terminating. */
        if (rd_kafka_terminating(rkb->rkb_rk))
                goto done;

        if (md->broker_cnt == 0 && md->topic_cnt == 0) {
                rd_rkb_dbg(rkb, METADATA, "METADATA",
                           "No brokers or topics in metadata: retrying");
                goto err;
        }

        /* Update our list of brokers. */
        for (i = 0 ; i < md->broker_cnt ; i++) {
                rd_rkb_dbg(rkb, METADATA, "METADATA",
                           "  Broker #%i/%i: %s:%i NodeId %"PRId32,
                           i, md->broker_cnt,
                           md->brokers[i].host,
                           md->brokers[i].port,
                           md->brokers[i].id);
                rd_kafka_broker_update(rkb->rkb_rk, rkb->rkb_proto,
                                       &md->brokers[i]);
        }

        /* Update partition count and leader for each topic we know about */
        for (i = 0 ; i < md->topic_cnt ; i++) {
                rd_kafka_metadata_topic_t *mdt = &md->topics[i];
                rd_rkb_dbg(rkb, METADATA, "METADATA",
                           "  Topic #%i/%i: %s with %i partitions%s%s",
                           i, md->topic_cnt, mdt->topic,
                           mdt->partition_cnt,
                           mdt->err ? ": " : "",
                           mdt->err ? rd_kafka_err2str(mdt->err) : "");

                /* Ignore topics in blacklist */
                if (rkb->rkb_rk->rk_conf.topic_blacklist &&
                    rd_kafka_pattern_match(rkb->rkb_rk->rk_conf.topic_blacklist,
                                           mdt->topic)) {
                        rd_rkb_dbg(rkb, TOPIC, "BLACKLIST",
                                   "Ignoring blacklisted topic \"%s\" "
                                   "in metadata", mdt->topic);
                        continue;
                }

                /* Ignore metadata completely for temporary errors. (issue #513)
                 *   LEADER_NOT_AVAILABLE: Broker is rebalancing
                 */
                if (mdt->err == RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE &&
                    mdt->partition_cnt == 0) {
                        rd_rkb_dbg(rkb, TOPIC, "METADATA",
                                   "Temporary error in metadata reply for "
                                   "topic %s (PartCnt %i): %s: ignoring",
                                   mdt->topic, mdt->partition_cnt,
                                   rd_kafka_err2str(mdt->err));
                        rd_list_free_cb(missing_topics,
                                        rd_list_remove_cmp(missing_topics,
                                                           mdt->topic,
                                                           (void *)strcmp));
                        continue;
                }


                /* Update local topic & partition state based on metadata */
                rd_kafka_topic_metadata_update2(rkb, mdt);

                if (requested_topics) {
                        rd_list_free_cb(missing_topics,
                                        rd_list_remove_cmp(missing_topics,
                                                           mdt->topic,
                                                           (void*)strcmp));
                        if (!all_topics) {
                                rd_kafka_wrlock(rk);
                                rd_kafka_metadata_cache_topic_update(rk, mdt);
                                rd_kafka_wrunlock(rk);
                        }
                }
        }


        /* Requested topics not seen in metadata? Propogate to topic code. */
        if (missing_topics) {
                char *topic;
                rd_rkb_dbg(rkb, TOPIC, "METADATA",
                           "%d/%d requested topic(s) seen in metadata",
                           rd_list_cnt(requested_topics) -
                           rd_list_cnt(missing_topics),
                           rd_list_cnt(requested_topics));
                for (i = 0 ; i < rd_list_cnt(missing_topics) ; i++)
                        rd_rkb_dbg(rkb, TOPIC, "METADATA", "wanted %s",
                                   (char *)(missing_topics->rl_elems[i]));
                RD_LIST_FOREACH(topic, missing_topics, i) {
                        shptr_rd_kafka_itopic_t *s_rkt;

                        s_rkt = rd_kafka_topic_find(rkb->rkb_rk, topic, 1/*lock*/);
                        if (s_rkt) {
                                rd_kafka_topic_metadata_none(
                                        rd_kafka_topic_s2i(s_rkt));
                                rd_kafka_topic_destroy0(s_rkt);
                        }
                }
        }


        rd_kafka_wrlock(rkb->rkb_rk);
        rkb->rkb_rk->rk_ts_metadata = rd_clock();

        /* Update cached cluster id. */
        if (RD_KAFKAP_STR_LEN(&cluster_id) > 0 &&
            (!rkb->rkb_rk->rk_clusterid ||
             rd_kafkap_str_cmp_str(&cluster_id, rkb->rkb_rk->rk_clusterid))) {
                rd_rkb_dbg(rkb, BROKER|RD_KAFKA_DBG_GENERIC, "CLUSTERID",
                           "ClusterId update \"%s\" -> \"%.*s\"",
                           rkb->rkb_rk->rk_clusterid ?
                           rkb->rkb_rk->rk_clusterid : "",
                           RD_KAFKAP_STR_PR(&cluster_id));
                if (rkb->rkb_rk->rk_clusterid)
                        rd_free(rkb->rkb_rk->rk_clusterid);
                rkb->rkb_rk->rk_clusterid = RD_KAFKAP_STR_DUP(&cluster_id);
        }

        if (all_topics) {
                rd_kafka_metadata_cache_update(rkb->rkb_rk,
                                               md, 1/*abs update*/);

                if (rkb->rkb_rk->rk_full_metadata)
                        rd_kafka_metadata_destroy(rkb->rkb_rk->rk_full_metadata);
                rkb->rkb_rk->rk_full_metadata =
                        rd_kafka_metadata_copy(md, tbuf.of);
                rkb->rkb_rk->rk_ts_full_metadata = rkb->rkb_rk->rk_ts_metadata;
                rd_rkb_dbg(rkb, METADATA, "METADATA",
                           "Caching full metadata with "
                           "%d broker(s) and %d topic(s): %s",
                           md->broker_cnt, md->topic_cnt, reason);
        } else {
                rd_kafka_metadata_cache_expiry_start(rk);
        }

        /* Remove cache hints for the originally requested topics. */
        if (requested_topics)
                rd_kafka_metadata_cache_purge_hints(rk, requested_topics);

        rd_kafka_wrunlock(rkb->rkb_rk);

        /* Check if cgrp effective subscription is affected by
         * new metadata. */
        if (rkb->rkb_rk->rk_cgrp)
                rd_kafka_cgrp_metadata_update_check(
                        rkb->rkb_rk->rk_cgrp, 1/*do join*/);



done:
        if (missing_topics)
                rd_list_destroy(missing_topics);

        /* This metadata request was triggered by someone wanting
         * the metadata information back as a reply, so send that reply now.
         * In this case we must not rd_free the metadata memory here,
         * the requestee will do.
         * The tbuf is explicitly not destroyed as we return its memory
         * to the caller. */
        return md;

 err_parse:
err:
        if (requested_topics) {
                /* Failed requests shall purge cache hints for
                 * the requested topics. */
                rd_kafka_wrlock(rkb->rkb_rk);
                rd_kafka_metadata_cache_purge_hints(rk, requested_topics);
                rd_kafka_wrunlock(rkb->rkb_rk);
        }

        if (missing_topics)
                rd_list_destroy(missing_topics);

        rd_tmpabuf_destroy(&tbuf);
        return NULL;
}


/**
 * @brief Add all topics in current cached full metadata
 *        to \p tinfos (rd_kafka_topic_info_t *)
 *        that matches the topics in \p match
 *
 * @returns the number of topics matched and added to \p list
 *
 * @locks none
 * @locality any
 */
size_t
rd_kafka_metadata_topic_match (rd_kafka_t *rk, rd_list_t *tinfos,
                               const rd_kafka_topic_partition_list_t *match) {
        int ti;
        size_t cnt = 0;
        const struct rd_kafka_metadata *metadata;


        rd_kafka_rdlock(rk);
        metadata = rk->rk_full_metadata;
        if (!metadata) {
                rd_kafka_rdunlock(rk);
                return 0;
        }

        /* For each topic in the cluster, scan through the match list
         * to find matching topic. */
        for (ti = 0 ; ti < metadata->topic_cnt ; ti++) {
                const char *topic = metadata->topics[ti].topic;
                int i;

                /* Ignore topics in blacklist */
                if (rk->rk_conf.topic_blacklist &&
                    rd_kafka_pattern_match(rk->rk_conf.topic_blacklist, topic))
                        continue;

                /* Scan for matches */
                for (i = 0 ; i < match->cnt ; i++) {
                        if (!rd_kafka_topic_match(rk,
                                                  match->elems[i].topic, topic))
                                continue;

                        if (metadata->topics[ti].err)
                                continue; /* Skip errored topics */

                        rd_list_add(tinfos,
                                    rd_kafka_topic_info_new(
                                            topic,
                                            metadata->topics[ti].partition_cnt));
                        cnt++;
                }
        }
        rd_kafka_rdunlock(rk);

        return cnt;
}


/**
 * @brief Add all topics in \p match that matches cached metadata.
 * @remark MUST NOT be used with wildcard topics,
 *         see rd_kafka_metadata_topic_match() for that.
 *
 * @returns the number of topics matched and added to \p tinfos
 * @locks none
 */
size_t
rd_kafka_metadata_topic_filter (rd_kafka_t *rk, rd_list_t *tinfos,
                               const rd_kafka_topic_partition_list_t *match) {
        int i;
        size_t cnt = 0;

        rd_kafka_rdlock(rk);
        /* For each topic in match, look up the topic in the cache. */
        for (i = 0 ; i < match->cnt ; i++) {
                const char *topic = match->elems[i].topic;
                const rd_kafka_metadata_topic_t *mtopic;

                /* Ignore topics in blacklist */
                if (rk->rk_conf.topic_blacklist &&
                    rd_kafka_pattern_match(rk->rk_conf.topic_blacklist, topic))
                        continue;

                mtopic = rd_kafka_metadata_cache_topic_get(rk, topic,
                                                           1/*valid*/);
                if (mtopic && !mtopic->err) {
                        rd_list_add(tinfos,
                                    rd_kafka_topic_info_new(
                                            topic, mtopic->partition_cnt));

                        cnt++;
                }
        }
        rd_kafka_rdunlock(rk);

        return cnt;
}


void rd_kafka_metadata_log (rd_kafka_t *rk, const char *fac,
                            const struct rd_kafka_metadata *md) {
        int i;

        rd_kafka_dbg(rk, METADATA, fac,
                     "Metadata with %d broker(s) and %d topic(s):",
                     md->broker_cnt, md->topic_cnt);

        for (i = 0 ; i < md->broker_cnt ; i++) {
                rd_kafka_dbg(rk, METADATA, fac,
                             "  Broker #%i/%i: %s:%i NodeId %"PRId32,
                             i, md->broker_cnt,
                             md->brokers[i].host,
                             md->brokers[i].port,
                             md->brokers[i].id);
        }

        for (i = 0 ; i < md->topic_cnt ; i++) {
                rd_kafka_dbg(rk, METADATA, fac,
                             "  Topic #%i/%i: %s with %i partitions%s%s",
                             i, md->topic_cnt, md->topics[i].topic,
                             md->topics[i].partition_cnt,
                             md->topics[i].err ? ": " : "",
                             md->topics[i].err ?
                             rd_kafka_err2str(md->topics[i].err) : "");
        }
}




/**
 * @brief Refresh metadata for \p topics
 *
 * @param rk: used to look up usable broker if \p rkb is NULL.
 * @param rkb: use this broker, unless NULL then any usable broker from \p rk
 * @param force: force refresh even if topics are up-to-date in cache
 *
 * @returns an error code
 *
 * @locality any
 * @locks none
 */
rd_kafka_resp_err_t
rd_kafka_metadata_refresh_topics (rd_kafka_t *rk, rd_kafka_broker_t *rkb,
                                  const rd_list_t *topics, int force,
                                  const char *reason) {
        rd_list_t q_topics;
        int destroy_rkb = 0;

        if (!rk)
                rk = rkb->rkb_rk;

        rd_kafka_wrlock(rk);

        if (!rkb) {
                if (!(rkb = rd_kafka_broker_any_usable(rk, RD_POLL_NOWAIT, 0))){
                        rd_kafka_wrunlock(rk);
                        rd_kafka_dbg(rk, METADATA, "METADATA",
                                     "Skipping metadata refresh of %d topic(s):"
                                     " no usable brokers",
                                     rd_list_cnt(topics));
                        return RD_KAFKA_RESP_ERR__TRANSPORT;
                }
                destroy_rkb = 1;
        }

        rd_list_init(&q_topics, rd_list_cnt(topics), rd_free);

        if (!force) {

                /* Hint cache of upcoming MetadataRequest and filter
                 * out any topics that are already being requested.
                 * q_topics will contain remaining topics to query. */
                rd_kafka_metadata_cache_hint(rk, topics, &q_topics,
                                             0/*dont replace*/);
                rd_kafka_wrunlock(rk);

                if (rd_list_cnt(&q_topics) == 0) {
                        /* No topics need new query. */
                        rd_kafka_dbg(rk, METADATA, "METADATA",
                                     "Skipping metadata refresh of "
                                     "%d topic(s): %s: "
                                     "already being requested",
                                     rd_list_cnt(topics), reason);
                        rd_list_destroy(&q_topics);
                        if (destroy_rkb)
                                rd_kafka_broker_destroy(rkb);
                        return RD_KAFKA_RESP_ERR_NO_ERROR;
                }

        } else {
                rd_kafka_wrunlock(rk);
                rd_list_copy_to(&q_topics, topics, rd_list_string_copy, NULL);
        }

        rd_kafka_dbg(rk, METADATA, "METADATA",
                     "Requesting metadata for %d/%d topics: %s",
                     rd_list_cnt(&q_topics), rd_list_cnt(topics), reason);

        rd_kafka_MetadataRequest(rkb, &q_topics, reason, NULL);

        rd_list_destroy(&q_topics);

        if (destroy_rkb)
                rd_kafka_broker_destroy(rkb);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Refresh metadata for known topics
 *
 * @param rk: used to look up usable broker if \p rkb is NULL.
 * @param rkb: use this broker, unless NULL then any usable broker from \p rk
 * @param force: refresh even if cache is up-to-date
 *
 * @returns an error code (__UNKNOWN_TOPIC if there are no local topics)
 *
 * @locality any
 * @locks none
 */
rd_kafka_resp_err_t
rd_kafka_metadata_refresh_known_topics (rd_kafka_t *rk, rd_kafka_broker_t *rkb,
                                        int force, const char *reason) {
        rd_list_t topics;
        rd_kafka_resp_err_t err;

        if (!rk)
                rk = rkb->rkb_rk;

        rd_list_init(&topics, 8, rd_free);
        rd_kafka_local_topics_to_list(rk, &topics);

        if (rd_list_cnt(&topics) == 0)
                err = RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC;
        else
                err = rd_kafka_metadata_refresh_topics(rk, rkb,
                                                       &topics, force, reason);

        rd_list_destroy(&topics);

        return err;
}


/**
 * @brief Refresh broker list by metadata.
 *
 * Attempts to use sparse metadata request if possible, else falls back
 * on a full metadata request. (NOTE: sparse not implemented, KIP-4)
 *
 * @param rk: used to look up usable broker if \p rkb is NULL.
 * @param rkb: use this broker, unless NULL then any usable broker from \p rk
 *
 * @returns an error code
 *
 * @locality any
 * @locks none
 */
rd_kafka_resp_err_t
rd_kafka_metadata_refresh_brokers (rd_kafka_t *rk, rd_kafka_broker_t *rkb,
                                   const char *reason) {
        return rd_kafka_metadata_request(rk, rkb, NULL /*brokers only*/,
                                         reason, NULL);
}



/**
 * @brief Refresh metadata for all topics in cluster.
 *        This is a full metadata request which might be taxing on the
 *        broker if the cluster has many topics.
 *
 * @locality any
 * @locks none
 */
rd_kafka_resp_err_t
rd_kafka_metadata_refresh_all (rd_kafka_t *rk, rd_kafka_broker_t *rkb,
                               const char *reason) {
        int destroy_rkb = 0;
        rd_list_t topics;

        if (!rk)
                rk = rkb->rkb_rk;

        if (!rkb) {
                if (!(rkb = rd_kafka_broker_any_usable(rk, RD_POLL_NOWAIT, 1)))
                        return RD_KAFKA_RESP_ERR__TRANSPORT;
                destroy_rkb = 1;
        }

        rd_list_init(&topics, 0, NULL); /* empty list = all topics */
        rd_kafka_MetadataRequest(rkb, &topics, reason, NULL);
        rd_list_destroy(&topics);

        if (destroy_rkb)
                rd_kafka_broker_destroy(rkb);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**

 * @brief Lower-level Metadata request that takes a callback (with replyq set)
 *        which will be triggered after parsing is complete.
 *
 * @locks none
 * @locality any
 */
rd_kafka_resp_err_t
rd_kafka_metadata_request (rd_kafka_t *rk, rd_kafka_broker_t *rkb,
                           const rd_list_t *topics,
                           const char *reason, rd_kafka_op_t *rko) {
        int destroy_rkb = 0;

        if (!rkb) {
                if (!(rkb = rd_kafka_broker_any_usable(rk, RD_POLL_NOWAIT, 1)))
                        return RD_KAFKA_RESP_ERR__TRANSPORT;
                destroy_rkb = 1;
        }

        rd_kafka_MetadataRequest(rkb, topics, reason, rko);

        if (destroy_rkb)
                rd_kafka_broker_destroy(rkb);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Query timer callback to trigger refresh for topics
 *        that are missing their leaders.
 *
 * @locks none
 * @locality rdkafka main thread
 */
static void rd_kafka_metadata_leader_query_tmr_cb (rd_kafka_timers_t *rkts,
                                                   void *arg) {
        rd_kafka_t *rk = rkts->rkts_rk;
        rd_kafka_timer_t *rtmr = &rk->rk_metadata_cache.rkmc_query_tmr;
        rd_kafka_itopic_t *rkt;
        rd_list_t topics;

        rd_kafka_wrlock(rk);
        rd_list_init(&topics, rk->rk_topic_cnt, rd_free);

        TAILQ_FOREACH(rkt, &rk->rk_topics, rkt_link) {
                int i, no_leader = 0;
                rd_kafka_topic_rdlock(rkt);

                if (rkt->rkt_state == RD_KAFKA_TOPIC_S_NOTEXISTS) {
                        /* Skip topics that are known to not exist. */
                        rd_kafka_topic_rdunlock(rkt);
                        continue;
                }

                no_leader = rkt->rkt_flags & RD_KAFKA_TOPIC_F_LEADER_UNAVAIL;

                /* Check if any partitions are missing their leaders. */
                for (i = 0 ; !no_leader && i < rkt->rkt_partition_cnt ; i++) {
                        rd_kafka_toppar_t *rktp =
                                rd_kafka_toppar_s2i(rkt->rkt_p[i]);
                        rd_kafka_toppar_lock(rktp);
                        no_leader = !rktp->rktp_leader &&
                                !rktp->rktp_next_leader;
                        rd_kafka_toppar_unlock(rktp);
                }

                if (no_leader || rkt->rkt_partition_cnt == 0)
                        rd_list_add(&topics, rd_strdup(rkt->rkt_topic->str));

                rd_kafka_topic_rdunlock(rkt);
        }

        rd_kafka_wrunlock(rk);

        if (rd_list_cnt(&topics) == 0) {
                /* No leader-less topics+partitions, stop the timer. */
                rd_kafka_timer_stop(rkts, rtmr, 1/*lock*/);
        } else {
                rd_kafka_metadata_refresh_topics(rk, NULL, &topics, 1/*force*/,
                                                 "partition leader query");
                /* Back off next query exponentially until we reach
                 * the standard query interval - then stop the timer
                 * since the intervalled querier will do the job for us. */
                if (rk->rk_conf.metadata_refresh_interval_ms > 0 &&
                    rtmr->rtmr_interval * 2 / 1000 >=
                    rk->rk_conf.metadata_refresh_interval_ms)
                        rd_kafka_timer_stop(rkts, rtmr, 1/*lock*/);
                else
                        rd_kafka_timer_backoff(rkts, rtmr,
                                               (int)rtmr->rtmr_interval);
        }

        rd_list_destroy(&topics);
}



/**
 * @brief Trigger fast leader query to quickly pick up on leader changes.
 *        The fast leader query is a quick query followed by later queries at
 *        exponentially increased intervals until no topics are missing
 *        leaders.
 *
 * @locks none
 * @locality any
 */
void rd_kafka_metadata_fast_leader_query (rd_kafka_t *rk) {
        rd_ts_t next;

        /* Restart the timer if it will speed things up. */
        next = rd_kafka_timer_next(&rk->rk_timers,
                                   &rk->rk_metadata_cache.rkmc_query_tmr,
                                   1/*lock*/);
        if (next == -1 /* not started */ ||
            next > rk->rk_conf.metadata_refresh_fast_interval_ms*1000) {
                rd_kafka_dbg(rk, METADATA|RD_KAFKA_DBG_TOPIC, "FASTQUERY",
                             "Starting fast leader query");
                rd_kafka_timer_start(&rk->rk_timers,
                                     &rk->rk_metadata_cache.rkmc_query_tmr,
                                     rk->rk_conf.
                                     metadata_refresh_fast_interval_ms*1000,
                                     rd_kafka_metadata_leader_query_tmr_cb,
                                     NULL);
        }
}
