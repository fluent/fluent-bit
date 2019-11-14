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
#include "rdkafka_int.h"
#include "rdkafka_assignor.h"

#include <ctype.h>

/**
 * Clear out and free any memory used by the member, but not the rkgm itself.
 */
void rd_kafka_group_member_clear (rd_kafka_group_member_t *rkgm) {
        if (rkgm->rkgm_subscription)
                rd_kafka_topic_partition_list_destroy(rkgm->rkgm_subscription);

        if (rkgm->rkgm_assignment)
                rd_kafka_topic_partition_list_destroy(rkgm->rkgm_assignment);

        rd_list_destroy(&rkgm->rkgm_eligible);

        if (rkgm->rkgm_member_id)
                rd_kafkap_str_destroy(rkgm->rkgm_member_id);

        if (rkgm->rkgm_userdata)
                rd_kafkap_bytes_destroy(rkgm->rkgm_userdata);

        if (rkgm->rkgm_member_metadata)
                rd_kafkap_bytes_destroy(rkgm->rkgm_member_metadata);

        memset(rkgm, 0, sizeof(*rkgm));
}


/**
 * Member id string comparator (takes rd_kafka_group_member_t *)
 */
int rd_kafka_group_member_cmp (const void *_a, const void *_b) {
        const rd_kafka_group_member_t *a =
                (const rd_kafka_group_member_t *)_a;
        const rd_kafka_group_member_t *b =
                (const rd_kafka_group_member_t *)_b;

        return rd_kafkap_str_cmp(a->rkgm_member_id, b->rkgm_member_id);
}


/**
 * Returns true if member subscribes to topic, else false.
 */
int
rd_kafka_group_member_find_subscription (rd_kafka_t *rk,
					 const rd_kafka_group_member_t *rkgm,
					 const char *topic) {
	int i;

	/* Match against member's subscription. */
        for (i = 0 ; i < rkgm->rkgm_subscription->cnt ; i++) {
                const rd_kafka_topic_partition_t *rktpar =
                        &rkgm->rkgm_subscription->elems[i];

		if (rd_kafka_topic_partition_match(rk, rkgm, rktpar,
						   topic, NULL))
			return 1;
	}

	return 0;
}



static rd_kafkap_bytes_t *
rd_kafka_consumer_protocol_member_metadata_new (
	const rd_list_t *topics,
        const void *userdata, size_t userdata_size) {
        rd_kafka_buf_t *rkbuf;
        rd_kafkap_bytes_t *kbytes;
        int i;
	int topic_cnt = rd_list_cnt(topics);
	const rd_kafka_topic_info_t *tinfo;
        size_t len;

        /*
         * MemberMetadata => Version Subscription AssignmentStrategies
         *   Version      => int16
         *   Subscription => Topics UserData
         *     Topics     => [String]
         *     UserData     => Bytes
         */

        rkbuf = rd_kafka_buf_new(1, 100 + (topic_cnt * 100) + userdata_size);

        rd_kafka_buf_write_i16(rkbuf, 0);
        rd_kafka_buf_write_i32(rkbuf, topic_cnt);
	RD_LIST_FOREACH(tinfo, topics, i)
                rd_kafka_buf_write_str(rkbuf, tinfo->topic, -1);
	if (userdata)
		rd_kafka_buf_write_bytes(rkbuf, userdata, userdata_size);
	else /* Kafka 0.9.0.0 cant parse NULL bytes, so we provide empty. */
		rd_kafka_buf_write_bytes(rkbuf, "", 0);

        /* Get binary buffer and allocate a new Kafka Bytes with a copy. */
        rd_slice_init_full(&rkbuf->rkbuf_reader, &rkbuf->rkbuf_buf);
        len = rd_slice_remains(&rkbuf->rkbuf_reader);
        kbytes = rd_kafkap_bytes_new(NULL, (int32_t)len);
        rd_slice_read(&rkbuf->rkbuf_reader, (void *)kbytes->data, len);
        rd_kafka_buf_destroy(rkbuf);

        return kbytes;

}




rd_kafkap_bytes_t *
rd_kafka_assignor_get_metadata (rd_kafka_assignor_t *rkas,
				const rd_list_t *topics) {
        return rd_kafka_consumer_protocol_member_metadata_new(
                topics, rkas->rkas_userdata,
                rkas->rkas_userdata_size);
}





/**
 * Returns 1 if all subscriptions are satifised for this member, else 0.
 */
static int rd_kafka_member_subscription_match (
        rd_kafka_cgrp_t *rkcg,
        rd_kafka_group_member_t *rkgm,
        const rd_kafka_metadata_topic_t *topic_metadata,
        rd_kafka_assignor_topic_t *eligible_topic) {
        int i;
        int has_regex = 0;
        int matched = 0;

        /* Match against member's subscription. */
        for (i = 0 ; i < rkgm->rkgm_subscription->cnt ; i++) {
                const rd_kafka_topic_partition_t *rktpar =
                        &rkgm->rkgm_subscription->elems[i];
		int matched_by_regex = 0;

		if (rd_kafka_topic_partition_match(rkcg->rkcg_rk, rkgm, rktpar,
						   topic_metadata->topic,
						   &matched_by_regex)) {
			rd_list_add(&rkgm->rkgm_eligible,
				    (void *)topic_metadata);
			matched++;
			has_regex += matched_by_regex;
		}
	}

        if (matched)
                rd_list_add(&eligible_topic->members, rkgm);

        if (!has_regex &&
            rd_list_cnt(&rkgm->rkgm_eligible) == rkgm->rkgm_subscription->cnt)
                return 1; /* All subscriptions matched */
        else
                return 0;
}


static void
rd_kafka_assignor_topic_destroy (rd_kafka_assignor_topic_t *at) {
        rd_list_destroy(&at->members);
        rd_free(at);
}

int rd_kafka_assignor_topic_cmp (const void *_a, const void *_b) {
        const rd_kafka_assignor_topic_t *a =
                *(const rd_kafka_assignor_topic_t * const *)_a;
        const rd_kafka_assignor_topic_t *b =
                *(const rd_kafka_assignor_topic_t * const *)_b;

        return !strcmp(a->metadata->topic, b->metadata->topic);
}

/**
 * Maps the available topics to the group members' subscriptions
 * and updates the `member` map with the proper list of eligible topics,
 * the latter are returned in `eligible_topics`.
 */
static void
rd_kafka_member_subscriptions_map (rd_kafka_cgrp_t *rkcg,
                                   rd_list_t *eligible_topics,
                                   const rd_kafka_metadata_t *metadata,
                                   rd_kafka_group_member_t *members,
                                   int member_cnt) {
        int ti;
        rd_kafka_assignor_topic_t *eligible_topic = NULL;

        rd_list_init(eligible_topics, RD_MIN(metadata->topic_cnt, 10),
                     (void *)rd_kafka_assignor_topic_destroy);

        /* For each topic in the cluster, scan through the member list
         * to find matching subscriptions. */
        for (ti = 0 ; ti < metadata->topic_cnt ; ti++) {
                int complete_cnt = 0;
                int i;

                /* Ignore topics in blacklist */
                if (rkcg->rkcg_rk->rk_conf.topic_blacklist &&
		    rd_kafka_pattern_match(rkcg->rkcg_rk->rk_conf.
                                           topic_blacklist,
                                           metadata->topics[ti].topic)) {
                        rd_kafka_dbg(rkcg->rkcg_rk, TOPIC, "BLACKLIST",
                                   "Assignor ignoring blacklisted "
                                     "topic \"%s\"",
                                     metadata->topics[ti].topic);
                        continue;
                }

                if (!eligible_topic)
                        eligible_topic = rd_calloc(1, sizeof(*eligible_topic));

                rd_list_init(&eligible_topic->members, member_cnt, NULL);

                /* For each member: scan through its topic subscription */
                for (i = 0 ; i < member_cnt ; i++) {
                        /* Match topic against existing metadata,
                           incl regex matching. */
                        if (rd_kafka_member_subscription_match(
                                    rkcg, &members[i], &metadata->topics[ti],
                                    eligible_topic))
                                complete_cnt++;
                }

                if (rd_list_empty(&eligible_topic->members)) {
                        rd_list_destroy(&eligible_topic->members);
                        continue;
                }

                eligible_topic->metadata = &metadata->topics[ti];
                rd_list_add(eligible_topics, eligible_topic);
                eligible_topic = NULL;

                if (complete_cnt == (int)member_cnt)
                        break;
        }

        if (eligible_topic)
                rd_free(eligible_topic);
}


rd_kafka_resp_err_t
rd_kafka_assignor_run (rd_kafka_cgrp_t *rkcg,
                       const char *protocol_name,
                       rd_kafka_metadata_t *metadata,
                       rd_kafka_group_member_t *members,
                       int member_cnt,
                       char *errstr, size_t errstr_size) {
        rd_kafka_resp_err_t err;
        rd_kafka_assignor_t *rkas;
        rd_ts_t ts_start = rd_clock();
        int i;
        rd_list_t eligible_topics;
        int j;

	if (!(rkas = rd_kafka_assignor_find(rkcg->rkcg_rk, protocol_name)) ||
	    !rkas->rkas_enabled) {
		rd_snprintf(errstr, errstr_size,
			    "Unsupported assignor \"%s\"", protocol_name);
		return RD_KAFKA_RESP_ERR__UNKNOWN_PROTOCOL;
	}


        /* Map available topics to subscribing members */
        rd_kafka_member_subscriptions_map(rkcg, &eligible_topics, metadata,
                                          members, member_cnt);


        if (rkcg->rkcg_rk->rk_conf.debug & RD_KAFKA_DBG_CGRP) {
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "ASSIGN",
                             "Group \"%s\" running %s assignment for "
                             "%d member(s):",
                             rkcg->rkcg_group_id->str, protocol_name,
                             member_cnt);

                for (i = 0 ; i < member_cnt ; i++) {
                        const rd_kafka_group_member_t *member = &members[i];

                        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "ASSIGN",
                                     " Member \"%.*s\"%s with "
                                     "%d subscription(s):",
                                     RD_KAFKAP_STR_PR(member->rkgm_member_id),
                                     !rd_kafkap_str_cmp(member->rkgm_member_id,
                                                        rkcg->rkcg_member_id) ?
                                     " (me)":"",
                                     member->rkgm_subscription->cnt);
                        for (j = 0 ; j < member->rkgm_subscription->cnt ; j++) {
                                const rd_kafka_topic_partition_t *p =
                                        &member->rkgm_subscription->elems[j];
                                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "ASSIGN",
                                             "  %s [%"PRId32"]",
                                             p->topic, p->partition);
                        }
                }


        }

        /* Call assignors assign callback */
        err = rkas->rkas_assign_cb(rkcg->rkcg_rk,
                                    rkcg->rkcg_member_id->str,
                                    protocol_name, metadata,
                                    members, member_cnt,
                                    (rd_kafka_assignor_topic_t **)
                                    eligible_topics.rl_elems,
                                    eligible_topics.rl_cnt,
                                    errstr, sizeof(errstr),
                                    rkas->rkas_opaque);

        if (err) {
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "ASSIGN",
                             "Group \"%s\" %s assignment failed "
                             "for %d member(s): %s",
                             rkcg->rkcg_group_id->str, protocol_name,
                             (int)member_cnt, errstr);
        } else if (rkcg->rkcg_rk->rk_conf.debug & RD_KAFKA_DBG_CGRP) {
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "ASSIGN",
                             "Group \"%s\" %s assignment for %d member(s) "
                             "finished in %.3fms:",
                             rkcg->rkcg_group_id->str, protocol_name,
                             (int)member_cnt,
                             (float)(rd_clock() - ts_start)/1000.0f);
                for (i = 0 ; i < member_cnt ; i++) {
                        const rd_kafka_group_member_t *member = &members[i];

                        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "ASSIGN",
                                     " Member \"%.*s\"%s assigned "
                                     "%d partition(s):",
                                     RD_KAFKAP_STR_PR(member->rkgm_member_id),
                                     !rd_kafkap_str_cmp(member->rkgm_member_id,
                                                        rkcg->rkcg_member_id) ?
                                     " (me)":"",
                                     member->rkgm_assignment->cnt);
                        for (j = 0 ; j < member->rkgm_assignment->cnt ; j++) {
                                const rd_kafka_topic_partition_t *p =
                                        &member->rkgm_assignment->elems[j];
                                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "ASSIGN",
                                             "  %s [%"PRId32"]",
                                             p->topic, p->partition);
                        }
                }
        }

        rd_list_destroy(&eligible_topics);

        return err;
}


/**
 * Assignor protocol string comparator
 */
static int rd_kafka_assignor_cmp_str (const void *_a, const void *_b) {
        const char *a = _a;
        const rd_kafka_assignor_t *b = _b;

        return rd_kafkap_str_cmp_str2(a, b->rkas_protocol_name);
}

/**
 * Find assignor by protocol name.
 *
 * Locality: any
 * Locks: none
 */
rd_kafka_assignor_t *
rd_kafka_assignor_find (rd_kafka_t *rk, const char *protocol) {
        return (rd_kafka_assignor_t *)
                rd_list_find(&rk->rk_conf.partition_assignors, protocol,
                             rd_kafka_assignor_cmp_str);
}


/**
 * Destroys an assignor (but does not unlink).
 */
static void rd_kafka_assignor_destroy (rd_kafka_assignor_t *rkas) {
        rd_kafkap_str_destroy(rkas->rkas_protocol_type);
        rd_kafkap_str_destroy(rkas->rkas_protocol_name);
        rd_free(rkas);
}



/**
 * Add an assignor, overwriting any previous one with the same protocol_name.
 */
static rd_kafka_resp_err_t
rd_kafka_assignor_add (rd_kafka_t *rk,
		       rd_kafka_assignor_t **rkasp,
                       const char *protocol_type,
                       const char *protocol_name,
                       rd_kafka_resp_err_t (*assign_cb) (
                               rd_kafka_t *rk,
                               const char *member_id,
                               const char *protocol_name,
                               const rd_kafka_metadata_t *metadata,
                               rd_kafka_group_member_t *members,
                               size_t member_cnt,
                               rd_kafka_assignor_topic_t **eligible_topics,
                               size_t eligible_topic_cnt,
                               char *errstr, size_t errstr_size, void *opaque),
                       void *opaque) {
        rd_kafka_assignor_t *rkas;

	if (rkasp)
		*rkasp = NULL;

        if (rd_kafkap_str_cmp_str(rk->rk_conf.group_protocol_type,
                                  protocol_type))
                return RD_KAFKA_RESP_ERR__UNKNOWN_PROTOCOL;

        /* Dont overwrite application assignors */
        if ((rkas = rd_kafka_assignor_find(rk, protocol_name))) {
		if (rkasp)
			*rkasp = rkas;
		return RD_KAFKA_RESP_ERR__CONFLICT;
	}

        rkas = rd_calloc(1, sizeof(*rkas));

        rkas->rkas_protocol_name    = rd_kafkap_str_new(protocol_name, -1);
        rkas->rkas_protocol_type    = rd_kafkap_str_new(protocol_type, -1);
        rkas->rkas_assign_cb        = assign_cb;
        rkas->rkas_get_metadata_cb  = rd_kafka_assignor_get_metadata;
        rkas->rkas_opaque = opaque;

        rd_list_add(&rk->rk_conf.partition_assignors, rkas);

	if (rkasp)
		*rkasp = rkas;

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/* Right trim string of whitespaces */
static void rtrim (char *s) {
	char *e = s + strlen(s);

	if (e == s)
		return;

	while (e >= s && isspace(*e))
		e--;

	*e = '\0';
}


/**
 * Initialize assignor list based on configuration.
 */
int rd_kafka_assignors_init (rd_kafka_t *rk, char *errstr, size_t errstr_size) {
	char *wanted;
	char *s;

        rd_list_init(&rk->rk_conf.partition_assignors, 2,
                     (void *)rd_kafka_assignor_destroy);

	rd_strdupa(&wanted, rk->rk_conf.partition_assignment_strategy);

	s = wanted;
	while (*s) {
		rd_kafka_assignor_t *rkas = NULL;
		char *t;

		/* Left trim */
		while (*s == ' ' || *s == ',')
			s++;

		if ((t = strchr(s, ','))) {
			*t = '\0';
			t++;
		} else {
			t = s + strlen(s);
		}

		/* Right trim */
		rtrim(s);

		/* Match builtin consumer assignors */
		if (!strcmp(s, "range"))
			rd_kafka_assignor_add(
				rk, &rkas, "consumer", "range",
				rd_kafka_range_assignor_assign_cb,
				NULL);
		else if (!strcmp(s, "roundrobin"))
			rd_kafka_assignor_add(
				rk, &rkas, "consumer", "roundrobin",
				rd_kafka_roundrobin_assignor_assign_cb,
				NULL);
		else {
			rd_snprintf(errstr, errstr_size,
				    "Unsupported partition.assignment.strategy:"
				    " %s", s);
			return -1;
		}

		if (rkas) {
			if (!rkas->rkas_enabled) {
				rkas->rkas_enabled = 1;
				rk->rk_conf.enabled_assignor_cnt++;
			}
		}

		s = t;
	}

	return 0;
}



/**
 * Free assignors
 */
void rd_kafka_assignors_term (rd_kafka_t *rk) {
        rd_list_destroy(&rk->rk_conf.partition_assignors);
}
