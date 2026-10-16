/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2025, Confluent Inc.
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
 * Mocks
 *
 */


#include "rdkafka_int.h"
#include "rdbuf.h"
#include "rdkafka_mock_int.h"
#include <math.h>

/**
 * @brief Share group target assignment (manual)
 */
typedef struct rd_kafka_mock_sharegroup_target_assignments_s {
        rd_list_t member_ids; /**< List of member ids (char *) */
        rd_list_t assignment; /**< List of rd_kafka_topic_partition_list_t */
} rd_kafka_mock_sharegroup_target_assignment_t;

/* Forward declarations */
static void rd_kafka_mock_sharegroup_session_tmr_cb(rd_kafka_timers_t *rkts,
                                                    void *arg);

/**
 * @brief Initializes sharegroups in mock cluster
 */
void rd_kafka_mock_sharegrps_init(rd_kafka_mock_cluster_t *mcluster) {
        TAILQ_INIT(&mcluster->sharegrps);
        mcluster->defaults.sharegroup_session_timeout_ms      = 45000;
        mcluster->defaults.sharegroup_heartbeat_interval_ms   = 5000;
        mcluster->defaults.sharegroup_max_delivery_attempts   = 5;
        mcluster->defaults.sharegroup_record_lock_duration_ms = 30000;
        mcluster->defaults.sharegroup_max_size                = 200;
        mcluster->defaults.sharegroup_isolation_level         = 0;
        mcluster->defaults.sharegroup_max_fetch_sessions      = 2000;
        mcluster->defaults.sharegroup_max_record_locks        = 2000;
        mcluster->defaults.sharegroup_auto_offset_reset       = 0; /* latest */
}

/**
 * @brief Find a share group by GroupId.
 */
rd_kafka_mock_sharegroup_t *
rd_kafka_mock_sharegroup_find(rd_kafka_mock_cluster_t *mcluster,
                              const rd_kafkap_str_t *GroupId) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link) {
                if (!rd_kafkap_str_cmp_str(GroupId, mshgrp->id))
                        return mshgrp;
        }
        return NULL;
}

/**
 * @brief Get or create a share group
 */
rd_kafka_mock_sharegroup_t *
rd_kafka_mock_sharegroup_get(rd_kafka_mock_cluster_t *mcluster,
                             const rd_kafkap_str_t *GroupID) {
        rd_kafka_mock_sharegroup_t *mshgrp;

        /* Check if the share group already exists */
        mshgrp = rd_kafka_mock_sharegroup_find(mcluster, GroupID);
        if (mshgrp)
                return mshgrp;

        /* Create new share group */
        mshgrp              = rd_calloc(1, sizeof(*mshgrp));
        mshgrp->cluster     = mcluster;
        mshgrp->id          = RD_KAFKAP_STR_DUP(GroupID);
        mshgrp->group_epoch = 1;
        mshgrp->session_timeout_ms =
            mcluster->defaults.sharegroup_session_timeout_ms;
        mshgrp->heartbeat_interval_ms =
            mcluster->defaults.sharegroup_heartbeat_interval_ms;

        TAILQ_INIT(&mshgrp->members);
        mshgrp->member_cnt = 0;

        /* ShareFetch state */
        TAILQ_INIT(&mshgrp->partitions);
        TAILQ_INIT(&mshgrp->fetch_sessions);
        mshgrp->partition_cnt     = 0;
        mshgrp->fetch_session_cnt = 0;

        /* Per-record limits */
        mshgrp->max_delivery_attempts =
            mcluster->defaults.sharegroup_max_delivery_attempts;
        mshgrp->record_lock_duration_ms =
            mcluster->defaults.sharegroup_record_lock_duration_ms;
        mshgrp->isolation_level = mcluster->defaults.sharegroup_isolation_level;
        mshgrp->max_size        = mcluster->defaults.sharegroup_max_size;
        mshgrp->max_fetch_sessions =
            mcluster->defaults.sharegroup_max_fetch_sessions;
        mshgrp->max_record_locks =
            mcluster->defaults.sharegroup_max_record_locks;
        mshgrp->auto_offset_reset =
            mcluster->defaults.sharegroup_auto_offset_reset;

        rd_kafka_timer_start(&mcluster->timers, &mshgrp->session_tmr,
                             1000 * 1000 /* 1s */,
                             rd_kafka_mock_sharegroup_session_tmr_cb, mshgrp);

        /* Fetch session expiry timer */
        rd_kafka_timer_start(&mcluster->timers, &mshgrp->fetch_session_tmr,
                             1000 * 1000 /* 1s */,
                             rd_kafka_mock_sgrp_fetch_session_tmr_cb, mshgrp);

        TAILQ_INSERT_TAIL(&mcluster->sharegrps, mshgrp, link);

        return mshgrp;
}

/**
 * @brief Destroy a share group
 */
void rd_kafka_mock_sharegroup_destroy(rd_kafka_mock_sharegroup_t *mshgrp) {
        rd_kafka_mock_sharegroup_member_t *member;
        rd_kafka_mock_sgrp_partmeta_t *pmeta;
        rd_kafka_mock_sgrp_fetch_session_t *session;

        TAILQ_REMOVE(&mshgrp->cluster->sharegrps, mshgrp, link);
        rd_kafka_timer_stop(&mshgrp->cluster->timers, &mshgrp->session_tmr,
                            RD_DO_LOCK);
        rd_kafka_timer_stop(&mshgrp->cluster->timers,
                            &mshgrp->fetch_session_tmr, RD_DO_LOCK);

        /* Destroy all members */
        while ((member = TAILQ_FIRST(&mshgrp->members)))
                rd_kafka_mock_sharegroup_member_destroy(mshgrp, member);

        /* Destroy ShareFetch partition metadata */
        while ((pmeta = TAILQ_FIRST(&mshgrp->partitions))) {
                rd_kafka_mock_sgrp_record_state_t *state;
                TAILQ_REMOVE(&mshgrp->partitions, pmeta, link);
                while ((state = TAILQ_FIRST(&pmeta->inflight))) {
                        TAILQ_REMOVE(&pmeta->inflight, state, link);
                        rd_free(state->owner_member_id);
                        rd_free(state);
                }
                rd_free(pmeta);
        }

        /* Destroy ShareFetch sessions */
        while ((session = TAILQ_FIRST(&mshgrp->fetch_sessions))) {
                TAILQ_REMOVE(&mshgrp->fetch_sessions, session, link);
                mshgrp->fetch_session_cnt--;
                rd_kafka_mock_sgrp_fetch_session_destroy(session);
        }

        rd_free(mshgrp->id);
        rd_free(mshgrp);
}

/**
 * @brief Find a share group member by MemberId.
 */
rd_kafka_mock_sharegroup_member_t *
rd_kafka_mock_sharegroup_member_find(rd_kafka_mock_sharegroup_t *mshgrp,
                                     const rd_kafkap_str_t *MemberId) {
        rd_kafka_mock_sharegroup_member_t *member;
        TAILQ_FOREACH(member, &mshgrp->members, link) {
                if (!rd_kafkap_str_cmp_str(MemberId, member->id))
                        return member;
        }
        return NULL;
}

/**
 * @brief Destroy a share group member.
 */
void rd_kafka_mock_sharegroup_member_destroy(
    rd_kafka_mock_sharegroup_t *mshgrp,
    rd_kafka_mock_sharegroup_member_t *member) {
        rd_assert(mshgrp->member_cnt > 0);
        TAILQ_REMOVE(&mshgrp->members, member, link);
        mshgrp->member_cnt--;
        rd_free(member->id);

        RD_IF_FREE(member->subscribed_topic_names, rd_list_destroy_free);
        RD_IF_FREE(member->assignment, rd_kafka_topic_partition_list_destroy);
        rd_free(member);
}

/**
 * @brief Mark member as active.
 */
void rd_kafka_mock_sharegroup_member_active(
    rd_kafka_mock_sharegroup_t *mshgrp,
    rd_kafka_mock_sharegroup_member_t *member) {
        rd_kafka_dbg(mshgrp->cluster->rk, MOCK, "MOCK",
                     "Marking mock share group member %s as active",
                     member->id);
        member->ts_last_activity = rd_clock();
}

/**
 * @brief Fence a member.
 */
void rd_kafka_mock_sharegroup_member_fenced(
    rd_kafka_mock_sharegroup_t *mshgrp,
    rd_kafka_mock_sharegroup_member_t *member) {
        rd_kafka_dbg(mshgrp->cluster->rk, MOCK, "MOCK",
                     "Member %s is fenced from sharegroup %s", member->id,
                     mshgrp->id);

        rd_kafka_mock_sharegroup_member_destroy(mshgrp, member);

        /* Recalculate assignments so remaining members get the
         * freed partitions. */
        rd_kafka_mock_sharegroup_assignment_recalculate(mshgrp);
}

/**
 * @brief Check all members for inactivity and remove them if timed out.
 */
static void rd_kafka_mock_sharegroup_session_tmr_cb(rd_kafka_timers_t *rkts,
                                                    void *arg) {
        rd_kafka_mock_sharegroup_t *mshgrp = arg;
        rd_kafka_mock_sharegroup_member_t *member, *tmp;
        rd_ts_t now                       = rd_clock();
        rd_kafka_mock_cluster_t *mcluster = mshgrp->cluster;

        mtx_lock(&mcluster->lock);
        TAILQ_FOREACH_SAFE(member, &mshgrp->members, link, tmp) {
                if (member->ts_last_activity +
                        (mshgrp->session_timeout_ms * 1000) >
                    now)
                        continue;

                rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                             "Member %s session timed out for sharegroup %s",
                             member->id, mshgrp->id);

                rd_kafka_mock_sharegroup_member_fenced(mshgrp, member);
        }
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Get or create a share group member.
 */
rd_kafka_mock_sharegroup_member_t *
rd_kafka_mock_sharegroup_member_get(rd_kafka_mock_sharegroup_t *mshgrp,
                                    const rd_kafkap_str_t *MemberID,
                                    int32_t MemberEpoch,
                                    rd_kafka_mock_connection_t *mconn) {
        rd_kafka_mock_sharegroup_member_t *member;

        /* Check if the member already exists */
        member = rd_kafka_mock_sharegroup_member_find(mshgrp, MemberID);
        if (member) {
                member->conn = mconn;
                rd_kafka_mock_sharegroup_member_active(mshgrp, member);
                return member;
        }

        /* Only create if epoch is 0 */
        if (MemberEpoch != 0)
                return NULL;

        /* Create new member */
        member               = rd_calloc(1, sizeof(*member));
        member->mshgrp       = mshgrp;
        member->id           = RD_KAFKAP_STR_DUP(MemberID);
        member->member_epoch = mshgrp->group_epoch;
        member->previous_member_epoch =
            -1; /* No previous epoch for new members */
        member->conn = mconn;

        TAILQ_INSERT_TAIL(&mshgrp->members, member, link);
        mshgrp->member_cnt++;
        rd_kafka_mock_sharegroup_member_active(mshgrp, member);

        return member;
}

/**
 * @brief Update share group member's subscribed topic names.
 *
 * @param member The member to update.
 * @param SubscribedTopicNames Array of topic names.
 * @param SubscribedTopicNamesCnt Count of topic names:
 *        -1 = unchanged (no modification)
 *         0 = clear all subscriptions
 *        >0 = set to provided topics
 *
 * @returns rd_true if subscriptions changed, rd_false otherwise.
 */
rd_bool_t rd_kafka_mock_sharegroup_member_subscribed_topic_names_set(
    rd_kafka_mock_sharegroup_member_t *member,
    const rd_kafkap_str_t *SubscribedTopicNames,
    int32_t SubscribedTopicNamesCnt) {
        int32_t i;

        if (SubscribedTopicNamesCnt < 0) {
                /* -1 means unchanged */
                return rd_false;
        }

        if (SubscribedTopicNamesCnt == 0) {
                /* 0 means clear all subscriptions */
                if (!member->subscribed_topic_names ||
                    rd_list_cnt(member->subscribed_topic_names) == 0) {
                        /* Already empty, no change */
                        return rd_false;
                }
                rd_list_destroy(member->subscribed_topic_names);
                member->subscribed_topic_names = NULL;
                return rd_true;
        }

        /* SubscribedTopicNamesCnt > 0: Check if subscription changed */
        if (member->subscribed_topic_names) {
                if (rd_list_cnt(member->subscribed_topic_names) ==
                    SubscribedTopicNamesCnt) {
                        rd_bool_t same = rd_true;
                        char *topic;
                        int j;

                        RD_LIST_FOREACH(topic, member->subscribed_topic_names,
                                        j) {
                                rd_bool_t found = rd_false;
                                for (i = 0; i < SubscribedTopicNamesCnt; i++) {
                                        if (!rd_kafkap_str_cmp_str(
                                                &SubscribedTopicNames[i],
                                                topic)) {
                                                found = rd_true;
                                                break;
                                        }
                                }
                                if (!found) {
                                        same = rd_false;
                                        break;
                                }
                        }
                        if (same)
                                return rd_false;
                }
        }

        /* Subscription changed, update the list */
        RD_IF_FREE(member->subscribed_topic_names, rd_list_destroy);
        member->subscribed_topic_names =
            rd_list_new(SubscribedTopicNamesCnt, rd_free);

        for (i = 0; i < SubscribedTopicNamesCnt; i++) {
                rd_list_add(member->subscribed_topic_names,
                            RD_KAFKAP_STR_DUP(&SubscribedTopicNames[i]));
        }

        return rd_true;
}

/**
 * @brief Collect all subscribed topic names from all members.
 */
static rd_list_t *rd_kafka_mock_sharegroup_collect_subscribed_topics(
    rd_kafka_mock_sharegroup_t *mshgrp) {
        rd_kafka_mock_sharegroup_member_t *member;
        rd_list_t *all_topics;

        all_topics = rd_list_new(32, rd_free);

        TAILQ_FOREACH(member, &mshgrp->members, link) {
                const char *topic;
                int i;

                if (!member->subscribed_topic_names)
                        continue;

                RD_LIST_FOREACH(topic, member->subscribed_topic_names, i) {
                        const char *existing;
                        int j;
                        rd_bool_t found = rd_false;

                        /* Check if topic already in all_topics */
                        RD_LIST_FOREACH(existing, all_topics, j) {
                                if (!strcmp(topic, existing)) {
                                        found = rd_true;
                                        break;
                                }
                        }

                        /* Add if not found */
                        if (!found) {
                                rd_list_add(all_topics, rd_strdup(topic));
                        }
                }
        }

        return all_topics;
}

/**
 * @brief Get list of member ID's subscribed to a topic.
 */
rd_list_t *rd_kafka_mock_sharegroup_get_members_for_topic(
    rd_kafka_mock_sharegroup_t *mshgrp,
    char *topic_name) {
        rd_kafka_mock_sharegroup_member_t *member;
        rd_list_t *subscribed_members;
        int member_idx = 0;

        subscribed_members = rd_list_new(mshgrp->member_cnt, rd_free);

        TAILQ_FOREACH(member, &mshgrp->members, link) {
                char *topic;
                int i;

                if (member->subscribed_topic_names) {
                        RD_LIST_FOREACH(topic, member->subscribed_topic_names,
                                        i) {
                                if (!strcmp(topic, topic_name)) {
                                        int *idx = rd_malloc(sizeof(*idx));
                                        *idx     = member_idx;
                                        rd_list_add(subscribed_members, idx);
                                        break;
                                }
                        }
                }
                member_idx++;
        }

        return subscribed_members;
}

/**
 * @brief Assign partitions of a single topic to subscribed members.
 */
void rd_kafka_mock_sharegroup_assign_topic_partitions(
    rd_kafka_mock_sharegroup_t *mshgrp,
    rd_kafka_mock_topic_t *mtopic,
    rd_list_t *subscribed_member_indices) {
        int member_count;
        int partition_cnt;
        int partition_idx;
        double precise;
        int i;

        member_count  = rd_list_cnt(subscribed_member_indices);
        partition_cnt = mtopic->partition_cnt;

        if (member_count == 0 || partition_cnt == 0)
                return;

        precise       = (double)partition_cnt / (double)member_count;
        partition_idx = 0;

        for (i = 0; i < member_count; i++) {
                int *member_idx_ptr =
                    (int *)rd_list_elem(subscribed_member_indices, i);
                rd_kafka_mock_sharegroup_member_t *member;
                int j, cnt = 0;
                int num_partitions;

                TAILQ_FOREACH(member, &mshgrp->members, link) {
                        if (cnt == *member_idx_ptr)
                                break;
                        cnt++;
                }

                if (!member)
                        continue;

                num_partitions = (int)ceil(precise * (double)(i + 1)) -
                                 (int)ceil(precise * (double)i);

                if (!member->assignment)
                        member->assignment =
                            rd_kafka_topic_partition_list_new(num_partitions);

                for (j = 0; j < num_partitions && partition_idx < partition_cnt;
                     j++, partition_idx++) {
                        rd_kafka_topic_partition_t *rktpar;
                        rktpar = rd_kafka_topic_partition_list_add(
                            member->assignment, mtopic->name, partition_idx);
                        /* Set topic ID so the response can include it */
                        rd_kafka_topic_partition_set_topic_id(rktpar,
                                                              mtopic->id);
                }
        }
}

/**
 * @brief Recalculate assignments for all members in the share group.
 */
void rd_kafka_mock_sharegroup_assignment_recalculate(
    rd_kafka_mock_sharegroup_t *mshgrp) {
        rd_kafka_mock_sharegroup_member_t *member;
        rd_list_t *all_topics;
        char *topic_name;
        int i;

        if (mshgrp->member_cnt == 0)
                return;

        /* Skip automatic assignment if manual mode is enabled */
        if (mshgrp->manual_assignment)
                return;

        TAILQ_FOREACH(member, &mshgrp->members, link) {
                if (member->assignment) {
                        rd_kafka_topic_partition_list_destroy(
                            member->assignment);
                        member->assignment = NULL;
                }
        }

        all_topics = rd_kafka_mock_sharegroup_collect_subscribed_topics(mshgrp);

        RD_LIST_FOREACH(topic_name, all_topics, i) {
                rd_kafka_mock_topic_t *mtopic;
                rd_list_t *subscribed_members;

                mtopic = rd_kafka_mock_topic_find(mshgrp->cluster, topic_name);
                if (!mtopic)
                        continue;

                subscribed_members =
                    rd_kafka_mock_sharegroup_get_members_for_topic(mshgrp,
                                                                   topic_name);

                rd_kafka_mock_sharegroup_assign_topic_partitions(
                    mshgrp, mtopic, subscribed_members);

                rd_list_destroy(subscribed_members);
        }

        mshgrp->group_epoch++;

        TAILQ_FOREACH(member, &mshgrp->members, link) {
                /* Save the current epoch as previous before bumping.
                 * This allows the client to catch up if the response
                 * with the new epoch was lost. */
                member->previous_member_epoch = member->member_epoch;
                member->member_epoch          = mshgrp->group_epoch;
        }

        rd_list_destroy(all_topics);
}

/**
 * @brief Create a new target assignment (manual)
 */
rd_kafka_mock_sharegroup_target_assignment_t *
rd_kafka_mock_sharegroup_target_assignment_new(void) {
        rd_kafka_mock_sharegroup_target_assignment_t *target_assignment;
        target_assignment = rd_calloc(1, sizeof(*target_assignment));
        rd_list_init(&target_assignment->member_ids, 0, rd_free);
        rd_list_init(&target_assignment->assignment, 0,
                     (void *)rd_kafka_topic_partition_list_destroy);

        return target_assignment;
}

/**
 * @brief Destroy target assignment
 */
void rd_kafka_mock_sharegroup_target_assignment_destroy(
    rd_kafka_mock_sharegroup_target_assignment_t *target_assignment) {
        rd_list_destroy(&target_assignment->member_ids);
        rd_list_destroy(&target_assignment->assignment);
        rd_free(target_assignment);
}

/**
 * @brief Set the target assignment for the sharegroup.
 * This applies the manual assignment to the members.
 *
 * @locks mcluster->lock MUST be held.
 */
static void rd_kafka_mock_sharegroup_target_assignment_set(
    rd_kafka_mock_sharegroup_t *mshgrp,
    rd_kafka_mock_sharegroup_target_assignment_t *target_assignment) {
        rd_kafka_mock_sharegroup_member_t *member;
        int i;

        for (i = 0; i < rd_list_cnt(&target_assignment->member_ids); i++) {
                const char *member_id =
                    rd_list_elem(&target_assignment->member_ids, i);
                const rd_kafka_topic_partition_list_t *partitions =
                    rd_list_elem(&target_assignment->assignment, i);
                rd_kafkap_str_t *member_id_str;

                member_id_str = rd_kafkap_str_new(member_id, -1);
                member =
                    rd_kafka_mock_sharegroup_member_find(mshgrp, member_id_str);
                rd_kafkap_str_destroy(member_id_str);

                if (!member) {
                        rd_kafka_dbg(mshgrp->cluster->rk, MOCK, "MOCK",
                                     "Cannot set target assignment for "
                                     "non-existing member %s in sharegroup %s",
                                     member_id, mshgrp->id);
                        continue;
                }

                if (member->assignment) {
                        rd_kafka_topic_partition_list_destroy(
                            member->assignment);
                }

                member->assignment =
                    rd_kafka_topic_partition_list_copy(partitions);

                /* Set topic IDs on each partition so the heartbeat response
                 * can include them (ShareGroupHeartbeat uses topic IDs) */
                {
                        int j;
                        for (j = 0; j < member->assignment->cnt; j++) {
                                rd_kafka_topic_partition_t *rktpar =
                                    &member->assignment->elems[j];
                                rd_kafkap_str_t topic_str = {
                                    .str = rktpar->topic,
                                    .len = strlen(rktpar->topic)};
                                rd_kafka_mock_topic_t *mtopic =
                                    rd_kafka_mock_topic_find_by_kstr(
                                        mshgrp->cluster, &topic_str);
                                if (mtopic) {
                                        rd_kafka_topic_partition_set_topic_id(
                                            rktpar, mtopic->id);
                                }
                        }
                }

                rd_kafka_dbg(
                    mshgrp->cluster->rk, MOCK, "MOCK",
                    "Target assignment set for member %s: %d partition(s)",
                    member_id, member->assignment->cnt);
        }

        /* Bump the epochs */
        TAILQ_FOREACH(member, &mshgrp->members, link) {
                member->previous_member_epoch = member->member_epoch;
                member->member_epoch          = ++mshgrp->group_epoch;
        }
}

/**
 * @brief Manual target assignment interface for sharegroups.
 */
void rd_kafka_mock_sharegroup_target_assignment(
    rd_kafka_mock_cluster_t *mcluster,
    const char *group_id,
    const char **member_ids,
    rd_kafka_topic_partition_list_t **assignment,
    size_t member_cnt) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        rd_kafka_mock_sharegroup_target_assignment_t *target_assignment;
        size_t i;
        rd_kafkap_str_t *group_id_str;

        mtx_lock(&mcluster->lock);
        group_id_str = rd_kafkap_str_new(group_id, -1);
        mshgrp       = rd_kafka_mock_sharegroup_find(mcluster, group_id_str);
        rd_kafkap_str_destroy(group_id_str);

        if (!mshgrp) {
                rd_kafka_log(mcluster->rk, LOG_ERR, "MOCK",
                             "Sharegroup %s not found for target assignment",
                             group_id);
                mtx_unlock(&mcluster->lock);
                return;
        }

        mshgrp->manual_assignment = rd_true;
        target_assignment = rd_kafka_mock_sharegroup_target_assignment_new();

        for (i = 0; i < member_cnt; i++) {
                rd_list_add(&target_assignment->member_ids,
                            rd_strdup(member_ids[i]));
                rd_list_add(&target_assignment->assignment,
                            rd_kafka_topic_partition_list_copy(assignment[i]));
        }
        rd_kafka_mock_sharegroup_target_assignment_set(mshgrp,
                                                       target_assignment);
        rd_kafka_mock_sharegroup_target_assignment_destroy(target_assignment);
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Set the sharegroup session timeout for the sharegroup.
 */
void rd_kafka_mock_sharegroup_set_session_timeout(
    rd_kafka_mock_cluster_t *mcluster,
    int session_timeout_ms) {
        mtx_lock(&mcluster->lock);
        mcluster->defaults.sharegroup_session_timeout_ms = session_timeout_ms;
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Set the sharegroup heartbeat interval for the sharegroup.
 */
void rd_kafka_mock_sharegroup_set_heartbeat_interval(
    rd_kafka_mock_cluster_t *mcluster,
    int heartbeat_interval_ms) {
        mtx_lock(&mcluster->lock);
        mcluster->defaults.sharegroup_heartbeat_interval_ms =
            heartbeat_interval_ms;
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Set the maximum delivery attempts per record for the sharegroup.
 */
void rd_kafka_mock_sharegroup_set_max_delivery_attempts(
    rd_kafka_mock_cluster_t *mcluster,
    int max_attempts) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        mtx_lock(&mcluster->lock);
        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link)
        mshgrp->max_delivery_attempts                       = max_attempts;
        mcluster->defaults.sharegroup_max_delivery_attempts = max_attempts;
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Set the per-record lock duration in milliseconds for the sharegroup.
 */
void rd_kafka_mock_sharegroup_set_record_lock_duration(
    rd_kafka_mock_cluster_t *mcluster,
    int lock_duration_ms) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        mtx_lock(&mcluster->lock);
        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link)
        mshgrp->record_lock_duration_ms = lock_duration_ms;
        mcluster->defaults.sharegroup_record_lock_duration_ms =
            lock_duration_ms;
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Set the share group isolation level for transactions.
 */
void rd_kafka_mock_sharegroup_set_isolation_level(
    rd_kafka_mock_cluster_t *mcluster,
    int level) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        mtx_lock(&mcluster->lock);
        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link)
        mshgrp->isolation_level                       = level;
        mcluster->defaults.sharegroup_isolation_level = level;
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Set the maximum number of members allowed in a share group.
 */
void rd_kafka_mock_sharegroup_set_max_size(rd_kafka_mock_cluster_t *mcluster,
                                           int max_size) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        mtx_lock(&mcluster->lock);
        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link)
        mshgrp->max_size                       = max_size;
        mcluster->defaults.sharegroup_max_size = max_size;
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Set the maximum number of fetch sessions allowed per broker.
 */
void rd_kafka_mock_sharegroup_set_max_fetch_sessions(
    rd_kafka_mock_cluster_t *mcluster,
    int max_fetch_sessions) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        mtx_lock(&mcluster->lock);
        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link)
        mshgrp->max_fetch_sessions                       = max_fetch_sessions;
        mcluster->defaults.sharegroup_max_fetch_sessions = max_fetch_sessions;
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Set the maximum number of in-flight record locks per
 *        share-partition.
 */
void rd_kafka_mock_sharegroup_set_max_record_locks(
    rd_kafka_mock_cluster_t *mcluster,
    int max_record_locks) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        mtx_lock(&mcluster->lock);
        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link)
        mshgrp->max_record_locks                       = max_record_locks;
        mcluster->defaults.sharegroup_max_record_locks = max_record_locks;
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Set the auto offset reset policy for share groups.
 */
void rd_kafka_mock_sharegroup_set_auto_offset_reset(
    rd_kafka_mock_cluster_t *mcluster,
    int auto_offset_reset) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        mtx_lock(&mcluster->lock);
        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link)
        mshgrp->auto_offset_reset                       = auto_offset_reset;
        mcluster->defaults.sharegroup_auto_offset_reset = auto_offset_reset;
        mtx_unlock(&mcluster->lock);
}

/**
 * @brief Destroy share fetch session.
 */
void rd_kafka_mock_sgrp_fetch_session_destroy(
    rd_kafka_mock_sgrp_fetch_session_t *session) {
        rd_free(session->member_id);
        RD_IF_FREE(session->partitions, rd_kafka_topic_partition_list_destroy);
        rd_free(session);
}


/**
 * @brief Common share-session validation for ShareFetch / ShareAcknowledge.
 *
 * Performs:
 *  1. Session lookup by (MemberId, NodeId).
 *  2. SessionEpoch == 0  : destroy old session if any (caller creates new).
 *  3. SessionEpoch == -1 : keep session alive (FinalContext behaviour).
 *  4. SessionEpoch  > 0  : validate that session exists and epoch matches.
 *
 * On return, \p *sessionp is set to the looked-up session (or NULL if
 * no session was found or it was closed).
 *
 * @note Does NOT handle SessionEpoch == 0 (open new session), which is
 *       ShareFetch-specific.  The caller is also responsible for
 *       incrementing session_epoch and updating ts_last_activity on
 *       success.
 *
 * @param sgrp          Share group.
 * @param MemberId      Member identifier from the request.
 * @param NodeId        Node ID of the broker handling the request.
 * @param SessionEpoch  Session epoch from the request.
 * @param sessionp      [out] Session pointer.
 * @param api_name      API name for debug messages ("ShareFetch" etc.).
 *
 * @returns Error code, or RD_KAFKA_RESP_ERR_NO_ERROR on success.
 *
 * @locks mcluster->lock MUST be held.
 */
rd_kafka_resp_err_t rd_kafka_mock_sgrp_session_validate(
    rd_kafka_mock_sharegroup_t *sgrp,
    const rd_kafkap_str_t *MemberId,
    int32_t NodeId,
    int32_t SessionEpoch,
    rd_kafka_mock_sgrp_fetch_session_t **sessionp,
    const char *api_name) {
        rd_kafka_mock_sgrp_fetch_session_t *session = NULL;

        *sessionp = NULL;

        /* The real Kafka broker's partition leader does NOT
         * validate group membership on ShareFetch — share sessions are
         * managed independently of the group coordinator. */

        /* 1. Look up existing session by (MemberId, NodeId).
         *    In real Kafka, ShareSessionCache is per-broker, so each
         *    broker maintains its own independent session for the same
         *    member.  We emulate this by keying on both fields. */
        TAILQ_FOREACH(session, &sgrp->fetch_sessions, link) {
                if (!rd_kafkap_str_cmp_str(MemberId, session->member_id) &&
                    session->node_id == NodeId)
                        break;
        }

        /* 2. SessionEpoch == 0: open a new session.
         *    If an old session exists for this member (e.g. after a
         *    LEAVE→rejoin cycle), destroy it so the caller creates a
         *    fresh one. */
        if (SessionEpoch == 0) {
                if (session) {
                        rd_kafka_mock_sgrp_release_session_locks(sgrp, session);
                        TAILQ_REMOVE(&sgrp->fetch_sessions, session, link);
                        sgrp->fetch_session_cnt--;
                        rd_kafka_mock_sgrp_fetch_session_destroy(session);
                        session = NULL;
                }
        } else if (SessionEpoch == -1) {
                /* 3. SessionEpoch == -1 (FINAL_EPOCH): return the existing
                 *    session so the caller can process final acks and
                 *    then close it.  If no session exists, fail with
                 *    SHARE_SESSION_NOT_FOUND per the protocol. */
                if (!session) {
                        *sessionp = NULL;
                        return RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND;
                }
        } else if (SessionEpoch > 0) {
                /* 4. SessionEpoch > 0: validate epoch. */
                if (!session) {
                        /* Session not in cache →
                         * SHARE_SESSION_NOT_FOUND (distinct from epoch
                         * mismatch which uses
                         * INVALID_SHARE_SESSION_EPOCH). */
                        *sessionp = NULL;
                        return RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND;
                } else if (SessionEpoch != session->session_epoch) {
                        /* Epoch mismatch → destroy the stale
                         * session and return INVALID_SHARE_SESSION_EPOCH.
                         * The client handles this by resetting its
                         * per-broker epoch to 0 (opening a fresh session
                         * on the next fetch). */
                        rd_kafka_mock_sgrp_release_session_locks(sgrp, session);
                        TAILQ_REMOVE(&sgrp->fetch_sessions, session, link);
                        sgrp->fetch_session_cnt--;
                        rd_kafka_mock_sgrp_fetch_session_destroy(session);
                        *sessionp = NULL;
                        return RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH;
                }
        }

        *sessionp = session;
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Release a single ACQUIRED record state back to AVAILABLE or ARCHIVED.
 *
 * If \p mshgrp has a max_delivery_attempts limit and the record's
 * delivery_count has reached it, the record is archived instead of
 * made available again.  Clears owner_member_id and lock_expiry_ts.
 *
 * @locks mcluster->lock MUST be held.
 */
void rd_kafka_mock_sgrp_record_release(
    rd_kafka_mock_sharegroup_t *mshgrp,
    rd_kafka_mock_sgrp_partmeta_t *pmeta,
    rd_kafka_mock_sgrp_record_state_t *state) {
        if (state->state == RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED)
                pmeta->acquired_cnt--;
        if (mshgrp->max_delivery_attempts > 0 &&
            state->delivery_count >= mshgrp->max_delivery_attempts) {
                state->state = RD_KAFKA_MOCK_SGRP_RECORD_ARCHIVED;
        } else {
                state->state = RD_KAFKA_MOCK_SGRP_RECORD_AVAILABLE;
        }
        rd_free(state->owner_member_id);
        state->owner_member_id = NULL;
        state->lock_expiry_ts  = 0;
}

/**
 * @brief Release all ACQUIRED records owned by \p session's member on
 *        the partitions belonging to \p session.
 *
 * Share sessions are per-broker: closing one broker's session must
 * only release the records acquired through that session (the
 * partitions that broker leads), never the member's locks held
 * through other brokers' intact sessions.
 *
 * This is called when a session is closed (epoch=-1), replaced
 * (epoch=0), invalidated (epoch mismatch), times out, or its
 * connection is closed.
 *
 * @locks mcluster->lock MUST be held.
 */
void rd_kafka_mock_sgrp_release_session_locks(
    rd_kafka_mock_sharegroup_t *mshgrp,
    const rd_kafka_mock_sgrp_fetch_session_t *session) {
        rd_kafka_mock_sgrp_partmeta_t *pmeta;

        if (!session->partitions)
                return;

        TAILQ_FOREACH(pmeta, &mshgrp->partitions, link) {
                rd_kafka_mock_sgrp_record_state_t *state, *tmp;
                rd_kafka_mock_topic_t *mtopic;
                rd_kafka_mock_partition_t *mpart;

                if (rd_kafka_topic_partition_list_find_idx_by_id(
                        session->partitions, pmeta->topic_id,
                        pmeta->partition) < 0)
                        continue;

                /* A session can only release locks for partitions its
                 * broker currently leads: a session's partition list
                 * can be stale after a leader change, while the locks
                 * now belong to the new leader's session. */
                mtopic = rd_kafka_mock_topic_find_by_id(mshgrp->cluster,
                                                        pmeta->topic_id);
                mpart  = mtopic ? rd_kafka_mock_partition_find(mtopic,
                                                               pmeta->partition)
                                : NULL;
                if (!mpart || !mpart->leader ||
                    mpart->leader->id != session->node_id)
                        continue;

                TAILQ_FOREACH_SAFE(state, &pmeta->inflight, link, tmp) {
                        if (state->state != RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED)
                                continue;
                        if (!state->owner_member_id)
                                continue;
                        if (strcmp(state->owner_member_id,
                                   session->member_id) != 0)
                                continue;

                        rd_kafka_mock_sgrp_record_release(mshgrp, pmeta, state);
                }
        }
}

/**
 * @brief Proactively release any expired acquisition locks.
 *
 * Iterates all partition metadata in the share group and flips
 * ACQUIRED records whose lock_expiry_ts has passed back to AVAILABLE.
 *
 * @locks mcluster->lock MUST be held.
 */
static void rd_kafka_mock_sgrp_expire_locks(rd_kafka_mock_sharegroup_t *mshgrp,
                                            rd_ts_t now) {
        rd_kafka_mock_sgrp_partmeta_t *pmeta;

        TAILQ_FOREACH(pmeta, &mshgrp->partitions, link) {
                rd_kafka_mock_sgrp_record_state_t *state, *tmp;
                TAILQ_FOREACH_SAFE(state, &pmeta->inflight, link, tmp) {
                        if (state->state != RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED)
                                continue;
                        if (!state->lock_expiry_ts ||
                            state->lock_expiry_ts > now)
                                continue;

                        /* Lock has expired. If delivery
                         * count has reached the limit, archive the
                         * record instead of making it available. */
                        rd_kafka_mock_sgrp_record_release(mshgrp, pmeta, state);
                }
        }
}

/**
 * @brief Periodic timer: expire stale share-fetch sessions and
 *        proactively reclaim expired acquisition locks.
 *
 * @locks mcluster->lock is acquired and released.
 */
void rd_kafka_mock_sgrp_fetch_session_tmr_cb(rd_kafka_timers_t *rkts,
                                             void *arg) {
        rd_kafka_mock_sharegroup_t *mshgrp = arg;
        rd_kafka_mock_sgrp_fetch_session_t *session, *tmp;
        rd_ts_t now                       = rd_clock();
        rd_kafka_mock_cluster_t *mcluster = mshgrp->cluster;

        (void)rkts;

        mtx_lock(&mcluster->lock);

        /* 1. Expire stale sessions and release their member locks. */
        TAILQ_FOREACH_SAFE(session, &mshgrp->fetch_sessions, link, tmp) {
                if (session->ts_last_activity +
                        (mshgrp->session_timeout_ms * 1000) >
                    now)
                        continue;

                /* Release all locks held by this member before
                 * destroying the session. */
                rd_kafka_mock_sgrp_release_session_locks(mshgrp, session);

                TAILQ_REMOVE(&mshgrp->fetch_sessions, session, link);
                mshgrp->fetch_session_cnt--;
                rd_kafka_mock_sgrp_fetch_session_destroy(session);
        }

        /* 2. Proactively reclaim any expired acquisition locks.
         *    This catches records whose owning consumer crashed
         *    without closing its session cleanly. */
        rd_kafka_mock_sgrp_expire_locks(mshgrp, now);

        mtx_unlock(&mcluster->lock);
}

/**
 * @brief A client connection closed, check if any sharegroup has any
 * state for this connection that needs to be cleared.
 *
 * @param mcluster Cluster to search in.
 * @param mconn Connection that was closed.
 *
 * @locks mcluster->lock MUST be held.
 */
void rd_kafka_mock_sharegrps_connection_closed(
    rd_kafka_mock_cluster_t *mcluster,
    rd_kafka_mock_connection_t *mconn) {
        rd_kafka_mock_sharegroup_t *mshgrp;

        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link) {
                rd_kafka_mock_sharegroup_member_t *member;
                /* Clear heartbeat connection for any member on this conn. */
                TAILQ_FOREACH(member, &mshgrp->members, link) {
                        if (member->conn == mconn)
                                member->conn = NULL;
                }
        }
}

/**
 * @brief Close all share fetch sessions on \p node_id.
 *
 * Called from rd_kafka_mock_connection_close() where mconn->broker is
 * guaranteed to be valid.  Must NOT be called with a fake connection pointer.
 *
 * @locks mcluster->lock MUST be held.
 */
void rd_kafka_mock_sharegrps_node_connection_closed(
    rd_kafka_mock_cluster_t *mcluster,
    int32_t node_id) {
        rd_kafka_mock_sharegroup_t *mshgrp;

        TAILQ_FOREACH(mshgrp, &mcluster->sharegrps, link) {
                rd_kafka_mock_sgrp_fetch_session_t *session, *tmp;
                /* When a connection is disconnected, any share session
                 * on that broker is automatically closed. */
                TAILQ_FOREACH_SAFE(session, &mshgrp->fetch_sessions, link,
                                   tmp) {
                        if (session->node_id != node_id)
                                continue;
                        rd_kafka_mock_sgrp_release_session_locks(mshgrp,
                                                                 session);
                        TAILQ_REMOVE(&mshgrp->fetch_sessions, session, link);
                        mshgrp->fetch_session_cnt--;
                        rd_kafka_mock_sgrp_fetch_session_destroy(session);
                }
        }
}

/**
 * @brief Retrieve the member IDs from a sharegroup.
 *
 * @param mcluster Mock cluster instance.
 * @param group_id The sharegroup ID.
 * @param member_ids_out Output array of member IDs (caller must free each
 *                       string and the array itself).
 * @param member_cnt_out Output count of members.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success,
 *          RD_KAFKA_RESP_ERR_GROUP_ID_NOT_FOUND if sharegroup not found.
 */
rd_kafka_resp_err_t
rd_kafka_mock_sharegroup_get_member_ids(rd_kafka_mock_cluster_t *mcluster,
                                        const char *group_id,
                                        char ***member_ids_out,
                                        size_t *member_cnt_out) {
        rd_kafka_mock_sharegroup_t *mshgrp;
        rd_kafka_mock_sharegroup_member_t *member;
        rd_kafkap_str_t *group_id_str;
        char **member_ids;
        size_t i;

        mtx_lock(&mcluster->lock);
        group_id_str = rd_kafkap_str_new(group_id, -1);
        mshgrp       = rd_kafka_mock_sharegroup_find(mcluster, group_id_str);
        rd_kafkap_str_destroy(group_id_str);

        if (!mshgrp) {
                mtx_unlock(&mcluster->lock);
                *member_ids_out = NULL;
                *member_cnt_out = 0;
                return RD_KAFKA_RESP_ERR_GROUP_ID_NOT_FOUND;
        }

        *member_cnt_out = mshgrp->member_cnt;
        if (mshgrp->member_cnt == 0) {
                mtx_unlock(&mcluster->lock);
                *member_ids_out = NULL;
                return RD_KAFKA_RESP_ERR_NO_ERROR;
        }

        member_ids = rd_malloc(sizeof(*member_ids) * mshgrp->member_cnt);
        i          = 0;
        TAILQ_FOREACH(member, &mshgrp->members, link) {
                member_ids[i++] = rd_strdup(member->id);
        }

        mtx_unlock(&mcluster->lock);
        *member_ids_out = member_ids;
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}