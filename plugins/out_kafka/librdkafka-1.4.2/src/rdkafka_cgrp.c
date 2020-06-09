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

#include "rdkafka_int.h"
#include "rdkafka_broker.h"
#include "rdkafka_request.h"
#include "rdkafka_topic.h"
#include "rdkafka_partition.h"
#include "rdkafka_assignor.h"
#include "rdkafka_offset.h"
#include "rdkafka_metadata.h"
#include "rdkafka_cgrp.h"
#include "rdkafka_interceptor.h"

#include "rdunittest.h"

#include <ctype.h>


static void rd_kafka_cgrp_check_unassign_done (rd_kafka_cgrp_t *rkcg,
                                               const char *reason);
static void rd_kafka_cgrp_offset_commit_tmr_cb (rd_kafka_timers_t *rkts,
                                                void *arg);
static rd_kafka_resp_err_t
rd_kafka_cgrp_assign (rd_kafka_cgrp_t *rkcg,
                      rd_kafka_topic_partition_list_t *assignment);
static rd_kafka_resp_err_t rd_kafka_cgrp_unassign (rd_kafka_cgrp_t *rkcg);
static void
rd_kafka_cgrp_partitions_fetch_start0 (rd_kafka_cgrp_t *rkcg,
				       rd_kafka_topic_partition_list_t
				       *assignment, int usable_offsets,
				       int line);
#define rd_kafka_cgrp_partitions_fetch_start(rkcg,assignment,usable_offsets) \
	rd_kafka_cgrp_partitions_fetch_start0(rkcg,assignment,usable_offsets,\
					      __LINE__)
static rd_kafka_op_res_t
rd_kafka_cgrp_op_serve (rd_kafka_t *rk, rd_kafka_q_t *rkq,
                        rd_kafka_op_t *rko, rd_kafka_q_cb_type_t cb_type,
                        void *opaque);

static void rd_kafka_cgrp_group_leader_reset (rd_kafka_cgrp_t *rkcg,
                                              const char *reason);

static RD_INLINE int rd_kafka_cgrp_try_terminate (rd_kafka_cgrp_t *rkcg);

static void rd_kafka_cgrp_rebalance (rd_kafka_cgrp_t *rkcg,
                                     const char *reason);

static void
rd_kafka_cgrp_max_poll_interval_check_tmr_cb (rd_kafka_timers_t *rkts,
                                              void *arg);


/**
 * @returns true if cgrp can start partition fetchers, which is true if
 *          there is a subscription and the group is fully joined, or there
 *          is no subscription (in which case the join state is irrelevant)
 *          such as for an assign() without subscribe(). */
#define RD_KAFKA_CGRP_CAN_FETCH_START(rkcg) \
	((rkcg)->rkcg_join_state == RD_KAFKA_CGRP_JOIN_STATE_ASSIGNED)

/**
 * @returns true if cgrp is waiting for a rebalance_cb to be handled by
 *          the application.
 */
#define RD_KAFKA_CGRP_WAIT_REBALANCE_CB(rkcg)			\
	((rkcg)->rkcg_join_state ==				\
	 RD_KAFKA_CGRP_JOIN_STATE_WAIT_ASSIGN_REBALANCE_CB ||	\
	 (rkcg)->rkcg_join_state ==				\
	 RD_KAFKA_CGRP_JOIN_STATE_WAIT_REVOKE_REBALANCE_CB)


const char *rd_kafka_cgrp_state_names[] = {
        "init",
        "term",
        "query-coord",
        "wait-coord",
        "wait-broker",
        "wait-broker-transport",
        "up"
};

const char *rd_kafka_cgrp_join_state_names[] = {
        "init",
        "wait-join",
        "wait-metadata",
        "wait-sync",
        "wait-unassign",
        "wait-assign-rebalance_cb",
	"wait-revoke-rebalance_cb",
        "assigned",
	"started"
};


/**
 * @brief Change the cgrp state.
 *
 * @returns 1 if the state was changed, else 0.
 */
static int rd_kafka_cgrp_set_state (rd_kafka_cgrp_t *rkcg, int state) {
        if ((int)rkcg->rkcg_state == state)
                return 0;

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPSTATE",
                     "Group \"%.*s\" changed state %s -> %s "
                     "(v%d, join-state %s)",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_kafka_cgrp_state_names[rkcg->rkcg_state],
                     rd_kafka_cgrp_state_names[state],
		     rkcg->rkcg_version,
                     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state]);
        rkcg->rkcg_state = state;
        rkcg->rkcg_ts_statechange = rd_clock();

	rd_kafka_brokers_broadcast_state_change(rkcg->rkcg_rk);

        return 1;
}


void rd_kafka_cgrp_set_join_state (rd_kafka_cgrp_t *rkcg, int join_state) {
        if ((int)rkcg->rkcg_join_state == join_state)
                return;

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPJOINSTATE",
                     "Group \"%.*s\" changed join state %s -> %s "
                     "(v%d, state %s)",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state],
                     rd_kafka_cgrp_join_state_names[join_state],
		     rkcg->rkcg_version,
                     rd_kafka_cgrp_state_names[rkcg->rkcg_state]);
        rkcg->rkcg_join_state = join_state;
}


static RD_INLINE void
rd_kafka_cgrp_version_new_barrier0 (rd_kafka_cgrp_t *rkcg,
				    const char *func, int line) {
	rkcg->rkcg_version++;
	rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "BARRIER",
		     "Group \"%.*s\": %s:%d: new version barrier v%d",
		     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id), func, line,
		     rkcg->rkcg_version);
}

#define rd_kafka_cgrp_version_new_barrier(rkcg) \
	rd_kafka_cgrp_version_new_barrier0(rkcg, __FUNCTION__, __LINE__)


void rd_kafka_cgrp_destroy_final (rd_kafka_cgrp_t *rkcg) {
        rd_kafka_assert(rkcg->rkcg_rk, !rkcg->rkcg_assignment);
        rd_kafka_assert(rkcg->rkcg_rk, !rkcg->rkcg_subscription);
        rd_kafka_assert(rkcg->rkcg_rk, !rkcg->rkcg_group_leader.members);
        rd_kafka_cgrp_set_member_id(rkcg, NULL);
        if (rkcg->rkcg_group_instance_id)
                 rd_kafkap_str_destroy(rkcg->rkcg_group_instance_id);

        rd_kafka_q_destroy_owner(rkcg->rkcg_q);
        rd_kafka_q_destroy_owner(rkcg->rkcg_ops);
	rd_kafka_q_destroy_owner(rkcg->rkcg_wait_coord_q);
        rd_kafka_assert(rkcg->rkcg_rk, TAILQ_EMPTY(&rkcg->rkcg_topics));
        rd_kafka_assert(rkcg->rkcg_rk, rd_list_empty(&rkcg->rkcg_toppars));
        rd_list_destroy(&rkcg->rkcg_toppars);
        rd_list_destroy(rkcg->rkcg_subscribed_topics);
        rd_free(rkcg);
}



/**
 * @brief Update the absolute session timeout following a successfull
 *        response from the coordinator.
 *        This timeout is used to enforce the session timeout in the
 *        consumer itself.
 *
 * @param reset if true the timeout is updated even if the session has expired.
 */
static RD_INLINE void
rd_kafka_cgrp_update_session_timeout (rd_kafka_cgrp_t *rkcg, rd_bool_t reset) {
        if (reset || rkcg->rkcg_ts_session_timeout != 0)
                rkcg->rkcg_ts_session_timeout = rd_clock() +
                        (rkcg->rkcg_rk->rk_conf.group_session_timeout_ms*1000);
}



rd_kafka_cgrp_t *rd_kafka_cgrp_new (rd_kafka_t *rk,
                                    const rd_kafkap_str_t *group_id,
                                    const rd_kafkap_str_t *client_id) {
        rd_kafka_cgrp_t *rkcg;

        rkcg = rd_calloc(1, sizeof(*rkcg));

        rkcg->rkcg_rk = rk;
        rkcg->rkcg_group_id = group_id;
        rkcg->rkcg_client_id = client_id;
        rkcg->rkcg_coord_id = -1;
        rkcg->rkcg_generation_id = -1;
	rkcg->rkcg_version = 1;

        mtx_init(&rkcg->rkcg_lock, mtx_plain);
        rkcg->rkcg_ops = rd_kafka_q_new(rk);
        rkcg->rkcg_ops->rkq_serve = rd_kafka_cgrp_op_serve;
        rkcg->rkcg_ops->rkq_opaque = rkcg;
        rkcg->rkcg_wait_coord_q = rd_kafka_q_new(rk);
        rkcg->rkcg_wait_coord_q->rkq_serve = rkcg->rkcg_ops->rkq_serve;
        rkcg->rkcg_wait_coord_q->rkq_opaque = rkcg->rkcg_ops->rkq_opaque;
        rkcg->rkcg_q = rd_kafka_q_new(rk);
        rkcg->rkcg_group_instance_id =
                rd_kafkap_str_new(rk->rk_conf.group_instance_id, -1);

        TAILQ_INIT(&rkcg->rkcg_topics);
        rd_list_init(&rkcg->rkcg_toppars, 32, NULL);
        rd_kafka_cgrp_set_member_id(rkcg, "");
        rkcg->rkcg_subscribed_topics =
                rd_list_new(0, (void *)rd_kafka_topic_info_destroy);
        rd_interval_init(&rkcg->rkcg_coord_query_intvl);
        rd_interval_init(&rkcg->rkcg_heartbeat_intvl);
        rd_interval_init(&rkcg->rkcg_join_intvl);
        rd_interval_init(&rkcg->rkcg_timeout_scan_intvl);

        /* Create a logical group coordinator broker to provide
         * a dedicated connection for group coordination.
         * This is needed since JoinGroup may block for up to
         * max.poll.interval.ms, effectively blocking and timing out
         * any other protocol requests (such as Metadata).
         * The address for this broker will be updated when
         * the group coordinator is assigned. */
        rkcg->rkcg_coord = rd_kafka_broker_add_logical(rk, "GroupCoordinator");

        if (rk->rk_conf.enable_auto_commit &&
            rk->rk_conf.auto_commit_interval_ms > 0)
                rd_kafka_timer_start(&rk->rk_timers,
                                     &rkcg->rkcg_offset_commit_tmr,
                                     rk->rk_conf.
				     auto_commit_interval_ms * 1000ll,
                                     rd_kafka_cgrp_offset_commit_tmr_cb,
                                     rkcg);

        return rkcg;
}


/**
 * @brief Set the group coordinator broker.
 */
static void rd_kafka_cgrp_coord_set_broker (rd_kafka_cgrp_t *rkcg,
                                            rd_kafka_broker_t *rkb) {

        rd_assert(rkcg->rkcg_curr_coord == NULL);

        rd_assert(RD_KAFKA_CGRP_BROKER_IS_COORD(rkcg, rkb));

        rkcg->rkcg_curr_coord = rkb;
        rd_kafka_broker_keep(rkb);

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "COORDSET",
                     "Group \"%.*s\" coordinator set to broker %s",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_kafka_broker_name(rkb));

        /* Reset query interval to trigger an immediate
         * coord query if required */
        if (!rd_interval_disabled(&rkcg->rkcg_coord_query_intvl))
                rd_interval_reset(&rkcg->rkcg_coord_query_intvl);

        rd_kafka_cgrp_set_state(rkcg,
                                RD_KAFKA_CGRP_STATE_WAIT_BROKER_TRANSPORT);

        rd_kafka_broker_persistent_connection_add(
                rkcg->rkcg_coord, &rkcg->rkcg_coord->rkb_persistconn.coord);

        /* Set the logical coordinator's nodename to the
         * proper broker's nodename, this will trigger a (re)connect
         * to the new address. */
        rd_kafka_broker_set_nodename(rkcg->rkcg_coord, rkb);
}


/**
 * @brief Reset/clear the group coordinator broker.
 */
static void rd_kafka_cgrp_coord_clear_broker (rd_kafka_cgrp_t *rkcg) {
        rd_kafka_broker_t *rkb = rkcg->rkcg_curr_coord;

        rd_assert(rkcg->rkcg_curr_coord);
        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "COORDCLEAR",
                     "Group \"%.*s\" broker %s is no longer coordinator",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_kafka_broker_name(rkb));

        rd_assert(rkcg->rkcg_coord);

        rd_kafka_broker_persistent_connection_del(
                rkcg->rkcg_coord,
                &rkcg->rkcg_coord->rkb_persistconn.coord);

        /* Clear the ephemeral broker's nodename.
         * This will also trigger a disconnect. */
        rd_kafka_broker_set_nodename(rkcg->rkcg_coord, NULL);

        rkcg->rkcg_curr_coord = NULL;
        rd_kafka_broker_destroy(rkb); /* from set_coord_broker() */
}


/**
 * @brief Update/set the group coordinator.
 *
 * Will do nothing if there's been no change.
 *
 * @returns 1 if the coordinator, or state, was updated, else 0.
 */
static int rd_kafka_cgrp_coord_update (rd_kafka_cgrp_t *rkcg,
                                       int32_t coord_id) {

        /* Don't do anything while terminating */
        if (rkcg->rkcg_state == RD_KAFKA_CGRP_STATE_TERM)
                return 0;

        /* Check if coordinator changed */
        if (rkcg->rkcg_coord_id != coord_id) {
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPCOORD",
                             "Group \"%.*s\" changing coordinator %"PRId32
                             " -> %"PRId32,
                             RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                             rkcg->rkcg_coord_id, coord_id);

                /* Update coord id */
                rkcg->rkcg_coord_id = coord_id;

                /* Clear previous broker handle, if any */
                if (rkcg->rkcg_curr_coord)
                        rd_kafka_cgrp_coord_clear_broker(rkcg);
        }


        if (rkcg->rkcg_curr_coord) {
                /* There is already a known coordinator and a
                 * corresponding broker handle. */
                if (rkcg->rkcg_state != RD_KAFKA_CGRP_STATE_UP)
                        return rd_kafka_cgrp_set_state(
                                rkcg,
                                RD_KAFKA_CGRP_STATE_WAIT_BROKER_TRANSPORT);

        } else if (rkcg->rkcg_coord_id != -1) {
                rd_kafka_broker_t *rkb;

                /* Try to find the coordinator broker handle */
                rd_kafka_rdlock(rkcg->rkcg_rk);
                rkb = rd_kafka_broker_find_by_nodeid(rkcg->rkcg_rk, coord_id);
                rd_kafka_rdunlock(rkcg->rkcg_rk);

                /* It is possible, due to stale metadata, that the
                 * coordinator id points to a broker we still don't know
                 * about. In this case the client will continue
                 * querying metadata and querying for the coordinator
                 * until a match is found. */

                if (rkb) {
                        /* Coordinator is known and broker handle exists */
                        rd_kafka_cgrp_coord_set_broker(rkcg, rkb);
                        rd_kafka_broker_destroy(rkb); /*from find_by_nodeid()*/

                        return 1;
                } else {
                        /* Coordinator is known but no corresponding
                         * broker handle. */
                        return rd_kafka_cgrp_set_state(
                                rkcg, RD_KAFKA_CGRP_STATE_WAIT_BROKER);

                }

        } else {
                /* Coordinator still not known, re-query */
                if (rkcg->rkcg_state >= RD_KAFKA_CGRP_STATE_WAIT_COORD)
                        return rd_kafka_cgrp_set_state(
                                rkcg, RD_KAFKA_CGRP_STATE_QUERY_COORD);
        }

        return 0; /* no change */
}




/**
 * Handle FindCoordinator response
 */
static void rd_kafka_cgrp_handle_FindCoordinator (rd_kafka_t *rk,
                                                  rd_kafka_broker_t *rkb,
                                                  rd_kafka_resp_err_t err,
                                                  rd_kafka_buf_t *rkbuf,
                                                  rd_kafka_buf_t *request,
                                                  void *opaque) {
        const int log_decode_errors = LOG_ERR;
        int16_t ErrorCode = 0;
        int32_t CoordId;
        rd_kafkap_str_t CoordHost = RD_ZERO_INIT;
        int32_t CoordPort;
        rd_kafka_cgrp_t *rkcg = opaque;
        struct rd_kafka_metadata_broker mdb = RD_ZERO_INIT;
        char *errstr = NULL;

        if (likely(!(ErrorCode = err))) {
                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1)
                        rd_kafka_buf_read_throttle_time(rkbuf);

                rd_kafka_buf_read_i16(rkbuf, &ErrorCode);

                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                        rd_kafkap_str_t ErrorMsg;

                        rd_kafka_buf_read_str(rkbuf, &ErrorMsg);

                        if (!RD_KAFKAP_STR_IS_NULL(&ErrorMsg))
                                RD_KAFKAP_STR_DUPA(&errstr, &ErrorMsg);
                }

                rd_kafka_buf_read_i32(rkbuf, &CoordId);
                rd_kafka_buf_read_str(rkbuf, &CoordHost);
                rd_kafka_buf_read_i32(rkbuf, &CoordPort);
        }

        if (ErrorCode)
                goto err2;


        mdb.id = CoordId;
	RD_KAFKAP_STR_DUPA(&mdb.host, &CoordHost);
	mdb.port = CoordPort;

        rd_rkb_dbg(rkb, CGRP, "CGRPCOORD",
                   "Group \"%.*s\" coordinator is %s:%i id %"PRId32,
                   RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                   mdb.host, mdb.port, mdb.id);
        rd_kafka_broker_update(rkb->rkb_rk, rkb->rkb_proto, &mdb, NULL);

        rd_kafka_cgrp_coord_update(rkcg, CoordId);
        rd_kafka_cgrp_serve(rkcg); /* Serve updated state, if possible */
        return;

err_parse: /* Parse error */
        ErrorCode = rkbuf->rkbuf_err;
        /* FALLTHRU */

err2:
        if (!errstr)
                errstr = (char *)rd_kafka_err2str(ErrorCode);

        rd_rkb_dbg(rkb, CGRP, "CGRPCOORD",
                   "Group \"%.*s\" FindCoordinator response error: %s: %s",
                   RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                   rd_kafka_err2name(ErrorCode), errstr);

        if (ErrorCode == RD_KAFKA_RESP_ERR__DESTROY)
                return;

        /* No need for retries since the coord query is intervalled. */

        if (ErrorCode == RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE)
                rd_kafka_cgrp_coord_update(rkcg, -1);
	else {
                if (rkcg->rkcg_last_err != ErrorCode) {
                        rd_kafka_q_op_err(rkcg->rkcg_q,
                                          RD_KAFKA_OP_CONSUMER_ERR,
                                          ErrorCode, 0, NULL, 0,
                                          "FindCoordinator response error: %s",
                                          errstr);

                        /* Suppress repeated errors */
                        rkcg->rkcg_last_err = ErrorCode;
                }

		/* Continue querying */
		rd_kafka_cgrp_set_state(rkcg, RD_KAFKA_CGRP_STATE_QUERY_COORD);
        }

        rd_kafka_cgrp_serve(rkcg); /* Serve updated state, if possible */
}


/**
 * Query for coordinator.
 * Ask any broker in state UP
 *
 * Locality: main thread
 */
void rd_kafka_cgrp_coord_query (rd_kafka_cgrp_t *rkcg,
				const char *reason) {
	rd_kafka_broker_t *rkb;
        rd_kafka_resp_err_t err;

	rd_kafka_rdlock(rkcg->rkcg_rk);
        rkb = rd_kafka_broker_any_up(rkcg->rkcg_rk,
                                     NULL,
                                     rd_kafka_broker_filter_can_coord_query,
                                     NULL, "coordinator query");
	rd_kafka_rdunlock(rkcg->rkcg_rk);

	if (!rkb) {
		rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPQUERY",
			     "Group \"%.*s\": "
			     "no broker available for coordinator query: %s",
			     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id), reason);
		return;
	}

        rd_rkb_dbg(rkb, CGRP, "CGRPQUERY",
                   "Group \"%.*s\": querying for coordinator: %s",
                   RD_KAFKAP_STR_PR(rkcg->rkcg_group_id), reason);

        err = rd_kafka_FindCoordinatorRequest(
                rkb, RD_KAFKA_COORD_GROUP, rkcg->rkcg_group_id->str,
                RD_KAFKA_REPLYQ(rkcg->rkcg_ops, 0),
                rd_kafka_cgrp_handle_FindCoordinator, rkcg);

        if (err) {
                rd_rkb_dbg(rkb, CGRP, "CGRPQUERY",
                           "Group \"%.*s\": "
                           "unable to send coordinator query: %s",
                           RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                           rd_kafka_err2str(err));
                rd_kafka_broker_destroy(rkb);
                return;
        }

        if (rkcg->rkcg_state == RD_KAFKA_CGRP_STATE_QUERY_COORD)
                rd_kafka_cgrp_set_state(rkcg, RD_KAFKA_CGRP_STATE_WAIT_COORD);

	rd_kafka_broker_destroy(rkb);

        /* Back off the next intervalled query since we just sent one. */
        rd_interval_reset_to_now(&rkcg->rkcg_coord_query_intvl, 0);
}

/**
 * @brief Mark the current coordinator as dead.
 *
 * @locality main thread
 */
void rd_kafka_cgrp_coord_dead (rd_kafka_cgrp_t *rkcg, rd_kafka_resp_err_t err,
                               const char *reason) {
        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "COORD",
                     "Group \"%.*s\": "
                     "marking the coordinator (%"PRId32") dead: %s: %s",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rkcg->rkcg_coord_id, rd_kafka_err2str(err), reason);

	rd_kafka_cgrp_coord_update(rkcg, -1);

	/* Re-query for coordinator */
	rd_kafka_cgrp_set_state(rkcg, RD_KAFKA_CGRP_STATE_QUERY_COORD);
	rd_kafka_cgrp_coord_query(rkcg, reason);
}



/**
 * @brief cgrp handling of LeaveGroup responses
 * @param opaque must be the cgrp handle.
 * @locality rdkafka main thread (unless err==ERR__DESTROY)
 */
static void rd_kafka_cgrp_handle_LeaveGroup (rd_kafka_t *rk,
                                             rd_kafka_broker_t *rkb,
                                             rd_kafka_resp_err_t err,
                                             rd_kafka_buf_t *rkbuf,
                                             rd_kafka_buf_t *request,
                                             void *opaque) {
        rd_kafka_cgrp_t *rkcg = opaque;
        const int log_decode_errors = LOG_ERR;
        int16_t ErrorCode = 0;

        if (err) {
                ErrorCode = err;
                goto err;
        }

        if (request->rkbuf_reqhdr.ApiVersion >= 1)
                rd_kafka_buf_read_throttle_time(rkbuf);

        rd_kafka_buf_read_i16(rkbuf, &ErrorCode);

err:
        if (ErrorCode)
                rd_kafka_dbg(rkb->rkb_rk, CGRP, "LEAVEGROUP",
                             "LeaveGroup response error in state %s: %s",
                             rd_kafka_cgrp_state_names[rkcg->rkcg_state],
                             rd_kafka_err2str(ErrorCode));
        else
                rd_kafka_dbg(rkb->rkb_rk, CGRP, "LEAVEGROUP",
                             "LeaveGroup response received in state %s",
                             rd_kafka_cgrp_state_names[rkcg->rkcg_state]);

        if (ErrorCode != RD_KAFKA_RESP_ERR__DESTROY) {
                rd_assert(thrd_is_current(rk->rk_thread));
                rkcg->rkcg_flags &= ~RD_KAFKA_CGRP_F_WAIT_LEAVE;
                rd_kafka_cgrp_try_terminate(rkcg);
        }



        return;

 err_parse:
        ErrorCode = rkbuf->rkbuf_err;
        goto err;
}


static void rd_kafka_cgrp_leave (rd_kafka_cgrp_t *rkcg) {

        if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_WAIT_LEAVE) {
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "LEAVE",
                             "Group \"%.*s\": leave (in state %s): "
                             "LeaveGroupRequest already in-transit",
                             RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                             rd_kafka_cgrp_state_names[rkcg->rkcg_state]);
                return;
        }

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "LEAVE",
                     "Group \"%.*s\": leave (in state %s)",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_kafka_cgrp_state_names[rkcg->rkcg_state]);

        rkcg->rkcg_flags |= RD_KAFKA_CGRP_F_WAIT_LEAVE;

        if (rkcg->rkcg_state == RD_KAFKA_CGRP_STATE_UP) {
                rd_rkb_dbg(rkcg->rkcg_curr_coord, CONSUMER, "LEAVE",
                           "Leaving group");
                rd_kafka_LeaveGroupRequest(rkcg->rkcg_coord,
                                           rkcg->rkcg_group_id,
                                           rkcg->rkcg_member_id,
                                           rkcg->rkcg_group_instance_id,
                                           RD_KAFKA_REPLYQ(rkcg->rkcg_ops, 0),
                                           rd_kafka_cgrp_handle_LeaveGroup,
                                           rkcg);
        } else
                rd_kafka_cgrp_handle_LeaveGroup(rkcg->rkcg_rk,
                                                rkcg->rkcg_coord,
                                                RD_KAFKA_RESP_ERR__WAIT_COORD,
                                                NULL, NULL, rkcg);
}


/**
 * Enqueue a rebalance op (if configured). 'partitions' is copied.
 * This delegates the responsibility of assign() and unassign() to the
 * application.
 *
 * Returns 1 if a rebalance op was enqueued, else 0.
 * Returns 0 if there was no rebalance_cb or 'assignment' is NULL,
 * in which case rd_kafka_cgrp_assign(rkcg,assignment) is called immediately.
 */
static int
rd_kafka_rebalance_op (rd_kafka_cgrp_t *rkcg,
		       rd_kafka_resp_err_t err,
		       rd_kafka_topic_partition_list_t *assignment,
		       const char *reason) {
	rd_kafka_op_t *rko;

        rd_kafka_wrlock(rkcg->rkcg_rk);
        rkcg->rkcg_c.ts_rebalance = rd_clock();
        rkcg->rkcg_c.rebalance_cnt++;
        rd_kafka_wrunlock(rkcg->rkcg_rk);

        /* Pause current partition set consumers until new assign() is called */
        if (rkcg->rkcg_assignment)
                rd_kafka_toppars_pause_resume(rkcg->rkcg_rk,
                                              rd_true/*pause*/,
                                              RD_ASYNC,
                                              RD_KAFKA_TOPPAR_F_LIB_PAUSE,
                                              rkcg->rkcg_assignment);

	if (!(rkcg->rkcg_rk->rk_conf.enabled_events & RD_KAFKA_EVENT_REBALANCE)
	    || !assignment
            || rd_kafka_destroy_flags_no_consumer_close(rkcg->rkcg_rk)
            || rd_kafka_fatal_error_code(rkcg->rkcg_rk)) {
	no_delegation:
		if (err == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS)
			rd_kafka_cgrp_assign(rkcg, assignment);
		else
			rd_kafka_cgrp_unassign(rkcg);
		return 0;
	}

	rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "ASSIGN",
		     "Group \"%s\": delegating %s of %d partition(s) "
		     "to application rebalance callback on queue %s: %s",
		     rkcg->rkcg_group_id->str,
		     err == RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS ?
		     "revoke":"assign", assignment->cnt,
		     rd_kafka_q_dest_name(rkcg->rkcg_q), reason);

	rd_kafka_cgrp_set_join_state(
		rkcg,
		err == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS ?
		RD_KAFKA_CGRP_JOIN_STATE_WAIT_ASSIGN_REBALANCE_CB :
		RD_KAFKA_CGRP_JOIN_STATE_WAIT_REVOKE_REBALANCE_CB);

	rko = rd_kafka_op_new(RD_KAFKA_OP_REBALANCE);
	rko->rko_err = err;
	rko->rko_u.rebalance.partitions =
		rd_kafka_topic_partition_list_copy(assignment);

	if (rd_kafka_q_enq(rkcg->rkcg_q, rko) == 0) {
		/* Queue disabled, handle assignment here. */
		goto no_delegation;
	}

	return 1;
}


/**
 * @brief Run group assignment.
 */
static void
rd_kafka_cgrp_assignor_run (rd_kafka_cgrp_t *rkcg,
                            const char *protocol_name,
                            rd_kafka_resp_err_t err,
                            rd_kafka_metadata_t *metadata,
                            rd_kafka_group_member_t *members,
                            int member_cnt) {
        char errstr[512];

        if (err) {
                rd_snprintf(errstr, sizeof(errstr),
                            "Failed to get cluster metadata: %s",
                            rd_kafka_err2str(err));
                goto err;
        }

        *errstr = '\0';

        /* Run assignor */
        err = rd_kafka_assignor_run(rkcg, protocol_name, metadata,
                                    members, member_cnt,
                                    errstr, sizeof(errstr));

        if (err) {
                if (!*errstr)
                        rd_snprintf(errstr, sizeof(errstr), "%s",
                                    rd_kafka_err2str(err));
                goto err;
        }

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP|RD_KAFKA_DBG_CONSUMER, "ASSIGNOR",
                     "Group \"%s\": \"%s\" assignor run for %d member(s)",
                     rkcg->rkcg_group_id->str, protocol_name, member_cnt);

        rd_kafka_cgrp_set_join_state(rkcg, RD_KAFKA_CGRP_JOIN_STATE_WAIT_SYNC);

        /* Respond to broker with assignment set or error */
        rd_kafka_SyncGroupRequest(rkcg->rkcg_coord,
                                  rkcg->rkcg_group_id,
                                  rkcg->rkcg_generation_id,
                                  rkcg->rkcg_member_id,
                                  rkcg->rkcg_group_instance_id,
                                  members, err ? 0 : member_cnt,
                                  RD_KAFKA_REPLYQ(rkcg->rkcg_ops, 0),
                                  rd_kafka_handle_SyncGroup, rkcg);
        return;

err:
        rd_kafka_log(rkcg->rkcg_rk, LOG_ERR, "ASSIGNOR",
                     "Group \"%s\": failed to run assignor \"%s\" for "
                     "%d member(s): %s",
                     rkcg->rkcg_group_id->str, protocol_name,
                     member_cnt, errstr);

        rd_kafka_cgrp_set_join_state(rkcg, RD_KAFKA_CGRP_JOIN_STATE_INIT);

}



/**
 * @brief Op callback from handle_JoinGroup
 */
static rd_kafka_op_res_t
rd_kafka_cgrp_assignor_handle_Metadata_op (rd_kafka_t *rk,
                                           rd_kafka_q_t *rkq,
                                           rd_kafka_op_t *rko) {
        rd_kafka_cgrp_t *rkcg = rk->rk_cgrp;

        if (rko->rko_err == RD_KAFKA_RESP_ERR__DESTROY)
                return RD_KAFKA_OP_RES_HANDLED; /* Terminating */

        if (rkcg->rkcg_join_state != RD_KAFKA_CGRP_JOIN_STATE_WAIT_METADATA)
                return RD_KAFKA_OP_RES_HANDLED; /* From outdated state */

        if (!rkcg->rkcg_group_leader.protocol) {
                rd_kafka_dbg(rk, CGRP, "GRPLEADER",
                             "Group \"%.*s\": no longer leader: "
                             "not running assignor",
                             RD_KAFKAP_STR_PR(rkcg->rkcg_group_id));
                return RD_KAFKA_OP_RES_HANDLED;
        }

        rd_kafka_cgrp_assignor_run(rkcg,
                                   rkcg->rkcg_group_leader.protocol,
                                   rko->rko_err, rko->rko_u.metadata.md,
                                   rkcg->rkcg_group_leader.members,
                                   rkcg->rkcg_group_leader.member_cnt);

        return RD_KAFKA_OP_RES_HANDLED;
}


/**
 * Parse single JoinGroup.Members.MemberMetadata for "consumer" ProtocolType
 *
 * Protocol definition:
 * https://cwiki.apache.org/confluence/display/KAFKA/Kafka+Client-side+Assignment+Proposal
 *
 * Returns 0 on success or -1 on error.
 */
static int
rd_kafka_group_MemberMetadata_consumer_read (
        rd_kafka_broker_t *rkb, rd_kafka_group_member_t *rkgm,
        const rd_kafkap_str_t *GroupProtocol,
        const rd_kafkap_bytes_t *MemberMetadata) {

        rd_kafka_buf_t *rkbuf;
        int16_t Version;
        int32_t subscription_cnt;
        rd_kafkap_bytes_t UserData;
        const int log_decode_errors = LOG_ERR;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR__BAD_MSG;

        /* Create a shadow-buffer pointing to the metadata to ease parsing. */
        rkbuf = rd_kafka_buf_new_shadow(MemberMetadata->data,
                                        RD_KAFKAP_BYTES_LEN(MemberMetadata),
                                        NULL);

        rd_kafka_buf_read_i16(rkbuf, &Version);
        rd_kafka_buf_read_i32(rkbuf, &subscription_cnt);

        if (subscription_cnt > 10000 || subscription_cnt <= 0)
                goto err;

        rkgm->rkgm_subscription =
                rd_kafka_topic_partition_list_new(subscription_cnt);

        while (subscription_cnt-- > 0) {
                rd_kafkap_str_t Topic;
                char *topic_name;
                rd_kafka_buf_read_str(rkbuf, &Topic);
                RD_KAFKAP_STR_DUPA(&topic_name, &Topic);
                rd_kafka_topic_partition_list_add(rkgm->rkgm_subscription,
                                                  topic_name,
                                                  RD_KAFKA_PARTITION_UA);
        }

        rd_kafka_buf_read_bytes(rkbuf, &UserData);
        rkgm->rkgm_userdata = rd_kafkap_bytes_copy(&UserData);

        rd_kafka_buf_destroy(rkbuf);

        return 0;

 err_parse:
        err = rkbuf->rkbuf_err;

 err:
        rd_rkb_dbg(rkb, CGRP, "MEMBERMETA",
                   "Failed to parse MemberMetadata for \"%.*s\": %s",
                   RD_KAFKAP_STR_PR(rkgm->rkgm_member_id),
                   rd_kafka_err2str(err));
        if (rkgm->rkgm_subscription) {
                rd_kafka_topic_partition_list_destroy(rkgm->
                                                      rkgm_subscription);
                rkgm->rkgm_subscription = NULL;
        }

        rd_kafka_buf_destroy(rkbuf);
        return -1;
}




/**
 * @brief cgrp handler for JoinGroup responses
 * opaque must be the cgrp handle.
 *
 * @locality rdkafka main thread (unless ERR__DESTROY: arbitrary thread)
 */
static void rd_kafka_cgrp_handle_JoinGroup (rd_kafka_t *rk,
                                            rd_kafka_broker_t *rkb,
                                            rd_kafka_resp_err_t err,
                                            rd_kafka_buf_t *rkbuf,
                                            rd_kafka_buf_t *request,
                                            void *opaque) {
        rd_kafka_cgrp_t *rkcg = opaque;
        const int log_decode_errors = LOG_ERR;
        int16_t ErrorCode = 0;
        int32_t GenerationId;
        rd_kafkap_str_t Protocol, LeaderId;
        rd_kafkap_str_t MyMemberId = RD_KAFKAP_STR_INITIALIZER;
        int32_t member_cnt;
        int actions;
        int i_am_leader = 0;

        if (err == RD_KAFKA_RESP_ERR__DESTROY)
                return; /* Terminating */

        if (rkcg->rkcg_join_state != RD_KAFKA_CGRP_JOIN_STATE_WAIT_JOIN) {
                rd_kafka_dbg(rkb->rkb_rk, CGRP, "JOINGROUP",
                             "JoinGroup response: discarding outdated request "
                             "(now in join-state %s)",
                             rd_kafka_cgrp_join_state_names[rkcg->
                                                            rkcg_join_state]);
                return;
        }

        if (err) {
                ErrorCode = err;
                goto err;
        }

        if (request->rkbuf_reqhdr.ApiVersion >= 2)
                rd_kafka_buf_read_throttle_time(rkbuf);

        rd_kafka_buf_read_i16(rkbuf, &ErrorCode);
        rd_kafka_buf_read_i32(rkbuf, &GenerationId);
        rd_kafka_buf_read_str(rkbuf, &Protocol);
        rd_kafka_buf_read_str(rkbuf, &LeaderId);
        rd_kafka_buf_read_str(rkbuf, &MyMemberId);
        rd_kafka_buf_read_i32(rkbuf, &member_cnt);

        if (!ErrorCode && RD_KAFKAP_STR_IS_NULL(&Protocol)) {
                /* Protocol not set, we will not be able to find
                 * a matching assignor so error out early. */
                ErrorCode = RD_KAFKA_RESP_ERR__BAD_MSG;
        }

        rd_kafka_dbg(rkb->rkb_rk, CGRP, "JOINGROUP",
                     "JoinGroup response: GenerationId %"PRId32", "
                     "Protocol %.*s, LeaderId %.*s%s, my MemberId %.*s, "
                     "%"PRId32" members in group: %s",
                     GenerationId,
                     RD_KAFKAP_STR_PR(&Protocol),
                     RD_KAFKAP_STR_PR(&LeaderId),
                     !rd_kafkap_str_cmp(&LeaderId, &MyMemberId) ? " (me)" : "",
                     RD_KAFKAP_STR_PR(&MyMemberId),
                     member_cnt,
                     ErrorCode ? rd_kafka_err2str(ErrorCode) : "(no error)");

        if (!ErrorCode) {
                char *my_member_id;
                RD_KAFKAP_STR_DUPA(&my_member_id, &MyMemberId);
                rd_kafka_cgrp_set_member_id(rkcg, my_member_id);
                rkcg->rkcg_generation_id = GenerationId;
                i_am_leader = !rd_kafkap_str_cmp(&LeaderId, &MyMemberId);
        } else {
                rd_interval_backoff(&rkcg->rkcg_join_intvl, 1000*1000);
                goto err;
        }

        if (i_am_leader) {
                rd_kafka_group_member_t *members;
                int i;
                int sub_cnt = 0;
                rd_list_t topics;
                rd_kafka_op_t *rko;
                rd_kafka_dbg(rkb->rkb_rk, CGRP, "JOINGROUP",
                             "Elected leader for group \"%s\" "
                             "with %"PRId32" member(s)",
                             rkcg->rkcg_group_id->str, member_cnt);

                if (member_cnt > 100000) {
                        err = RD_KAFKA_RESP_ERR__BAD_MSG;
                        goto err;
                }

                rd_list_init(&topics, member_cnt, rd_free);

                members = rd_calloc(member_cnt, sizeof(*members));

                for (i = 0 ; i < member_cnt ; i++) {
                        rd_kafkap_str_t MemberId;
                        rd_kafkap_bytes_t MemberMetadata;
                        rd_kafka_group_member_t *rkgm;
                        rd_kafkap_str_t GroupInstanceId = RD_KAFKAP_STR_INITIALIZER;

                        rd_kafka_buf_read_str(rkbuf, &MemberId);
                        if (request->rkbuf_reqhdr.ApiVersion >= 5)
                                rd_kafka_buf_read_str(rkbuf, &GroupInstanceId);
                        rd_kafka_buf_read_bytes(rkbuf, &MemberMetadata);

                        rkgm = &members[sub_cnt];
                        rkgm->rkgm_member_id = rd_kafkap_str_copy(&MemberId);
                        rkgm->rkgm_group_instance_id =
                                rd_kafkap_str_copy(&GroupInstanceId);
                        rd_list_init(&rkgm->rkgm_eligible, 0, NULL);

                        if (rd_kafka_group_MemberMetadata_consumer_read(
                                    rkb, rkgm, &Protocol, &MemberMetadata)) {
                                /* Failed to parse this member's metadata,
                                 * ignore it. */
                        } else {
                                sub_cnt++;
                                rkgm->rkgm_assignment =
                                        rd_kafka_topic_partition_list_new(
                                                rkgm->rkgm_subscription->size);
                                rd_kafka_topic_partition_list_get_topic_names(
                                        rkgm->rkgm_subscription, &topics,
                                        0/*dont include regex*/);
                        }

                }

                /* FIXME: What to do if parsing failed for some/all members?
                 *        It is a sign of incompatibility. */


                rd_kafka_cgrp_group_leader_reset(rkcg,
                                                 "JoinGroup response clean-up");

                rkcg->rkcg_group_leader.protocol = RD_KAFKAP_STR_DUP(&Protocol);
                rd_kafka_assert(NULL, rkcg->rkcg_group_leader.members == NULL);
                rkcg->rkcg_group_leader.members    = members;
                rkcg->rkcg_group_leader.member_cnt = sub_cnt;

                rd_kafka_cgrp_set_join_state(
                        rkcg, RD_KAFKA_CGRP_JOIN_STATE_WAIT_METADATA);

                /* The assignor will need metadata so fetch it asynchronously
                 * and run the assignor when we get a reply.
                 * Create a callback op that the generic metadata code
                 * will trigger when metadata has been parsed. */
                rko = rd_kafka_op_new_cb(
                        rkcg->rkcg_rk, RD_KAFKA_OP_METADATA,
                        rd_kafka_cgrp_assignor_handle_Metadata_op);
                rd_kafka_op_set_replyq(rko, rkcg->rkcg_ops, NULL);

                rd_kafka_MetadataRequest(rkb, &topics,
                                         "partition assignor", rko);
                rd_list_destroy(&topics);

        } else {
                rd_kafka_cgrp_set_join_state(
                        rkcg, RD_KAFKA_CGRP_JOIN_STATE_WAIT_SYNC);

                rd_kafka_SyncGroupRequest(rkb, rkcg->rkcg_group_id,
                                          rkcg->rkcg_generation_id,
                                          rkcg->rkcg_member_id,
                                          rkcg->rkcg_group_instance_id,
                                          NULL, 0,
                                          RD_KAFKA_REPLYQ(rkcg->rkcg_ops, 0),
                                          rd_kafka_handle_SyncGroup, rkcg);

        }

err:
        actions = rd_kafka_err_action(rkb, ErrorCode, request,
                                      RD_KAFKA_ERR_ACTION_IGNORE,
                                      RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID,

                                      RD_KAFKA_ERR_ACTION_IGNORE,
                                      RD_KAFKA_RESP_ERR_MEMBER_ID_REQUIRED,

                                      RD_KAFKA_ERR_ACTION_PERMANENT,
                                      RD_KAFKA_RESP_ERR_FENCED_INSTANCE_ID,

                                      RD_KAFKA_ERR_ACTION_END);

        if (actions & RD_KAFKA_ERR_ACTION_REFRESH) {
                /* Re-query for coordinator */
                rd_kafka_cgrp_op(rkcg, NULL, RD_KAFKA_NO_REPLYQ,
                                 RD_KAFKA_OP_COORD_QUERY, ErrorCode);
        }

        /* No need for retries here since the join is intervalled,
         * see rkcg_join_intvl */

        if (ErrorCode) {
                if (ErrorCode == RD_KAFKA_RESP_ERR__DESTROY)
                        return; /* Termination */

                if (ErrorCode == RD_KAFKA_RESP_ERR_FENCED_INSTANCE_ID) {
                        rd_kafka_set_fatal_error(rkcg->rkcg_rk, ErrorCode,
                                                 "Fatal consumer error: %s",
                                                 rd_kafka_err2str(ErrorCode));
                        ErrorCode = RD_KAFKA_RESP_ERR__FATAL;

                } else if (actions & RD_KAFKA_ERR_ACTION_PERMANENT)
                        rd_kafka_q_op_err(rkcg->rkcg_q,
                                          RD_KAFKA_OP_CONSUMER_ERR,
                                          ErrorCode, 0, NULL, 0,
                                          "JoinGroup failed: %s",
                                          rd_kafka_err2str(ErrorCode));

                if (ErrorCode == RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID)
                        rd_kafka_cgrp_set_member_id(rkcg, "");
                else if (ErrorCode == RD_KAFKA_RESP_ERR_MEMBER_ID_REQUIRED) {
                        /* KIP-394 requires member.id on initial join
                         * group request */
                        char *my_member_id;
                        RD_KAFKAP_STR_DUPA(&my_member_id, &MyMemberId);
                        rd_kafka_cgrp_set_member_id(rkcg, my_member_id);
                        /* Skip the join backoff */
                        rd_interval_reset(&rkcg->rkcg_join_intvl);
                }

                rd_kafka_cgrp_set_join_state(rkcg,
                                             RD_KAFKA_CGRP_JOIN_STATE_INIT);
        }

        return;

 err_parse:
        ErrorCode = rkbuf->rkbuf_err;
        goto err;
}


/**
 * @brief Check subscription against requested Metadata.
 */
static rd_kafka_op_res_t
rd_kafka_cgrp_handle_Metadata_op (rd_kafka_t *rk, rd_kafka_q_t *rkq,
                                  rd_kafka_op_t *rko) {
        rd_kafka_cgrp_t *rkcg = rk->rk_cgrp;

        if (rko->rko_err == RD_KAFKA_RESP_ERR__DESTROY)
                return RD_KAFKA_OP_RES_HANDLED; /* Terminating */

        rd_kafka_cgrp_metadata_update_check(rkcg, 0/*dont rejoin*/);

        return RD_KAFKA_OP_RES_HANDLED;
}


/**
 * @brief (Async) Refresh metadata (for cgrp's needs)
 *
 * @returns 1 if metadata refresh was requested, or 0 if metadata is
 *          up to date, or -1 if no broker is available for metadata requests.
 *
 * @locks none
 * @locality rdkafka main thread
 */
static int rd_kafka_cgrp_metadata_refresh (rd_kafka_cgrp_t *rkcg,
                                            int *metadata_agep,
                                            const char *reason) {
        rd_kafka_t *rk = rkcg->rkcg_rk;
        rd_kafka_op_t *rko;
        rd_list_t topics;
        rd_kafka_resp_err_t err;

        rd_list_init(&topics, 8, rd_free);

        /* Insert all non-wildcard topics in cache. */
        rd_kafka_metadata_cache_hint_rktparlist(rkcg->rkcg_rk,
                                                rkcg->rkcg_subscription,
                                                NULL, 0/*dont replace*/);

        if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_WILDCARD_SUBSCRIPTION) {
                /* For wildcard subscriptions make sure the
                 * cached full metadata isn't too old. */
                int metadata_age = -1;

                if (rk->rk_ts_full_metadata)
                        metadata_age = (int)(rd_clock() -
                                             rk->rk_ts_full_metadata)/1000;

                *metadata_agep = metadata_age;

                if (metadata_age != -1 &&
                    metadata_age <=
                    /* The +1000 is since metadata.refresh.interval.ms
                     * can be set to 0. */
                    rk->rk_conf.metadata_refresh_interval_ms + 1000) {
                        rd_kafka_dbg(rk, CGRP|RD_KAFKA_DBG_METADATA,
                                     "CGRPMETADATA",
                                     "%s: metadata for wildcard subscription "
                                     "is up to date (%dms old)",
                                     reason, *metadata_agep);
                        rd_list_destroy(&topics);
                        return 0; /* Up-to-date */
                }

        } else {
                /* Check that all subscribed topics are in the cache. */
                int r;

                rd_kafka_topic_partition_list_get_topic_names(
                        rkcg->rkcg_subscription, &topics, 0/*no regexps*/);

                rd_kafka_rdlock(rk);
                r = rd_kafka_metadata_cache_topics_count_exists(rk, &topics,
                                                                metadata_agep);
                rd_kafka_rdunlock(rk);

                if (r == rd_list_cnt(&topics)) {
                        rd_kafka_dbg(rk, CGRP|RD_KAFKA_DBG_METADATA,
                                     "CGRPMETADATA",
                                     "%s: metadata for subscription "
                                     "is up to date (%dms old)", reason,
                                     *metadata_agep);
                        rd_list_destroy(&topics);
                        return 0; /* Up-to-date and all topics exist. */
                }

                rd_kafka_dbg(rk, CGRP|RD_KAFKA_DBG_METADATA,
                             "CGRPMETADATA",
                             "%s: metadata for subscription "
                             "only available for %d/%d topics (%dms old)",
                             reason, r, rd_list_cnt(&topics), *metadata_agep);

        }

        /* Async request, result will be triggered from
         * rd_kafka_parse_metadata(). */
        rko = rd_kafka_op_new_cb(rkcg->rkcg_rk, RD_KAFKA_OP_METADATA,
                                 rd_kafka_cgrp_handle_Metadata_op);
        rd_kafka_op_set_replyq(rko, rkcg->rkcg_ops, 0);

        err = rd_kafka_metadata_request(rkcg->rkcg_rk, NULL, &topics,
                                        reason, rko);
        if (err) {
                rd_kafka_dbg(rk, CGRP|RD_KAFKA_DBG_METADATA,
                             "CGRPMETADATA",
                             "%s: need to refresh metadata (%dms old) "
                             "but no usable brokers available: %s",
                             reason, *metadata_agep, rd_kafka_err2str(err));
                rd_kafka_op_destroy(rko);
        }

        rd_list_destroy(&topics);

        return err ? -1 : 1;
}



static void rd_kafka_cgrp_join (rd_kafka_cgrp_t *rkcg) {
        int metadata_age;

        if (rkcg->rkcg_state != RD_KAFKA_CGRP_STATE_UP ||
            rkcg->rkcg_join_state != RD_KAFKA_CGRP_JOIN_STATE_INIT)
                return;

        /* On max.poll.interval.ms failure, do not rejoin group until the
         * application has called poll. */
        if ((rkcg->rkcg_flags & RD_KAFKA_CGRP_F_MAX_POLL_EXCEEDED) &&
            rd_kafka_max_poll_exceeded(rkcg->rkcg_rk))
                return;

        rkcg->rkcg_flags &= ~RD_KAFKA_CGRP_F_MAX_POLL_EXCEEDED;

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "JOIN",
                     "Group \"%.*s\": join with %d (%d) subscribed topic(s)",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_list_cnt(rkcg->rkcg_subscribed_topics),
                     rkcg->rkcg_subscription->cnt);


        /* See if we need to query metadata to continue:
         * - if subscription contains wildcards:
         *   * query all topics in cluster
         *
         * - if subscription does not contain wildcards but
         *   some topics are missing from the local metadata cache:
         *   * query subscribed topics (all cached ones)
         *
         * - otherwise:
         *   * rely on topic metadata cache
         */
        /* We need up-to-date full metadata to continue,
         * refresh metadata if necessary. */
        if (rd_kafka_cgrp_metadata_refresh(rkcg, &metadata_age,
                                           "consumer join") == 1) {
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP|RD_KAFKA_DBG_CONSUMER, "JOIN",
                             "Group \"%.*s\": "
                             "postponing join until up-to-date "
                             "metadata is available",
                             RD_KAFKAP_STR_PR(rkcg->rkcg_group_id));
                return; /* ^ async call */
        }

        if (rd_list_empty(rkcg->rkcg_subscribed_topics))
                rd_kafka_cgrp_metadata_update_check(rkcg, 0/*dont join*/);

        if (rd_list_empty(rkcg->rkcg_subscribed_topics)) {
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP|RD_KAFKA_DBG_CONSUMER, "JOIN",
                             "Group \"%.*s\": "
                             "no matching topics based on %dms old metadata: "
                             "next metadata refresh in %dms",
                             RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                             metadata_age,
                             rkcg->rkcg_rk->rk_conf.
                             metadata_refresh_interval_ms - metadata_age);
                return;
        }

        rd_rkb_dbg(rkcg->rkcg_curr_coord, CONSUMER, "JOIN",
                   "Joining group \"%.*s\" with %d subscribed topic(s)",
                   RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                   rd_list_cnt(rkcg->rkcg_subscribed_topics));

        rd_kafka_cgrp_set_join_state(rkcg, RD_KAFKA_CGRP_JOIN_STATE_WAIT_JOIN);
        rd_kafka_JoinGroupRequest(rkcg->rkcg_coord, rkcg->rkcg_group_id,
                                  rkcg->rkcg_member_id,
                                  rkcg->rkcg_group_instance_id,
                                  rkcg->rkcg_rk->rk_conf.group_protocol_type,
                                  rkcg->rkcg_subscribed_topics,
                                  RD_KAFKA_REPLYQ(rkcg->rkcg_ops, 0),
                                  rd_kafka_cgrp_handle_JoinGroup, rkcg);
}

/**
 * Rejoin group on update to effective subscribed topics list
 */
static void rd_kafka_cgrp_rejoin (rd_kafka_cgrp_t *rkcg) {
        /*
         * Clean-up group leader duties, if any.
         */
        rd_kafka_cgrp_group_leader_reset(rkcg, "Group rejoin");

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "REJOIN",
                     "Group \"%.*s\" rejoining in join-state %s "
                     "with%s an assignment",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state],
                     rkcg->rkcg_assignment ? "" : "out");

        rd_kafka_cgrp_rebalance(rkcg, "group rejoin");
}

/**
 * Update the effective list of subscribed topics and trigger a rejoin
 * if it changed.
 *
 * Set \p tinfos to NULL for clearing the list.
 *
 * @param tinfos rd_list_t(rd_kafka_topic_info_t *): new effective topic list
 *
 * @returns 1 on change, else 0.
 *
 * @remark Takes ownership of \p tinfos
 */
static int
rd_kafka_cgrp_update_subscribed_topics (rd_kafka_cgrp_t *rkcg,
                                        rd_list_t *tinfos) {
        rd_kafka_topic_info_t *tinfo;
        int i;

        if (!tinfos) {
                if (!rd_list_empty(rkcg->rkcg_subscribed_topics))
                        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "SUBSCRIPTION",
                                     "Group \"%.*s\": "
                                     "clearing subscribed topics list (%d)",
                                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                                     rd_list_cnt(rkcg->rkcg_subscribed_topics));
                tinfos = rd_list_new(0, (void *)rd_kafka_topic_info_destroy);

        } else {
                if (rd_list_cnt(tinfos) == 0)
                        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "SUBSCRIPTION",
                                     "Group \"%.*s\": "
                                     "no topics in metadata matched "
                                     "subscription",
                                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id));
        }

        /* Sort for comparison */
        rd_list_sort(tinfos, rd_kafka_topic_info_cmp);

        /* Compare to existing to see if anything changed. */
        if (!rd_list_cmp(rkcg->rkcg_subscribed_topics, tinfos,
                         rd_kafka_topic_info_cmp)) {
                /* No change */
                rd_list_destroy(tinfos);
                return 0;
        }

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP|RD_KAFKA_DBG_METADATA, "SUBSCRIPTION",
                     "Group \"%.*s\": effective subscription list changed "
                     "from %d to %d topic(s):",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_list_cnt(rkcg->rkcg_subscribed_topics),
                     rd_list_cnt(tinfos));

        RD_LIST_FOREACH(tinfo, tinfos, i)
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP|RD_KAFKA_DBG_METADATA,
                             "SUBSCRIPTION",
                             " Topic %s with %d partition(s)",
                             tinfo->topic, tinfo->partition_cnt);

        rd_list_destroy(rkcg->rkcg_subscribed_topics);

        rkcg->rkcg_subscribed_topics = tinfos;

        return 1;
}



/**
 * @brief Handle Heartbeat response.
 */
void rd_kafka_cgrp_handle_Heartbeat (rd_kafka_t *rk,
                                     rd_kafka_broker_t *rkb,
                                     rd_kafka_resp_err_t err,
                                     rd_kafka_buf_t *rkbuf,
                                     rd_kafka_buf_t *request,
                                     void *opaque) {
        rd_kafka_cgrp_t *rkcg = rk->rk_cgrp;
        const int log_decode_errors = LOG_ERR;
        int16_t ErrorCode = 0;
        int actions = 0;
        const char *rebalance_reason = NULL;

        rd_dassert(rkcg->rkcg_flags & RD_KAFKA_CGRP_F_HEARTBEAT_IN_TRANSIT);
        rkcg->rkcg_flags &= ~RD_KAFKA_CGRP_F_HEARTBEAT_IN_TRANSIT;

        rkcg->rkcg_last_heartbeat_err = RD_KAFKA_RESP_ERR_NO_ERROR;

        if (err)
                goto err;

        if (request->rkbuf_reqhdr.ApiVersion >= 1)
                rd_kafka_buf_read_throttle_time(rkbuf);

        rd_kafka_buf_read_i16(rkbuf, &ErrorCode);
        if (ErrorCode) {
                err = ErrorCode;
                goto err;
        }

        rd_kafka_cgrp_update_session_timeout(
                rkcg, rd_false/*dont update if session has expired*/);

        return;

 err_parse:
        err = rkbuf->rkbuf_err;
 err:
        rkcg->rkcg_last_heartbeat_err = err;

	rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "HEARTBEAT",
		     "Group \"%s\" heartbeat error response in "
		     "state %s (join state %s, %d partition(s) assigned): %s",
		     rkcg->rkcg_group_id->str,
		     rd_kafka_cgrp_state_names[rkcg->rkcg_state],
		     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state],
		     rkcg->rkcg_assignment ? rkcg->rkcg_assignment->cnt : 0,
		     rd_kafka_err2str(err));

	if (rkcg->rkcg_join_state <= RD_KAFKA_CGRP_JOIN_STATE_WAIT_SYNC) {
		rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "HEARTBEAT",
			     "Heartbeat response: discarding outdated "
			     "request (now in join-state %s)",
			     rd_kafka_cgrp_join_state_names[rkcg->
                                                            rkcg_join_state]);
		return;
	}

	switch (err)
	{
	case RD_KAFKA_RESP_ERR__DESTROY:
		/* quick cleanup */
                return;

	case RD_KAFKA_RESP_ERR_NOT_COORDINATOR_FOR_GROUP:
	case RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE:
	case RD_KAFKA_RESP_ERR__TRANSPORT:
                rd_kafka_dbg(rkcg->rkcg_rk, CONSUMER, "HEARTBEAT",
                             "Heartbeat failed due to coordinator (%s) "
                             "no longer available: %s: "
                             "re-querying for coordinator",
                             rkcg->rkcg_curr_coord ?
                             rd_kafka_broker_name(rkcg->rkcg_curr_coord) :
                             "none",
                             rd_kafka_err2str(err));
		/* Remain in joined state and keep querying for coordinator */
                actions = RD_KAFKA_ERR_ACTION_REFRESH;
                break;

        case RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS:
                /* No further action if already rebalancing */
                if (rkcg->rkcg_join_state ==
                    RD_KAFKA_CGRP_JOIN_STATE_WAIT_REVOKE_REBALANCE_CB)
                        return;
                rebalance_reason = "group is rebalancing";
                break;

        case RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID:
                rd_kafka_cgrp_set_member_id(rkcg, "");
                rebalance_reason = "resetting member-id";
                break;

        case RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION:
                rebalance_reason = "group is rebalancing";
                break;

        case RD_KAFKA_RESP_ERR_FENCED_INSTANCE_ID:
                rd_kafka_set_fatal_error(rkcg->rkcg_rk, err,
                                         "Fatal consumer error: %s",
                                         rd_kafka_err2str(err));
                rebalance_reason = "consumer fenced by newer instance";
                break;

        default:
                actions = rd_kafka_err_action(rkb, err, request,
                                              RD_KAFKA_ERR_ACTION_END);
                break;
        }


        if (actions & RD_KAFKA_ERR_ACTION_REFRESH) {
                /* Re-query for coordinator */
                rd_kafka_cgrp_coord_query(rkcg, rd_kafka_err2str(err));
        }

        if (actions & RD_KAFKA_ERR_ACTION_RETRY &&
            rd_kafka_buf_retry(rkb, request)) {
                /* Retry */
                rkcg->rkcg_flags |= RD_KAFKA_CGRP_F_HEARTBEAT_IN_TRANSIT;
                return;
        }

        if (rebalance_reason)
                rd_kafka_cgrp_rebalance(rkcg, rebalance_reason);
}



/**
 * @brief Send Heartbeat
 */
static void rd_kafka_cgrp_heartbeat (rd_kafka_cgrp_t *rkcg) {
        /* Don't send heartbeats if max.poll.interval.ms was exceeded */
        if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_MAX_POLL_EXCEEDED)
                return;

        /* Skip heartbeat if we have one in transit */
        if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_HEARTBEAT_IN_TRANSIT)
                return;

        rkcg->rkcg_flags |= RD_KAFKA_CGRP_F_HEARTBEAT_IN_TRANSIT;
        rd_kafka_HeartbeatRequest(rkcg->rkcg_coord, rkcg->rkcg_group_id,
                                  rkcg->rkcg_generation_id,
                                  rkcg->rkcg_member_id,
                                  rkcg->rkcg_group_instance_id,
                                  RD_KAFKA_REPLYQ(rkcg->rkcg_ops, 0),
                                  rd_kafka_cgrp_handle_Heartbeat, NULL);
}

/**
 * Cgrp is now terminated: decommission it and signal back to application.
 */
static void rd_kafka_cgrp_terminated (rd_kafka_cgrp_t *rkcg) {

	rd_kafka_assert(NULL, rkcg->rkcg_wait_unassign_cnt == 0);
	rd_kafka_assert(NULL, rkcg->rkcg_wait_commit_cnt == 0);
	rd_kafka_assert(NULL, !(rkcg->rkcg_flags&RD_KAFKA_CGRP_F_WAIT_UNASSIGN));
        rd_kafka_assert(NULL, rkcg->rkcg_state == RD_KAFKA_CGRP_STATE_TERM);

        rd_kafka_timer_stop(&rkcg->rkcg_rk->rk_timers,
                            &rkcg->rkcg_offset_commit_tmr, 1/*lock*/);

	rd_kafka_q_purge(rkcg->rkcg_wait_coord_q);

	/* Disable and empty ops queue since there will be no
	 * (broker) thread serving it anymore after the unassign_broker
	 * below.
	 * This prevents hang on destroy where responses are enqueued on rkcg_ops
	 * without anything serving the queue. */
	rd_kafka_q_disable(rkcg->rkcg_ops);
	rd_kafka_q_purge(rkcg->rkcg_ops);

	if (rkcg->rkcg_curr_coord)
		rd_kafka_cgrp_coord_clear_broker(rkcg);

        if (rkcg->rkcg_coord) {
                rd_kafka_broker_destroy(rkcg->rkcg_coord);
                rkcg->rkcg_coord = NULL;
        }

        if (rkcg->rkcg_reply_rko) {
                /* Signal back to application. */
                rd_kafka_replyq_enq(&rkcg->rkcg_reply_rko->rko_replyq,
				    rkcg->rkcg_reply_rko, 0);
                rkcg->rkcg_reply_rko = NULL;
        }
}


/**
 * If a cgrp is terminating and all outstanding ops are now finished
 * then progress to final termination and return 1.
 * Else returns 0.
 */
static RD_INLINE int rd_kafka_cgrp_try_terminate (rd_kafka_cgrp_t *rkcg) {

        if (rkcg->rkcg_state == RD_KAFKA_CGRP_STATE_TERM)
                return 1;

	if (likely(!(rkcg->rkcg_flags & RD_KAFKA_CGRP_F_TERMINATE)))
		return 0;

	/* Check if wait-coord queue has timed out. */
	if (rd_kafka_q_len(rkcg->rkcg_wait_coord_q) > 0 &&
	    rkcg->rkcg_ts_terminate +
	    (rkcg->rkcg_rk->rk_conf.group_session_timeout_ms * 1000) <
	    rd_clock()) {
		rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPTERM",
			     "Group \"%s\": timing out %d op(s) in "
			     "wait-for-coordinator queue",
			     rkcg->rkcg_group_id->str,
			     rd_kafka_q_len(rkcg->rkcg_wait_coord_q));
		rd_kafka_q_disable(rkcg->rkcg_wait_coord_q);
		if (rd_kafka_q_concat(rkcg->rkcg_ops,
				      rkcg->rkcg_wait_coord_q) == -1) {
			/* ops queue shut down, purge coord queue */
			rd_kafka_q_purge(rkcg->rkcg_wait_coord_q);
		}
	}

	if (!RD_KAFKA_CGRP_WAIT_REBALANCE_CB(rkcg) &&
	    rd_list_empty(&rkcg->rkcg_toppars) &&
	    rkcg->rkcg_wait_unassign_cnt == 0 &&
	    rkcg->rkcg_wait_commit_cnt == 0 &&
            !(rkcg->rkcg_flags & (RD_KAFKA_CGRP_F_WAIT_UNASSIGN |
                                  RD_KAFKA_CGRP_F_WAIT_LEAVE))) {
                /* Since we might be deep down in a 'rko' handler
                 * called from cgrp_op_serve() we cant call terminated()
                 * directly since it will decommission the rkcg_ops queue
                 * that might be locked by intermediate functions.
                 * Instead set the TERM state and let the cgrp terminate
                 * at its own discretion. */
                rd_kafka_cgrp_set_state(rkcg, RD_KAFKA_CGRP_STATE_TERM);
                return 1;
        } else {
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPTERM",
                             "Group \"%s\": "
                             "waiting for %s%d toppar(s), %d unassignment(s), "
                             "%d commit(s)%s%s (state %s, join-state %s) "
                             "before terminating",
                             rkcg->rkcg_group_id->str,
                             RD_KAFKA_CGRP_WAIT_REBALANCE_CB(rkcg) ?
                             "rebalance_cb, ": "",
                             rd_list_cnt(&rkcg->rkcg_toppars),
                             rkcg->rkcg_wait_unassign_cnt,
                             rkcg->rkcg_wait_commit_cnt,
                             (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_WAIT_UNASSIGN)?
                             ", wait-unassign flag," : "",
                             (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_WAIT_LEAVE)?
                             ", wait-leave," : "",
                             rd_kafka_cgrp_state_names[rkcg->rkcg_state],
                             rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state]);
                return 0;
        }
}


/**
 * Add partition to this cgrp management
 */
static void rd_kafka_cgrp_partition_add (rd_kafka_cgrp_t *rkcg,
                                         rd_kafka_toppar_t *rktp) {
        rd_kafka_dbg(rkcg->rkcg_rk, CGRP,"PARTADD",
                     "Group \"%s\": add %s [%"PRId32"]",
                     rkcg->rkcg_group_id->str,
                     rktp->rktp_rkt->rkt_topic->str,
                     rktp->rktp_partition);

        rd_kafka_assert(rkcg->rkcg_rk, !rktp->rktp_s_for_cgrp);
        rktp->rktp_s_for_cgrp = rd_kafka_toppar_keep(rktp);
        rd_list_add(&rkcg->rkcg_toppars, rktp->rktp_s_for_cgrp);
}

/**
 * Remove partition from this cgrp management
 */
static void rd_kafka_cgrp_partition_del (rd_kafka_cgrp_t *rkcg,
                                         rd_kafka_toppar_t *rktp) {
        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "PARTDEL",
                     "Group \"%s\": delete %s [%"PRId32"]",
                     rkcg->rkcg_group_id->str,
                     rktp->rktp_rkt->rkt_topic->str,
                     rktp->rktp_partition);
        rd_kafka_assert(rkcg->rkcg_rk, rktp->rktp_s_for_cgrp);

        rd_list_remove(&rkcg->rkcg_toppars, rktp->rktp_s_for_cgrp);
        rd_kafka_toppar_destroy(rktp->rktp_s_for_cgrp);
        rktp->rktp_s_for_cgrp = NULL;

        rd_kafka_cgrp_try_terminate(rkcg);
}



/**
 * Reply for OffsetFetch from call below.
 */
static void rd_kafka_cgrp_offsets_fetch_response (
	rd_kafka_t *rk,
	rd_kafka_broker_t *rkb,
	rd_kafka_resp_err_t err,
	rd_kafka_buf_t *reply,
	rd_kafka_buf_t *request,
	void *opaque) {
	rd_kafka_topic_partition_list_t *offsets = opaque;
	rd_kafka_cgrp_t *rkcg;

	if (err == RD_KAFKA_RESP_ERR__DESTROY) {
                /* Termination, quick cleanup. */
		rd_kafka_topic_partition_list_destroy(offsets);
                return;
        }

        rkcg = rd_kafka_cgrp_get(rk);

        if (rd_kafka_buf_version_outdated(request, rkcg->rkcg_version)) {
                rd_kafka_topic_partition_list_destroy(offsets);
                return;
        }

	rd_kafka_topic_partition_list_log(rk, "OFFSETFETCH",
                                          RD_KAFKA_DBG_TOPIC|RD_KAFKA_DBG_CGRP,
                                          offsets);
	/* If all partitions already had usable offsets then there
	 * was no request sent and thus no reply, the offsets list is
	 * good to go. */
	if (reply) {
		err = rd_kafka_handle_OffsetFetch(rk, rkb, err,
						  reply, request, offsets,
						  1/* Update toppars */);
                if (err == RD_KAFKA_RESP_ERR__IN_PROGRESS)
                        return; /* retrying */
        }
	if (err) {
		rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "OFFSET",
			     "Offset fetch error: %s",
			     rd_kafka_err2str(err));

		if (err != RD_KAFKA_RESP_ERR__WAIT_COORD)
			rd_kafka_q_op_err(rkcg->rkcg_q,
					  RD_KAFKA_OP_CONSUMER_ERR, err, 0,
					  NULL, 0,
					  "Failed to fetch offsets: %s",
					  rd_kafka_err2str(err));
	} else {
		if (RD_KAFKA_CGRP_CAN_FETCH_START(rkcg))
			rd_kafka_cgrp_partitions_fetch_start(
				rkcg, offsets, 1 /* usable offsets */);
		else
			rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "OFFSET",
				     "Group \"%.*s\": "
				     "ignoring Offset fetch response for "
				     "%d partition(s): in state %s",
				     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
				     offsets ? offsets->cnt : -1,
				     rd_kafka_cgrp_join_state_names[
					     rkcg->rkcg_join_state]);
	}

	rd_kafka_topic_partition_list_destroy(offsets);
}

/**
 * Fetch offsets for a list of partitions
 */
static void
rd_kafka_cgrp_offsets_fetch (rd_kafka_cgrp_t *rkcg, rd_kafka_broker_t *rkb,
                             rd_kafka_topic_partition_list_t *offsets) {
	rd_kafka_topic_partition_list_t *use_offsets;

	/* Make a copy of the offsets */
	use_offsets = rd_kafka_topic_partition_list_copy(offsets);

        if (rkcg->rkcg_state != RD_KAFKA_CGRP_STATE_UP || !rkb)
		rd_kafka_cgrp_offsets_fetch_response(
			rkcg->rkcg_rk, rkb, RD_KAFKA_RESP_ERR__WAIT_COORD,
			NULL, NULL, use_offsets);
        else {
                rd_kafka_OffsetFetchRequest(
                        rkb, 1, offsets,
                        RD_KAFKA_REPLYQ(rkcg->rkcg_ops, rkcg->rkcg_version),
			rd_kafka_cgrp_offsets_fetch_response,
			use_offsets);
	}

}


/**
 * Start fetching all partitions in 'assignment' (async)
 */
static void
rd_kafka_cgrp_partitions_fetch_start0 (rd_kafka_cgrp_t *rkcg,
				       rd_kafka_topic_partition_list_t
				       *assignment, int usable_offsets,
				       int line) {
        int i;

	/* If waiting for offsets to commit we need that to finish first
	 * before starting fetchers (which might fetch those stored offsets).*/
	if (rkcg->rkcg_wait_commit_cnt > 0) {
		rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "FETCHSTART",
			     "Group \"%s\": not starting fetchers "
			     "for %d assigned partition(s) in join-state %s "
			     "(usable_offsets=%s, v%"PRId32", line %d): "
			     "waiting for %d commit(s)",
			     rkcg->rkcg_group_id->str, assignment->cnt,
			     rd_kafka_cgrp_join_state_names[rkcg->
							    rkcg_join_state],
			     usable_offsets ? "yes":"no",
			     rkcg->rkcg_version, line,
			     rkcg->rkcg_wait_commit_cnt);
		return;
	}

	rd_kafka_cgrp_version_new_barrier(rkcg);

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "FETCHSTART",
                     "Group \"%s\": starting fetchers for %d assigned "
                     "partition(s) in join-state %s "
		     "(usable_offsets=%s, v%"PRId32", line %d)",
                     rkcg->rkcg_group_id->str, assignment->cnt,
		     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state],
		     usable_offsets ? "yes":"no",
		     rkcg->rkcg_version, line);

	rd_kafka_topic_partition_list_log(rkcg->rkcg_rk,
					  "FETCHSTART",
                                          RD_KAFKA_DBG_TOPIC|RD_KAFKA_DBG_CGRP,
                                          assignment);

        if (assignment->cnt == 0)
                return;

	/* Check if offsets are really unusable, this is to catch the
	 * case where the entire assignment has absolute offsets set which
	 * should make us skip offset lookups. */
	if (!usable_offsets)
		usable_offsets =
			rd_kafka_topic_partition_list_count_abs_offsets(
				assignment) == assignment->cnt;

        if (!usable_offsets &&
            rkcg->rkcg_rk->rk_conf.offset_store_method ==
            RD_KAFKA_OFFSET_METHOD_BROKER) {

                /* Fetch offsets for all assigned partitions */
                rd_kafka_cgrp_offsets_fetch(rkcg, rkcg->rkcg_coord,
                                            assignment);

        } else {
		rd_kafka_cgrp_set_join_state(rkcg,
					     RD_KAFKA_CGRP_JOIN_STATE_STARTED);

                if (rkcg->rkcg_subscription) {
                        /* If using subscribe(), start a timer to enforce
                         * `max.poll.interval.ms`.
                         * Instead of restarting the timer on each ...poll()
                         * call, which would be costly (once per message),
                         * set up an intervalled timer that checks a timestamp
                         * (that is updated on ..poll()).
                         * The timer interval is 2 hz. */
                        rd_kafka_timer_start(
                                &rkcg->rkcg_rk->rk_timers,
                                &rkcg->rkcg_max_poll_interval_tmr,
                                500 * 1000ll /* 500ms */,
                                rd_kafka_cgrp_max_poll_interval_check_tmr_cb,
                                rkcg);
                }

                for (i = 0 ; i < assignment->cnt ; i++) {
                        rd_kafka_topic_partition_t *rktpar =
                                &assignment->elems[i];
                        shptr_rd_kafka_toppar_t *s_rktp = rktpar->_private;
                        rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(s_rktp);

			if (!rktp->rktp_assigned) {
				rktp->rktp_assigned = 1;
				rkcg->rkcg_assigned_cnt++;

				/* Start fetcher for partition and
				 * forward partition's fetchq to
				 * consumer groups queue. */
				rd_kafka_toppar_op_fetch_start(
					rktp, rktpar->offset,
					rkcg->rkcg_q, RD_KAFKA_NO_REPLYQ);
			} else {
				int64_t offset;
				/* Fetcher already started,
				 * just do seek to update offset */
				rd_kafka_toppar_lock(rktp);
				if (rktpar->offset < rktp->rktp_app_offset)
					offset = rktp->rktp_app_offset;
				else
					offset = rktpar->offset;
				rd_kafka_toppar_unlock(rktp);
				rd_kafka_toppar_op_seek(rktp, offset,
							RD_KAFKA_NO_REPLYQ);
			}
                }
        }

	rd_kafka_assert(NULL, rkcg->rkcg_assigned_cnt <=
			(rkcg->rkcg_assignment ? rkcg->rkcg_assignment->cnt : 0));
}





/**
 * @brief Defer offset commit (rko) until coordinator is available.
 *
 * @returns 1 if the rko was deferred or 0 if the defer queue is disabled
 *          or rko already deferred.
 */
static int rd_kafka_cgrp_defer_offset_commit (rd_kafka_cgrp_t *rkcg,
                                              rd_kafka_op_t *rko,
                                              const char *reason) {

        /* wait_coord_q is disabled session.timeout.ms after
         * group close() has been initated. */
        if (rko->rko_u.offset_commit.ts_timeout != 0 ||
            !rd_kafka_q_ready(rkcg->rkcg_wait_coord_q))
                return 0;

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "COMMIT",
                     "Group \"%s\": "
                     "unable to OffsetCommit in state %s: %s: "
                     "coordinator (%s) is unavailable: "
                     "retrying later",
                     rkcg->rkcg_group_id->str,
                     rd_kafka_cgrp_state_names[rkcg->rkcg_state],
                     reason,
                     rkcg->rkcg_curr_coord ?
                     rd_kafka_broker_name(rkcg->rkcg_curr_coord) :
                     "none");

        rko->rko_flags |= RD_KAFKA_OP_F_REPROCESS;
        rko->rko_u.offset_commit.ts_timeout = rd_clock() +
                (rkcg->rkcg_rk->rk_conf.group_session_timeout_ms
                 * 1000);
        rd_kafka_q_enq(rkcg->rkcg_wait_coord_q, rko);

        return 1;
}


/**
 * @brief Handler of OffsetCommit response (after parsing).
 * @remark \p offsets may be NULL if \p err is set
 * @returns the number of partitions with errors encountered
 */
static int
rd_kafka_cgrp_handle_OffsetCommit (rd_kafka_cgrp_t *rkcg,
                                   rd_kafka_resp_err_t err,
                                   rd_kafka_topic_partition_list_t
                                   *offsets) {
	int i;
        int errcnt = 0;

        /* Update toppars' committed offset or global error */
        for (i = 0 ; offsets && i < offsets->cnt ; i++) {
                rd_kafka_topic_partition_t *rktpar =&offsets->elems[i];
                shptr_rd_kafka_toppar_t *s_rktp;
                rd_kafka_toppar_t *rktp;

                /* Ignore logical offsets since they were never
                 * sent to the broker. */
                if (RD_KAFKA_OFFSET_IS_LOGICAL(rktpar->offset))
                        continue;

                /* Propagate global error to all partitions that don't have
                 * explicit error set. */
                if (err && !rktpar->err)
                        rktpar->err = err;

                if (rktpar->err) {
                        rd_kafka_dbg(rkcg->rkcg_rk, TOPIC,
                                     "OFFSET",
                                     "OffsetCommit failed for "
                                     "%s [%"PRId32"] at offset "
                                     "%"PRId64": %s",
                                     rktpar->topic, rktpar->partition,
                                     rktpar->offset,
                                     rd_kafka_err2str(rktpar->err));
                        errcnt++;
                        continue;
                }

                s_rktp = rd_kafka_topic_partition_list_get_toppar(
                        rkcg->rkcg_rk, rktpar);
                if (!s_rktp)
                        continue;

                rktp = rd_kafka_toppar_s2i(s_rktp);
                rd_kafka_toppar_lock(rktp);
                rktp->rktp_committed_offset = rktpar->offset;
                rd_kafka_toppar_unlock(rktp);

                rd_kafka_toppar_destroy(s_rktp);
        }

        if (rkcg->rkcg_join_state == RD_KAFKA_CGRP_JOIN_STATE_WAIT_UNASSIGN)
                rd_kafka_cgrp_check_unassign_done(rkcg, "OffsetCommit done");

        rd_kafka_cgrp_try_terminate(rkcg);

        return errcnt;
}




/**
 * Handle OffsetCommitResponse
 * Takes the original 'rko' as opaque argument.
 * @remark \p rkb, rkbuf, and request may be NULL in a number of
 *         error cases (e.g., _NO_OFFSET, _WAIT_COORD)
 */
static void rd_kafka_cgrp_op_handle_OffsetCommit (rd_kafka_t *rk,
						  rd_kafka_broker_t *rkb,
						  rd_kafka_resp_err_t err,
						  rd_kafka_buf_t *rkbuf,
						  rd_kafka_buf_t *request,
						  void *opaque) {
	rd_kafka_cgrp_t *rkcg = rk->rk_cgrp;
        rd_kafka_op_t *rko_orig = opaque;
	rd_kafka_topic_partition_list_t *offsets =
		rko_orig->rko_u.offset_commit.partitions; /* maybe NULL */
        int errcnt;
        int offset_commit_cb_served = 0;

	RD_KAFKA_OP_TYPE_ASSERT(rko_orig, RD_KAFKA_OP_OFFSET_COMMIT);

        if (rd_kafka_buf_version_outdated(request, rkcg->rkcg_version))
                err = RD_KAFKA_RESP_ERR__DESTROY;

	err = rd_kafka_handle_OffsetCommit(rk, rkb, err, rkbuf,
					   request, offsets);

        if (rkb)
                rd_rkb_dbg(rkb, CGRP, "COMMIT",
                           "OffsetCommit for %d partition(s): %s: returned: %s",
                           offsets ? offsets->cnt : -1,
                           rko_orig->rko_u.offset_commit.reason,
                           rd_kafka_err2str(err));
        else
                rd_kafka_dbg(rk, CGRP, "COMMIT",
                             "OffsetCommit for %d partition(s): %s: returned: %s",
                             offsets ? offsets->cnt : -1,
                             rko_orig->rko_u.offset_commit.reason,
                             rd_kafka_err2str(err));

        if (err == RD_KAFKA_RESP_ERR__IN_PROGRESS)
                return; /* Retrying */
        else if (err == RD_KAFKA_RESP_ERR_NOT_COORDINATOR_FOR_GROUP ||
                 err == RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE ||
                 err == RD_KAFKA_RESP_ERR__TRANSPORT) {
                /* The coordinator is not available, defer the offset commit
                 * to when the coordinator is back up again. */

                /* future-proofing, see timeout_scan(). */
                rd_kafka_assert(NULL, err != RD_KAFKA_RESP_ERR__WAIT_COORD);

                if (rd_kafka_cgrp_defer_offset_commit(rkcg, rko_orig,
                                                      rd_kafka_err2str(err)))
                        return;

                /* FALLTHRU and error out */
        }

	rd_kafka_assert(NULL, rkcg->rkcg_wait_commit_cnt > 0);
	rkcg->rkcg_wait_commit_cnt--;

        if (err == RD_KAFKA_RESP_ERR_NO_ERROR) {
                if (rkcg->rkcg_wait_commit_cnt == 0 &&
                    rkcg->rkcg_assignment &&
                    RD_KAFKA_CGRP_CAN_FETCH_START(rkcg))
                        rd_kafka_cgrp_partitions_fetch_start(rkcg,
                                                             rkcg->rkcg_assignment, 0);
	}

	if (err == RD_KAFKA_RESP_ERR__DESTROY ||
            (err == RD_KAFKA_RESP_ERR__NO_OFFSET &&
             rko_orig->rko_u.offset_commit.silent_empty)) {
		rd_kafka_op_destroy(rko_orig);
                rd_kafka_cgrp_check_unassign_done(
                        rkcg,
                        err == RD_KAFKA_RESP_ERR__DESTROY ?
                        "OffsetCommit done (__DESTROY)" :
                        "OffsetCommit done (__NO_OFFSET)");
		return;
	}

        /* Call on_commit interceptors */
        if (err != RD_KAFKA_RESP_ERR__NO_OFFSET &&
            err != RD_KAFKA_RESP_ERR__DESTROY &&
            offsets && offsets->cnt > 0)
                rd_kafka_interceptors_on_commit(rk, offsets, err);


	/* If no special callback is set but a offset_commit_cb has
	 * been set in conf then post an event for the latter. */
	if (!rko_orig->rko_u.offset_commit.cb && rk->rk_conf.offset_commit_cb) {
                rd_kafka_op_t *rko_reply = rd_kafka_op_new_reply(rko_orig, err);

                rd_kafka_op_set_prio(rko_reply, RD_KAFKA_PRIO_HIGH);

		if (offsets)
			rko_reply->rko_u.offset_commit.partitions =
				rd_kafka_topic_partition_list_copy(offsets);

		rko_reply->rko_u.offset_commit.cb =
			rk->rk_conf.offset_commit_cb;
		rko_reply->rko_u.offset_commit.opaque = rk->rk_conf.opaque;

                rd_kafka_q_enq(rk->rk_rep, rko_reply);
                offset_commit_cb_served++;
	}


	/* Enqueue reply to requester's queue, if any. */
	if (rko_orig->rko_replyq.q) {
                rd_kafka_op_t *rko_reply = rd_kafka_op_new_reply(rko_orig, err);

                rd_kafka_op_set_prio(rko_reply, RD_KAFKA_PRIO_HIGH);

		/* Copy offset & partitions & callbacks to reply op */
		rko_reply->rko_u.offset_commit = rko_orig->rko_u.offset_commit;
		if (offsets)
			rko_reply->rko_u.offset_commit.partitions =
				rd_kafka_topic_partition_list_copy(offsets);
                if (rko_reply->rko_u.offset_commit.reason)
                        rko_reply->rko_u.offset_commit.reason =
                        rd_strdup(rko_reply->rko_u.offset_commit.reason);

                rd_kafka_replyq_enq(&rko_orig->rko_replyq, rko_reply, 0);
                offset_commit_cb_served++;
        }

        errcnt = rd_kafka_cgrp_handle_OffsetCommit(rkcg, err, offsets);

        if (!offset_commit_cb_served &&
            offsets &&
            (errcnt > 0 ||
             (err != RD_KAFKA_RESP_ERR_NO_ERROR &&
              err != RD_KAFKA_RESP_ERR__NO_OFFSET))) {
                /* If there is no callback or handler for this (auto)
                 * commit then raise an error to the application (#1043) */
                char tmp[512];

                rd_kafka_topic_partition_list_str(
                        offsets, tmp, sizeof(tmp),
                        /* Print per-partition errors unless there was a
                         * request-level error. */
                        RD_KAFKA_FMT_F_OFFSET |
                        (errcnt ? RD_KAFKA_FMT_F_ONLY_ERR : 0));

                rd_kafka_log(rkcg->rkcg_rk, LOG_WARNING, "COMMITFAIL",
                             "Offset commit (%s) failed "
                             "for %d/%d partition(s): "
                             "%s%s%s",
                             rko_orig->rko_u.offset_commit.reason,
                             errcnt ? offsets->cnt : errcnt, offsets->cnt,
                             errcnt ? rd_kafka_err2str(err) : "",
                             errcnt ? ": " : "",
                             tmp);
        }

        rd_kafka_op_destroy(rko_orig);
}


static size_t rd_kafka_topic_partition_has_absolute_offset (
        const rd_kafka_topic_partition_t *rktpar, void *opaque) {
        return rktpar->offset >= 0 ? 1 : 0;
}


/**
 * Commit a list of offsets.
 * Reuse the orignating 'rko' for the async reply.
 * 'rko->rko_payload' should either by NULL (to commit current assignment) or
 * a proper topic_partition_list_t with offsets to commit.
 * The offset list will be altered.
 *
 * \p rko...silent_empty: if there are no offsets to commit bail out
 *                        silently without posting an op on the reply queue.
 * \p set_offsets: set offsets in rko->rko_u.offset_commit.partitions
 *
 * \p op_version: cgrp's op version to use (or 0)
 *
 * Locality: cgrp thread
 */
static void rd_kafka_cgrp_offsets_commit (rd_kafka_cgrp_t *rkcg,
                                          rd_kafka_op_t *rko,
                                          int set_offsets,
                                          const char *reason,
                                          int op_version) {
	rd_kafka_topic_partition_list_t *offsets;
	rd_kafka_resp_err_t err;
        int valid_offsets = 0;

	/* If offsets is NULL we shall use the current assignment. */
	if (!rko->rko_u.offset_commit.partitions && rkcg->rkcg_assignment)
		rko->rko_u.offset_commit.partitions =
			rd_kafka_topic_partition_list_copy(
				rkcg->rkcg_assignment);

	offsets = rko->rko_u.offset_commit.partitions;

        if (offsets) {
                /* Set offsets to commits */
                if (set_offsets)
                        rd_kafka_topic_partition_list_set_offsets(
			rkcg->rkcg_rk, rko->rko_u.offset_commit.partitions, 1,
			RD_KAFKA_OFFSET_INVALID/* def */,
			1 /* is commit */);

                /*  Check the number of valid offsets to commit. */
                valid_offsets = (int)rd_kafka_topic_partition_list_sum(
                        offsets,
                        rd_kafka_topic_partition_has_absolute_offset, NULL);
        }

        if (!(rko->rko_flags & RD_KAFKA_OP_F_REPROCESS)) {
                /* wait_commit_cnt has already been increased for
                 * reprocessed ops. */
                rkcg->rkcg_wait_commit_cnt++;
        }

        if (rd_kafka_fatal_error_code(rkcg->rkcg_rk)) {
                /* Commits are not allowed when a fatal error has been raised */
                err = RD_KAFKA_RESP_ERR__FATAL;
                goto err;
        }

	if (!valid_offsets) {
                /* No valid offsets */
                err = RD_KAFKA_RESP_ERR__NO_OFFSET;
                goto err;
	}

        if (rkcg->rkcg_state != RD_KAFKA_CGRP_STATE_UP) {
                rd_kafka_dbg(rkcg->rkcg_rk, CONSUMER, "COMMIT",
                             "Deferring \"%s\" offset commit "
                             "for %d partition(s) in state %s: "
                             "no coordinator available",
                             reason, valid_offsets,
                             rd_kafka_cgrp_state_names[rkcg->rkcg_state]);

		if (rd_kafka_cgrp_defer_offset_commit(rkcg, rko, reason))
			return;

		err = RD_KAFKA_RESP_ERR__WAIT_COORD;

	} else {
                int r;

                rd_rkb_dbg(rkcg->rkcg_coord, CONSUMER, "COMMIT",
                           "Committing offsets for %d partition(s): %s",
                           valid_offsets, reason);

                /* Send OffsetCommit */
                r = rd_kafka_OffsetCommitRequest(
                            rkcg->rkcg_coord, rkcg, offsets,
                            RD_KAFKA_REPLYQ(rkcg->rkcg_ops, op_version),
                            rd_kafka_cgrp_op_handle_OffsetCommit, rko,
                        reason);

                /* Must have valid offsets to commit if we get here */
                rd_kafka_assert(NULL, r != 0);

                return;
        }



 err:
	/* Propagate error to whoever wanted offset committed. */
        if (err != RD_KAFKA_RESP_ERR__NO_OFFSET)
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "COMMIT",
                             "OffsetCommit internal error: %s",
                             rd_kafka_err2str(err));
	rd_kafka_cgrp_op_handle_OffsetCommit(rkcg->rkcg_rk, NULL, err,
					     NULL, NULL, rko);
}


/**
 * Commit offsets for all assigned partitions.
 */
static void
rd_kafka_cgrp_assigned_offsets_commit (rd_kafka_cgrp_t *rkcg,
                                       const rd_kafka_topic_partition_list_t
                                       *offsets, const char *reason) {
        rd_kafka_op_t *rko;

	rko = rd_kafka_op_new(RD_KAFKA_OP_OFFSET_COMMIT);
        rko->rko_u.offset_commit.reason = rd_strdup(reason);
	if (rkcg->rkcg_rk->rk_conf.enabled_events & RD_KAFKA_EVENT_OFFSET_COMMIT) {
		rd_kafka_op_set_replyq(rko, rkcg->rkcg_rk->rk_rep, 0);
		rko->rko_u.offset_commit.cb =
			rkcg->rkcg_rk->rk_conf.offset_commit_cb; /*maybe NULL*/
		rko->rko_u.offset_commit.opaque = rkcg->rkcg_rk->rk_conf.opaque;
	}
        /* NULL partitions means current assignment */
        if (offsets)
                rko->rko_u.offset_commit.partitions =
                        rd_kafka_topic_partition_list_copy(offsets);
	rko->rko_u.offset_commit.silent_empty = 1;
        rd_kafka_cgrp_offsets_commit(rkcg, rko, 1/* set offsets */, reason,
                                     rkcg->rkcg_version);
}


/**
 * auto.commit.interval.ms commit timer callback.
 *
 * Trigger a group offset commit.
 *
 * Locality: rdkafka main thread
 */
static void rd_kafka_cgrp_offset_commit_tmr_cb (rd_kafka_timers_t *rkts,
                                                void *arg) {
        rd_kafka_cgrp_t *rkcg = arg;

	rd_kafka_cgrp_assigned_offsets_commit(rkcg, NULL,
                                              "cgrp auto commit timer");
}




/**
 * Call when all unassign operations are done to transition to the next state
 */
static void rd_kafka_cgrp_unassign_done (rd_kafka_cgrp_t *rkcg,
                                         const char *reason) {
	rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "UNASSIGN",
		     "Group \"%s\": unassign done in state %s (join state %s): "
		     "%s: %s",
		     rkcg->rkcg_group_id->str,
		     rd_kafka_cgrp_state_names[rkcg->rkcg_state],
		     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state],
		     rkcg->rkcg_assignment ?
		     "with new assignment" : "without new assignment",
                     reason);

        /* Don't send Leave when termating with NO_CONSUMER_CLOSE flag */
        if (rd_kafka_destroy_flags_no_consumer_close(rkcg->rkcg_rk))
                rkcg->rkcg_flags &= ~RD_KAFKA_CGRP_F_LEAVE_ON_UNASSIGN;

        /*
         * KIP-345: Static group members must not send a LeaveGroupRequest
         * on termination.
         */
        if (RD_KAFKA_CGRP_IS_STATIC_MEMBER(rkcg) &&
            rkcg->rkcg_flags & RD_KAFKA_CGRP_F_TERMINATE)
                rkcg->rkcg_flags &= ~RD_KAFKA_CGRP_F_LEAVE_ON_UNASSIGN;

	if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_LEAVE_ON_UNASSIGN) {
		rd_kafka_cgrp_leave(rkcg);
		rkcg->rkcg_flags &= ~RD_KAFKA_CGRP_F_LEAVE_ON_UNASSIGN;
	}

        if (rkcg->rkcg_join_state != RD_KAFKA_CGRP_JOIN_STATE_WAIT_UNASSIGN) {
                rd_kafka_cgrp_try_terminate(rkcg);
                return;
        }

        if (rkcg->rkcg_assignment) {
		rd_kafka_cgrp_set_join_state(rkcg,
					     RD_KAFKA_CGRP_JOIN_STATE_ASSIGNED);
                if (RD_KAFKA_CGRP_CAN_FETCH_START(rkcg))
                        rd_kafka_cgrp_partitions_fetch_start(
                                rkcg, rkcg->rkcg_assignment, 0);
	} else {
		rd_kafka_cgrp_set_join_state(rkcg,
					     RD_KAFKA_CGRP_JOIN_STATE_INIT);
	}

	rd_kafka_cgrp_try_terminate(rkcg);
}


/**
 * Checks if the current unassignment is done and if so
 * calls .._done().
 * Else does nothing.
 */
static void rd_kafka_cgrp_check_unassign_done (rd_kafka_cgrp_t *rkcg,
                                               const char *reason) {
	if (rkcg->rkcg_wait_unassign_cnt > 0 ||
	    rkcg->rkcg_assigned_cnt > 0 ||
	    rkcg->rkcg_wait_commit_cnt > 0 ||
	    rkcg->rkcg_flags & RD_KAFKA_CGRP_F_WAIT_UNASSIGN) {

                if (rkcg->rkcg_join_state != RD_KAFKA_CGRP_JOIN_STATE_STARTED)
                        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "UNASSIGN",
                                     "Unassign not done yet "
                                     "(%d wait_unassign, %d assigned, "
                                     "%d wait commit"
                                     "%s, join state %s): %s",
                                     rkcg->rkcg_wait_unassign_cnt,
                                     rkcg->rkcg_assigned_cnt,
                                     rkcg->rkcg_wait_commit_cnt,
                                     (rkcg->rkcg_flags &
                                      RD_KAFKA_CGRP_F_WAIT_UNASSIGN)?
                                     ", F_WAIT_UNASSIGN" : "",
                                     rd_kafka_cgrp_join_state_names[
                                             rkcg->rkcg_join_state],
                                     reason);

		return;
        }

	rd_kafka_cgrp_unassign_done(rkcg, reason);
}



/**
 * Remove existing assignment.
 */
static rd_kafka_resp_err_t
rd_kafka_cgrp_unassign (rd_kafka_cgrp_t *rkcg) {
        int i;
        rd_kafka_topic_partition_list_t *old_assignment;

        rd_kafka_cgrp_set_join_state(rkcg,
                                     RD_KAFKA_CGRP_JOIN_STATE_WAIT_UNASSIGN);

	rkcg->rkcg_flags &= ~RD_KAFKA_CGRP_F_WAIT_UNASSIGN;
        old_assignment = rkcg->rkcg_assignment;
        if (!old_assignment) {
		rd_kafka_cgrp_check_unassign_done(
                        rkcg, "unassign (no previous assignment)");
                return RD_KAFKA_RESP_ERR_NO_ERROR;
	}
        rkcg->rkcg_assignment = NULL;

	rd_kafka_cgrp_version_new_barrier(rkcg);

	rd_kafka_dbg(rkcg->rkcg_rk, CGRP|RD_KAFKA_DBG_CONSUMER, "UNASSIGN",
                     "Group \"%s\": unassigning %d partition(s) (v%"PRId32")",
                     rkcg->rkcg_group_id->str, old_assignment->cnt,
		     rkcg->rkcg_version);

        if (rkcg->rkcg_rk->rk_conf.offset_store_method ==
            RD_KAFKA_OFFSET_METHOD_BROKER &&
	    rkcg->rkcg_rk->rk_conf.enable_auto_commit &&
            !rd_kafka_destroy_flags_no_consumer_close(rkcg->rkcg_rk)) {
                /* Commit all offsets for all assigned partitions to broker */
                rd_kafka_cgrp_assigned_offsets_commit(rkcg, old_assignment,
                                                      "unassign");
        }

        for (i = 0 ; i < old_assignment->cnt ; i++) {
                rd_kafka_topic_partition_t *rktpar;
                shptr_rd_kafka_toppar_t *s_rktp;
                rd_kafka_toppar_t *rktp;

                rktpar = &old_assignment->elems[i];
                s_rktp = rktpar->_private;
                rktp = rd_kafka_toppar_s2i(s_rktp);

                if (rktp->rktp_assigned) {
                        rd_kafka_toppar_op_fetch_stop(
				rktp, RD_KAFKA_REPLYQ(rkcg->rkcg_ops, 0));
                        rkcg->rkcg_wait_unassign_cnt++;
                }

                rd_kafka_toppar_lock(rktp);
                /* Reset the stored offset to invalid so that
                 * a manual offset-less commit() or the auto-committer
                 * will not commit a stored offset from a previous
                 * assignment (issue #2782). */
                rd_kafka_offset_store0(rktp, RD_KAFKA_OFFSET_INVALID,
                                       RD_DONT_LOCK);
                rd_kafka_toppar_desired_del(rktp);
                rd_kafka_toppar_unlock(rktp);
        }

        /* Resume partition consumption. */
        rd_kafka_toppars_pause_resume(rkcg->rkcg_rk,
                                      rd_false/*resume*/,
                                      RD_ASYNC,
                                      RD_KAFKA_TOPPAR_F_LIB_PAUSE,
                                      old_assignment);

        rd_kafka_topic_partition_list_destroy(old_assignment);

        rd_kafka_cgrp_check_unassign_done(rkcg, "unassign");

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Set new atomic partition assignment
 *        May update \p assignment but will not hold on to it.
 *
 * @returns 0 on success or an error if a fatal error has been raised.
 */
static rd_kafka_resp_err_t
rd_kafka_cgrp_assign (rd_kafka_cgrp_t *rkcg,
                      rd_kafka_topic_partition_list_t *assignment) {
        int i;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP|RD_KAFKA_DBG_CONSUMER, "ASSIGN",
                     "Group \"%s\": new assignment of %d partition(s) "
                     "in join state %s",
                     rkcg->rkcg_group_id->str,
                     assignment ? assignment->cnt : 0,
                     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state]);

        /* Get toppar object for each partition.
         * This is to make sure the rktp stays alive during unassign(). */
        for (i = 0 ; assignment && i < assignment->cnt ; i++) {
                rd_kafka_topic_partition_t *rktpar;
                shptr_rd_kafka_toppar_t *s_rktp;

                rktpar = &assignment->elems[i];

                /* Use existing toppar if set */
                if (rktpar->_private)
                        continue;

                s_rktp = rd_kafka_toppar_get2(rkcg->rkcg_rk,
                                              rktpar->topic,
                                              rktpar->partition,
                                              0/*no-ua*/, 1/*create-on-miss*/);
                if (s_rktp)
                        rktpar->_private = s_rktp;
        }

        rd_kafka_cgrp_version_new_barrier(rkcg);

        rd_kafka_wrlock(rkcg->rkcg_rk);
        rkcg->rkcg_c.assignment_size = assignment ? assignment->cnt : 0;
        rd_kafka_wrunlock(rkcg->rkcg_rk);


        /* Remove existing assignment (async operation) */
	if (rkcg->rkcg_assignment)
		rd_kafka_cgrp_unassign(rkcg);

        /* If the consumer has raised a fatal error we treat all
         * assigns as unassigns */
        if (rd_kafka_fatal_error_code(rkcg->rkcg_rk)) {
                err = RD_KAFKA_RESP_ERR__FATAL;
                assignment = NULL;
        }

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "ASSIGN",
                     "Group \"%s\": assigning %d partition(s) in join state %s",
                     rkcg->rkcg_group_id->str, assignment ? assignment->cnt : 0,
                     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state]);


	if (assignment) {
		rkcg->rkcg_assignment =
			rd_kafka_topic_partition_list_copy(assignment);

                /* Mark partition(s) as desired */
                for (i = 0 ; i < rkcg->rkcg_assignment->cnt ; i++) {
                        rd_kafka_topic_partition_t *rktpar =
                                &rkcg->rkcg_assignment->elems[i];
                        shptr_rd_kafka_toppar_t *s_rktp = rktpar->_private;
                        rd_kafka_toppar_t *rktp =
                                rd_kafka_toppar_s2i(s_rktp);
                        rd_kafka_toppar_lock(rktp);
                        rd_kafka_toppar_desired_add0(rktp);
                        rd_kafka_toppar_unlock(rktp);
                }
        }

        if (rkcg->rkcg_join_state == RD_KAFKA_CGRP_JOIN_STATE_WAIT_UNASSIGN)
                return err;

        rd_dassert(rkcg->rkcg_wait_unassign_cnt == 0);

        if (rkcg->rkcg_assignment) {
                /* No existing assignment that needs to be decommissioned,
                 * start partition fetchers right away */
		rd_kafka_cgrp_set_join_state(rkcg,
					     RD_KAFKA_CGRP_JOIN_STATE_ASSIGNED);
                if (RD_KAFKA_CGRP_CAN_FETCH_START(rkcg))
                        rd_kafka_cgrp_partitions_fetch_start(
                                rkcg, rkcg->rkcg_assignment, 0);
	} else {
		rd_kafka_cgrp_set_join_state(rkcg,
					     RD_KAFKA_CGRP_JOIN_STATE_INIT);
	}

        return err;
}




/**
 * Handle a rebalance-triggered partition assignment.
 *
 * If a rebalance_cb has been registered we enqueue an op for the app
 * and let the app perform the actual assign() call.
 * Otherwise we assign() directly from here.
 *
 * This provides the most flexibility, allowing the app to perform any
 * operation it seem fit (e.g., offset writes or reads) before actually
 * updating the assign():ment.
 */
static void
rd_kafka_cgrp_handle_assignment (rd_kafka_cgrp_t *rkcg,
				 rd_kafka_topic_partition_list_t *assignment) {

	rd_kafka_rebalance_op(rkcg, RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
			      assignment, "new assignment");
}


/**
 * Clean up any group-leader related resources.
 *
 * Locality: cgrp thread
 */
static void rd_kafka_cgrp_group_leader_reset (rd_kafka_cgrp_t *rkcg,
                                              const char *reason) {
        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "GRPLEADER",
                     "Group \"%.*s\": resetting group leader info: %s",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id), reason);
        if (rkcg->rkcg_group_leader.protocol) {
                rd_free(rkcg->rkcg_group_leader.protocol);
                rkcg->rkcg_group_leader.protocol = NULL;
        }

        if (rkcg->rkcg_group_leader.members) {
                int i;

                for (i = 0 ; i < rkcg->rkcg_group_leader.member_cnt ; i++)
                        rd_kafka_group_member_clear(&rkcg->rkcg_group_leader.
                                                    members[i]);
                rkcg->rkcg_group_leader.member_cnt = 0;
                rd_free(rkcg->rkcg_group_leader.members);
                rkcg->rkcg_group_leader.members = NULL;
        }
}


/**
 * @brief Group is rebalancing, trigger rebalance callback to application,
 *        and transition to INIT state for (eventual) rejoin.
 */
static void rd_kafka_cgrp_rebalance (rd_kafka_cgrp_t *rkcg,
                                     const char *reason) {

        rd_kafka_dbg(rkcg->rkcg_rk, CONSUMER|RD_KAFKA_DBG_CGRP, "REBALANCE",
                     "Group \"%.*s\" is rebalancing in "
                     "state %s (join-state %s) %s assignment: %s",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_kafka_cgrp_state_names[rkcg->rkcg_state],
                     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state],
                     rkcg->rkcg_assignment ? "with" : "without",
                     reason);

        rd_snprintf(rkcg->rkcg_c.rebalance_reason,
                    sizeof(rkcg->rkcg_c.rebalance_reason), "%s", reason);

        /* Remove assignment (async), if any. If there is already an
         * unassign in progress we dont need to bother. */
        if (!RD_KAFKA_CGRP_WAIT_REBALANCE_CB(rkcg) &&
            !(rkcg->rkcg_flags & RD_KAFKA_CGRP_F_WAIT_UNASSIGN)) {
                rkcg->rkcg_flags |= RD_KAFKA_CGRP_F_WAIT_UNASSIGN;

                rd_kafka_rebalance_op(
                        rkcg,
                        RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS,
                        rkcg->rkcg_assignment, reason);
        }
}


/**
 * @brief `max.poll.interval.ms` enforcement check timer.
 *
 * @locality rdkafka main thread
 * @locks none
 */
static void
rd_kafka_cgrp_max_poll_interval_check_tmr_cb (rd_kafka_timers_t *rkts,
                                              void *arg) {
        rd_kafka_cgrp_t *rkcg = arg;
        rd_kafka_t *rk = rkcg->rkcg_rk;
        int exceeded;

        exceeded = rd_kafka_max_poll_exceeded(rk);

        if (likely(!exceeded))
                return;

        rd_kafka_log(rk, LOG_WARNING, "MAXPOLL",
                     "Application maximum poll interval (%dms) "
                     "exceeded by %dms "
                     "(adjust max.poll.interval.ms for "
                     "long-running message processing): "
                     "leaving group",
                     rk->rk_conf.max_poll_interval_ms, exceeded);

        rd_kafka_q_op_err(rkcg->rkcg_q, RD_KAFKA_OP_CONSUMER_ERR,
                          RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED, 0, NULL, 0,
                          "Application maximum poll interval (%dms) "
                          "exceeded by %dms",
                          rk->rk_conf.max_poll_interval_ms, exceeded);

        rkcg->rkcg_flags |= RD_KAFKA_CGRP_F_MAX_POLL_EXCEEDED;

        rd_kafka_timer_stop(rkts, &rkcg->rkcg_max_poll_interval_tmr,
                            1/*lock*/);

        /* Leave the group before calling rebalance since the standard leave
         * will be triggered first after the rebalance callback has been served.
         * But since the application is blocked still doing processing
         * that leave will be further delayed.
         *
         * KIP-345: static group members should continue to respect
         * `max.poll.interval.ms` but should not send a LeaveGroupRequest.
         */
        if (!RD_KAFKA_CGRP_IS_STATIC_MEMBER(rkcg))
                rd_kafka_cgrp_leave(rkcg);

        /* Timing out or leaving the group invalidates the member id, reset it
         * now to avoid an ERR_UNKNOWN_MEMBER_ID on the next join. */
        rd_kafka_cgrp_set_member_id(rkcg, "");

        /* Trigger rebalance */
        rd_kafka_cgrp_rebalance(rkcg, "max.poll.interval.ms exceeded");
}


/**
 * Remove existing topic subscription.
 */
static rd_kafka_resp_err_t
rd_kafka_cgrp_unsubscribe (rd_kafka_cgrp_t *rkcg, int leave_group) {

	rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "UNSUBSCRIBE",
		     "Group \"%.*s\": unsubscribe from current %ssubscription "
		     "of %d topics (leave group=%s, join state %s, v%"PRId32")",
		     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
		     rkcg->rkcg_subscription ? "" : "unset ",
		     rkcg->rkcg_subscription ? rkcg->rkcg_subscription->cnt : 0,
		     leave_group ? "yes":"no",
		     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state],
		     rkcg->rkcg_version);

        rd_kafka_timer_stop(&rkcg->rkcg_rk->rk_timers,
                            &rkcg->rkcg_max_poll_interval_tmr, 1/*lock*/);


        if (rkcg->rkcg_subscription) {
                rd_kafka_topic_partition_list_destroy(rkcg->rkcg_subscription);
                rkcg->rkcg_subscription = NULL;
        }

	rd_kafka_cgrp_update_subscribed_topics(rkcg, NULL);

        /*
         * Clean-up group leader duties, if any.
         */
        rd_kafka_cgrp_group_leader_reset(rkcg, "unsubscribe");

	if (leave_group)
		rkcg->rkcg_flags |= RD_KAFKA_CGRP_F_LEAVE_ON_UNASSIGN;

        rd_kafka_cgrp_rebalance(rkcg, "unsubscribe");

        rkcg->rkcg_flags &= ~(RD_KAFKA_CGRP_F_SUBSCRIPTION |
                              RD_KAFKA_CGRP_F_WILDCARD_SUBSCRIPTION);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * Set new atomic topic subscription.
 */
static rd_kafka_resp_err_t
rd_kafka_cgrp_subscribe (rd_kafka_cgrp_t *rkcg,
                         rd_kafka_topic_partition_list_t *rktparlist) {

	rd_kafka_dbg(rkcg->rkcg_rk, CGRP|RD_KAFKA_DBG_CONSUMER, "SUBSCRIBE",
		     "Group \"%.*s\": subscribe to new %ssubscription "
		     "of %d topics (join state %s)",
		     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
		     rktparlist ? "" : "unset ",
		     rktparlist ? rktparlist->cnt : 0,
		     rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state]);

        if (rkcg->rkcg_rk->rk_conf.enabled_assignor_cnt == 0)
                return RD_KAFKA_RESP_ERR__INVALID_ARG;

        /* Remove existing subscription first */
        rd_kafka_cgrp_unsubscribe(rkcg,
                                  rktparlist ?
                                  0/* dont leave group if new subscription */ :
                                  1/* leave group if no new subscription */);

        /* If the consumer has raised a fatal error we treat all
         * subscribes as unsubscribe */
        if (rd_kafka_fatal_error_code(rkcg->rkcg_rk))
                return RD_KAFKA_RESP_ERR__FATAL;

        if (!rktparlist)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        rkcg->rkcg_flags |= RD_KAFKA_CGRP_F_SUBSCRIPTION;

        if (rd_kafka_topic_partition_list_regex_cnt(rktparlist) > 0)
                rkcg->rkcg_flags |= RD_KAFKA_CGRP_F_WILDCARD_SUBSCRIPTION;

        rkcg->rkcg_subscription = rktparlist;

        rd_kafka_cgrp_join(rkcg);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}






/**
 * Same as cgrp_terminate() but called from the cgrp/main thread upon receiving
 * the op 'rko' from cgrp_terminate().
 *
 * NOTE: Takes ownership of 'rko'
 *
 * Locality: main thread
 */
void
rd_kafka_cgrp_terminate0 (rd_kafka_cgrp_t *rkcg, rd_kafka_op_t *rko) {

	rd_kafka_assert(NULL, thrd_is_current(rkcg->rkcg_rk->rk_thread));

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPTERM",
                     "Terminating group \"%.*s\" in state %s "
                     "with %d partition(s)",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rd_kafka_cgrp_state_names[rkcg->rkcg_state],
                     rd_list_cnt(&rkcg->rkcg_toppars));

        if (unlikely(rkcg->rkcg_state == RD_KAFKA_CGRP_STATE_TERM ||
		     (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_TERMINATE) ||
		     rkcg->rkcg_reply_rko != NULL)) {
                /* Already terminating or handling a previous terminate */
		if (rko) {
			rd_kafka_q_t *rkq = rko->rko_replyq.q;
			rko->rko_replyq.q = NULL;
			rd_kafka_q_op_err(rkq, RD_KAFKA_OP_CONSUMER_ERR,
					  RD_KAFKA_RESP_ERR__IN_PROGRESS,
					  rko->rko_replyq.version,
					  NULL, 0,
					  "Group is %s",
					  rkcg->rkcg_reply_rko ?
					  "terminating":"terminated");
			rd_kafka_q_destroy(rkq);
			rd_kafka_op_destroy(rko);
		}
                return;
        }

        /* Mark for stopping, the actual state transition
         * is performed when all toppars have left. */
        rkcg->rkcg_flags |= RD_KAFKA_CGRP_F_TERMINATE;
	rkcg->rkcg_ts_terminate = rd_clock();
        rkcg->rkcg_reply_rko = rko;

         if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_SUBSCRIPTION)
                 rd_kafka_cgrp_unsubscribe(
                         rkcg,
                         /* Leave group if this is a controlled shutdown */
                         !rd_kafka_destroy_flags_no_consumer_close(
                                 rkcg->rkcg_rk));

         /* Reset the wait-for-LeaveGroup flag if there is an outstanding
          * LeaveGroupRequest being waited on (from a prior unsubscribe), but
          * the destroy flags have NO_CONSUMER_CLOSE set, which calls
          * for immediate termination. */
         if (rd_kafka_destroy_flags_no_consumer_close(rkcg->rkcg_rk))
                 rkcg->rkcg_flags &= ~RD_KAFKA_CGRP_F_WAIT_LEAVE;

         /* If there's an oustanding rebalance_cb which has not yet been
          * served by the application it will be served from consumer_close().
          * If the instate is being terminated with NO_CONSUMER_CLOSE we
          * trigger unassign directly to avoid stalling on rebalance callback
          * queues that are no longer served by the application. */
         if ((!RD_KAFKA_CGRP_WAIT_REBALANCE_CB(rkcg) &&
              !(rkcg->rkcg_flags & RD_KAFKA_CGRP_F_WAIT_UNASSIGN)) ||
             rd_kafka_destroy_flags_no_consumer_close(rkcg->rkcg_rk))
                 rd_kafka_cgrp_unassign(rkcg);

        /* Try to terminate right away if all preconditions are met. */
        rd_kafka_cgrp_try_terminate(rkcg);
}


/**
 * Terminate and decommission a cgrp asynchronously.
 *
 * Locality: any thread
 */
void rd_kafka_cgrp_terminate (rd_kafka_cgrp_t *rkcg, rd_kafka_replyq_t replyq) {
	rd_kafka_assert(NULL, !thrd_is_current(rkcg->rkcg_rk->rk_thread));
        rd_kafka_cgrp_op(rkcg, NULL, replyq, RD_KAFKA_OP_TERMINATE, 0);
}


struct _op_timeout_offset_commit {
        rd_ts_t now;
        rd_kafka_t *rk;
        rd_list_t expired;
};

/**
 * q_filter callback for expiring OFFSET_COMMIT timeouts.
 */
static int rd_kafka_op_offset_commit_timeout_check (rd_kafka_q_t *rkq,
                                                    rd_kafka_op_t *rko,
                                                    void *opaque) {
        struct _op_timeout_offset_commit *state =
                (struct _op_timeout_offset_commit*)opaque;

        if (likely(rko->rko_type != RD_KAFKA_OP_OFFSET_COMMIT ||
                   rko->rko_u.offset_commit.ts_timeout == 0 ||
                   rko->rko_u.offset_commit.ts_timeout > state->now)) {
                return 0;
        }

        rd_kafka_q_deq0(rkq, rko);

        /* Add to temporary list to avoid recursive
         * locking of rkcg_wait_coord_q. */
        rd_list_add(&state->expired, rko);
        return 1;
}


/**
 * Scan for various timeouts.
 */
static void rd_kafka_cgrp_timeout_scan (rd_kafka_cgrp_t *rkcg, rd_ts_t now) {
        struct _op_timeout_offset_commit ofc_state;
        int i, cnt = 0;
        rd_kafka_op_t *rko;

        ofc_state.now = now;
        ofc_state.rk = rkcg->rkcg_rk;
        rd_list_init(&ofc_state.expired, 0, NULL);

        cnt += rd_kafka_q_apply(rkcg->rkcg_wait_coord_q,
                                rd_kafka_op_offset_commit_timeout_check,
                                &ofc_state);

        RD_LIST_FOREACH(rko, &ofc_state.expired, i)
                rd_kafka_cgrp_op_handle_OffsetCommit(
                        rkcg->rkcg_rk, NULL,
                        RD_KAFKA_RESP_ERR__WAIT_COORD,
                        NULL, NULL, rko);

        rd_list_destroy(&ofc_state.expired);

        if (cnt > 0)
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPTIMEOUT",
                             "Group \"%.*s\": timed out %d op(s), %d remain",
                             RD_KAFKAP_STR_PR(rkcg->rkcg_group_id), cnt,
                             rd_kafka_q_len(rkcg->rkcg_wait_coord_q));


}


/**
 * @brief Handle cgrp queue op.
 * @locality rdkafka main thread
 * @locks none
 */
static rd_kafka_op_res_t
rd_kafka_cgrp_op_serve (rd_kafka_t *rk, rd_kafka_q_t *rkq,
                        rd_kafka_op_t *rko, rd_kafka_q_cb_type_t cb_type,
                        void *opaque) {
        rd_kafka_cgrp_t *rkcg = opaque;
        rd_kafka_toppar_t *rktp;
        rd_kafka_resp_err_t err;
        const int silent_op = rko->rko_type == RD_KAFKA_OP_RECV_BUF;

        if (rko->rko_version && rkcg->rkcg_version > rko->rko_version) {
                rd_kafka_op_destroy(rko); /* outdated */
                return RD_KAFKA_OP_RES_HANDLED;
        }

        rktp = rko->rko_rktp ? rd_kafka_toppar_s2i(rko->rko_rktp) : NULL;

        if (rktp && !silent_op)
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPOP",
                             "Group \"%.*s\" received op %s in state %s "
                             "(join state %s, v%"PRId32") "
                             "for %.*s [%"PRId32"]",
                             RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                             rd_kafka_op2str(rko->rko_type),
                             rd_kafka_cgrp_state_names[rkcg->rkcg_state],
                             rd_kafka_cgrp_join_state_names[rkcg->
                                                            rkcg_join_state],
                             rkcg->rkcg_version,
                             RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                             rktp->rktp_partition);
        else if (!silent_op)
                rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "CGRPOP",
                             "Group \"%.*s\" received op %s (v%d) in state %s "
                             "(join state %s, v%"PRId32" vs %"PRId32")",
                             RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                             rd_kafka_op2str(rko->rko_type),
                             rko->rko_version,
                             rd_kafka_cgrp_state_names[rkcg->rkcg_state],
                             rd_kafka_cgrp_join_state_names[rkcg->
                                                            rkcg_join_state],
                             rkcg->rkcg_version, rko->rko_version);

        switch ((int)rko->rko_type)
        {
        case RD_KAFKA_OP_NAME:
                /* Return the currently assigned member id. */
                if (rkcg->rkcg_member_id)
                        rko->rko_u.name.str =
                                RD_KAFKAP_STR_DUP(rkcg->rkcg_member_id);
                rd_kafka_op_reply(rko, 0);
                rko = NULL;
                break;

        case RD_KAFKA_OP_OFFSET_FETCH:
                if (rkcg->rkcg_state != RD_KAFKA_CGRP_STATE_UP ||
                    (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_TERMINATE)) {
                        rd_kafka_op_handle_OffsetFetch(
                                rkcg->rkcg_rk, NULL,
                                RD_KAFKA_RESP_ERR__WAIT_COORD,
                                NULL, NULL, rko);
                        rko = NULL; /* rko freed by handler */
                        break;
                }

                rd_kafka_OffsetFetchRequest(
                        rkcg->rkcg_coord, 1,
                        rko->rko_u.offset_fetch.partitions,
                        RD_KAFKA_REPLYQ(rkcg->rkcg_ops,
                                        rkcg->rkcg_version),
                        rd_kafka_op_handle_OffsetFetch, rko);
                rko = NULL; /* rko now owned by request */
                break;

        case RD_KAFKA_OP_PARTITION_JOIN:
                rd_kafka_cgrp_partition_add(rkcg, rktp);

                /* If terminating tell the partition to leave */
                if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_TERMINATE)
                        rd_kafka_toppar_op_fetch_stop(
                                rktp, RD_KAFKA_NO_REPLYQ);
                break;

        case RD_KAFKA_OP_PARTITION_LEAVE:
                rd_kafka_cgrp_partition_del(rkcg, rktp);
                break;

        case RD_KAFKA_OP_FETCH_STOP|RD_KAFKA_OP_REPLY:
                /* Reply from toppar FETCH_STOP */
                rd_kafka_assert(rkcg->rkcg_rk,
                                rkcg->rkcg_wait_unassign_cnt > 0);
                rkcg->rkcg_wait_unassign_cnt--;

                rd_kafka_assert(rkcg->rkcg_rk, rktp->rktp_assigned);
                rd_kafka_assert(rkcg->rkcg_rk,
                                rkcg->rkcg_assigned_cnt > 0);
                rktp->rktp_assigned = 0;
                rkcg->rkcg_assigned_cnt--;

                /* All unassigned toppars now stopped and commit done:
                 * transition to the next state. */
                if (rkcg->rkcg_join_state ==
                    RD_KAFKA_CGRP_JOIN_STATE_WAIT_UNASSIGN)
                        rd_kafka_cgrp_check_unassign_done(rkcg,
                                                          "FETCH_STOP done");
                break;

        case RD_KAFKA_OP_OFFSET_COMMIT:
                /* Trigger offsets commit. */
                rd_kafka_cgrp_offsets_commit(rkcg, rko,
                                             /* only set offsets
                                              * if no partitions were
                                              * specified. */
                                             rko->rko_u.offset_commit.
                                             partitions ? 0 : 1,
                                             rko->rko_u.offset_commit.reason,
                                             0);
                rko = NULL; /* rko now owned by request */
                break;

        case RD_KAFKA_OP_COORD_QUERY:
                rd_kafka_cgrp_coord_query(rkcg,
                                          rko->rko_err ?
                                          rd_kafka_err2str(rko->
                                                           rko_err):
                                          "from op");
                break;

        case RD_KAFKA_OP_SUBSCRIBE:
                rd_kafka_app_polled(rk);

                /* New atomic subscription (may be NULL) */
                err = rd_kafka_cgrp_subscribe(
                        rkcg, rko->rko_u.subscribe.topics);

                if (!err) /* now owned by rkcg */
                        rko->rko_u.subscribe.topics = NULL;

                rd_kafka_op_reply(rko, err);
                rko = NULL;
                break;

        case RD_KAFKA_OP_ASSIGN:
                /* New atomic assignment (payload != NULL),
                 * or unassignment (payload == NULL) */
                err = 0;
                if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_TERMINATE) {
                        /* Treat all assignments as unassign
                         * when terminating. */
                        rd_kafka_cgrp_unassign(rkcg);
                        if (rko->rko_u.assign.partitions)
                                err = RD_KAFKA_RESP_ERR__DESTROY;
                } else {
                        err = rd_kafka_cgrp_assign(rkcg,
                                                   rko->rko_u.assign.partitions);
                }
                rd_kafka_op_reply(rko, err);
                rko = NULL;
                break;

        case RD_KAFKA_OP_GET_SUBSCRIPTION:
                if (rkcg->rkcg_subscription)
                        rko->rko_u.subscribe.topics =
                                rd_kafka_topic_partition_list_copy(
                                        rkcg->rkcg_subscription);
                rd_kafka_op_reply(rko, 0);
                rko = NULL;
                break;

        case RD_KAFKA_OP_GET_ASSIGNMENT:
                if (rkcg->rkcg_assignment)
                        rko->rko_u.assign.partitions =
                                rd_kafka_topic_partition_list_copy(
                                        rkcg->rkcg_assignment);

                rd_kafka_op_reply(rko, 0);
                rko = NULL;
                break;

        case RD_KAFKA_OP_TERMINATE:
                rd_kafka_cgrp_terminate0(rkcg, rko);
                rko = NULL; /* terminate0() takes ownership */
                break;

        default:
                rd_kafka_assert(rkcg->rkcg_rk, !*"unknown type");
                break;
        }

        if (rko)
                rd_kafka_op_destroy(rko);

        return RD_KAFKA_OP_RES_HANDLED;
}


/**
 * @returns true if the session timeout has expired (due to no successful
 *          Heartbeats in session.timeout.ms) and triggers a rebalance.
 */
static rd_bool_t
rd_kafka_cgrp_session_timeout_check (rd_kafka_cgrp_t *rkcg, rd_ts_t now) {
        rd_ts_t delta;
        char buf[256];

        if (unlikely(!rkcg->rkcg_ts_session_timeout))
                return rd_true; /* Session has expired */

        delta = now - rkcg->rkcg_ts_session_timeout;
        if (likely(delta < 0))
                return rd_false;

        delta += rkcg->rkcg_rk->rk_conf.group_session_timeout_ms * 1000;

        rd_snprintf(buf, sizeof(buf),
                    "Consumer group session timed out (in join-state %s) after "
                    "%"PRId64" ms without a successful response from the "
                    "group coordinator (broker %"PRId32", last error was %s)",
                    rd_kafka_cgrp_join_state_names[rkcg->rkcg_join_state],
                    delta/1000, rkcg->rkcg_coord_id,
                    rd_kafka_err2str(rkcg->rkcg_last_heartbeat_err));

        rkcg->rkcg_last_heartbeat_err = RD_KAFKA_RESP_ERR_NO_ERROR;

        rd_kafka_log(rkcg->rkcg_rk, LOG_WARNING, "SESSTMOUT",
                     "%s: revoking assignment and rejoining group", buf);

        /* Prevent further rebalances */
        rkcg->rkcg_ts_session_timeout = 0;

        /* Timing out invalidates the member id, reset it
         * now to avoid an ERR_UNKNOWN_MEMBER_ID on the next join. */
        rd_kafka_cgrp_set_member_id(rkcg, "");

        /* Revoke and rebalance */
        rd_kafka_cgrp_rebalance(rkcg, buf);

        return rd_true;
}


/**
 * Client group's join state handling
 */
static void rd_kafka_cgrp_join_state_serve (rd_kafka_cgrp_t *rkcg) {
        rd_ts_t now = rd_clock();

        if (unlikely(rd_kafka_fatal_error_code(rkcg->rkcg_rk)))
                return;

        switch (rkcg->rkcg_join_state)
        {
        case RD_KAFKA_CGRP_JOIN_STATE_INIT:
                /* If we have a subscription start the join process. */
                if (!rkcg->rkcg_subscription)
                        break;

                if (rd_interval_immediate(&rkcg->rkcg_join_intvl,
					  1000*1000, now) > 0)
                        rd_kafka_cgrp_join(rkcg);
                break;

        case RD_KAFKA_CGRP_JOIN_STATE_WAIT_JOIN:
        case RD_KAFKA_CGRP_JOIN_STATE_WAIT_METADATA:
        case RD_KAFKA_CGRP_JOIN_STATE_WAIT_SYNC:
        case RD_KAFKA_CGRP_JOIN_STATE_WAIT_UNASSIGN:
		break;

        case RD_KAFKA_CGRP_JOIN_STATE_ASSIGNED:
	case RD_KAFKA_CGRP_JOIN_STATE_STARTED:
                if (rd_kafka_cgrp_session_timeout_check(rkcg, now))
                        return;
                /* FALLTHRU */
        case RD_KAFKA_CGRP_JOIN_STATE_WAIT_REVOKE_REBALANCE_CB:
        case RD_KAFKA_CGRP_JOIN_STATE_WAIT_ASSIGN_REBALANCE_CB:
                if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_SUBSCRIPTION &&
                    rd_interval(&rkcg->rkcg_heartbeat_intvl,
                                rkcg->rkcg_rk->rk_conf.
                                group_heartbeat_intvl_ms * 1000, now) > 0)
                        rd_kafka_cgrp_heartbeat(rkcg);
                break;
        }

}
/**
 * Client group handling.
 * Called from main thread to serve the operational aspects of a cgrp.
 */
void rd_kafka_cgrp_serve (rd_kafka_cgrp_t *rkcg) {
	rd_kafka_broker_t *rkb = rkcg->rkcg_coord;
	int rkb_state = RD_KAFKA_BROKER_STATE_INIT;
        rd_ts_t now;

	if (rkb) {
		rd_kafka_broker_lock(rkb);
		rkb_state = rkb->rkb_state;
		rd_kafka_broker_unlock(rkb);

		/* Go back to querying state if we lost the current coordinator
		 * connection. */
		if (rkb_state < RD_KAFKA_BROKER_STATE_UP &&
		    rkcg->rkcg_state == RD_KAFKA_CGRP_STATE_UP)
			rd_kafka_cgrp_set_state(rkcg,
						RD_KAFKA_CGRP_STATE_QUERY_COORD);
	}

        now = rd_clock();

	/* Check for cgrp termination */
	if (unlikely(rd_kafka_cgrp_try_terminate(rkcg))) {
                rd_kafka_cgrp_terminated(rkcg);
                return; /* cgrp terminated */
        }

        /* Bail out if we're terminating. */
        if (unlikely(rd_kafka_terminating(rkcg->rkcg_rk)))
                return;

 retry:
        switch (rkcg->rkcg_state)
        {
        case RD_KAFKA_CGRP_STATE_TERM:
                break;

        case RD_KAFKA_CGRP_STATE_INIT:
                rd_kafka_cgrp_set_state(rkcg, RD_KAFKA_CGRP_STATE_QUERY_COORD);
                /* FALLTHRU */

        case RD_KAFKA_CGRP_STATE_QUERY_COORD:
                /* Query for coordinator. */
                if (rd_interval_immediate(&rkcg->rkcg_coord_query_intvl,
					  500*1000, now) > 0)
                        rd_kafka_cgrp_coord_query(rkcg,
                                                  "intervaled in "
                                                  "state query-coord");
                break;

        case RD_KAFKA_CGRP_STATE_WAIT_COORD:
                /* Waiting for FindCoordinator response */
                break;

        case RD_KAFKA_CGRP_STATE_WAIT_BROKER:
                /* See if the group should be reassigned to another broker. */
                if (rd_kafka_cgrp_coord_update(rkcg, rkcg->rkcg_coord_id))
                        goto retry; /* Coordinator changed, retry state-machine
                                     * to speed up next transition. */

                /* Coordinator query */
                if (rd_interval(&rkcg->rkcg_coord_query_intvl,
				1000*1000, now) > 0)
                        rd_kafka_cgrp_coord_query(rkcg,
                                                  "intervaled in "
                                                  "state wait-broker");
                break;

        case RD_KAFKA_CGRP_STATE_WAIT_BROKER_TRANSPORT:
                /* Waiting for broker transport to come up.
		 * Also make sure broker supports groups. */
                if (rkb_state < RD_KAFKA_BROKER_STATE_UP || !rkb ||
		    !rd_kafka_broker_supports(
			    rkb, RD_KAFKA_FEATURE_BROKER_GROUP_COORD)) {
			/* Coordinator query */
			if (rd_interval(&rkcg->rkcg_coord_query_intvl,
					1000*1000, now) > 0)
				rd_kafka_cgrp_coord_query(
					rkcg,
					"intervaled in state "
					"wait-broker-transport");

                } else {
                        rd_kafka_cgrp_set_state(rkcg, RD_KAFKA_CGRP_STATE_UP);

                        /* Serve join state to trigger (re)join */
                        rd_kafka_cgrp_join_state_serve(rkcg);

                        /* Start fetching if we have an assignment. */
                        if (rkcg->rkcg_assignment &&
			    RD_KAFKA_CGRP_CAN_FETCH_START(rkcg))
                                rd_kafka_cgrp_partitions_fetch_start(
                                        rkcg, rkcg->rkcg_assignment, 0);
                }
                break;

        case RD_KAFKA_CGRP_STATE_UP:
		/* Move any ops awaiting the coordinator to the ops queue
		 * for reprocessing. */
		rd_kafka_q_concat(rkcg->rkcg_ops, rkcg->rkcg_wait_coord_q);

                /* Relaxed coordinator queries. */
                if (rd_interval(&rkcg->rkcg_coord_query_intvl,
                                rkcg->rkcg_rk->rk_conf.
                                coord_query_intvl_ms * 1000, now) > 0)
                        rd_kafka_cgrp_coord_query(rkcg,
                                                  "intervaled in state up");

                rd_kafka_cgrp_join_state_serve(rkcg);
                break;

        }

        if (unlikely(rkcg->rkcg_state != RD_KAFKA_CGRP_STATE_UP &&
                     rd_interval(&rkcg->rkcg_timeout_scan_intvl,
                                 1000*1000, now) > 0))
                rd_kafka_cgrp_timeout_scan(rkcg, now);
}





/**
 * Send an op to a cgrp.
 *
 * Locality: any thread
 */
void rd_kafka_cgrp_op (rd_kafka_cgrp_t *rkcg, rd_kafka_toppar_t *rktp,
                       rd_kafka_replyq_t replyq, rd_kafka_op_type_t type,
                       rd_kafka_resp_err_t err) {
        rd_kafka_op_t *rko;

        rko = rd_kafka_op_new(type);
        rko->rko_err = err;
	rko->rko_replyq = replyq;

	if (rktp)
                rko->rko_rktp = rd_kafka_toppar_keep(rktp);

        rd_kafka_q_enq(rkcg->rkcg_ops, rko);
}







void rd_kafka_cgrp_set_member_id (rd_kafka_cgrp_t *rkcg, const char *member_id){
        if (rkcg->rkcg_member_id && member_id &&
            !rd_kafkap_str_cmp_str(rkcg->rkcg_member_id, member_id))
                return; /* No change */

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "MEMBERID",
                     "Group \"%.*s\": updating member id \"%s\" -> \"%s\"",
                     RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                     rkcg->rkcg_member_id ?
                     rkcg->rkcg_member_id->str : "(not-set)",
                     member_id ? member_id : "(not-set)");

        if (rkcg->rkcg_member_id) {
                rd_kafkap_str_destroy(rkcg->rkcg_member_id);
                rkcg->rkcg_member_id = NULL;
        }

        if (member_id)
                rkcg->rkcg_member_id = rd_kafkap_str_new(member_id, -1);
}




/**
 * @brief Check if the latest metadata affects the current subscription:
 * - matched topic added
 * - matched topic removed
 * - matched topic's partition count change
 *
 * @locks none
 * @locality rdkafka main thread
 */
void rd_kafka_cgrp_metadata_update_check (rd_kafka_cgrp_t *rkcg, int do_join) {
        rd_list_t *tinfos;

        rd_kafka_assert(NULL, thrd_is_current(rkcg->rkcg_rk->rk_thread));

        if (!rkcg->rkcg_subscription || rkcg->rkcg_subscription->cnt == 0)
                return;

        /*
         * Create a list of the topics in metadata that matches our subscription
         */
        tinfos = rd_list_new(rkcg->rkcg_subscription->cnt,
                             (void *)rd_kafka_topic_info_destroy);

        if (rkcg->rkcg_flags & RD_KAFKA_CGRP_F_WILDCARD_SUBSCRIPTION)
                rd_kafka_metadata_topic_match(rkcg->rkcg_rk,
                                              tinfos, rkcg->rkcg_subscription);
        else
                rd_kafka_metadata_topic_filter(rkcg->rkcg_rk,
                                               tinfos,
                                               rkcg->rkcg_subscription);


        /*
         * Update (takes ownership of \c tinfos)
         */
        if (rd_kafka_cgrp_update_subscribed_topics(rkcg, tinfos) && do_join) {
                /* List of subscribed topics changed, trigger rejoin. */
                rd_kafka_dbg(rkcg->rkcg_rk,
                             CGRP|RD_KAFKA_DBG_METADATA|RD_KAFKA_DBG_CONSUMER,
                             "REJOIN",
                             "Group \"%.*s\": "
                             "subscription updated from metadata change: "
                             "rejoining group",
                             RD_KAFKAP_STR_PR(rkcg->rkcg_group_id));
                rd_kafka_cgrp_rejoin(rkcg);
        }
}


void rd_kafka_cgrp_handle_SyncGroup (rd_kafka_cgrp_t *rkcg,
				     rd_kafka_broker_t *rkb,
                                     rd_kafka_resp_err_t err,
                                     const rd_kafkap_bytes_t *member_state) {
        rd_kafka_buf_t *rkbuf = NULL;
        rd_kafka_topic_partition_list_t *assignment = NULL;
        const int log_decode_errors = LOG_ERR;
        int16_t Version;
        int32_t TopicCnt;
        rd_kafkap_bytes_t UserData;

	/* Dont handle new assignments when terminating */
	if (!err && rkcg->rkcg_flags & RD_KAFKA_CGRP_F_TERMINATE)
		err = RD_KAFKA_RESP_ERR__DESTROY;

        if (err)
                goto err;


	if (RD_KAFKAP_BYTES_LEN(member_state) == 0) {
		/* Empty assignment. */
		assignment = rd_kafka_topic_partition_list_new(0);
		memset(&UserData, 0, sizeof(UserData));
		goto done;
	}

        /* Parse assignment from MemberState */
        rkbuf = rd_kafka_buf_new_shadow(member_state->data,
                                        RD_KAFKAP_BYTES_LEN(member_state),
                                        NULL);
	/* Protocol parser needs a broker handle to log errors on. */
	if (rkb) {
		rkbuf->rkbuf_rkb = rkb;
		rd_kafka_broker_keep(rkb);
	} else
		rkbuf->rkbuf_rkb = rd_kafka_broker_internal(rkcg->rkcg_rk);

        rd_kafka_buf_read_i16(rkbuf, &Version);
        rd_kafka_buf_read_i32(rkbuf, &TopicCnt);

        if (TopicCnt > 10000) {
                err = RD_KAFKA_RESP_ERR__BAD_MSG;
                goto err;
        }

        assignment = rd_kafka_topic_partition_list_new(TopicCnt);
        while (TopicCnt-- > 0) {
                rd_kafkap_str_t Topic;
                int32_t PartCnt;
                rd_kafka_buf_read_str(rkbuf, &Topic);
                rd_kafka_buf_read_i32(rkbuf, &PartCnt);
                while (PartCnt-- > 0) {
                        int32_t Partition;
			char *topic_name;
			RD_KAFKAP_STR_DUPA(&topic_name, &Topic);
                        rd_kafka_buf_read_i32(rkbuf, &Partition);

                        rd_kafka_topic_partition_list_add(
                                assignment, topic_name, Partition);
                }
        }

        rd_kafka_buf_read_bytes(rkbuf, &UserData);

 done:
        rd_kafka_cgrp_update_session_timeout(rkcg, rd_true/*reset timeout*/);

        /* Set the new assignment */
	rd_kafka_cgrp_handle_assignment(rkcg, assignment);

        rd_kafka_topic_partition_list_destroy(assignment);

        if (rkbuf)
                rd_kafka_buf_destroy(rkbuf);

        return;

 err_parse:
        err = rkbuf->rkbuf_err;

 err:
        if (rkbuf)
                rd_kafka_buf_destroy(rkbuf);

        if (assignment)
                rd_kafka_topic_partition_list_destroy(assignment);

        rd_kafka_dbg(rkcg->rkcg_rk, CGRP, "GRPSYNC",
                     "Group \"%s\": synchronization failed: %s: rejoining",
                     rkcg->rkcg_group_id->str, rd_kafka_err2str(err));

        if (err == RD_KAFKA_RESP_ERR_FENCED_INSTANCE_ID)
                rd_kafka_set_fatal_error(rkcg->rkcg_rk, err,
                                         "Fatal consumer error: %s",
                                         rd_kafka_err2str(err));

        rd_kafka_cgrp_set_join_state(rkcg, RD_KAFKA_CGRP_JOIN_STATE_INIT);
}




rd_kafka_consumer_group_metadata_t *
rd_kafka_consumer_group_metadata_new (const char *group_id) {
        rd_kafka_consumer_group_metadata_t *cgmetadata;

        if (!group_id)
                return NULL;

        cgmetadata = rd_calloc(1, sizeof(*cgmetadata));
        cgmetadata->group_id = rd_strdup(group_id);

        return cgmetadata;
}

rd_kafka_consumer_group_metadata_t *
rd_kafka_consumer_group_metadata (rd_kafka_t *rk) {
        if (rk->rk_type != RD_KAFKA_CONSUMER ||
            !rk->rk_conf.group_id_str)
                return NULL;

        return rd_kafka_consumer_group_metadata_new(rk->rk_conf.group_id_str);
}

void
rd_kafka_consumer_group_metadata_destroy (
        rd_kafka_consumer_group_metadata_t *cgmetadata) {
        rd_free(cgmetadata->group_id);
        rd_free(cgmetadata);
}

rd_kafka_consumer_group_metadata_t *
rd_kafka_consumer_group_metadata_dup (
        const rd_kafka_consumer_group_metadata_t *cgmetadata) {
        rd_kafka_consumer_group_metadata_t *ret;

        ret = rd_calloc(1, sizeof(*cgmetadata));
        ret->group_id = rd_strdup(cgmetadata->group_id);

        return ret;
}


/*
 * Consumer group metadata serialization format v1:
 *  "CGMDv1:"<group_id>"\0"
 * Where <group_id> is the group_id string.
 */
static const char rd_kafka_consumer_group_metadata_magic[7] = "CGMDv1:";

rd_kafka_error_t *rd_kafka_consumer_group_metadata_write (
        const rd_kafka_consumer_group_metadata_t *cgmd,
        void **bufferp, size_t *sizep) {
        char *buf;
        size_t size;
        size_t of = 0;
        size_t magic_len = sizeof(rd_kafka_consumer_group_metadata_magic);
        size_t groupid_len = strlen(cgmd->group_id) + 1;

        size = magic_len + groupid_len;
        buf = rd_malloc(size);

        memcpy(buf, rd_kafka_consumer_group_metadata_magic, magic_len);
        of += magic_len;

        memcpy(buf+of, cgmd->group_id, groupid_len);

        *bufferp = buf;
        *sizep = size;

        return NULL;
}


rd_kafka_error_t *rd_kafka_consumer_group_metadata_read (
        rd_kafka_consumer_group_metadata_t **cgmdp,
        const void *buffer, size_t size) {
        size_t magic_len = sizeof(rd_kafka_consumer_group_metadata_magic);
        const char *buf = (const char *)buffer;
        const char *end = buf + size;
        const char *group_id;
        const char *s;

        if (size < magic_len + 1)
                return rd_kafka_error_new(RD_KAFKA_RESP_ERR__BAD_MSG,
                                          "Input buffer is too short");

        if (memcmp(buffer, rd_kafka_consumer_group_metadata_magic, magic_len))
                return rd_kafka_error_new(
                        RD_KAFKA_RESP_ERR__BAD_MSG,
                        "Input buffer is not a serialized "
                        "consumer group metadata object");

        group_id = buf + magic_len;

        /* Check that group_id is safe */
        for (s = group_id ; s < end - 1 ; s++) {
                if (!isprint((int)*s))
                        return rd_kafka_error_new(
                                RD_KAFKA_RESP_ERR__BAD_MSG,
                                "Input buffer group id is not safe");
        }

        if (*s != '\0')
                return rd_kafka_error_new(
                        RD_KAFKA_RESP_ERR__BAD_MSG,
                        "Input buffer has invalid stop byte");

        /* We now know that group_id is printable-safe and is nul-terminated. */
        *cgmdp = rd_kafka_consumer_group_metadata_new(group_id);

        return NULL;
}


static int unittest_consumer_group_metadata (void) {
        rd_kafka_consumer_group_metadata_t *cgmd;
        const char *group_ids[] = {
                "mY. group id:.",
                "0",
                "2222222222222222222222221111111111111111111111111111112222",
                "",
                NULL,
        };
        int i;

        for (i = 0 ; group_ids[i] ; i++) {
                const char *group_id = group_ids[i];
                void *buffer, *buffer2;
                size_t size, size2;
                rd_kafka_error_t *error;

                cgmd = rd_kafka_consumer_group_metadata_new(group_id);
                RD_UT_ASSERT(cgmd != NULL, "failed to create metadata");

                error = rd_kafka_consumer_group_metadata_write(cgmd, &buffer,
                                                               &size);
                RD_UT_ASSERT(!error, "metadata_write failed: %s",
                             rd_kafka_error_string(error));

                rd_kafka_consumer_group_metadata_destroy(cgmd);

                cgmd = NULL;
                error = rd_kafka_consumer_group_metadata_read(&cgmd, buffer,
                                                              size);
                RD_UT_ASSERT(!error, "metadata_read failed: %s",
                             rd_kafka_error_string(error));

                /* Serialize again and compare buffers */
                error = rd_kafka_consumer_group_metadata_write(cgmd, &buffer2,
                                                               &size2);
                RD_UT_ASSERT(!error, "metadata_write failed: %s",
                             rd_kafka_error_string(error));

                RD_UT_ASSERT(size == size2 && !memcmp(buffer, buffer2, size),
                             "metadata_read/write size or content mismatch: "
                             "size %"PRIusz", size2 %"PRIusz,
                             size, size2);

                rd_kafka_consumer_group_metadata_destroy(cgmd);
                rd_free(buffer);
                rd_free(buffer2);
        }

        RD_UT_PASS();
}


/**
 * @brief Consumer group unit tests
 */
int unittest_cgrp (void) {
        int fails = 0;

        fails += unittest_consumer_group_metadata();

        return fails;
}
