/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2026, Confluent Inc.
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
#ifndef _RDKAFKA_SHARE_ACKNOWLEDGEMENT_H_
#define _RDKAFKA_SHARE_ACKNOWLEDGEMENT_H_

/* Forward declarations */
typedef struct rd_kafka_op_s rd_kafka_op_t;
typedef struct rd_kafka_broker_s rd_kafka_broker_t;
typedef struct rd_kafka_cgrp_s rd_kafka_cgrp_t;

typedef enum rd_kafka_internal_ShareAcknowledgement_type_s {
        RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED =
            -1, /* Acquired records, not acknowledged yet */
        RD_KAFKA_SHARE_INTERNAL_ACK_GAP     = 0, /* gap */
        RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT  = 1, /* accept */
        RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE = 2, /* release */
        RD_KAFKA_SHARE_INTERNAL_ACK_REJECT  = 3  /* reject */
} rd_kafka_share_internal_acknowledgement_type;

/**
 * @brief Acknowledgement batch entry for a contiguous offset range.
 *
 * Tracks acknowledgement status for each offset in the range.
 * Used for building ShareAcknowledge requests.
 *
 * The size field always represents the number of offsets in the range
 * (end_offset - start_offset + 1).
 *
 * The types_cnt field represents the actual size of the types array:
 *   - For inflight tracking: types_cnt == size (one type per offset)
 *   - For collated batches: types_cnt == 1 (single consolidated type)
 */
/**
 * TODO KIP-932: Check naming.
 */
typedef struct rd_kafka_share_ack_batch_entry_s {
        int64_t start_offset;   /**< First offset in range */
        int64_t end_offset;     /**< Last offset in range (inclusive) */
        int64_t size;           /**< Number of offsets (end - start + 1) */
        int32_t types_cnt;      /**< Number of elements in types array */
        int16_t delivery_count; /**< From AcquiredRecords DeliveryCount */
        rd_kafka_share_internal_acknowledgement_type
            *types; /**< Array of ack types */
} rd_kafka_share_ack_batch_entry_t;

/**
 * @brief Per topic-partition inflight acknowledgement batches.
 *
 * Tracks all acquired records for a topic-partition that are
 * pending acknowledgement from the application.
 *
 * The rktpar field contains topic, partition, and in its _private:
 *   - rktp (toppar reference, refcount held)
 *   - topic_id
 *
 * response_leader_id is the broker id from which the records were
 * acquired and is used to send the acknowledgement back to the same
 * broker. It may differ from the current leader when sending
 * acknowledgements.
 */
/**
 * TODO KIP-932: Check naming.
 */
typedef struct rd_kafka_share_ack_batches_s {
        rd_kafka_topic_partition_t
            *rktpar;                /**< Topic-partition with rktp ref */
        int32_t response_leader_id; /**< Leader broker id when records
                                     *   were acquired */
        int64_t response_acquired_offsets_count; /**< Total acquired messages */
        rd_list_t entries; /**< rd_kafka_share_ack_batch_entry_t*,
                            *   sorted by start_offset */
} rd_kafka_share_ack_batches_t;

/** Allocate and initialize a share ack batch entry (offset range + types
 * array). */
rd_kafka_share_ack_batch_entry_t *
rd_kafka_share_ack_batch_entry_new(int64_t start_offset,
                                   int64_t end_offset,
                                   int32_t types_cnt,
                                   int16_t delivery_count);
/** Destroy a share ack batch entry (frees types array and entry). */
void rd_kafka_share_ack_batch_entry_destroy(
    rd_kafka_share_ack_batch_entry_t *entry);

/** Deep copy a share ack batch entry. */
rd_kafka_share_ack_batch_entry_t *rd_kafka_share_ack_batch_entry_copy(
    const rd_kafka_share_ack_batch_entry_t *src);

/** Allocate and initialize a share ack batches.
 *  Takes ownership of \p rktpar.
 *  TODO KIP-932: We should keep a copy of the rktpar instead of taking
 * ownership. */
rd_kafka_share_ack_batches_t *
rd_kafka_share_ack_batches_new(rd_kafka_topic_partition_t *rktpar,
                               int32_t response_leader_id,
                               int64_t response_acquired_offsets_count);

/** Allocate an empty share ack batches (all fields zeroed). */
rd_kafka_share_ack_batches_t *rd_kafka_share_ack_batches_new_empty(void);

/** void* wrapper for rd_kafka_share_ack_batches_destroy.
 *  Suitable as rd_list_t / rd_map_t value destructor. */
void rd_kafka_share_ack_batches_destroy_free(void *ptr);

/** Destroy share ack batches (frees entries, rktpar, and struct). */
void rd_kafka_share_ack_batches_destroy(rd_kafka_share_ack_batches_t *batches);

/** Deep copy a share ack batches (copies rktpar and all entries). */
rd_kafka_share_ack_batches_t *
rd_kafka_share_ack_batches_copy(const rd_kafka_share_ack_batches_t *src);

/** void* wrapper for rd_kafka_share_ack_batches_copy.
 *  Suitable as rd_list_copy_to callback. */
void *rd_kafka_share_ack_batches_copy_void(const void *elem, void *opaque);

/**
 * @brief Transfer inflight acks from response RKO into rkshare's inflight map.
 */
void rd_kafka_share_build_inflight_acks_map(rd_kafka_share_t *rkshare,
                                            rd_kafka_op_t *response_rko);


/**
 * @brief Implicit ack: convert all ACQUIRED types to ACCEPT in inflight map.
 */
void rd_kafka_share_ack_all(rd_kafka_share_t *rkshare);

rd_kafka_share_ack_batches_t *
rd_kafka_share_find_ack_batch(rd_list_t *ack_list,
                              const rd_kafka_topic_partition_t *rktpar);

/**
 * @brief Find an existing ack batch by topic id and partition.
 *
 * TODO KIP-932: Merge with rd_kafka_share_find_ack_batch and use
 * binary search once ack_list is kept sorted.
 */
rd_kafka_share_ack_batches_t *
rd_kafka_share_find_ack_batch_by_id(rd_list_t *ack_list,
                                    rd_kafka_Uuid_t topic_id,
                                    int32_t partition);

/**
 * @brief Reply to a SHARE_FETCH op, propagating any top-level error
 *        to each batch in ack_details.
 *
 * On top-level error (err != 0), sets batch->rktpar->err = err on
 * each batch in rko->rko_u.share_fetch.ack_details since the
 * partition-level data was not parsed. On success (err == 0), the
 * per-partition errors have already been set by the response parser
 * and ack_details is left untouched. Always calls rd_kafka_op_reply
 * at the end. Safe to use as a drop-in replacement for
 * rd_kafka_op_reply on SHARE_FETCH ops.
 */
void rd_kafka_share_fetch_op_reply_and_update_ack_details_with_err(
    rd_kafka_op_t *rko,
    rd_kafka_resp_err_t err);

void rd_kafka_share_segregate_acks_by_leader(rd_kafka_t *rk,
                                             rd_list_t *ack_batches);

/**
 * @brief Segregate sync ack batches by partition leader into each
 *        broker's pending_commit_sync list.
 *
 * @locality main thread
 */
void rd_kafka_share_segregate_sync_acks_by_leader(rd_kafka_t *rk,
                                                  rd_kafka_cgrp_t *rkcg,
                                                  rd_list_t *ack_batches,
                                                  rd_ts_t abs_timeout);

/**
 * @brief Extract acknowledged (non-ACQUIRED) records from inflight map.
 *
 * Non-ACQUIRED offsets are collated into ack_details for sending.
 * ACQUIRED offsets remain in the map. Empty entries are removed.
 *
 * @returns Allocated list or NULL if nothing to send. Caller must destroy.
 */
rd_list_t *rd_kafka_share_build_ack_details(rd_kafka_share_t *rkshare);

/**
 * @brief Check if share consumer uses implicit acknowledgement mode.
 */
rd_bool_t
rd_kafka_share_acknowledgement_mode_is_implicit(rd_kafka_share_t *rkshare);

/**
 * @brief Check if share consumer uses explicit acknowledgement mode.
 */
rd_bool_t
rd_kafka_share_acknowledgement_mode_is_explicit(rd_kafka_share_t *rkshare);

/**
 * @brief In implicit mode, acknowledge all acquired records as ACCEPT.
 */
void rd_kafka_share_acknowledge_all_if_implicit(rd_kafka_share_t *rkshare);

/**
 * @brief In explicit mode, ensure all acquired records have been acknowledged.
 * @returns Error if there are unacknowledged records, NULL otherwise.
 */
rd_kafka_error_t *
rd_kafka_share_ensure_all_acknowledged_if_explicit(rd_kafka_share_t *rkshare);

/**
 * @brief Comparator for sorting/checking entries by start_offset.
 *
 * Used with rd_list_is_sorted().
 */
int rd_kafka_share_ack_entries_sort_cmp_ptr(const void *_a, const void *_b);

/**
 * @struct rd_kafka_share_partition_offsets_s
 * @brief Partition with set of acknowledged offsets.
 */
struct rd_kafka_share_partition_offsets_s {
        rd_kafka_topic_partition_t
            *partition;    /**< Topic partition information */
        size_t cnt;        /**< Number of offsets in array */
        int64_t offsets[]; /**< Flexible array of acknowledged offsets */
};

/**
 * @struct rd_kafka_share_partition_offsets_list_s
 * @brief List of share partition offsets for callback.
 */
struct rd_kafka_share_partition_offsets_list_s {
        size_t cnt; /**< Number of partitions */
        rd_kafka_share_partition_offsets_t *elems[]; /**< Flexible array of
                                                          pointers to partition
                                                          offsets */
};


/**
 * @brief Destroy a partition offsets list.
 *
 * Frees all elements and the list itself.
 *
 * @param list List to destroy (may be NULL).
 */
void rd_kafka_share_partition_offsets_list_destroy(
    rd_kafka_share_partition_offsets_list_t *list);

/**
 * @brief Build partition offsets list for a single partition.
 *
 * Creates an rd_kafka_share_partition_offsets_list_t with exactly one element
 * for the given batches. Used for per-partition callback invocation.
 *
 * @param batches Single partition's ack batches.
 * @returns Allocated list with one element, or NULL if no offsets.
 *          Caller must destroy with
 *          rd_kafka_share_partition_offsets_list_destroy().
 */
rd_kafka_share_partition_offsets_list_t *
rd_kafka_share_build_partition_offsets_list(
    rd_kafka_share_ack_batches_t *batches);

/**
 * @brief Enqueue share acknowledgement callback for a single partition.
 *
 * Creates and enqueues a callback op for the given partition with the
 * specified error code. Used for both per-partition acknowledgement results
 * and top-level errors.
 *
 * @param rk Kafka handle.
 * @param batches The ack batches for this partition (contains offsets).
 * @param err Error code to report in callback.
 */
void rd_kafka_share_enqueue_ack_commit_cb_op(
    rd_kafka_t *rk,
    rd_kafka_share_ack_batches_t *batches,
    rd_kafka_resp_err_t err);


/**
 * @brief Enqueue acknowledgement callbacks to application for each partition.
 *
 * Iterates through each partition in ack_details and enqueues one callback
 * operation (RD_KAFKA_OP_SHARE_ACK_COMMIT_CB_EXECUTE) per partition to the
 * application's reply queue. Each operation contains:
 * - The partition's acknowledged offsets
 * - Per-partition error code from batch->rktpar->err
 *
 * The application's runtime acknowledgement callback (set via
 * rd_kafka_share_set_acknowledgement_commit_cb()) is invoked once per
 * partition when the app calls rd_kafka_consumer_poll() or
 * rd_kafka_queue_poll().
 *
 * @param rk Kafka handle.
 * @param ack_details List of rd_kafka_share_ack_batches_t* with acknowledgement
 *                    results and per-partition error codes.
 */
void rd_kafka_share_dispatch_ack_callbacks(rd_kafka_t *rk,
                                           rd_list_t *ack_details);


/**
 * @brief Clear cached share-ack state on a broker that is being
 *        decommissioned.
 *
 * For each pending async ack batch on the broker, stamps
 * SHARE_SESSION_NOT_FOUND on the batch and fires the share-ack
 * callback so the application sees the failure. For sync acks
 * (pending_commit_sync), stamps the same err and applies it to the
 * in-flight commit_sync request (decrements awaiting count, completes
 * sync if last broker outstanding).
 *
 * @locality main thread.
 */
void rd_kafka_share_acks_clear_during_broker_decommission(
    rd_kafka_t *rk,
    rd_kafka_broker_t *rkb);


/**
 * @brief Apply a broker's commit_sync result: copy each batch's
 *        per-partition err onto the corresponding entry in
 *        rkcg_commit_sync_request.results, decrement the count of
 *        brokers still awaiting reply, and complete the commit_sync
 *        if this was the last broker outstanding.
 *
 * @locality main thread.
 */
void rd_kafka_share_commit_sync_apply_result(rd_kafka_t *rk,
                                             rd_kafka_cgrp_t *rkcg,
                                             rd_list_t *ack_batches);

/**
 * @brief Check if all broker results are in and send response if done.
 *
 * @locality main thread.
 */
void rd_kafka_share_commit_sync_maybe_complete(rd_kafka_t *rk,
                                               rd_kafka_cgrp_t *rkcg);

/**
 * @brief Send commit_sync response to the app thread and clear state.
 *
 * @locality main thread.
 */
void rd_kafka_share_commit_sync_send_response(rd_kafka_cgrp_t *rkcg);


#endif /* _RDKAFKA_SHARE_ACKNOWLEDGEMENT_H_ */
