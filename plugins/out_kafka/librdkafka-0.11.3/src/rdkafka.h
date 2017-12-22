/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2013 Magnus Edenhill
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
 * @file rdkafka.h
 * @brief Apache Kafka C/C++ consumer and producer client library.
 *
 * rdkafka.h contains the public API for librdkafka.
 * The API is documented in this file as comments prefixing the function, type,
 * enum, define, etc.
 *
 * @sa For the C++ interface see rdkafkacpp.h
 *
 * @tableofcontents
 */


/* @cond NO_DOC */
#pragma once

#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#if 0
} /* Restore indent */
#endif
#endif

#ifdef _MSC_VER
#include <basetsd.h>
#ifndef WIN32_MEAN_AND_LEAN
#define WIN32_MEAN_AND_LEAN
#endif
#include <Winsock2.h>  /* for sockaddr, .. */
typedef SSIZE_T ssize_t;
#define RD_UNUSED
#define RD_INLINE __inline
#define RD_DEPRECATED __declspec(deprecated)
#undef RD_EXPORT
#ifdef LIBRDKAFKA_STATICLIB
#define RD_EXPORT
#else
#ifdef LIBRDKAFKA_EXPORTS
#define RD_EXPORT __declspec(dllexport)
#else
#define RD_EXPORT __declspec(dllimport)
#endif
#ifndef LIBRDKAFKA_TYPECHECKS
#define LIBRDKAFKA_TYPECHECKS 0
#endif
#endif

#else
#include <sys/socket.h> /* for sockaddr, .. */

#define RD_UNUSED __attribute__((unused))
#define RD_INLINE inline
#define RD_EXPORT
#define RD_DEPRECATED __attribute__((deprecated))

#ifndef LIBRDKAFKA_TYPECHECKS
#define LIBRDKAFKA_TYPECHECKS 1
#endif
#endif


/**
 * @brief Type-checking macros
 * Compile-time checking that \p ARG is of type \p TYPE.
 * @returns \p RET
 */
#if LIBRDKAFKA_TYPECHECKS
#define _LRK_TYPECHECK(RET,TYPE,ARG)                    \
        ({ if (0) { TYPE __t RD_UNUSED = (ARG); } RET; })

#define _LRK_TYPECHECK2(RET,TYPE,ARG,TYPE2,ARG2)        \
        ({                                              \
                if (0) {                                \
                        TYPE __t RD_UNUSED = (ARG);     \
                        TYPE2 __t2 RD_UNUSED = (ARG2);  \
                }                                       \
                RET; })
#else
#define _LRK_TYPECHECK(RET,TYPE,ARG)  (RET)
#define _LRK_TYPECHECK2(RET,TYPE,ARG,TYPE2,ARG2) (RET)
#endif

/* @endcond */


/**
 * @name librdkafka version
 * @{
 *
 *
 */

/**
 * @brief librdkafka version
 *
 * Interpreted as hex \c MM.mm.rr.xx:
 *  - MM = Major
 *  - mm = minor
 *  - rr = revision
 *  - xx = pre-release id (0xff is the final release)
 *
 * E.g.: \c 0x000801ff = 0.8.1
 *
 * @remark This value should only be used during compile time,
 *         for runtime checks of version use rd_kafka_version()
 */
#define RD_KAFKA_VERSION  0x000b03ff

/**
 * @brief Returns the librdkafka version as integer.
 *
 * @returns Version integer.
 *
 * @sa See RD_KAFKA_VERSION for how to parse the integer format.
 * @sa Use rd_kafka_version_str() to retreive the version as a string.
 */
RD_EXPORT
int rd_kafka_version(void);

/**
 * @brief Returns the librdkafka version as string.
 *
 * @returns Version string
 */
RD_EXPORT
const char *rd_kafka_version_str (void);

/**@}*/


/**
 * @name Constants, errors, types
 * @{
 *
 *
 */


/**
 * @enum rd_kafka_type_t
 *
 * @brief rd_kafka_t handle type.
 *
 * @sa rd_kafka_new()
 */
typedef enum rd_kafka_type_t {
	RD_KAFKA_PRODUCER, /**< Producer client */
	RD_KAFKA_CONSUMER  /**< Consumer client */
} rd_kafka_type_t;


/**
 * @enum Timestamp types
 *
 * @sa rd_kafka_message_timestamp()
 */
typedef enum rd_kafka_timestamp_type_t {
	RD_KAFKA_TIMESTAMP_NOT_AVAILABLE,   /**< Timestamp not available */
	RD_KAFKA_TIMESTAMP_CREATE_TIME,     /**< Message creation time */
	RD_KAFKA_TIMESTAMP_LOG_APPEND_TIME  /**< Log append time */
} rd_kafka_timestamp_type_t;



/**
 * @brief Retrieve supported debug contexts for use with the \c \"debug\"
 *        configuration property. (runtime)
 *
 * @returns Comma-separated list of available debugging contexts.
 */
RD_EXPORT
const char *rd_kafka_get_debug_contexts(void);

/**
 * @brief Supported debug contexts. (compile time)
 *
 * @deprecated This compile time value may be outdated at runtime due to
 *             linking another version of the library.
 *             Use rd_kafka_get_debug_contexts() instead.
 */
#define RD_KAFKA_DEBUG_CONTEXTS \
	"all,generic,broker,topic,metadata,queue,msg,protocol,cgrp,security,fetch,feature"


/* @cond NO_DOC */
/* Private types to provide ABI compatibility */
typedef struct rd_kafka_s rd_kafka_t;
typedef struct rd_kafka_topic_s rd_kafka_topic_t;
typedef struct rd_kafka_conf_s rd_kafka_conf_t;
typedef struct rd_kafka_topic_conf_s rd_kafka_topic_conf_t;
typedef struct rd_kafka_queue_s rd_kafka_queue_t;
/* @endcond */


/**
 * @enum rd_kafka_resp_err_t
 * @brief Error codes.
 *
 * The negative error codes delimited by two underscores
 * (\c RD_KAFKA_RESP_ERR__..) denotes errors internal to librdkafka and are
 * displayed as \c \"Local: \<error string..\>\", while the error codes
 * delimited by a single underscore (\c RD_KAFKA_RESP_ERR_..) denote broker
 * errors and are displayed as \c \"Broker: \<error string..\>\".
 *
 * @sa Use rd_kafka_err2str() to translate an error code a human readable string
 */
typedef enum {
	/* Internal errors to rdkafka: */
	/** Begin internal error codes */
	RD_KAFKA_RESP_ERR__BEGIN = -200,
	/** Received message is incorrect */
	RD_KAFKA_RESP_ERR__BAD_MSG = -199,
	/** Bad/unknown compression */
	RD_KAFKA_RESP_ERR__BAD_COMPRESSION = -198,
	/** Broker is going away */
	RD_KAFKA_RESP_ERR__DESTROY = -197,
	/** Generic failure */
	RD_KAFKA_RESP_ERR__FAIL = -196,
	/** Broker transport failure */
	RD_KAFKA_RESP_ERR__TRANSPORT = -195,
	/** Critical system resource */
	RD_KAFKA_RESP_ERR__CRIT_SYS_RESOURCE = -194,
	/** Failed to resolve broker */
	RD_KAFKA_RESP_ERR__RESOLVE = -193,
	/** Produced message timed out*/
	RD_KAFKA_RESP_ERR__MSG_TIMED_OUT = -192,
	/** Reached the end of the topic+partition queue on
	 * the broker. Not really an error. */
	RD_KAFKA_RESP_ERR__PARTITION_EOF = -191,
	/** Permanent: Partition does not exist in cluster. */
	RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION = -190,
	/** File or filesystem error */
	RD_KAFKA_RESP_ERR__FS = -189,
	 /** Permanent: Topic does not exist in cluster. */
	RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC = -188,
	/** All broker connections are down. */
	RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN = -187,
	/** Invalid argument, or invalid configuration */
	RD_KAFKA_RESP_ERR__INVALID_ARG = -186,
	/** Operation timed out */
	RD_KAFKA_RESP_ERR__TIMED_OUT = -185,
	/** Queue is full */
	RD_KAFKA_RESP_ERR__QUEUE_FULL = -184,
	/** ISR count < required.acks */
        RD_KAFKA_RESP_ERR__ISR_INSUFF = -183,
	/** Broker node update */
        RD_KAFKA_RESP_ERR__NODE_UPDATE = -182,
	/** SSL error */
	RD_KAFKA_RESP_ERR__SSL = -181,
	/** Waiting for coordinator to become available. */
        RD_KAFKA_RESP_ERR__WAIT_COORD = -180,
	/** Unknown client group */
        RD_KAFKA_RESP_ERR__UNKNOWN_GROUP = -179,
	/** Operation in progress */
        RD_KAFKA_RESP_ERR__IN_PROGRESS = -178,
	 /** Previous operation in progress, wait for it to finish. */
        RD_KAFKA_RESP_ERR__PREV_IN_PROGRESS = -177,
	 /** This operation would interfere with an existing subscription */
        RD_KAFKA_RESP_ERR__EXISTING_SUBSCRIPTION = -176,
	/** Assigned partitions (rebalance_cb) */
        RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS = -175,
	/** Revoked partitions (rebalance_cb) */
        RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS = -174,
	/** Conflicting use */
        RD_KAFKA_RESP_ERR__CONFLICT = -173,
	/** Wrong state */
        RD_KAFKA_RESP_ERR__STATE = -172,
	/** Unknown protocol */
        RD_KAFKA_RESP_ERR__UNKNOWN_PROTOCOL = -171,
	/** Not implemented */
        RD_KAFKA_RESP_ERR__NOT_IMPLEMENTED = -170,
	/** Authentication failure*/
	RD_KAFKA_RESP_ERR__AUTHENTICATION = -169,
	/** No stored offset */
	RD_KAFKA_RESP_ERR__NO_OFFSET = -168,
	/** Outdated */
	RD_KAFKA_RESP_ERR__OUTDATED = -167,
	/** Timed out in queue */
	RD_KAFKA_RESP_ERR__TIMED_OUT_QUEUE = -166,
        /** Feature not supported by broker */
        RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE = -165,
        /** Awaiting cache update */
        RD_KAFKA_RESP_ERR__WAIT_CACHE = -164,
        /** Operation interrupted (e.g., due to yield)) */
        RD_KAFKA_RESP_ERR__INTR = -163,
        /** Key serialization error */
        RD_KAFKA_RESP_ERR__KEY_SERIALIZATION = -162,
        /** Value serialization error */
        RD_KAFKA_RESP_ERR__VALUE_SERIALIZATION = -161,
        /** Key deserialization error */
        RD_KAFKA_RESP_ERR__KEY_DESERIALIZATION = -160,
        /** Value deserialization error */
        RD_KAFKA_RESP_ERR__VALUE_DESERIALIZATION = -159,
        /** Partial response */
        RD_KAFKA_RESP_ERR__PARTIAL = -158,

	/** End internal error codes */
	RD_KAFKA_RESP_ERR__END = -100,

	/* Kafka broker errors: */
	/** Unknown broker error */
	RD_KAFKA_RESP_ERR_UNKNOWN = -1,
	/** Success */
	RD_KAFKA_RESP_ERR_NO_ERROR = 0,
	/** Offset out of range */
	RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE = 1,
	/** Invalid message */
	RD_KAFKA_RESP_ERR_INVALID_MSG = 2,
	/** Unknown topic or partition */
	RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART = 3,
	/** Invalid message size */
	RD_KAFKA_RESP_ERR_INVALID_MSG_SIZE = 4,
	/** Leader not available */
	RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE = 5,
	/** Not leader for partition */
	RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION = 6,
	/** Request timed out */
	RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT = 7,
	/** Broker not available */
	RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE = 8,
	/** Replica not available */
	RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE = 9,
	/** Message size too large */
	RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE = 10,
	/** StaleControllerEpochCode */
	RD_KAFKA_RESP_ERR_STALE_CTRL_EPOCH = 11,
	/** Offset metadata string too large */
	RD_KAFKA_RESP_ERR_OFFSET_METADATA_TOO_LARGE = 12,
	/** Broker disconnected before response received */
	RD_KAFKA_RESP_ERR_NETWORK_EXCEPTION = 13,
	/** Group coordinator load in progress */
        RD_KAFKA_RESP_ERR_GROUP_LOAD_IN_PROGRESS = 14,
	 /** Group coordinator not available */
        RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE = 15,
	/** Not coordinator for group */
        RD_KAFKA_RESP_ERR_NOT_COORDINATOR_FOR_GROUP = 16,
	/** Invalid topic */
        RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION = 17,
	/** Message batch larger than configured server segment size */
        RD_KAFKA_RESP_ERR_RECORD_LIST_TOO_LARGE = 18,
	/** Not enough in-sync replicas */
        RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS = 19,
	/** Message(s) written to insufficient number of in-sync replicas */
        RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS_AFTER_APPEND = 20,
	/** Invalid required acks value */
        RD_KAFKA_RESP_ERR_INVALID_REQUIRED_ACKS = 21,
	/** Specified group generation id is not valid */
        RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION = 22,
	/** Inconsistent group protocol */
        RD_KAFKA_RESP_ERR_INCONSISTENT_GROUP_PROTOCOL = 23,
	/** Invalid group.id */
	RD_KAFKA_RESP_ERR_INVALID_GROUP_ID = 24,
	/** Unknown member */
        RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID = 25,
	/** Invalid session timeout */
        RD_KAFKA_RESP_ERR_INVALID_SESSION_TIMEOUT = 26,
	/** Group rebalance in progress */
	RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS = 27,
	/** Commit offset data size is not valid */
        RD_KAFKA_RESP_ERR_INVALID_COMMIT_OFFSET_SIZE = 28,
	/** Topic authorization failed */
        RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED = 29,
	/** Group authorization failed */
	RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED = 30,
	/** Cluster authorization failed */
	RD_KAFKA_RESP_ERR_CLUSTER_AUTHORIZATION_FAILED = 31,
	/** Invalid timestamp */
	RD_KAFKA_RESP_ERR_INVALID_TIMESTAMP = 32,
	/** Unsupported SASL mechanism */
	RD_KAFKA_RESP_ERR_UNSUPPORTED_SASL_MECHANISM = 33,
	/** Illegal SASL state */
	RD_KAFKA_RESP_ERR_ILLEGAL_SASL_STATE = 34,
	/** Unuspported version */
	RD_KAFKA_RESP_ERR_UNSUPPORTED_VERSION = 35,
	/** Topic already exists */
	RD_KAFKA_RESP_ERR_TOPIC_ALREADY_EXISTS = 36,
	/** Invalid number of partitions */
	RD_KAFKA_RESP_ERR_INVALID_PARTITIONS = 37,
	/** Invalid replication factor */
	RD_KAFKA_RESP_ERR_INVALID_REPLICATION_FACTOR = 38,
	/** Invalid replica assignment */
	RD_KAFKA_RESP_ERR_INVALID_REPLICA_ASSIGNMENT = 39,
	/** Invalid config */
	RD_KAFKA_RESP_ERR_INVALID_CONFIG = 40,
	/** Not controller for cluster */
	RD_KAFKA_RESP_ERR_NOT_CONTROLLER = 41,
	/** Invalid request */
	RD_KAFKA_RESP_ERR_INVALID_REQUEST = 42,
	/** Message format on broker does not support request */
	RD_KAFKA_RESP_ERR_UNSUPPORTED_FOR_MESSAGE_FORMAT = 43,
        /** Isolation policy volation */
        RD_KAFKA_RESP_ERR_POLICY_VIOLATION = 44,
        /** Broker received an out of order sequence number */
        RD_KAFKA_RESP_ERR_OUT_OF_ORDER_SEQUENCE_NUMBER = 45,
        /** Broker received a duplicate sequence number */
        RD_KAFKA_RESP_ERR_DUPLICATE_SEQUENCE_NUMBER = 46,
        /** Producer attempted an operation with an old epoch */
        RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH = 47,
        /** Producer attempted a transactional operation in an invalid state */
        RD_KAFKA_RESP_ERR_INVALID_TXN_STATE = 48,
        /** Producer attempted to use a producer id which is not
         *  currently assigned to its transactional id */
        RD_KAFKA_RESP_ERR_INVALID_PRODUCER_ID_MAPPING = 49,
        /** Transaction timeout is larger than the maximum
         *  value allowed by the broker's max.transaction.timeout.ms */
        RD_KAFKA_RESP_ERR_INVALID_TRANSACTION_TIMEOUT = 50,
        /** Producer attempted to update a transaction while another
         *  concurrent operation on the same transaction was ongoing */
        RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS = 51,
        /** Indicates that the transaction coordinator sending a
         *  WriteTxnMarker is no longer the current coordinator for a
         *  given producer */
        RD_KAFKA_RESP_ERR_TRANSACTION_COORDINATOR_FENCED = 52,
        /** Transactional Id authorization failed */
        RD_KAFKA_RESP_ERR_TRANSACTIONAL_ID_AUTHORIZATION_FAILED = 53,
        /** Security features are disabled */
        RD_KAFKA_RESP_ERR_SECURITY_DISABLED = 54,
        /** Operation not attempted */
        RD_KAFKA_RESP_ERR_OPERATION_NOT_ATTEMPTED = 55,

	RD_KAFKA_RESP_ERR_END_ALL,
} rd_kafka_resp_err_t;


/**
 * @brief Error code value, name and description.
 *        Typically for use with language bindings to automatically expose
 *        the full set of librdkafka error codes.
 */
struct rd_kafka_err_desc {
	rd_kafka_resp_err_t code;/**< Error code */
	const char *name;      /**< Error name, same as code enum sans prefix */
	const char *desc;      /**< Human readable error description. */
};


/**
 * @brief Returns the full list of error codes.
 */
RD_EXPORT
void rd_kafka_get_err_descs (const struct rd_kafka_err_desc **errdescs,
			     size_t *cntp);




/**
 * @brief Returns a human readable representation of a kafka error.
 *
 * @param err Error code to translate
 */
RD_EXPORT
const char *rd_kafka_err2str (rd_kafka_resp_err_t err);



/**
 * @brief Returns the error code name (enum name).
 *
 * @param err Error code to translate
 */
RD_EXPORT
const char *rd_kafka_err2name (rd_kafka_resp_err_t err);


/**
 * @brief Returns the last error code generated by a legacy API call
 *        in the current thread.
 *
 * The legacy APIs are the ones using errno to propagate error value, namely:
 *  - rd_kafka_topic_new()
 *  - rd_kafka_consume_start()
 *  - rd_kafka_consume_stop()
 *  - rd_kafka_consume()
 *  - rd_kafka_consume_batch()
 *  - rd_kafka_consume_callback()
 *  - rd_kafka_consume_queue()
 *  - rd_kafka_produce()
 *
 * The main use for this function is to avoid converting system \p errno
 * values to rd_kafka_resp_err_t codes for legacy APIs.
 *
 * @remark The last error is stored per-thread, if multiple rd_kafka_t handles
 *         are used in the same application thread the developer needs to
 *         make sure rd_kafka_last_error() is called immediately after
 *         a failed API call.
 *
 * @remark errno propagation from librdkafka is not safe on Windows
 *         and should not be used, use rd_kafka_last_error() instead.
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_last_error (void);


/**
 * @brief Converts the system errno value \p errnox to a rd_kafka_resp_err_t
 *        error code upon failure from the following functions:
 *  - rd_kafka_topic_new()
 *  - rd_kafka_consume_start()
 *  - rd_kafka_consume_stop()
 *  - rd_kafka_consume()
 *  - rd_kafka_consume_batch()
 *  - rd_kafka_consume_callback()
 *  - rd_kafka_consume_queue()
 *  - rd_kafka_produce()
 *
 * @param errnox  System errno value to convert
 *
 * @returns Appropriate error code for \p errnox
 *
 * @remark A better alternative is to call rd_kafka_last_error() immediately
 *         after any of the above functions return -1 or NULL.
 *
 * @deprecated Use rd_kafka_last_error() to retrieve the last error code
 *             set by the legacy librdkafka APIs.
 *
 * @sa rd_kafka_last_error()
 */
RD_EXPORT RD_DEPRECATED
rd_kafka_resp_err_t rd_kafka_errno2err(int errnox);


/**
 * @brief Returns the thread-local system errno
 *
 * On most platforms this is the same as \p errno but in case of different
 * runtimes between library and application (e.g., Windows static DLLs)
 * this provides a means for exposing the errno librdkafka uses.
 *
 * @remark The value is local to the current calling thread.
 *
 * @deprecated Use rd_kafka_last_error() to retrieve the last error code
 *             set by the legacy librdkafka APIs.
 */
RD_EXPORT RD_DEPRECATED
int rd_kafka_errno (void);



/**
 * @brief Topic+Partition place holder
 *
 * Generic place holder for a Topic+Partition and its related information
 * used for multiple purposes:
 *   - consumer offset (see rd_kafka_commit(), et.al.)
 *   - group rebalancing callback (rd_kafka_conf_set_rebalance_cb())
 *   - offset commit result callback (rd_kafka_conf_set_offset_commit_cb())
 */

/**
 * @brief Generic place holder for a specific Topic+Partition.
 *
 * @sa rd_kafka_topic_partition_list_new()
 */
typedef struct rd_kafka_topic_partition_s {
        char        *topic;             /**< Topic name */
        int32_t      partition;         /**< Partition */
	int64_t      offset;            /**< Offset */
        void        *metadata;          /**< Metadata */
        size_t       metadata_size;     /**< Metadata size */
        void        *opaque;            /**< Application opaque */
        rd_kafka_resp_err_t err;        /**< Error code, depending on use. */
        void       *_private;           /**< INTERNAL USE ONLY,
                                         *   INITIALIZE TO ZERO, DO NOT TOUCH */
} rd_kafka_topic_partition_t;


/**
 * @brief Destroy a rd_kafka_topic_partition_t.
 * @remark This must not be called for elements in a topic partition list.
 */
RD_EXPORT
void rd_kafka_topic_partition_destroy (rd_kafka_topic_partition_t *rktpar);


/**
 * @brief A growable list of Topic+Partitions.
 *
 */
typedef struct rd_kafka_topic_partition_list_s {
        int cnt;               /**< Current number of elements */
        int size;              /**< Current allocated size */
        rd_kafka_topic_partition_t *elems; /**< Element array[] */
} rd_kafka_topic_partition_list_t;


/**
 * @brief Create a new list/vector Topic+Partition container.
 *
 * @param size  Initial allocated size used when the expected number of
 *              elements is known or can be estimated.
 *              Avoids reallocation and possibly relocation of the
 *              elems array.
 *
 * @returns A newly allocated Topic+Partition list.
 *
 * @remark Use rd_kafka_topic_partition_list_destroy() to free all resources
 *         in use by a list and the list itself.
 * @sa     rd_kafka_topic_partition_list_add()
 */
RD_EXPORT
rd_kafka_topic_partition_list_t *rd_kafka_topic_partition_list_new (int size);


/**
 * @brief Free all resources used by the list and the list itself.
 */
RD_EXPORT
void
rd_kafka_topic_partition_list_destroy (rd_kafka_topic_partition_list_t *rkparlist);

/**
 * @brief Add topic+partition to list
 *
 * @param rktparlist List to extend
 * @param topic      Topic name (copied)
 * @param partition  Partition id
 *
 * @returns The object which can be used to fill in additionals fields.
 */
RD_EXPORT
rd_kafka_topic_partition_t *
rd_kafka_topic_partition_list_add (rd_kafka_topic_partition_list_t *rktparlist,
                                   const char *topic, int32_t partition);


/**
 * @brief Add range of partitions from \p start to \p stop inclusive.
 *
 * @param rktparlist List to extend
 * @param topic      Topic name (copied)
 * @param start      Start partition of range
 * @param stop       Last partition of range (inclusive)
 */
RD_EXPORT
void
rd_kafka_topic_partition_list_add_range (rd_kafka_topic_partition_list_t
                                         *rktparlist,
                                         const char *topic,
                                         int32_t start, int32_t stop);



/**
 * @brief Delete partition from list.
 *
 * @param rktparlist List to modify
 * @param topic      Topic name to match
 * @param partition  Partition to match
 *
 * @returns 1 if partition was found (and removed), else 0.
 *
 * @remark Any held indices to elems[] are unusable after this call returns 1.
 */
RD_EXPORT
int
rd_kafka_topic_partition_list_del (rd_kafka_topic_partition_list_t *rktparlist,
				   const char *topic, int32_t partition);


/**
 * @brief Delete partition from list by elems[] index.
 *
 * @returns 1 if partition was found (and removed), else 0.
 *
 * @sa rd_kafka_topic_partition_list_del()
 */
RD_EXPORT
int
rd_kafka_topic_partition_list_del_by_idx (
	rd_kafka_topic_partition_list_t *rktparlist,
	int idx);


/**
 * @brief Make a copy of an existing list.
 *
 * @param src   The existing list to copy.
 *
 * @returns A new list fully populated to be identical to \p src
 */
RD_EXPORT
rd_kafka_topic_partition_list_t *
rd_kafka_topic_partition_list_copy (const rd_kafka_topic_partition_list_t *src);




/**
 * @brief Set offset to \p offset for \p topic and \p partition
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or
 *          RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION if \p partition was not found
 *          in the list.
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_topic_partition_list_set_offset (
	rd_kafka_topic_partition_list_t *rktparlist,
	const char *topic, int32_t partition, int64_t offset);



/**
 * @brief Find element by \p topic and \p partition.
 *
 * @returns a pointer to the first matching element, or NULL if not found.
 */
RD_EXPORT
rd_kafka_topic_partition_t *
rd_kafka_topic_partition_list_find (rd_kafka_topic_partition_list_t *rktparlist,
				    const char *topic, int32_t partition);


/**
 * @brief Sort list using comparator \p cmp.
 *
 * If \p cmp is NULL the default comparator will be used that
 * sorts by ascending topic name and partition.
 *
 */
RD_EXPORT void
rd_kafka_topic_partition_list_sort (rd_kafka_topic_partition_list_t *rktparlist,
                                    int (*cmp) (const void *a, const void *b,
                                                void *opaque),
                                    void *opaque);


/**@}*/



/**
 * @name Var-arg tag types
 * @{
 *
 */

/**
 * @enum rd_kafka_vtype_t
 *
 * @brief Var-arg tag types
 *
 * @sa rd_kafka_producev()
 */
typedef enum rd_kafka_vtype_t {
        RD_KAFKA_VTYPE_END,       /**< va-arg sentinel */
        RD_KAFKA_VTYPE_TOPIC,     /**< (const char *) Topic name */
        RD_KAFKA_VTYPE_RKT,       /**< (rd_kafka_topic_t *) Topic handle */
        RD_KAFKA_VTYPE_PARTITION, /**< (int32_t) Partition */
        RD_KAFKA_VTYPE_VALUE,     /**< (void *, size_t) Message value (payload)*/
        RD_KAFKA_VTYPE_KEY,       /**< (void *, size_t) Message key */
        RD_KAFKA_VTYPE_OPAQUE,    /**< (void *) Application opaque */
        RD_KAFKA_VTYPE_MSGFLAGS,  /**< (int) RD_KAFKA_MSG_F_.. flags */
        RD_KAFKA_VTYPE_TIMESTAMP, /**< (int64_t) Milliseconds since epoch UTC */
} rd_kafka_vtype_t;


/**
 * @brief Convenience macros for rd_kafka_vtype_t that takes the
 *        correct arguments for each vtype.
 */

/*!
 * va-arg end sentinel used to terminate the variable argument list
 */
#define RD_KAFKA_V_END RD_KAFKA_VTYPE_END

/*!
 * Topic name (const char *)
 */
#define RD_KAFKA_V_TOPIC(topic)                                         \
        _LRK_TYPECHECK(RD_KAFKA_VTYPE_TOPIC, const char *, topic),      \
        (const char *)topic
/*!
 * Topic object (rd_kafka_topic_t *)
 */
#define RD_KAFKA_V_RKT(rkt)                                             \
        _LRK_TYPECHECK(RD_KAFKA_VTYPE_RKT, rd_kafka_topic_t *, rkt),    \
        (rd_kafka_topic_t *)rkt
/*!
 * Partition (int32_t)
 */
#define RD_KAFKA_V_PARTITION(partition)                                 \
        _LRK_TYPECHECK(RD_KAFKA_VTYPE_PARTITION, int32_t, partition),   \
        (int32_t)partition
/*!
 * Message value/payload pointer and length (void *, size_t)
 */
#define RD_KAFKA_V_VALUE(VALUE,LEN)                                     \
        _LRK_TYPECHECK2(RD_KAFKA_VTYPE_VALUE, void *, VALUE, size_t, LEN), \
        (void *)VALUE, (size_t)LEN
/*!
 * Message key pointer and length (const void *, size_t)
 */
#define RD_KAFKA_V_KEY(KEY,LEN)                                         \
        _LRK_TYPECHECK2(RD_KAFKA_VTYPE_KEY, const void *, KEY, size_t, LEN), \
        (void *)KEY, (size_t)LEN
/*!
 * Opaque pointer (void *)
 */
#define RD_KAFKA_V_OPAQUE(opaque)                                 \
        _LRK_TYPECHECK(RD_KAFKA_VTYPE_OPAQUE, void *, opaque),    \
        (void *)opaque
/*!
 * Message flags (int)
 * @sa RD_KAFKA_MSG_F_COPY, et.al.
 */
#define RD_KAFKA_V_MSGFLAGS(msgflags)                                 \
        _LRK_TYPECHECK(RD_KAFKA_VTYPE_MSGFLAGS, int, msgflags),       \
        (int)msgflags
/*!
 * Timestamp (int64_t)
 */
#define RD_KAFKA_V_TIMESTAMP(timestamp)                                 \
        _LRK_TYPECHECK(RD_KAFKA_VTYPE_TIMESTAMP, int64_t, timestamp),   \
        (int64_t)timestamp

/**@}*/


/**
 * @name Kafka messages
 * @{
 *
 */



// FIXME: This doesn't show up in docs for some reason
// "Compound rd_kafka_message_t is not documented."

/**
 * @brief A Kafka message as returned by the \c rd_kafka_consume*() family
 *        of functions as well as provided to the Producer \c dr_msg_cb().
 *
 * For the consumer this object has two purposes:
 *  - provide the application with a consumed message. (\c err == 0)
 *  - report per-topic+partition consumer errors (\c err != 0)
 *
 * The application must check \c err to decide what action to take.
 *
 * When the application is finished with a message it must call
 * rd_kafka_message_destroy() unless otherwise noted.
 */
typedef struct rd_kafka_message_s {
	rd_kafka_resp_err_t err;   /**< Non-zero for error signaling. */
	rd_kafka_topic_t *rkt;     /**< Topic */
	int32_t partition;         /**< Partition */
	void   *payload;           /**< Producer: original message payload.
				    * Consumer: Depends on the value of \c err :
				    * - \c err==0: Message payload.
				    * - \c err!=0: Error string */
	size_t  len;               /**< Depends on the value of \c err :
				    * - \c err==0: Message payload length
				    * - \c err!=0: Error string length */
	void   *key;               /**< Depends on the value of \c err :
				    * - \c err==0: Optional message key */
	size_t  key_len;           /**< Depends on the value of \c err :
				    * - \c err==0: Optional message key length*/
	int64_t offset;            /**< Consume:
                                    * - Message offset (or offset for error
				    *   if \c err!=0 if applicable).
                                    * - dr_msg_cb:
                                    *   Message offset assigned by broker.
                                    *   If \c produce.offset.report is set then
                                    *   each message will have this field set,
                                    *   otherwise only the last message in
                                    *   each produced internal batch will
                                    *   have this field set, otherwise 0. */
	void  *_private;           /**< Consume:
				    *  - rdkafka private pointer: DO NOT MODIFY
				    *  - dr_msg_cb:
                                    *    msg_opaque from produce() call */
} rd_kafka_message_t;


/**
 * @brief Frees resources for \p rkmessage and hands ownership back to rdkafka.
 */
RD_EXPORT
void rd_kafka_message_destroy(rd_kafka_message_t *rkmessage);




/**
 * @brief Returns the error string for an errored rd_kafka_message_t or NULL if
 *        there was no error.
 *
 * @remark This function MUST NOT be used with the producer.
 */
static RD_INLINE const char *
RD_UNUSED 
rd_kafka_message_errstr(const rd_kafka_message_t *rkmessage) {
	if (!rkmessage->err)
		return NULL;

	if (rkmessage->payload)
		return (const char *)rkmessage->payload;

	return rd_kafka_err2str(rkmessage->err);
}



/**
 * @brief Returns the message timestamp for a consumed message.
 *
 * The timestamp is the number of milliseconds since the epoch (UTC).
 *
 * \p tstype (if not NULL) is updated to indicate the type of timestamp.
 *
 * @returns message timestamp, or -1 if not available.
 *
 * @remark Message timestamps require broker version 0.10.0 or later.
 */
RD_EXPORT
int64_t rd_kafka_message_timestamp (const rd_kafka_message_t *rkmessage,
				    rd_kafka_timestamp_type_t *tstype);



/**
 * @brief Returns the latency for a produced message measured from
 *        the produce() call.
 *
 * @returns the latency in microseconds, or -1 if not available.
 */
RD_EXPORT
int64_t rd_kafka_message_latency (const rd_kafka_message_t *rkmessage);


/**@}*/


/**
 * @name Configuration interface
 * @{
 *
 * @brief Main/global configuration property interface
 *
 */

/**
 * @enum rd_kafka_conf_res_t
 * @brief Configuration result type
 */
typedef enum {
	RD_KAFKA_CONF_UNKNOWN = -2, /**< Unknown configuration name. */
	RD_KAFKA_CONF_INVALID = -1, /**< Invalid configuration value. */
	RD_KAFKA_CONF_OK = 0        /**< Configuration okay */
} rd_kafka_conf_res_t;


/**
 * @brief Create configuration object.
 *
 * When providing your own configuration to the \c rd_kafka_*_new_*() calls
 * the rd_kafka_conf_t objects needs to be created with this function
 * which will set up the defaults.
 * I.e.:
 * @code
 *   rd_kafka_conf_t *myconf;
 *   rd_kafka_conf_res_t res;
 *
 *   myconf = rd_kafka_conf_new();
 *   res = rd_kafka_conf_set(myconf, "socket.timeout.ms", "600",
 *                           errstr, sizeof(errstr));
 *   if (res != RD_KAFKA_CONF_OK)
 *      die("%s\n", errstr);
 *   
 *   rk = rd_kafka_new(..., myconf);
 * @endcode
 *
 * Please see CONFIGURATION.md for the default settings or use
 * rd_kafka_conf_properties_show() to provide the information at runtime.
 *
 * The properties are identical to the Apache Kafka configuration properties
 * whenever possible.
 *
 * @returns A new rd_kafka_conf_t object with defaults set.
 *
 * @sa rd_kafka_conf_set(), rd_kafka_conf_destroy()
 */
RD_EXPORT
rd_kafka_conf_t *rd_kafka_conf_new(void);


/**
 * @brief Destroys a conf object.
 */
RD_EXPORT
void rd_kafka_conf_destroy(rd_kafka_conf_t *conf);


/**
 * @brief Creates a copy/duplicate of configuration object \p conf
 *
 * @remark Interceptors are NOT copied to the new configuration object.
 * @sa rd_kafka_interceptor_f_on_conf_dup
 */
RD_EXPORT
rd_kafka_conf_t *rd_kafka_conf_dup(const rd_kafka_conf_t *conf);


/**
 * @brief Same as rd_kafka_conf_dup() but with an array of property name
 *        prefixes to filter out (ignore) when copying.
 */
RD_EXPORT
rd_kafka_conf_t *rd_kafka_conf_dup_filter (const rd_kafka_conf_t *conf,
                                           size_t filter_cnt,
                                           const char **filter);



/**
 * @brief Sets a configuration property.
 *
 * \p conf must have been previously created with rd_kafka_conf_new().
 *
 * Fallthrough:
 * Topic-level configuration properties may be set using this interface
 * in which case they are applied on the \c default_topic_conf.
 * If no \c default_topic_conf has been set one will be created.
 * Any sub-sequent rd_kafka_conf_set_default_topic_conf() calls will
 * replace the current default topic configuration.
 *
 * @returns \c rd_kafka_conf_res_t to indicate success or failure.
 * In case of failure \p errstr is updated to contain a human readable
 * error string.
 */
RD_EXPORT
rd_kafka_conf_res_t rd_kafka_conf_set(rd_kafka_conf_t *conf,
				       const char *name,
				       const char *value,
				       char *errstr, size_t errstr_size);


/**
 * @brief Enable event sourcing.
 * \p events is a bitmask of \c RD_KAFKA_EVENT_* of events to enable
 * for consumption by `rd_kafka_queue_poll()`.
 */
RD_EXPORT
void rd_kafka_conf_set_events(rd_kafka_conf_t *conf, int events);


/**
 @deprecated See rd_kafka_conf_set_dr_msg_cb()
*/
RD_EXPORT
void rd_kafka_conf_set_dr_cb(rd_kafka_conf_t *conf,
			      void (*dr_cb) (rd_kafka_t *rk,
					     void *payload, size_t len,
					     rd_kafka_resp_err_t err,
					     void *opaque, void *msg_opaque));

/**
 * @brief \b Producer: Set delivery report callback in provided \p conf object.
 *
 * The delivery report callback will be called once for each message
 * accepted by rd_kafka_produce() (et.al) with \p err set to indicate
 * the result of the produce request.
 * 
 * The callback is called when a message is succesfully produced or
 * if librdkafka encountered a permanent failure, or the retry counter for
 * temporary errors has been exhausted.
 *
 * An application must call rd_kafka_poll() at regular intervals to
 * serve queued delivery report callbacks.
 */
RD_EXPORT
void rd_kafka_conf_set_dr_msg_cb(rd_kafka_conf_t *conf,
                                  void (*dr_msg_cb) (rd_kafka_t *rk,
                                                     const rd_kafka_message_t *
                                                     rkmessage,
                                                     void *opaque));


/**
 * @brief \b Consumer: Set consume callback for use with rd_kafka_consumer_poll()
 *
 */
RD_EXPORT
void rd_kafka_conf_set_consume_cb (rd_kafka_conf_t *conf,
                                   void (*consume_cb) (rd_kafka_message_t *
                                                       rkmessage,
                                                       void *opaque));

/**
 * @brief \b Consumer: Set rebalance callback for use with
 *                     coordinated consumer group balancing.
 *
 * The \p err field is set to either RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS
 * or RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS and 'partitions'
 * contains the full partition set that was either assigned or revoked.
 *
 * Registering a \p rebalance_cb turns off librdkafka's automatic
 * partition assignment/revocation and instead delegates that responsibility
 * to the application's \p rebalance_cb.
 *
 * The rebalance callback is responsible for updating librdkafka's
 * assignment set based on the two events: RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS
 * and RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS but should also be able to handle
 * arbitrary rebalancing failures where \p err is neither of those.
 * @remark In this latter case (arbitrary error), the application must
 *         call rd_kafka_assign(rk, NULL) to synchronize state.
 *
 * Without a rebalance callback this is done automatically by librdkafka
 * but registering a rebalance callback gives the application flexibility
 * in performing other operations along with the assinging/revocation,
 * such as fetching offsets from an alternate location (on assign)
 * or manually committing offsets (on revoke).
 *
 * @remark The \p partitions list is destroyed by librdkafka on return
 *         return from the rebalance_cb and must not be freed or
 *         saved by the application.
 * 
 * The following example shows the application's responsibilities:
 * @code
 *    static void rebalance_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
 *                              rd_kafka_topic_partition_list_t *partitions,
 *                              void *opaque) {
 *
 *        switch (err)
 *        {
 *          case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
 *             // application may load offets from arbitrary external
 *             // storage here and update \p partitions
 *
 *             rd_kafka_assign(rk, partitions);
 *             break;
 *
 *          case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
 *             if (manual_commits) // Optional explicit manual commit
 *                 rd_kafka_commit(rk, partitions, 0); // sync commit
 *
 *             rd_kafka_assign(rk, NULL);
 *             break;
 *
 *          default:
 *             handle_unlikely_error(err);
 *             rd_kafka_assign(rk, NULL); // sync state
 *             break;
 *         }
 *    }
 * @endcode
 */
RD_EXPORT
void rd_kafka_conf_set_rebalance_cb (
        rd_kafka_conf_t *conf,
        void (*rebalance_cb) (rd_kafka_t *rk,
                              rd_kafka_resp_err_t err,
                              rd_kafka_topic_partition_list_t *partitions,
                              void *opaque));



/**
 * @brief \b Consumer: Set offset commit callback for use with consumer groups.
 *
 * The results of automatic or manual offset commits will be scheduled
 * for this callback and is served by rd_kafka_consumer_poll().
 *
 * If no partitions had valid offsets to commit this callback will be called
 * with \p err == RD_KAFKA_RESP_ERR__NO_OFFSET which is not to be considered
 * an error.
 *
 * The \p offsets list contains per-partition information:
 *   - \c offset: committed offset (attempted)
 *   - \c err:    commit error
 */
RD_EXPORT
void rd_kafka_conf_set_offset_commit_cb (
        rd_kafka_conf_t *conf,
        void (*offset_commit_cb) (rd_kafka_t *rk,
                                  rd_kafka_resp_err_t err,
                                  rd_kafka_topic_partition_list_t *offsets,
                                  void *opaque));


/**
 * @brief Set error callback in provided conf object.
 *
 * The error callback is used by librdkafka to signal critical errors
 * back to the application.
 *
 * If no \p error_cb is registered then the errors will be logged instead.
 */
RD_EXPORT
void rd_kafka_conf_set_error_cb(rd_kafka_conf_t *conf,
				 void  (*error_cb) (rd_kafka_t *rk, int err,
						    const char *reason,
						    void *opaque));

/**
 * @brief Set throttle callback.
 *
 * The throttle callback is used to forward broker throttle times to the
 * application for Produce and Fetch (consume) requests.
 *
 * Callbacks are triggered whenever a non-zero throttle time is returned by
 * the broker, or when the throttle time drops back to zero.
 *
 * An application must call rd_kafka_poll() or rd_kafka_consumer_poll() at
 * regular intervals to serve queued callbacks.
 *
 * @remark Requires broker version 0.9.0 or later.
 */
RD_EXPORT
void rd_kafka_conf_set_throttle_cb (rd_kafka_conf_t *conf,
				    void (*throttle_cb) (
					    rd_kafka_t *rk,
					    const char *broker_name,
					    int32_t broker_id,
					    int throttle_time_ms,
					    void *opaque));


/**
 * @brief Set logger callback.
 *
 * The default is to print to stderr, but a syslog logger is also available,
 * see rd_kafka_log_print and rd_kafka_log_syslog for the builtin alternatives.
 * Alternatively the application may provide its own logger callback.
 * Or pass \p func as NULL to disable logging.
 *
 * This is the configuration alternative to the deprecated rd_kafka_set_logger()
 *
 * @remark The log_cb will be called spontaneously from librdkafka's internal
 *         threads unless logs have been forwarded to a poll queue through
 *         \c rd_kafka_set_log_queue().
 *         An application MUST NOT call any librdkafka APIs or do any prolonged
 *         work in a non-forwarded \c log_cb.
 */
RD_EXPORT
void rd_kafka_conf_set_log_cb(rd_kafka_conf_t *conf,
			  void (*log_cb) (const rd_kafka_t *rk, int level,
                                          const char *fac, const char *buf));


/**
 * @brief Set statistics callback in provided conf object.
 *
 * The statistics callback is triggered from rd_kafka_poll() every
 * \c statistics.interval.ms (needs to be configured separately).
 * Function arguments:
 *   - \p rk - Kafka handle
 *   - \p json - String containing the statistics data in JSON format
 *   - \p json_len - Length of \p json string.
 *   - \p opaque - Application-provided opaque.
 *
 * If the application wishes to hold on to the \p json pointer and free
 * it at a later time it must return 1 from the \p stats_cb.
 * If the application returns 0 from the \p stats_cb then librdkafka
 * will immediately free the \p json pointer.
 */
RD_EXPORT
void rd_kafka_conf_set_stats_cb(rd_kafka_conf_t *conf,
				 int (*stats_cb) (rd_kafka_t *rk,
						  char *json,
						  size_t json_len,
						  void *opaque));



/**
 * @brief Set socket callback.
 *
 * The socket callback is responsible for opening a socket
 * according to the supplied \p domain, \p type and \p protocol.
 * The socket shall be created with \c CLOEXEC set in a racefree fashion, if
 * possible.
 *
 * Default:
 *  - on linux: racefree CLOEXEC
 *  - others  : non-racefree CLOEXEC
 *
 * @remark The callback will be called from an internal librdkafka thread.
 */
RD_EXPORT
void rd_kafka_conf_set_socket_cb(rd_kafka_conf_t *conf,
                                  int (*socket_cb) (int domain, int type,
                                                    int protocol,
                                                    void *opaque));



/**
 * @brief Set connect callback.
 *
 * The connect callback is responsible for connecting socket \p sockfd
 * to peer address \p addr.
 * The \p id field contains the broker identifier.
 *
 * \p connect_cb shall return 0 on success (socket connected) or an error
 * number (errno) on error.
 *
 * @remark The callback will be called from an internal librdkafka thread.
 */
RD_EXPORT void
rd_kafka_conf_set_connect_cb (rd_kafka_conf_t *conf,
                              int (*connect_cb) (int sockfd,
                                                 const struct sockaddr *addr,
                                                 int addrlen,
                                                 const char *id,
                                                 void *opaque));

/**
 * @brief Set close socket callback.
 *
 * Close a socket (optionally opened with socket_cb()).
 *
 * @remark The callback will be called from an internal librdkafka thread.
 */
RD_EXPORT void
rd_kafka_conf_set_closesocket_cb (rd_kafka_conf_t *conf,
                                  int (*closesocket_cb) (int sockfd,
                                                         void *opaque));



#ifndef _MSC_VER
/**
 * @brief Set open callback.
 *
 * The open callback is responsible for opening the file specified by
 * pathname, flags and mode.
 * The file shall be opened with \c CLOEXEC set in a racefree fashion, if
 * possible.
 *
 * Default:
 *  - on linux: racefree CLOEXEC
 *  - others  : non-racefree CLOEXEC
 *
 * @remark The callback will be called from an internal librdkafka thread.
 */
RD_EXPORT
void rd_kafka_conf_set_open_cb (rd_kafka_conf_t *conf,
                                int (*open_cb) (const char *pathname,
                                                int flags, mode_t mode,
                                                void *opaque));
#endif

/**
 * @brief Sets the application's opaque pointer that will be passed to callbacks
 */
RD_EXPORT
void rd_kafka_conf_set_opaque(rd_kafka_conf_t *conf, void *opaque);

/**
 * @brief Retrieves the opaque pointer previously set with rd_kafka_conf_set_opaque()
 */
RD_EXPORT
void *rd_kafka_opaque(const rd_kafka_t *rk);



/**
 * Sets the default topic configuration to use for automatically
 * subscribed topics (e.g., through pattern-matched topics).
 * The topic config object is not usable after this call.
 */
RD_EXPORT
void rd_kafka_conf_set_default_topic_conf (rd_kafka_conf_t *conf,
                                           rd_kafka_topic_conf_t *tconf);



/**
 * @brief Retrieve configuration value for property \p name.
 *
 * If \p dest is non-NULL the value will be written to \p dest with at
 * most \p dest_size.
 *
 * \p *dest_size is updated to the full length of the value, thus if
 * \p *dest_size initially is smaller than the full length the application
 * may reallocate \p dest to fit the returned \p *dest_size and try again.
 *
 * If \p dest is NULL only the full length of the value is returned.
 *
 * Fallthrough:
 * Topic-level configuration properties from the \c default_topic_conf
 * may be retrieved using this interface.
 *
 * @returns \p RD_KAFKA_CONF_OK if the property name matched, else
 * \p RD_KAFKA_CONF_UNKNOWN.
 */
RD_EXPORT
rd_kafka_conf_res_t rd_kafka_conf_get (const rd_kafka_conf_t *conf,
                                       const char *name,
                                       char *dest, size_t *dest_size);


/**
 * @brief Retrieve topic configuration value for property \p name.
 *
 * @sa rd_kafka_conf_get()
 */
RD_EXPORT
rd_kafka_conf_res_t rd_kafka_topic_conf_get (const rd_kafka_topic_conf_t *conf,
                                             const char *name,
                                             char *dest, size_t *dest_size);


/**
 * @brief Dump the configuration properties and values of \p conf to an array
 *        with \"key\", \"value\" pairs.
 *
 * The number of entries in the array is returned in \p *cntp.
 *
 * The dump must be freed with `rd_kafka_conf_dump_free()`.
 */
RD_EXPORT
const char **rd_kafka_conf_dump(rd_kafka_conf_t *conf, size_t *cntp);


/**
 * @brief Dump the topic configuration properties and values of \p conf
 *        to an array with \"key\", \"value\" pairs.
 *
 * The number of entries in the array is returned in \p *cntp.
 *
 * The dump must be freed with `rd_kafka_conf_dump_free()`.
 */
RD_EXPORT
const char **rd_kafka_topic_conf_dump(rd_kafka_topic_conf_t *conf,
				       size_t *cntp);

/**
 * @brief Frees a configuration dump returned from `rd_kafka_conf_dump()` or
 *        `rd_kafka_topic_conf_dump().
 */
RD_EXPORT
void rd_kafka_conf_dump_free(const char **arr, size_t cnt);

/**
 * @brief Prints a table to \p fp of all supported configuration properties,
 *        their default values as well as a description.
 */
RD_EXPORT
void rd_kafka_conf_properties_show(FILE *fp);

/**@}*/


/**
 * @name Topic configuration
 * @{
 *
 * @brief Topic configuration property interface
 *
 */


/**
 * @brief Create topic configuration object
 *
 * @sa Same semantics as for rd_kafka_conf_new().
 */
RD_EXPORT
rd_kafka_topic_conf_t *rd_kafka_topic_conf_new(void);


/**
 * @brief Creates a copy/duplicate of topic configuration object \p conf.
 */
RD_EXPORT
rd_kafka_topic_conf_t *rd_kafka_topic_conf_dup(const rd_kafka_topic_conf_t
						*conf);


/**
 * @brief Destroys a topic conf object.
 */
RD_EXPORT
void rd_kafka_topic_conf_destroy(rd_kafka_topic_conf_t *topic_conf);


/**
 * @brief Sets a single rd_kafka_topic_conf_t value by property name.
 *
 * \p topic_conf should have been previously set up
 * with `rd_kafka_topic_conf_new()`.
 *
 * @returns rd_kafka_conf_res_t to indicate success or failure.
 */
RD_EXPORT
rd_kafka_conf_res_t rd_kafka_topic_conf_set(rd_kafka_topic_conf_t *conf,
					     const char *name,
					     const char *value,
					     char *errstr, size_t errstr_size);

/**
 * @brief Sets the application's opaque pointer that will be passed to all topic
 * callbacks as the \c rkt_opaque argument.
 */
RD_EXPORT
void rd_kafka_topic_conf_set_opaque(rd_kafka_topic_conf_t *conf, void *opaque);


/**
 * @brief \b Producer: Set partitioner callback in provided topic conf object.
 *
 * The partitioner may be called in any thread at any time,
 * it may be called multiple times for the same message/key.
 *
 * Partitioner function constraints:
 *   - MUST NOT call any rd_kafka_*() functions except:
 *       rd_kafka_topic_partition_available()
 *   - MUST NOT block or execute for prolonged periods of time.
 *   - MUST return a value between 0 and partition_cnt-1, or the
 *     special \c RD_KAFKA_PARTITION_UA value if partitioning
 *     could not be performed.
 */
RD_EXPORT
void
rd_kafka_topic_conf_set_partitioner_cb (rd_kafka_topic_conf_t *topic_conf,
					int32_t (*partitioner) (
						const rd_kafka_topic_t *rkt,
						const void *keydata,
						size_t keylen,
						int32_t partition_cnt,
						void *rkt_opaque,
						void *msg_opaque));

/**
 * @brief Check if partition is available (has a leader broker).
 *
 * @returns 1 if the partition is available, else 0.
 *
 * @warning This function must only be called from inside a partitioner function
 */
RD_EXPORT
int rd_kafka_topic_partition_available(const rd_kafka_topic_t *rkt,
					int32_t partition);


/*******************************************************************
 *								   *
 * Partitioners provided by rdkafka                                *
 *								   *
 *******************************************************************/

/**
 * @brief Random partitioner.
 *
 * Will try not to return unavailable partitions.
 *
 * @returns a random partition between 0 and \p partition_cnt - 1.
 *
 */
RD_EXPORT
int32_t rd_kafka_msg_partitioner_random(const rd_kafka_topic_t *rkt,
					 const void *key, size_t keylen,
					 int32_t partition_cnt,
					 void *opaque, void *msg_opaque);

/**
 * @brief Consistent partitioner.
 *
 * Uses consistent hashing to map identical keys onto identical partitions.
 *
 * @returns a \"random\" partition between 0 and \p partition_cnt - 1 based on
 *          the CRC value of the key
 */
RD_EXPORT
int32_t rd_kafka_msg_partitioner_consistent (const rd_kafka_topic_t *rkt,
					 const void *key, size_t keylen,
					 int32_t partition_cnt,
					 void *opaque, void *msg_opaque);

/**
 * @brief Consistent-Random partitioner.
 *
 * This is the default partitioner.
 * Uses consistent hashing to map identical keys onto identical partitions, and
 * messages without keys will be assigned via the random partitioner.
 *
 * @returns a \"random\" partition between 0 and \p partition_cnt - 1 based on
 *          the CRC value of the key (if provided)
 */
RD_EXPORT
int32_t rd_kafka_msg_partitioner_consistent_random (const rd_kafka_topic_t *rkt,
           const void *key, size_t keylen,
           int32_t partition_cnt,
           void *opaque, void *msg_opaque);


/**@}*/



/**
 * @name Main Kafka and Topic object handles
 * @{
 *
 *
 */




/**
 * @brief Creates a new Kafka handle and starts its operation according to the
 *        specified \p type (\p RD_KAFKA_CONSUMER or \p RD_KAFKA_PRODUCER).
 *
 * \p conf is an optional struct created with `rd_kafka_conf_new()` that will
 * be used instead of the default configuration.
 * The \p conf object is freed by this function on success and must not be used
 * or destroyed by the application sub-sequently.
 * See `rd_kafka_conf_set()` et.al for more information.
 *
 * \p errstr must be a pointer to memory of at least size \p errstr_size where
 * `rd_kafka_new()` may write a human readable error message in case the
 * creation of a new handle fails. In which case the function returns NULL.
 *
 * @remark \b RD_KAFKA_CONSUMER: When a new \p RD_KAFKA_CONSUMER
 *           rd_kafka_t handle is created it may either operate in the
 *           legacy simple consumer mode using the rd_kafka_consume_start()
 *           interface, or the High-level KafkaConsumer API.
 * @remark An application must only use one of these groups of APIs on a given
 *         rd_kafka_t RD_KAFKA_CONSUMER handle.

 *
 * @returns The Kafka handle on success or NULL on error (see \p errstr)
 *
 * @sa To destroy the Kafka handle, use rd_kafka_destroy().
 */
RD_EXPORT
rd_kafka_t *rd_kafka_new(rd_kafka_type_t type, rd_kafka_conf_t *conf,
			  char *errstr, size_t errstr_size);


/**
 * @brief Destroy Kafka handle.
 *
 * @remark This is a blocking operation.
 */
RD_EXPORT
void        rd_kafka_destroy(rd_kafka_t *rk);



/**
 * @brief Returns Kafka handle name.
 */
RD_EXPORT
const char *rd_kafka_name(const rd_kafka_t *rk);


/**
 * @brief Returns Kafka handle type.
 */
RD_EXPORT
rd_kafka_type_t rd_kafka_type(const rd_kafka_t *rk);


/**
 * @brief Returns this client's broker-assigned group member id 
 *
 * @remark This currently requires the high-level KafkaConsumer
 *
 * @returns An allocated string containing the current broker-assigned group
 *          member id, or NULL if not available.
 *          The application must free the string with \p free() or
 *          rd_kafka_mem_free()
 */
RD_EXPORT
char *rd_kafka_memberid (const rd_kafka_t *rk);



/**
 * @brief Returns the ClusterId as reported in broker metadata.
 *
 * @param timeout_ms If there is no cached value from metadata retrieval
 *                   then this specifies the maximum amount of time
 *                   (in milliseconds) the call will block waiting
 *                   for metadata to be retrieved.
 *                   Use 0 for non-blocking calls.

 * @remark Requires broker version >=0.10.0 and api.version.request=true.
 *
 * @remark The application must free the returned pointer
 *         using rd_kafka_mem_free().
 *
 * @returns a newly allocated string containing the ClusterId, or NULL
 *          if no ClusterId could be retrieved in the allotted timespan.
 */
RD_EXPORT
char *rd_kafka_clusterid (rd_kafka_t *rk, int timeout_ms);


/**
 * @brief Creates a new topic handle for topic named \p topic.
 *
 * \p conf is an optional configuration for the topic created with
 * `rd_kafka_topic_conf_new()` that will be used instead of the default
 * topic configuration.
 * The \p conf object is freed by this function and must not be used or
 * destroyed by the application sub-sequently.
 * See `rd_kafka_topic_conf_set()` et.al for more information.
 *
 * Topic handles are refcounted internally and calling rd_kafka_topic_new()
 * again with the same topic name will return the previous topic handle
 * without updating the original handle's configuration.
 * Applications must eventually call rd_kafka_topic_destroy() for each
 * succesfull call to rd_kafka_topic_new() to clear up resources.
 *
 * @returns the new topic handle or NULL on error (use rd_kafka_errno2err()
 *          to convert system \p errno to an rd_kafka_resp_err_t error code.
 *
 * @sa rd_kafka_topic_destroy()
 */
RD_EXPORT
rd_kafka_topic_t *rd_kafka_topic_new(rd_kafka_t *rk, const char *topic,
				      rd_kafka_topic_conf_t *conf);



/**
 * @brief Loose application's topic handle refcount as previously created
 *        with `rd_kafka_topic_new()`.
 *
 * @remark Since topic objects are refcounted (both internally and for the app)
 *         the topic object might not actually be destroyed by this call,
 *         but the application must consider the object destroyed.
 */
RD_EXPORT
void rd_kafka_topic_destroy(rd_kafka_topic_t *rkt);


/**
 * @brief Returns the topic name.
 */
RD_EXPORT
const char *rd_kafka_topic_name(const rd_kafka_topic_t *rkt);


/**
 * @brief Get the \p rkt_opaque pointer that was set in the topic configuration.
 */
RD_EXPORT
void *rd_kafka_topic_opaque (const rd_kafka_topic_t *rkt);


/**
 * @brief Unassigned partition.
 *
 * The unassigned partition is used by the producer API for messages
 * that should be partitioned using the configured or default partitioner.
 */
#define RD_KAFKA_PARTITION_UA  ((int32_t)-1)


/**
 * @brief Polls the provided kafka handle for events.
 *
 * Events will cause application provided callbacks to be called.
 *
 * The \p timeout_ms argument specifies the maximum amount of time
 * (in milliseconds) that the call will block waiting for events.
 * For non-blocking calls, provide 0 as \p timeout_ms.
 * To wait indefinately for an event, provide -1.
 *
 * @remark  An application should make sure to call poll() at regular
 *          intervals to serve any queued callbacks waiting to be called.
 *
 * Events:
 *   - delivery report callbacks  (if dr_cb/dr_msg_cb is configured) [producer]
 *   - error callbacks (rd_kafka_conf_set_error_cb()) [all]
 *   - stats callbacks (rd_kafka_conf_set_stats_cb()) [all]
 *   - throttle callbacks (rd_kafka_conf_set_throttle_cb()) [all]
 *
 * @returns the number of events served.
 */
RD_EXPORT
int rd_kafka_poll(rd_kafka_t *rk, int timeout_ms);


/**
 * @brief Cancels the current callback dispatcher (rd_kafka_poll(),
 *        rd_kafka_consume_callback(), etc).
 *
 * A callback may use this to force an immediate return to the calling
 * code (caller of e.g. rd_kafka_poll()) without processing any further
 * events.
 *
 * @remark This function MUST ONLY be called from within a librdkafka callback.
 */
RD_EXPORT
void rd_kafka_yield (rd_kafka_t *rk);




/**
 * @brief Pause producing or consumption for the provided list of partitions.
 *
 * Success or error is returned per-partition \p err in the \p partitions list.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_pause_partitions (rd_kafka_t *rk,
			   rd_kafka_topic_partition_list_t *partitions);



/**
 * @brief Resume producing consumption for the provided list of partitions.
 *
 * Success or error is returned per-partition \p err in the \p partitions list.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_resume_partitions (rd_kafka_t *rk,
			    rd_kafka_topic_partition_list_t *partitions);




/**
 * @brief Query broker for low (oldest/beginning) and high (newest/end) offsets
 *        for partition.
 *
 * Offsets are returned in \p *low and \p *high respectively.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or an error code on failure.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_query_watermark_offsets (rd_kafka_t *rk,
		      const char *topic, int32_t partition,
		      int64_t *low, int64_t *high, int timeout_ms);


/**
 * @brief Get last known low (oldest/beginning) and high (newest/end) offsets
 *        for partition.
 *
 * The low offset is updated periodically (if statistics.interval.ms is set)
 * while the high offset is updated on each fetched message set from the broker.
 *
 * If there is no cached offset (either low or high, or both) then
 * RD_KAFKA_OFFSET_INVALID will be returned for the respective offset.
 *
 * Offsets are returned in \p *low and \p *high respectively.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or an error code on failure.
 *
 * @remark Shall only be used with an active consumer instance.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_get_watermark_offsets (rd_kafka_t *rk,
				const char *topic, int32_t partition,
				int64_t *low, int64_t *high);



/**
 * @brief Look up the offsets for the given partitions by timestamp.
 *
 * The returned offset for each partition is the earliest offset whose
 * timestamp is greater than or equal to the given timestamp in the
 * corresponding partition.
 *
 * The timestamps to query are represented as \c offset in \p offsets
 * on input, and \c offset will contain the offset on output.
 *
 * The function will block for at most \p timeout_ms milliseconds.
 *
 * @remark Duplicate Topic+Partitions are not supported.
 * @remark Per-partition errors may be returned in \c rd_kafka_topic_partition_t.err
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR if offsets were be queried (do note
 *          that per-partition errors might be set),
 *          RD_KAFKA_RESP_ERR__TIMED_OUT if not all offsets could be fetched
 *          within \p timeout_ms,
 *          RD_KAFKA_RESP_ERR__INVALID_ARG if the \p offsets list is empty,
 *          RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION if all partitions are unknown,
 *          RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE if unable to query leaders
 *          for the given partitions.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_offsets_for_times (rd_kafka_t *rk,
                            rd_kafka_topic_partition_list_t *offsets,
                            int timeout_ms);


/**
 * @brief Free pointer returned by librdkafka
 *
 * This is typically an abstraction for the free(3) call and makes sure
 * the application can use the same memory allocator as librdkafka for
 * freeing pointers returned by librdkafka.
 *
 * In standard setups it is usually not necessary to use this interface
 * rather than the free(3) functione.
 *
 * @remark rd_kafka_mem_free() must only be used for pointers returned by APIs
 *         that explicitly mention using this function for freeing.
 */
RD_EXPORT
void rd_kafka_mem_free (rd_kafka_t *rk, void *ptr);


/**@}*/





/**
 * @name Queue API
 * @{
 *
 * Message queues allows the application to re-route consumed messages
 * from multiple topic+partitions into one single queue point.
 * This queue point containing messages from a number of topic+partitions
 * may then be served by a single rd_kafka_consume*_queue() call,
 * rather than one call per topic+partition combination.
 */


/**
 * @brief Create a new message queue.
 *
 * See rd_kafka_consume_start_queue(), rd_kafka_consume_queue(), et.al.
 */
RD_EXPORT
rd_kafka_queue_t *rd_kafka_queue_new(rd_kafka_t *rk);

/**
 * Destroy a queue, purging all of its enqueued messages.
 */
RD_EXPORT
void rd_kafka_queue_destroy(rd_kafka_queue_t *rkqu);


/**
 * @returns a reference to the main librdkafka event queue.
 * This is the queue served by rd_kafka_poll().
 *
 * Use rd_kafka_queue_destroy() to loose the reference.
 */
RD_EXPORT
rd_kafka_queue_t *rd_kafka_queue_get_main (rd_kafka_t *rk);


/**
 * @returns a reference to the librdkafka consumer queue.
 * This is the queue served by rd_kafka_consumer_poll().
 *
 * Use rd_kafka_queue_destroy() to loose the reference.
 *
 * @remark rd_kafka_queue_destroy() MUST be called on this queue
 *         prior to calling rd_kafka_consumer_close().
 */
RD_EXPORT
rd_kafka_queue_t *rd_kafka_queue_get_consumer (rd_kafka_t *rk);

/**
 * @returns a reference to the partition's queue, or NULL if
 *          partition is invalid.
 *
 * Use rd_kafka_queue_destroy() to loose the reference.
 *
 * @remark rd_kafka_queue_destroy() MUST be called on this queue
 * 
 * @remark This function only works on consumers.
 */
RD_EXPORT
rd_kafka_queue_t *rd_kafka_queue_get_partition (rd_kafka_t *rk,
                                                const char *topic,
                                                int32_t partition);

/**
 * @brief Forward/re-route queue \p src to \p dst.
 * If \p dst is \c NULL the forwarding is removed.
 *
 * The internal refcounts for both queues are increased.
 * 
 * @remark Regardless of whether \p dst is NULL or not, after calling this
 *         function, \p src will not forward it's fetch queue to the consumer
 *         queue.
 */
RD_EXPORT
void rd_kafka_queue_forward (rd_kafka_queue_t *src, rd_kafka_queue_t *dst);

/**
 * @brief Forward librdkafka logs (and debug) to the specified queue
 *        for serving with one of the ..poll() calls.
 *
 *        This allows an application to serve log callbacks (\c log_cb)
 *        in its thread of choice.
 *
 * @param rkqu Queue to forward logs to. If the value is NULL the logs
 *        are forwarded to the main queue.
 *
 * @remark The configuration property \c log.queue MUST also be set to true.
 *
 * @remark librdkafka maintains its own reference to the provided queue.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or an error code on error.
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_set_log_queue (rd_kafka_t *rk,
                                            rd_kafka_queue_t *rkqu);


/**
 * @returns the current number of elements in queue.
 */
RD_EXPORT
size_t rd_kafka_queue_length (rd_kafka_queue_t *rkqu);


/**
 * @brief Enable IO event triggering for queue.
 *
 * To ease integration with IO based polling loops this API
 * allows an application to create a separate file-descriptor
 * that librdkafka will write \p payload (of size \p size) to
 * whenever a new element is enqueued on a previously empty queue.
 *
 * To remove event triggering call with \p fd = -1.
 *
 * librdkafka will maintain a copy of the \p payload.
 *
 * @remark When using forwarded queues the IO event must only be enabled
 *         on the final forwarded-to (destination) queue.
 */
RD_EXPORT
void rd_kafka_queue_io_event_enable (rd_kafka_queue_t *rkqu, int fd,
				     const void *payload, size_t size);

/**@}*/

/**
 *
 * @name Simple Consumer API (legacy)
 * @{
 *
 */


#define RD_KAFKA_OFFSET_BEGINNING -2  /**< Start consuming from beginning of
				       *   kafka partition queue: oldest msg */
#define RD_KAFKA_OFFSET_END       -1  /**< Start consuming from end of kafka
				       *   partition queue: next msg */
#define RD_KAFKA_OFFSET_STORED -1000  /**< Start consuming from offset retrieved
				       *   from offset store */
#define RD_KAFKA_OFFSET_INVALID -1001 /**< Invalid offset */


/** @cond NO_DOC */
#define RD_KAFKA_OFFSET_TAIL_BASE -2000 /* internal: do not use */
/** @endcond */

/**
 * @brief Start consuming \p CNT messages from topic's current end offset.
 *
 * That is, if current end offset is 12345 and \p CNT is 200, it will start
 * consuming from offset \c 12345-200 = \c 12145. */
#define RD_KAFKA_OFFSET_TAIL(CNT)  (RD_KAFKA_OFFSET_TAIL_BASE - (CNT))

/**
 * @brief Start consuming messages for topic \p rkt and \p partition
 * at offset \p offset which may either be an absolute \c (0..N)
 * or one of the logical offsets:
 *  - RD_KAFKA_OFFSET_BEGINNING
 *  - RD_KAFKA_OFFSET_END
 *  - RD_KAFKA_OFFSET_STORED
 *  - RD_KAFKA_OFFSET_TAIL
 *
 * rdkafka will attempt to keep \c queued.min.messages (config property)
 * messages in the local queue by repeatedly fetching batches of messages
 * from the broker until the threshold is reached.
 *
 * The application shall use one of the `rd_kafka_consume*()` functions
 * to consume messages from the local queue, each kafka message being
 * represented as a `rd_kafka_message_t *` object.
 *
 * `rd_kafka_consume_start()` must not be called multiple times for the same
 * topic and partition without stopping consumption first with
 * `rd_kafka_consume_stop()`.
 *
 * @returns 0 on success or -1 on error in which case errno is set accordingly:
 *  - EBUSY    - Conflicts with an existing or previous subscription
 *               (RD_KAFKA_RESP_ERR__CONFLICT)
 *  - EINVAL   - Invalid offset, or incomplete configuration (lacking group.id)
 *               (RD_KAFKA_RESP_ERR__INVALID_ARG)
 *  - ESRCH    - requested \p partition is invalid.
 *               (RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION)
 *  - ENOENT   - topic is unknown in the Kafka cluster.
 *               (RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC)
 *
 * Use `rd_kafka_errno2err()` to convert sytem \c errno to `rd_kafka_resp_err_t`
 */
RD_EXPORT
int rd_kafka_consume_start(rd_kafka_topic_t *rkt, int32_t partition,
			    int64_t offset);

/**
 * @brief Same as rd_kafka_consume_start() but re-routes incoming messages to
 * the provided queue \p rkqu (which must have been previously allocated
 * with `rd_kafka_queue_new()`.
 *
 * The application must use one of the `rd_kafka_consume_*_queue()` functions
 * to receive fetched messages.
 *
 * `rd_kafka_consume_start_queue()` must not be called multiple times for the
 * same topic and partition without stopping consumption first with
 * `rd_kafka_consume_stop()`.
 * `rd_kafka_consume_start()` and `rd_kafka_consume_start_queue()` must not
 * be combined for the same topic and partition.
 */
RD_EXPORT
int rd_kafka_consume_start_queue(rd_kafka_topic_t *rkt, int32_t partition,
				  int64_t offset, rd_kafka_queue_t *rkqu);

/**
 * @brief Stop consuming messages for topic \p rkt and \p partition, purging
 * all messages currently in the local queue.
 *
 * NOTE: To enforce synchronisation this call will block until the internal
 *       fetcher has terminated and offsets are committed to configured
 *       storage method.
 *
 * The application needs to be stop all consumers before calling
 * `rd_kafka_destroy()` on the main object handle.
 *
 * @returns 0 on success or -1 on error (see `errno`).
 */
RD_EXPORT
int rd_kafka_consume_stop(rd_kafka_topic_t *rkt, int32_t partition);



/**
 * @brief Seek consumer for topic+partition to \p offset which is either an
 *        absolute or logical offset.
 *
 * If \p timeout_ms is not 0 the call will wait this long for the
 * seek to be performed. If the timeout is reached the internal state
 * will be unknown and this function returns `RD_KAFKA_RESP_ERR__TIMED_OUT`.
 * If \p timeout_ms is 0 it will initiate the seek but return
 * immediately without any error reporting (e.g., async).
 *
 * This call triggers a fetch queue barrier flush.
 *
 * @returns `RD_KAFKA_RESP_ERR__NO_ERROR` on success else an error code.
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_seek (rd_kafka_topic_t *rkt,
                                   int32_t partition,
                                   int64_t offset,
                                   int timeout_ms);


/**
 * @brief Consume a single message from topic \p rkt and \p partition
 *
 * \p timeout_ms is maximum amount of time to wait for a message to be received.
 * Consumer must have been previously started with `rd_kafka_consume_start()`.
 *
 * @returns a message object on success or \c NULL on error.
 * The message object must be destroyed with `rd_kafka_message_destroy()`
 * when the application is done with it.
 *
 * Errors (when returning NULL):
 *  - ETIMEDOUT - \p timeout_ms was reached with no new messages fetched.
 *  - ENOENT    - \p rkt + \p partition is unknown.
 *                 (no prior `rd_kafka_consume_start()` call)
 *
 * NOTE: The returned message's \c ..->err must be checked for errors.
 * NOTE: \c ..->err \c == \c RD_KAFKA_RESP_ERR__PARTITION_EOF signals that the
 *       end of the partition has been reached, which should typically not be
 *       considered an error. The application should handle this case
 *       (e.g., ignore).
 *
 * @remark on_consume() interceptors may be called from this function prior to
 *         passing message to application.
 */
RD_EXPORT
rd_kafka_message_t *rd_kafka_consume(rd_kafka_topic_t *rkt, int32_t partition,
				      int timeout_ms);



/**
 * @brief Consume up to \p rkmessages_size from topic \p rkt and \p partition
 *        putting a pointer to each message in the application provided
 *        array \p rkmessages (of size \p rkmessages_size entries).
 *
 * `rd_kafka_consume_batch()` provides higher throughput performance
 * than `rd_kafka_consume()`.
 *
 * \p timeout_ms is the maximum amount of time to wait for all of
 * \p rkmessages_size messages to be put into \p rkmessages.
 * If no messages were available within the timeout period this function
 * returns 0 and \p rkmessages remains untouched.
 * This differs somewhat from `rd_kafka_consume()`.
 *
 * The message objects must be destroyed with `rd_kafka_message_destroy()`
 * when the application is done with it.
 *
 * @returns the number of rkmessages added in \p rkmessages,
 * or -1 on error (same error codes as for `rd_kafka_consume()`.
 *
 * @sa rd_kafka_consume()
 *
 * @remark on_consume() interceptors may be called from this function prior to
 *         passing message to application.
 */
RD_EXPORT
ssize_t rd_kafka_consume_batch(rd_kafka_topic_t *rkt, int32_t partition,
				int timeout_ms,
				rd_kafka_message_t **rkmessages,
				size_t rkmessages_size);



/**
 * @brief Consumes messages from topic \p rkt and \p partition, calling
 * the provided callback for each consumed messsage.
 *
 * `rd_kafka_consume_callback()` provides higher throughput performance
 * than both `rd_kafka_consume()` and `rd_kafka_consume_batch()`.
 *
 * \p timeout_ms is the maximum amount of time to wait for one or more messages
 * to arrive.
 *
 * The provided \p consume_cb function is called for each message,
 * the application \b MUST \b NOT call `rd_kafka_message_destroy()` on the
 * provided \p rkmessage.
 *
 * The \p opaque argument is passed to the 'consume_cb' as \p opaque.
 *
 * @returns the number of messages processed or -1 on error.
 *
 * @sa rd_kafka_consume()
 *
 * @remark on_consume() interceptors may be called from this function prior to
 *         passing message to application.
 */
RD_EXPORT
int rd_kafka_consume_callback(rd_kafka_topic_t *rkt, int32_t partition,
			       int timeout_ms,
			       void (*consume_cb) (rd_kafka_message_t
						   *rkmessage,
						   void *opaque),
			       void *opaque);


/**
 * @name Simple Consumer API (legacy): Queue consumers
 * @{
 *
 * The following `..._queue()` functions are analogue to the functions above
 * but reads messages from the provided queue \p rkqu instead.
 * \p rkqu must have been previously created with `rd_kafka_queue_new()`
 * and the topic consumer must have been started with
 * `rd_kafka_consume_start_queue()` utilising the the same queue.
 */

/**
 * @brief Consume from queue
 *
 * @sa rd_kafka_consume()
 */
RD_EXPORT
rd_kafka_message_t *rd_kafka_consume_queue(rd_kafka_queue_t *rkqu,
					    int timeout_ms);

/**
 * @brief Consume batch of messages from queue
 *
 * @sa rd_kafka_consume_batch()
 */
RD_EXPORT
ssize_t rd_kafka_consume_batch_queue(rd_kafka_queue_t *rkqu,
				      int timeout_ms,
				      rd_kafka_message_t **rkmessages,
				      size_t rkmessages_size);

/**
 * @brief Consume multiple messages from queue with callback
 *
 * @sa rd_kafka_consume_callback()
 */
RD_EXPORT
int rd_kafka_consume_callback_queue(rd_kafka_queue_t *rkqu,
				     int timeout_ms,
				     void (*consume_cb) (rd_kafka_message_t
							 *rkmessage,
							 void *opaque),
				     void *opaque);


/**@}*/




/**
 * @name Simple Consumer API (legacy): Topic+partition offset store.
 * @{
 *
 * If \c auto.commit.enable is true the offset is stored automatically prior to
 * returning of the message(s) in each of the rd_kafka_consume*() functions
 * above.
 */


/**
 * @brief Store offset \p offset for topic \p rkt partition \p partition.
 *
 * The offset will be committed (written) to the offset store according
 * to \c `auto.commit.interval.ms` or manual offset-less commit()
 *
 * @remark \c `enable.auto.offset.store` must be set to "false" when using this API.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or an error code on error.
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_offset_store(rd_kafka_topic_t *rkt,
					   int32_t partition, int64_t offset);


/**
 * @brief Store offsets for next auto-commit for one or more partitions.
 *
 * The offset will be committed (written) to the offset store according
 * to \c `auto.commit.interval.ms` or manual offset-less commit().
 *
 * Per-partition success/error status propagated through each partition's
 * \c .err field.
 *
 * @remark \c `enable.auto.offset.store` must be set to "false" when using this API.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success, or
 *          RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION if none of the
 *          offsets could be stored, or
 *          RD_KAFKA_RESP_ERR__INVALID_ARG if \c enable.auto.offset.store is true.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_offsets_store(rd_kafka_t *rk,
                       rd_kafka_topic_partition_list_t *offsets);
/**@}*/




/**
 * @name KafkaConsumer (C)
 * @{
 * @brief High-level KafkaConsumer C API
 *
 *
 *
 */

/**
 * @brief Subscribe to topic set using balanced consumer groups.
 *
 * Wildcard (regex) topics are supported by the librdkafka assignor:
 * any topic name in the \p topics list that is prefixed with \c \"^\" will
 * be regex-matched to the full list of topics in the cluster and matching
 * topics will be added to the subscription list.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or
 *          RD_KAFKA_RESP_ERR__INVALID_ARG if list is empty, contains invalid
 *          topics or regexes.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_subscribe (rd_kafka_t *rk,
                    const rd_kafka_topic_partition_list_t *topics);


/**
 * @brief Unsubscribe from the current subscription set.
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_unsubscribe (rd_kafka_t *rk);


/**
 * @brief Returns the current topic subscription
 *
 * @returns An error code on failure, otherwise \p topic is updated
 *          to point to a newly allocated topic list (possibly empty).
 *
 * @remark The application is responsible for calling
 *         rd_kafka_topic_partition_list_destroy on the returned list.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_subscription (rd_kafka_t *rk,
                       rd_kafka_topic_partition_list_t **topics);



/**
 * @brief Poll the consumer for messages or events.
 *
 * Will block for at most \p timeout_ms milliseconds.
 *
 * @remark  An application should make sure to call consumer_poll() at regular
 *          intervals, even if no messages are expected, to serve any
 *          queued callbacks waiting to be called. This is especially
 *          important when a rebalance_cb has been registered as it needs
 *          to be called and handled properly to synchronize internal
 *          consumer state.
 *
 * @returns A message object which is a proper message if \p ->err is
 *          RD_KAFKA_RESP_ERR_NO_ERROR, or an event or error for any other
 *          value.
 *
 * @remark on_consume() interceptors may be called from this function prior to
 *         passing message to application.
 *
 * @sa rd_kafka_message_t
 */
RD_EXPORT
rd_kafka_message_t *rd_kafka_consumer_poll (rd_kafka_t *rk, int timeout_ms);

/**
 * @brief Close down the KafkaConsumer.
 *
 * @remark This call will block until the consumer has revoked its assignment,
 *         calling the \c rebalance_cb if it is configured, committed offsets
 *         to broker, and left the consumer group.
 *         The maximum blocking time is roughly limited to session.timeout.ms.
 *
 * @returns An error code indicating if the consumer close was succesful
 *          or not.
 *
 * @remark The application still needs to call rd_kafka_destroy() after
 *         this call finishes to clean up the underlying handle resources.
 *
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_consumer_close (rd_kafka_t *rk);



/**
 * @brief Atomic assignment of partitions to consume.
 *
 * The new \p partitions will replace the existing assignment.
 *
 * When used from a rebalance callback the application shall pass the
 * partition list passed to the callback (or a copy of it) (even if the list
 * is empty) rather than NULL to maintain internal join state.

 * A zero-length \p partitions will treat the partitions as a valid,
 * albeit empty, assignment, and maintain internal state, while a \c NULL
 * value for \p partitions will reset and clear the internal state.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_assign (rd_kafka_t *rk,
                 const rd_kafka_topic_partition_list_t *partitions);

/**
 * @brief Returns the current partition assignment
 *
 * @returns An error code on failure, otherwise \p partitions is updated
 *          to point to a newly allocated partition list (possibly empty).
 *
 * @remark The application is responsible for calling
 *         rd_kafka_topic_partition_list_destroy on the returned list.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_assignment (rd_kafka_t *rk,
                     rd_kafka_topic_partition_list_t **partitions);




/**
 * @brief Commit offsets on broker for the provided list of partitions.
 *
 * \p offsets should contain \c topic, \c partition, \c offset and possibly
 * \c metadata.
 * If \p offsets is NULL the current partition assignment will be used instead.
 *
 * If \p async is false this operation will block until the broker offset commit
 * is done, returning the resulting success or error code.
 *
 * If a rd_kafka_conf_set_offset_commit_cb() offset commit callback has been
 * configured the callback will be enqueued for a future call to
 * rd_kafka_poll(), rd_kafka_consumer_poll() or similar.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_commit (rd_kafka_t *rk, const rd_kafka_topic_partition_list_t *offsets,
                 int async);


/**
 * @brief Commit message's offset on broker for the message's partition.
 *
 * @sa rd_kafka_commit
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_commit_message (rd_kafka_t *rk, const rd_kafka_message_t *rkmessage,
                         int async);


/**
 * @brief Commit offsets on broker for the provided list of partitions.
 *
 * See rd_kafka_commit for \p offsets semantics.
 *
 * The result of the offset commit will be posted on the provided \p rkqu queue.
 *
 * If the application uses one of the poll APIs (rd_kafka_poll(),
 * rd_kafka_consumer_poll(), rd_kafka_queue_poll(), ..) to serve the queue
 * the \p cb callback is required. \p opaque is passed to the callback.
 *
 * If using the event API the callback is ignored and the offset commit result
 * will be returned as an RD_KAFKA_EVENT_COMMIT event. The \p opaque
 * value will be available with rd_kafka_event_opaque()
 *
 * If \p rkqu is NULL a temporary queue will be created and the callback will
 * be served by this call.
 *
 * @sa rd_kafka_commit()
 * @sa rd_kafka_conf_set_offset_commit_cb()
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_commit_queue (rd_kafka_t *rk,
		       const rd_kafka_topic_partition_list_t *offsets,
		       rd_kafka_queue_t *rkqu,
		       void (*cb) (rd_kafka_t *rk,
				   rd_kafka_resp_err_t err,
				   rd_kafka_topic_partition_list_t *offsets,
				   void *opaque),
		       void *opaque);


/**
 * @brief Retrieve committed offsets for topics+partitions.
 *
 * The \p offset field of each requested partition will either be set to
 * stored offset or to RD_KAFKA_OFFSET_INVALID in case there was no stored
 * offset for that partition.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success in which case the
 *          \p offset or \p err field of each \p partitions' element is filled
 *          in with the stored offset, or a partition specific error.
 *          Else returns an error code.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_committed (rd_kafka_t *rk,
		    rd_kafka_topic_partition_list_t *partitions,
		    int timeout_ms);



/**
 * @brief Retrieve current positions (offsets) for topics+partitions.
 *
 * The \p offset field of each requested partition will be set to the offset
 * of the last consumed message + 1, or RD_KAFKA_OFFSET_INVALID in case there was
 * no previous message.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success in which case the
 *          \p offset or \p err field of each \p partitions' element is filled
 *          in with the stored offset, or a partition specific error.
 *          Else returns an error code.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_position (rd_kafka_t *rk,
		   rd_kafka_topic_partition_list_t *partitions);


/**@}*/



/**
 * @name Producer API
 * @{
 *
 *
 */


/**
 * @brief Producer message flags
 */
#define RD_KAFKA_MSG_F_FREE  0x1 /**< Delegate freeing of payload to rdkafka. */
#define RD_KAFKA_MSG_F_COPY  0x2 /**< rdkafka will make a copy of the payload. */
#define RD_KAFKA_MSG_F_BLOCK 0x4 /**< Block produce*() on message queue full.
				  *   WARNING: If a delivery report callback
				  *            is used the application MUST
				  *            call rd_kafka_poll() (or equiv.)
				  *            to make sure delivered messages
				  *            are drained from the internal
				  *            delivery report queue.
				  *            Failure to do so will result
				  *            in indefinately blocking on
				  *            the produce() call when the
				  *            message queue is full.
				  */



/**
 * @brief Produce and send a single message to broker.
 *
 * \p rkt is the target topic which must have been previously created with
 * `rd_kafka_topic_new()`.
 *
 * `rd_kafka_produce()` is an asynch non-blocking API.
 *
 * \p partition is the target partition, either:
 *   - RD_KAFKA_PARTITION_UA (unassigned) for
 *     automatic partitioning using the topic's partitioner function, or
 *   - a fixed partition (0..N)
 *
 * \p msgflags is zero or more of the following flags OR:ed together:
 *    RD_KAFKA_MSG_F_BLOCK - block \p produce*() call if
 *                           \p queue.buffering.max.messages or
 *                           \p queue.buffering.max.kbytes are exceeded.
 *                           Messages are considered in-queue from the point they
 *                           are accepted by produce() until their corresponding
 *                           delivery report callback/event returns.
 *                           It is thus a requirement to call 
 *                           rd_kafka_poll() (or equiv.) from a separate
 *                           thread when F_BLOCK is used.
 *                           See WARNING on \c RD_KAFKA_MSG_F_BLOCK above.
 *
 *    RD_KAFKA_MSG_F_FREE - rdkafka will free(3) \p payload when it is done
 *                          with it.
 *    RD_KAFKA_MSG_F_COPY - the \p payload data will be copied and the 
 *                          \p payload pointer will not be used by rdkafka
 *                          after the call returns.
 *
 *    .._F_FREE and .._F_COPY are mutually exclusive.
 *
 *    If the function returns -1 and RD_KAFKA_MSG_F_FREE was specified, then
 *    the memory associated with the payload is still the caller's
 *    responsibility.
 *
 * \p payload is the message payload of size \p len bytes.
 *
 * \p key is an optional message key of size \p keylen bytes, if non-NULL it
 * will be passed to the topic partitioner as well as be sent with the
 * message to the broker and passed on to the consumer.
 *
 * \p msg_opaque is an optional application-provided per-message opaque
 * pointer that will provided in the delivery report callback (`dr_cb`) for
 * referencing this message.
 *
 * @remark on_send() and on_acknowledgement() interceptors may be called
 *         from this function. on_acknowledgement() will only be called if the
 *         message fails partitioning.
 *
 * @returns 0 on success or -1 on error in which case errno is set accordingly:
 *  - ENOBUFS  - maximum number of outstanding messages has been reached:
 *               "queue.buffering.max.messages"
 *               (RD_KAFKA_RESP_ERR__QUEUE_FULL)
 *  - EMSGSIZE - message is larger than configured max size:
 *               "messages.max.bytes".
 *               (RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE)
 *  - ESRCH    - requested \p partition is unknown in the Kafka cluster.
 *               (RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION)
 *  - ENOENT   - topic is unknown in the Kafka cluster.
 *               (RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC)
 *
 * @sa Use rd_kafka_errno2err() to convert `errno` to rdkafka error code.
 */
RD_EXPORT
int rd_kafka_produce(rd_kafka_topic_t *rkt, int32_t partition,
		      int msgflags,
		      void *payload, size_t len,
		      const void *key, size_t keylen,
		      void *msg_opaque);


/**
 * @brief Produce and send a single message to broker.
 *
 * The message is defined by a va-arg list using \c rd_kafka_vtype_t
 * tag tuples which must be terminated with a single \c RD_KAFKA_V_END.
 *
 * @returns \c RD_KAFKA_RESP_ERR_NO_ERROR on success, else an error code.
 *
 * @sa rd_kafka_produce, RD_KAFKA_V_END
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_producev (rd_kafka_t *rk, ...);


/**
 * @brief Produce multiple messages.
 *
 * If partition is RD_KAFKA_PARTITION_UA the configured partitioner will
 * be run for each message (slower), otherwise the messages will be enqueued
 * to the specified partition directly (faster).
 *
 * The messages are provided in the array \p rkmessages of count \p message_cnt
 * elements.
 * The \p partition and \p msgflags are used for all provided messages.
 *
 * Honoured \p rkmessages[] fields are:
 *  - payload,len    Message payload and length
 *  - key,key_len    Optional message key
 *  - _private       Message opaque pointer (msg_opaque)
 *  - err            Will be set according to success or failure.
 *                   Application only needs to check for errors if
 *                   return value != \p message_cnt.
 *
 * @returns the number of messages succesfully enqueued for producing.
 */
RD_EXPORT
int rd_kafka_produce_batch(rd_kafka_topic_t *rkt, int32_t partition,
                            int msgflags,
                            rd_kafka_message_t *rkmessages, int message_cnt);




/**
 * @brief Wait until all outstanding produce requests, et.al, are completed.
 *        This should typically be done prior to destroying a producer instance
 *        to make sure all queued and in-flight produce requests are completed
 *        before terminating.
 *
 * @remark This function will call rd_kafka_poll() and thus trigger callbacks.
 *
 * @returns RD_KAFKA_RESP_ERR__TIMED_OUT if \p timeout_ms was reached before all
 *          outstanding requests were completed, else RD_KAFKA_RESP_ERR_NO_ERROR
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_flush (rd_kafka_t *rk, int timeout_ms);


/**@}*/


/**
* @name Metadata API
* @{
*
*
*/


/**
 * @brief Broker information
 */
typedef struct rd_kafka_metadata_broker {
        int32_t     id;             /**< Broker Id */
        char       *host;           /**< Broker hostname */
        int         port;           /**< Broker listening port */
} rd_kafka_metadata_broker_t;

/**
 * @brief Partition information
 */
typedef struct rd_kafka_metadata_partition {
        int32_t     id;             /**< Partition Id */
        rd_kafka_resp_err_t err;    /**< Partition error reported by broker */
        int32_t     leader;         /**< Leader broker */
        int         replica_cnt;    /**< Number of brokers in \p replicas */
        int32_t    *replicas;       /**< Replica brokers */
        int         isr_cnt;        /**< Number of ISR brokers in \p isrs */
        int32_t    *isrs;           /**< In-Sync-Replica brokers */
} rd_kafka_metadata_partition_t;

/**
 * @brief Topic information
 */
typedef struct rd_kafka_metadata_topic {
        char       *topic;          /**< Topic name */
        int         partition_cnt;  /**< Number of partitions in \p partitions*/
        struct rd_kafka_metadata_partition *partitions; /**< Partitions */
        rd_kafka_resp_err_t err;    /**< Topic error reported by broker */
} rd_kafka_metadata_topic_t;


/**
 * @brief Metadata container
 */
typedef struct rd_kafka_metadata {
        int         broker_cnt;     /**< Number of brokers in \p brokers */
        struct rd_kafka_metadata_broker *brokers;  /**< Brokers */

        int         topic_cnt;      /**< Number of topics in \p topics */
        struct rd_kafka_metadata_topic *topics;    /**< Topics */

        int32_t     orig_broker_id;   /**< Broker originating this metadata */
        char       *orig_broker_name; /**< Name of originating broker */
} rd_kafka_metadata_t;


/**
 * @brief Request Metadata from broker.
 *
 * Parameters:
 *  - \p all_topics  if non-zero: request info about all topics in cluster,
 *                   if zero: only request info about locally known topics.
 *  - \p only_rkt    only request info about this topic
 *  - \p metadatap   pointer to hold metadata result.
 *                   The \p *metadatap pointer must be released
 *                   with rd_kafka_metadata_destroy().
 *  - \p timeout_ms  maximum response time before failing.
 *
 * Returns RD_KAFKA_RESP_ERR_NO_ERROR on success (in which case *metadatap)
 * will be set, else RD_KAFKA_RESP_ERR__TIMED_OUT on timeout or
 * other error code on error.
 */
RD_EXPORT
rd_kafka_resp_err_t
rd_kafka_metadata (rd_kafka_t *rk, int all_topics,
                   rd_kafka_topic_t *only_rkt,
                   const struct rd_kafka_metadata **metadatap,
                   int timeout_ms);

/**
 * @brief Release metadata memory.
 */
RD_EXPORT
void rd_kafka_metadata_destroy(const struct rd_kafka_metadata *metadata);


/**@}*/



/**
* @name Client group information
* @{
*
*
*/


/**
 * @brief Group member information
 *
 * For more information on \p member_metadata format, see
 * https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol#AGuideToTheKafkaProtocol-GroupMembershipAPI
 *
 */
struct rd_kafka_group_member_info {
        char *member_id;            /**< Member id (generated by broker) */
        char *client_id;            /**< Client's \p client.id */
        char *client_host;          /**< Client's hostname */
        void *member_metadata;      /**< Member metadata (binary),
                                     *   format depends on \p protocol_type. */
        int   member_metadata_size; /**< Member metadata size in bytes */
        void *member_assignment;    /**< Member assignment (binary),
                                     *    format depends on \p protocol_type. */
        int   member_assignment_size; /**< Member assignment size in bytes */
};

/**
 * @brief Group information
 */
struct rd_kafka_group_info {
        struct rd_kafka_metadata_broker broker; /**< Originating broker info */
        char *group;                            /**< Group name */
        rd_kafka_resp_err_t err;                /**< Broker-originated error */
        char *state;                            /**< Group state */
        char *protocol_type;                    /**< Group protocol type */
        char *protocol;                         /**< Group protocol */
        struct rd_kafka_group_member_info *members; /**< Group members */
        int   member_cnt;                       /**< Group member count */
};

/**
 * @brief List of groups
 *
 * @sa rd_kafka_group_list_destroy() to release list memory.
 */
struct rd_kafka_group_list {
        struct rd_kafka_group_info *groups;   /**< Groups */
        int    group_cnt;                     /**< Group count */
};


/**
 * @brief List and describe client groups in cluster.
 *
 * \p group is an optional group name to describe, otherwise (\p NULL) all
 * groups are returned.
 *
 * \p timeout_ms is the (approximate) maximum time to wait for response
 * from brokers and must be a positive value.
 *
 * @returns \c RD_KAFKA_RESP_ERR__NO_ERROR on success and \p grplistp is
 *           updated to point to a newly allocated list of groups.
 *           \c RD_KAFKA_RESP_ERR__PARTIAL if not all brokers responded
 *           in time but at least one group is returned in  \p grplistlp.
 *           \c RD_KAFKA_RESP_ERR__TIMED_OUT if no groups were returned in the
 *           given timeframe but not all brokers have yet responded, or
 *           if the list of brokers in the cluster could not be obtained within
 *           the given timeframe.
 *           \c RD_KAFKA_RESP_ERR__TRANSPORT if no brokers were found.
 *           Other error codes may also be returned from the request layer.
 *
 *           The \p grplistp remains untouched if any error code is returned,
 *           with the exception of RD_KAFKA_RESP_ERR__PARTIAL which behaves
 *           as RD_KAFKA_RESP_ERR__NO_ERROR (success) but with an incomplete
 *           group list.
 *
 * @sa Use rd_kafka_group_list_destroy() to release list memory.
 */
RD_EXPORT
rd_kafka_resp_err_t
rd_kafka_list_groups (rd_kafka_t *rk, const char *group,
                      const struct rd_kafka_group_list **grplistp,
                      int timeout_ms);

/**
 * @brief Release list memory
 */
RD_EXPORT
void rd_kafka_group_list_destroy (const struct rd_kafka_group_list *grplist);


/**@}*/



/**
 * @name Miscellaneous APIs
 * @{
 *
 */


/**
 * @brief Adds one or more brokers to the kafka handle's list of initial
 *        bootstrap brokers.
 *
 * Additional brokers will be discovered automatically as soon as rdkafka
 * connects to a broker by querying the broker metadata.
 *
 * If a broker name resolves to multiple addresses (and possibly
 * address families) all will be used for connection attempts in
 * round-robin fashion.
 *
 * \p brokerlist is a ,-separated list of brokers in the format:
 *   \c \<broker1\>,\<broker2\>,..
 * Where each broker is in either the host or URL based format:
 *   \c \<host\>[:\<port\>]
 *   \c \<proto\>://\<host\>[:port]
 * \c \<proto\> is either \c PLAINTEXT, \c SSL, \c SASL, \c SASL_PLAINTEXT
 * The two formats can be mixed but ultimately the value of the
 * `security.protocol` config property decides what brokers are allowed.
 *
 * Example:
 *    brokerlist = "broker1:10000,broker2"
 *    brokerlist = "SSL://broker3:9000,ssl://broker2"
 *
 * @returns the number of brokers successfully added.
 *
 * @remark Brokers may also be defined with the \c metadata.broker.list or
 *         \c bootstrap.servers configuration property (preferred method).
 */
RD_EXPORT
int rd_kafka_brokers_add(rd_kafka_t *rk, const char *brokerlist);




/**
 * @brief Set logger function.
 *
 * The default is to print to stderr, but a syslog logger is also available,
 * see rd_kafka_log_(print|syslog) for the builtin alternatives.
 * Alternatively the application may provide its own logger callback.
 * Or pass 'func' as NULL to disable logging.
 *
 * @deprecated Use rd_kafka_conf_set_log_cb()
 *
 * @remark \p rk may be passed as NULL in the callback.
 */
RD_EXPORT RD_DEPRECATED
void rd_kafka_set_logger(rd_kafka_t *rk,
			  void (*func) (const rd_kafka_t *rk, int level,
					const char *fac, const char *buf));


/**
 * @brief Specifies the maximum logging level produced by
 *        internal kafka logging and debugging.
 *
 * If the \p \"debug\" configuration property is set the level is automatically
 * adjusted to \c LOG_DEBUG (7).
 */
RD_EXPORT
void rd_kafka_set_log_level(rd_kafka_t *rk, int level);


/**
 * @brief Builtin (default) log sink: print to stderr
 */
RD_EXPORT
void rd_kafka_log_print(const rd_kafka_t *rk, int level,
			 const char *fac, const char *buf);


/**
 * @brief Builtin log sink: print to syslog.
 */
RD_EXPORT
void rd_kafka_log_syslog(const rd_kafka_t *rk, int level,
			  const char *fac, const char *buf);


/**
 * @brief Returns the current out queue length.
 *
 * The out queue contains messages waiting to be sent to, or acknowledged by,
 * the broker.
 *
 * An application should wait for this queue to reach zero before terminating
 * to make sure outstanding requests (such as offset commits) are fully
 * processed.
 *
 * @returns number of messages in the out queue.
 */
RD_EXPORT
int         rd_kafka_outq_len(rd_kafka_t *rk);



/**
 * @brief Dumps rdkafka's internal state for handle \p rk to stream \p fp
 *
 * This is only useful for debugging rdkafka, showing state and statistics
 * for brokers, topics, partitions, etc.
 */
RD_EXPORT
void rd_kafka_dump(FILE *fp, rd_kafka_t *rk);



/**
 * @brief Retrieve the current number of threads in use by librdkafka.
 *
 * Used by regression tests.
 */
RD_EXPORT
int rd_kafka_thread_cnt(void);


/**
 * @brief Wait for all rd_kafka_t objects to be destroyed.
 *
 * Returns 0 if all kafka objects are now destroyed, or -1 if the
 * timeout was reached.
 *
 * @remark This function is deprecated.
 */
RD_EXPORT
int rd_kafka_wait_destroyed(int timeout_ms);


/**
 * @brief Run librdkafka's built-in unit-tests.
 *
 * @returns the number of failures, or 0 if all tests passed.
 */
RD_EXPORT
int rd_kafka_unittest (void);


/**@}*/




/**
 * @name Experimental APIs
 * @{
 */

/**
 * @brief Redirect the main (rd_kafka_poll()) queue to the KafkaConsumer's
 *        queue (rd_kafka_consumer_poll()).
 *
 * @warning It is not permitted to call rd_kafka_poll() after directing the
 *          main queue with rd_kafka_poll_set_consumer().
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_poll_set_consumer (rd_kafka_t *rk);


/**@}*/

/**
 * @name Event interface
 *
 * @brief The event API provides an alternative pollable non-callback interface
 *        to librdkafka's message and event queues.
 *
 * @{
 */


/**
 * @brief Event types
 */
typedef int rd_kafka_event_type_t;
#define RD_KAFKA_EVENT_NONE          0x0
#define RD_KAFKA_EVENT_DR            0x1  /**< Producer Delivery report batch */
#define RD_KAFKA_EVENT_FETCH         0x2  /**< Fetched message (consumer) */
#define RD_KAFKA_EVENT_LOG           0x4  /**< Log message */
#define RD_KAFKA_EVENT_ERROR         0x8  /**< Error */
#define RD_KAFKA_EVENT_REBALANCE     0x10 /**< Group rebalance (consumer) */
#define RD_KAFKA_EVENT_OFFSET_COMMIT 0x20 /**< Offset commit result */
#define RD_KAFKA_EVENT_STATS         0x40 /**< Stats */


typedef struct rd_kafka_op_s rd_kafka_event_t;


/**
 * @returns the event type for the given event.
 *
 * @remark As a convenience it is okay to pass \p rkev as NULL in which case
 *         RD_KAFKA_EVENT_NONE is returned.
 */
RD_EXPORT
rd_kafka_event_type_t rd_kafka_event_type (const rd_kafka_event_t *rkev);

/**
 * @returns the event type's name for the given event.
 *
 * @remark As a convenience it is okay to pass \p rkev as NULL in which case
 *         the name for RD_KAFKA_EVENT_NONE is returned.
 */
RD_EXPORT
const char *rd_kafka_event_name (const rd_kafka_event_t *rkev);


/**
 * @brief Destroy an event.
 *
 * @remark Any references to this event, such as extracted messages,
 *         will not be usable after this call.
 *
 * @remark As a convenience it is okay to pass \p rkev as NULL in which case
 *         no action is performed.
 */
RD_EXPORT
void rd_kafka_event_destroy (rd_kafka_event_t *rkev);


/**
 * @returns the next message from an event.
 *
 * Call repeatedly until it returns NULL.
 *
 * Event types:
 *  - RD_KAFKA_EVENT_FETCH  (1 message)
 *  - RD_KAFKA_EVENT_DR     (>=1 message(s))
 *
 * @remark The returned message(s) MUST NOT be
 *         freed with rd_kafka_message_destroy().
 *
 * @remark on_consume() interceptor may be called
 *         from this function prior to passing message to application.
 */
RD_EXPORT
const rd_kafka_message_t *rd_kafka_event_message_next (rd_kafka_event_t *rkev);


/**
 * @brief Extacts \p size message(s) from the event into the
 *        pre-allocated array \p rkmessages.
 *
 * Event types:
 *  - RD_KAFKA_EVENT_FETCH  (1 message)
 *  - RD_KAFKA_EVENT_DR     (>=1 message(s))
 *
 * @returns the number of messages extracted.
 *
 * @remark on_consume() interceptor may be called
 *         from this function prior to passing message to application.
 */
RD_EXPORT
size_t rd_kafka_event_message_array (rd_kafka_event_t *rkev,
				     const rd_kafka_message_t **rkmessages,
				     size_t size);


/**
 * @returns the number of remaining messages in the event.
 *
 * Event types:
 *  - RD_KAFKA_EVENT_FETCH  (1 message)
 *  - RD_KAFKA_EVENT_DR     (>=1 message(s))
 */
RD_EXPORT
size_t rd_kafka_event_message_count (rd_kafka_event_t *rkev);


/**
 * @returns the error code for the event.
 *
 * Event types:
 *  - all
 */
RD_EXPORT
rd_kafka_resp_err_t rd_kafka_event_error (rd_kafka_event_t *rkev);


/**
 * @returns the error string (if any).
 *          An application should check that rd_kafka_event_error() returns
 *          non-zero before calling this function.
 *
 * Event types:
 *  - all
 */
RD_EXPORT
const char *rd_kafka_event_error_string (rd_kafka_event_t *rkev);



/**
 * @returns the user opaque (if any)
 *
 * Event types:
 *  - RD_KAFKA_OFFSET_COMMIT
 */
RD_EXPORT
void *rd_kafka_event_opaque (rd_kafka_event_t *rkev);


/**
 * @brief Extract log message from the event.
 *
 * Event types:
 *  - RD_KAFKA_EVENT_LOG
 *
 * @returns 0 on success or -1 if unsupported event type.
 */
RD_EXPORT
int rd_kafka_event_log (rd_kafka_event_t *rkev,
			const char **fac, const char **str, int *level);


/**
 * @brief Extract stats from the event.
 *
 * Event types:
 *  - RD_KAFKA_EVENT_STATS
 *
 * @returns stats json string.
 *
 * @remark the returned string will be freed automatically along with the event object
 *
 */
RD_EXPORT
const char *rd_kafka_event_stats (rd_kafka_event_t *rkev);


/**
 * @returns the topic partition list from the event.
 *
 * @remark The list MUST NOT be freed with rd_kafka_topic_partition_list_destroy()
 *
 * Event types:
 *  - RD_KAFKA_EVENT_REBALANCE
 *  - RD_KAFKA_EVENT_OFFSET_COMMIT
 */
RD_EXPORT rd_kafka_topic_partition_list_t *
rd_kafka_event_topic_partition_list (rd_kafka_event_t *rkev);


/**
 * @returns a newly allocated topic_partition container, if applicable for the event type,
 *          else NULL.
 *
 * @remark The returned pointer MUST be freed with rd_kafka_topic_partition_destroy().
 *
 * Event types:
 *   RD_KAFKA_EVENT_ERROR  (for partition level errors)
 */
RD_EXPORT rd_kafka_topic_partition_t *
rd_kafka_event_topic_partition (rd_kafka_event_t *rkev);


/**
 * @brief Poll a queue for an event for max \p timeout_ms.
 *
 * @returns an event, or NULL.
 *
 * @remark Use rd_kafka_event_destroy() to free the event.
 */
RD_EXPORT
rd_kafka_event_t *rd_kafka_queue_poll (rd_kafka_queue_t *rkqu, int timeout_ms);

/**
* @brief Poll a queue for events served through callbacks for max \p timeout_ms.
*
* @returns the number of events served.
*
* @remark This API must only be used for queues with callbacks registered
*         for all expected event types. E.g., not a message queue.
*/
RD_EXPORT
int rd_kafka_queue_poll_callback (rd_kafka_queue_t *rkqu, int timeout_ms);


/**@}*/


/**
 * @name Plugin interface
 *
 * @brief A plugin interface that allows external runtime-loaded libraries
 *        to integrate with a client instance without modifications to
 *        the application code.
 *
 *        Plugins are loaded when referenced through the `plugin.library.paths`
 *        configuration property and operates on the \c rd_kafka_conf_t
 *        object prior \c rd_kafka_t instance creation.
 *
 * @warning Plugins require the application to link librdkafka dynamically
 *          and not statically. Failure to do so will lead to missing symbols
 *          or finding symbols in another librdkafka library than the
 *          application was linked with.
 */


/**
 * @brief Plugin's configuration initializer method called each time the
 *        library is referenced from configuration (even if previously loaded by
 *        another client instance).
 *
 * @remark This method MUST be implemented by plugins and have the symbol name
 *         \c conf_init
 *
 * @param conf Configuration set up to this point.
 * @param plug_opaquep Plugin can set this pointer to a per-configuration
 *                     opaque pointer.
 * @param errstr String buffer of size \p errstr_size where plugin must write
 *               a human readable error string in the case the initializer
 *               fails (returns non-zero).
 *
 * @remark A plugin may add an on_conf_destroy() interceptor to clean up
 *         plugin-specific resources created in the plugin's conf_init() method.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or an error code on error.
 */
typedef rd_kafka_resp_err_t
(rd_kafka_plugin_f_conf_init_t) (rd_kafka_conf_t *conf,
                                 void **plug_opaquep,
                                 char *errstr, size_t errstr_size);

/**@}*/



/**
 * @name Interceptors
 *
 * @{
 *
 * @brief A callback interface that allows message interception for both
 *        producer and consumer data pipelines.
 *
 * Except for the on_new(), on_conf_set(), on_conf_dup() and on_conf_destroy()
 * interceptors, interceptors are added to the
 * newly created rd_kafka_t client instance. These interceptors MUST only
 * be added from on_new() and MUST NOT be added after rd_kafka_new() returns.
 *
 * The on_new(), on_conf_set(), on_conf_dup() and on_conf_destroy() interceptors
 * are added to the configuration object which is later passed to
 * rd_kafka_new() where on_new() is called to allow addition of
 * other interceptors.
 *
 * Each interceptor reference consists of a display name (ic_name),
 * a callback function, and an application-specified opaque value that is
 * passed as-is to the callback.
 * The ic_name must be unique for the interceptor implementation and is used
 * to reject duplicate interceptor methods.
 *
 * Any number of interceptors can be added and they are called in the order
 * they were added, unless otherwise noted.
 * The list of registered interceptor methods are referred to as
 * interceptor chains.
 *
 * @remark Contrary to the Java client the librdkafka interceptor interface
 *         does not support message modification. Message mutability is
 *         discouraged in the Java client and the combination of
 *         serializers and headers cover most use-cases.
 *
 * @remark Interceptors are NOT copied to the new configuration on
 *         rd_kafka_conf_dup() since it would be hard for interceptors to
 *         track usage of the interceptor's opaque value.
 *         An interceptor should rely on the plugin, which will be copied
 *         in rd_kafka_conf_conf_dup(), to set up the initial interceptors.
 *         An interceptor should implement the on_conf_dup() method
 *         to manually set up its internal configuration on the newly created
 *         configuration object that is being copied-to based on the
 *         interceptor-specific configuration properties.
 *         conf_dup() should thus be treated the same as conf_init().
 *
 * @remark Interceptors are keyed by the interceptor type (on_..()), the
 *         interceptor name (ic_name) and the interceptor method function.
 *         Duplicates are not allowed and the .._add_on_..() method will
 *         return RD_KAFKA_RESP_ERR__CONFLICT if attempting to add a duplicate
 *         method.
 *         The only exception is on_conf_destroy() which may be added multiple
 *         times by the same interceptor to allow proper cleanup of
 *         interceptor configuration state.
 */


/**
 * @brief on_conf_set() is called from rd_kafka_*_conf_set() in the order
 *        the interceptors were added.
 *
 * @param ic_opaque The interceptor's opaque pointer specified in ..add..().
 * @param name The configuration property to set.
 * @param val The configuration value to set, or NULL for reverting to default
 *            in which case the previous value should be freed.
 * @param errstr A human readable error string in case the interceptor fails.
 * @param errstr_size Maximum space (including \0) in \p errstr.
 *
 * @returns RD_KAFKA_CONF_RES_OK if the property was known and successfully
 *          handled by the interceptor, RD_KAFKA_CONF_RES_INVALID if the
 *          property was handled by the interceptor but the value was invalid,
 *          or RD_KAFKA_CONF_RES_UNKNOWN if the interceptor did not handle
 *          this property, in which case the property is passed on on the
 *          interceptor in the chain, finally ending up at the built-in
 *          configuration handler.
 */
typedef rd_kafka_conf_res_t
(rd_kafka_interceptor_f_on_conf_set_t) (rd_kafka_conf_t *conf,
                                        const char *name, const char *val,
                                        char *errstr, size_t errstr_size,
                                        void *ic_opaque);


/**
 * @brief on_conf_dup() is called from rd_kafka_conf_dup() in the
 *        order the interceptors were added and is used to let
 *        an interceptor re-register its conf interecptors with a new
 *        opaque value.
 *        The on_conf_dup() method is called prior to the configuration from
 *        \p old_conf being copied to \p new_conf.
 *
 * @param ic_opaque The interceptor's opaque pointer specified in ..add..().
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or an error code
 *          on failure (which is logged but otherwise ignored).
 *
 * @remark No on_conf_* interceptors are copied to the new configuration
 *         object on rd_kafka_conf_dup().
 */
typedef rd_kafka_resp_err_t
(rd_kafka_interceptor_f_on_conf_dup_t) (rd_kafka_conf_t *new_conf,
                                        const rd_kafka_conf_t *old_conf,
                                        size_t filter_cnt,
                                        const char **filter,
                                        void *ic_opaque);


/**
 * @brief on_conf_destroy() is called from rd_kafka_*_conf_destroy() in the
 *        order the interceptors were added.
 *
 * @param ic_opaque The interceptor's opaque pointer specified in ..add..().
 */
typedef rd_kafka_resp_err_t
(rd_kafka_interceptor_f_on_conf_destroy_t) (void *ic_opaque);


/**
 * @brief on_new() is called from rd_kafka_new() prior toreturning
 *        the newly created client instance to the application.
 *
 * @param rk The client instance.
 * @param conf The client instance's final configuration.
 * @param ic_opaque The interceptor's opaque pointer specified in ..add..().
 * @param errstr A human readable error string in case the interceptor fails.
 * @param errstr_size Maximum space (including \0) in \p errstr.
 *
 * @returns an error code on failure, the error is logged but otherwise ignored.
 *
 * @warning The \p rk client instance will not be fully set up when this
 *          interceptor is called and the interceptor MUST NOT call any
 *          other rk-specific APIs than rd_kafka_interceptor_add..().
 *
 */
typedef rd_kafka_resp_err_t
(rd_kafka_interceptor_f_on_new_t) (rd_kafka_t *rk, const rd_kafka_conf_t *conf,
                                   void *ic_opaque,
                                   char *errstr, size_t errstr_size);


/**
 * @brief on_destroy() is called from rd_kafka_destroy() or (rd_kafka_new()
 *        if rd_kafka_new() fails during initialization).
 *
 * @param rk The client instance.
 * @param ic_opaque The interceptor's opaque pointer specified in ..add..().
 */
typedef rd_kafka_resp_err_t
(rd_kafka_interceptor_f_on_destroy_t) (rd_kafka_t *rk, void *ic_opaque);




/**
 * @brief on_send() is called from rd_kafka_produce*() (et.al) prior to
 *        the partitioner being called.
 *
 * @param rk The client instance.
 * @param rkmessage The message being produced. Immutable.
 * @param ic_opaque The interceptor's opaque pointer specified in ..add..().
 *
 * @remark This interceptor is only used by producer instances.
 *
 * @remark The \p rkmessage object is NOT mutable and MUST NOT be modified
 *         by the interceptor.
 *
 * @remark If the partitioner fails or an unknown partition was specified,
 *         the on_acknowledgement() interceptor chain will be called from
 *         within the rd_kafka_produce*() call to maintain send-acknowledgement
 *         symmetry.
 *
 * @returns an error code on failure, the error is logged but otherwise ignored.
 */
typedef rd_kafka_resp_err_t
(rd_kafka_interceptor_f_on_send_t) (rd_kafka_t *rk,
                                    rd_kafka_message_t *rkmessage,
                                    void *ic_opaque);

/**
 * @brief on_acknowledgement() is called to inform interceptors that a message
 *        was succesfully delivered or permanently failed delivery.
 *        The interceptor chain is called from internal librdkafka background
 *        threads, or rd_kafka_produce*() if the partitioner failed.
 *
 * @param rk The client instance.
 * @param rkmessage The message being produced. Immutable.
 * @param ic_opaque The interceptor's opaque pointer specified in ..add..().
 *
 * @remark This interceptor is only used by producer instances.
 *
 * @remark The \p rkmessage object is NOT mutable and MUST NOT be modified
 *         by the interceptor.
 *
 * @warning The on_acknowledgement() method may be called from internal
 *         librdkafka threads. An on_acknowledgement() interceptor MUST NOT
 *         call any librdkafka API's associated with the \p rk, or perform
 *         any blocking or prolonged work.
 *
 * @returns an error code on failure, the error is logged but otherwise ignored.
 */
typedef rd_kafka_resp_err_t
(rd_kafka_interceptor_f_on_acknowledgement_t) (rd_kafka_t *rk,
                                               rd_kafka_message_t *rkmessage,
                                               void *ic_opaque);


/**
 * @brief on_consume() is called just prior to passing the message to the
 *        application in rd_kafka_consumer_poll(), rd_kafka_consume*(),
 *        the event interface, etc.
 *
 * @param rk The client instance.
 * @param rkmessage The message being consumed. Immutable.
 * @param ic_opaque The interceptor's opaque pointer specified in ..add..().
 *
 * @remark This interceptor is only used by consumer instances.
 *
 * @remark The \p rkmessage object is NOT mutable and MUST NOT be modified
 *         by the interceptor.
 *
 * @returns an error code on failure, the error is logged but otherwise ignored.
 */
typedef rd_kafka_resp_err_t
(rd_kafka_interceptor_f_on_consume_t) (rd_kafka_t *rk,
                                       rd_kafka_message_t *rkmessage,
                                       void *ic_opaque);

/**
 * @brief on_commit() is called on completed or failed offset commit.
 *        It is called from internal librdkafka threads.
 *
 * @param rk The client instance.
 * @param offsets List of topic+partition+offset+error that were committed.
 *                The error message of each partition should be checked for
 *                error.
 * @param ic_opaque The interceptor's opaque pointer specified in ..add..().
 *
 * @remark This interceptor is only used by consumer instances.
 *
 * @warning The on_commit() interceptor is called from internal
 *          librdkafka threads. An on_commit() interceptor MUST NOT
 *          call any librdkafka API's associated with the \p rk, or perform
 *          any blocking or prolonged work.
 *
 *
 * @returns an error code on failure, the error is logged but otherwise ignored.
 */
typedef rd_kafka_resp_err_t
(rd_kafka_interceptor_f_on_commit_t) (
        rd_kafka_t *rk,
        const rd_kafka_topic_partition_list_t *offsets,
        rd_kafka_resp_err_t err, void *ic_opaque);



/**
 * @brief Append an on_conf_set() interceptor.
 *
 * @param conf Configuration object.
 * @param ic_name Interceptor name, used in logging.
 * @param on_conf_set Function pointer.
 * @param ic_opaque Opaque value that will be passed to the function.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or RD_KAFKA_RESP_ERR__CONFLICT
 *          if an existing intercepted with the same \p ic_name and function
 *          has already been added to \p conf.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_conf_interceptor_add_on_conf_set (
        rd_kafka_conf_t *conf, const char *ic_name,
        rd_kafka_interceptor_f_on_conf_set_t *on_conf_set,
        void *ic_opaque);


/**
 * @brief Append an on_conf_dup() interceptor.
 *
 * @param conf Configuration object.
 * @param ic_name Interceptor name, used in logging.
 * @param on_conf_dup Function pointer.
 * @param ic_opaque Opaque value that will be passed to the function.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or RD_KAFKA_RESP_ERR__CONFLICT
 *          if an existing intercepted with the same \p ic_name and function
 *          has already been added to \p conf.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_conf_interceptor_add_on_conf_dup (
        rd_kafka_conf_t *conf, const char *ic_name,
        rd_kafka_interceptor_f_on_conf_dup_t *on_conf_dup,
        void *ic_opaque);

/**
 * @brief Append an on_conf_destroy() interceptor.
 *
 * @param conf Configuration object.
 * @param ic_name Interceptor name, used in logging.
 * @param on_conf_destroy Function pointer.
 * @param ic_opaque Opaque value that will be passed to the function.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR
 *
 * @remark Multiple on_conf_destroy() interceptors are allowed to be added
 *         to the same configuration object.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_conf_interceptor_add_on_conf_destroy (
        rd_kafka_conf_t *conf, const char *ic_name,
        rd_kafka_interceptor_f_on_conf_destroy_t *on_conf_destroy,
        void *ic_opaque);


/**
 * @brief Append an on_new() interceptor.
 *
 * @param conf Configuration object.
 * @param ic_name Interceptor name, used in logging.
 * @param on_send Function pointer.
 * @param ic_opaque Opaque value that will be passed to the function.
  *
 * @remark Since the on_new() interceptor is added to the configuration object
 *         it may be copied by rd_kafka_conf_dup().
 *         An interceptor implementation must thus be able to handle
 *         the same interceptor,ic_opaque tuple to be used by multiple
 *         client instances.
 *
 * @remark An interceptor plugin should check the return value to make sure it
 *         has not already been added.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or RD_KAFKA_RESP_ERR__CONFLICT
 *          if an existing intercepted with the same \p ic_name and function
 *          has already been added to \p conf.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_conf_interceptor_add_on_new (
        rd_kafka_conf_t *conf, const char *ic_name,
        rd_kafka_interceptor_f_on_new_t *on_new,
        void *ic_opaque);



/**
 * @brief Append an on_destroy() interceptor.
 *
 * @param rk Client instance.
 * @param ic_name Interceptor name, used in logging.
 * @param on_destroy Function pointer.
 * @param ic_opaque Opaque value that will be passed to the function.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or RD_KAFKA_RESP_ERR__CONFLICT
 *          if an existing intercepted with the same \p ic_name and function
 *          has already been added to \p conf.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_interceptor_add_on_destroy (
        rd_kafka_t *rk, const char *ic_name,
        rd_kafka_interceptor_f_on_destroy_t *on_destroy,
        void *ic_opaque);


/**
 * @brief Append an on_send() interceptor.
 *
 * @param rk Client instance.
 * @param ic_name Interceptor name, used in logging.
 * @param on_send Function pointer.
 * @param ic_opaque Opaque value that will be passed to the function.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or RD_KAFKA_RESP_ERR__CONFLICT
 *          if an existing intercepted with the same \p ic_name and function
 *          has already been added to \p conf.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_interceptor_add_on_send (
        rd_kafka_t *rk, const char *ic_name,
        rd_kafka_interceptor_f_on_send_t *on_send,
        void *ic_opaque);

/**
 * @brief Append an on_acknowledgement() interceptor.
 *
 * @param rk Client instance.
 * @param ic_name Interceptor name, used in logging.
 * @param on_acknowledgement Function pointer.
 * @param ic_opaque Opaque value that will be passed to the function.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or RD_KAFKA_RESP_ERR__CONFLICT
 *          if an existing intercepted with the same \p ic_name and function
 *          has already been added to \p conf.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_interceptor_add_on_acknowledgement (
        rd_kafka_t *rk, const char *ic_name,
        rd_kafka_interceptor_f_on_acknowledgement_t *on_acknowledgement,
        void *ic_opaque);


/**
 * @brief Append an on_consume() interceptor.
 *
 * @param rk Client instance.
 * @param ic_name Interceptor name, used in logging.
 * @param on_consume Function pointer.
 * @param ic_opaque Opaque value that will be passed to the function.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or RD_KAFKA_RESP_ERR__CONFLICT
 *          if an existing intercepted with the same \p ic_name and function
 *          has already been added to \p conf.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_interceptor_add_on_consume (
        rd_kafka_t *rk, const char *ic_name,
        rd_kafka_interceptor_f_on_consume_t *on_consume,
        void *ic_opaque);


/**
 * @brief Append an on_commit() interceptor.
 *
 * @param rk Client instance.
 * @param ic_name Interceptor name, used in logging.
 * @param on_commit() Function pointer.
 * @param ic_opaque Opaque value that will be passed to the function.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success or RD_KAFKA_RESP_ERR__CONFLICT
 *          if an existing intercepted with the same \p ic_name and function
 *          has already been added to \p conf.
 */
RD_EXPORT rd_kafka_resp_err_t
rd_kafka_interceptor_add_on_commit (
        rd_kafka_t *rk, const char *ic_name,
        rd_kafka_interceptor_f_on_commit_t *on_commit,
        void *ic_opaque);




/**@}*/


#ifdef __cplusplus
}
#endif
