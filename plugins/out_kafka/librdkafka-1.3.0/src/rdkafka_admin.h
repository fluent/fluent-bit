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

#ifndef _RDKAFKA_ADMIN_H_
#define _RDKAFKA_ADMIN_H_


#include "rdstring.h"
#include "rdkafka_confval.h"



/**
 * @brief Common AdminOptions type used for all admin APIs.
 *
 * @remark Visit AdminOptions_use() when you change this struct
 *         to make sure it is copied properly.
 */
struct rd_kafka_AdminOptions_s {
        rd_kafka_admin_op_t for_api;       /**< Limit allowed options to
                                            *   this API (optional) */

        /* Generic */
        rd_kafka_confval_t request_timeout;/**< I32: Full request timeout,
                                            *        includes looking up leader
                                            *        broker,
                                            *        waiting for req/response,
                                            *        etc. */
        rd_ts_t abs_timeout;               /**< Absolute timeout calculated
                                            *   from .timeout */

        /* Specific for one or more APIs */
        rd_kafka_confval_t operation_timeout; /**< I32: Timeout on broker.
                                               *   Valid for:
                                               *     CreateTopics
                                               *     DeleteTopics
                                               */
        rd_kafka_confval_t validate_only;  /**< BOOL: Only validate (on broker),
                                            *   but don't perform action.
                                            *   Valid for:
                                            *     CreateTopics
                                            *     CreatePartitions
                                            *     AlterConfigs
                                            */

        rd_kafka_confval_t incremental;    /**< BOOL: Incremental rather than
                                            *         absolute application
                                            *         of config.
                                            *   Valid for:
                                            *     AlterConfigs
                                            */

        rd_kafka_confval_t broker;         /**< INT: Explicitly override
                                            *        broker id to send
                                            *        requests to.
                                            *   Valid for:
                                            *     all
                                            */

        rd_kafka_confval_t opaque;         /**< PTR: Application opaque.
                                            *   Valid for all. */
};





/**
 * @name CreateTopics
 * @{
 */

/**
 * @brief NewTopic type, used with CreateTopics.
 */
struct rd_kafka_NewTopic_s {
        /* Required */
        char *topic;            /**< Topic to be created */
        int num_partitions;     /**< Number of partitions to create */
        int replication_factor; /**< Replication factor */

        /* Optional */
        rd_list_t replicas;     /**< Type (rd_list_t (int32_t)):
                                 *   Array of replica lists indexed by
                                 *   partition, size num_partitions. */
        rd_list_t config;       /**< Type (rd_kafka_ConfigEntry_t *):
                                 *   List of configuration entries */
};

/**@}*/


/**
 * @name DeleteTopics
 * @{
 */

/**
 * @brief DeleteTopics result
 */
struct rd_kafka_DeleteTopics_result_s {
        rd_list_t topics;   /**< Type (rd_kafka_topic_result_t *) */
};

struct rd_kafka_DeleteTopic_s {
        char *topic;   /**< Points to data */
        char  data[1]; /**< The topic name is allocated along with
                        *   the struct here. */
};

/**@}*/



/**
 * @name CreatePartitions
 * @{
 */


/**
 * @brief CreatePartitions result
 */
struct rd_kafka_CreatePartitions_result_s {
        rd_list_t topics;   /**< Type (rd_kafka_topic_result_t *) */
};

struct rd_kafka_NewPartitions_s {
        char *topic;      /**< Points to data */
        size_t total_cnt; /**< New total partition count */

        /* Optional */
        rd_list_t replicas;     /**< Type (rd_list_t (int32_t)):
                                 *   Array of replica lists indexed by
                                 *   new partition relative index.
                                 *   Size is dynamic since we don't
                                 *   know how many partitions are actually
                                 *   being added by total_cnt */

        char  data[1];    /**< The topic name is allocated along with
                           *   the struct here. */
};

/**@}*/



/**
 * @name ConfigEntry
 * @{
 */

/* KIP-248 */
typedef enum rd_kafka_AlterOperation_t {
        RD_KAFKA_ALTER_OP_ADD = 0,
        RD_KAFKA_ALTER_OP_SET = 1,
        RD_KAFKA_ALTER_OP_DELETE = 2,
} rd_kafka_AlterOperation_t;

struct rd_kafka_ConfigEntry_s {
        rd_strtup_t *kv;                     /**< Name/Value pair */

        /* Response */

        /* Attributes: this is a struct for easy copying */
        struct {
                rd_kafka_AlterOperation_t operation; /**< Operation */
                rd_kafka_ConfigSource_t source; /**< Config source */
                rd_bool_t is_readonly;    /**< Value is read-only (on broker) */
                rd_bool_t is_default;     /**< Value is at its default */
                rd_bool_t is_sensitive;   /**< Value is sensitive */
                rd_bool_t is_synonym;     /**< Value is synonym */
        } a;

        rd_list_t synonyms;       /**< Type (rd_kafka_configEntry *) */
};

/**
 * @brief A cluster ConfigResource constisting of:
 *         - resource type (BROKER, TOPIC)
 *         - configuration property name
 *         - configuration property value
 *
 * https://cwiki.apache.org/confluence/display/KAFKA/KIP-133%3A+Describe+and+Alter+Configs+Admin+APIs
 */
struct rd_kafka_ConfigResource_s {
        rd_kafka_ResourceType_t restype; /**< Resource type */
        char *name;                      /**< Resource name, points to .data*/
        rd_list_t config;                /**< Type (rd_kafka_ConfigEntry_t *):
                                          *   List of config props */

        /* Response */
        rd_kafka_resp_err_t err;         /**< Response error code */
        char *errstr;                    /**< Response error string */

        char  data[1];                   /**< The name is allocated along with
                                          *   the struct here. */
};




/**@}*/

/**
 * @name AlterConfigs
 * @{
 */




struct rd_kafka_AlterConfigs_result_s {
        rd_list_t resources;   /**< Type (rd_kafka_ConfigResource_t *) */
};

struct rd_kafka_ConfigResource_result_s {
        rd_list_t resources;  /**< Type (struct rd_kafka_ConfigResource *):
                               *   List of config resources, sans config
                               *   but with response error values. */
};

/**@}*/



/**
 * @name DescribeConfigs
 * @{
 */

struct rd_kafka_DescribeConfigs_result_s {
        rd_list_t configs;    /**< Type (rd_kafka_ConfigResource_t *) */
};

/**@}*/


/**@}*/

#endif /* _RDKAFKA_ADMIN_H_ */
