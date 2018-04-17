#ifndef _RDKAFKA_CONF_H_
#define _RDKAFKA_CONF_H_

#include "rdlist.h"


/**
 * Forward declarations
 */
struct rd_kafka_transport_s;


/**
 * MessageSet compression codecs
 */
typedef enum {
	RD_KAFKA_COMPRESSION_NONE,
	RD_KAFKA_COMPRESSION_GZIP = RD_KAFKA_MSG_ATTR_GZIP,
	RD_KAFKA_COMPRESSION_SNAPPY = RD_KAFKA_MSG_ATTR_SNAPPY,
        RD_KAFKA_COMPRESSION_LZ4 = RD_KAFKA_MSG_ATTR_LZ4,
	RD_KAFKA_COMPRESSION_INHERIT /* Inherit setting from global conf */
} rd_kafka_compression_t;


typedef enum {
	RD_KAFKA_PROTO_PLAINTEXT,
	RD_KAFKA_PROTO_SSL,
	RD_KAFKA_PROTO_SASL_PLAINTEXT,
	RD_KAFKA_PROTO_SASL_SSL,
	RD_KAFKA_PROTO_NUM,
} rd_kafka_secproto_t;


typedef enum {
	RD_KAFKA_CONFIGURED,
	RD_KAFKA_LEARNED,
	RD_KAFKA_INTERNAL,
} rd_kafka_confsource_t;

typedef	enum {
	_RK_GLOBAL = 0x1,
	_RK_PRODUCER = 0x2,
	_RK_CONSUMER = 0x4,
	_RK_TOPIC = 0x8,
        _RK_CGRP = 0x10
} rd_kafka_conf_scope_t;

typedef enum {
	_RK_CONF_PROP_SET_REPLACE,  /* Replace current value (default) */
	_RK_CONF_PROP_SET_ADD,      /* Add value (S2F) */
	_RK_CONF_PROP_SET_DEL      /* Remove value (S2F) */
} rd_kafka_conf_set_mode_t;



typedef enum {
        RD_KAFKA_OFFSET_METHOD_NONE,
        RD_KAFKA_OFFSET_METHOD_FILE,
        RD_KAFKA_OFFSET_METHOD_BROKER
} rd_kafka_offset_method_t;




/**
 * Optional configuration struct passed to rd_kafka_new*().
 *
 * The struct is populated ted through string properties
 * by calling rd_kafka_conf_set().
 *
 */
struct rd_kafka_conf_s {
	/*
	 * Generic configuration
	 */
	int     enabled_events;
	int     max_msg_size;
	int     msg_copy_max_size;
        int     recv_max_msg_size;
	int     max_inflight;
	int     metadata_request_timeout_ms;
	int     metadata_refresh_interval_ms;
	int     metadata_refresh_fast_cnt;
	int     metadata_refresh_fast_interval_ms;
        int     metadata_refresh_sparse;
        int     metadata_max_age_ms;
	int     debug;
	int     broker_addr_ttl;
        int     broker_addr_family;
	int     socket_timeout_ms;
	int     socket_blocking_max_ms;
	int     socket_sndbuf_size;
	int     socket_rcvbuf_size;
        int     socket_keepalive;
	int     socket_nagle_disable;
        int     socket_max_fails;
	char   *client_id_str;
	char   *brokerlist;
	int     stats_interval_ms;
	int     term_sig;
        int     reconnect_jitter_ms;
	int     api_version_request;
	int     api_version_request_timeout_ms;
	int     api_version_fallback_ms;
	char   *broker_version_fallback;
	rd_kafka_secproto_t security_protocol;

#if WITH_SSL
	struct {
		SSL_CTX *ctx;
		char *cipher_suites;
		char *key_location;
		char *key_password;
		char *cert_location;
		char *ca_location;
		char *crl_location;
		char *keystore_location;
		char *keystore_password;
	} ssl;
#endif

        struct {
                const struct rd_kafka_sasl_provider *provider;
                char *principal;
                char *mechanisms;
                char *service_name;
                char *kinit_cmd;
                char *keytab;
                int   relogin_min_time;
                char *username;
                char *password;
#if WITH_SASL_SCRAM
                /* SCRAM EVP-wrapped hash function
                 * (return value from EVP_shaX()) */
                const void/*EVP_MD*/ *scram_evp;
                /* SCRAM direct hash function (e.g., SHA256()) */
                unsigned char *(*scram_H) (const unsigned char *d, size_t n,
                                           unsigned char *md);
                /* Hash size */
                size_t         scram_H_size;
#endif
        } sasl;

#if WITH_PLUGINS
        char *plugin_paths;
        rd_list_t plugins;
#endif

        /* Interceptors */
        struct {
                /* rd_kafka_interceptor_method_t lists */
                rd_list_t on_conf_set;        /* on_conf_set interceptors
                                               * (not copied on conf_dup()) */
                rd_list_t on_conf_dup;        /* .. (not copied) */
                rd_list_t on_conf_destroy;    /* .. (not copied) */
                rd_list_t on_new;             /* .. (copied) */
                rd_list_t on_destroy;         /* .. (copied) */
                rd_list_t on_send;            /* .. (copied) */
                rd_list_t on_acknowledgement; /* .. (copied) */
                rd_list_t on_consume;         /* .. (copied) */
                rd_list_t on_commit;          /* .. (copied) */
                rd_list_t on_request_sent;    /* .. (copied) */

                /* rd_strtup_t list */
                rd_list_t config;             /* Configuration name=val's
                                               * handled by interceptors. */
        } interceptors;

        /* Client group configuration */
        int    coord_query_intvl_ms;

	int    builtin_features;
	/*
	 * Consumer configuration
	 */
        int    check_crcs;
	int    queued_min_msgs;
        int    queued_max_msg_kbytes;
        int64_t queued_max_msg_bytes;
	int    fetch_wait_max_ms;
        int    fetch_msg_max_bytes;
        int    fetch_max_bytes;
	int    fetch_min_bytes;
	int    fetch_error_backoff_ms;
        char  *group_id_str;

        rd_kafka_pattern_list_t *topic_blacklist;
        struct rd_kafka_topic_conf_s *topic_conf; /* Default topic config
                                                   * for automatically
                                                   * subscribed topics. */
        int enable_auto_commit;
	int enable_auto_offset_store;
        int auto_commit_interval_ms;
        int group_session_timeout_ms;
        int group_heartbeat_intvl_ms;
        rd_kafkap_str_t *group_protocol_type;
        char *partition_assignment_strategy;
        rd_list_t partition_assignors;
	int enabled_assignor_cnt;
        struct rd_kafka_assignor_s *assignor;

        void (*rebalance_cb) (rd_kafka_t *rk,
                              rd_kafka_resp_err_t err,
			      rd_kafka_topic_partition_list_t *partitions,
                              void *opaque);

        void (*offset_commit_cb) (rd_kafka_t *rk,
                                  rd_kafka_resp_err_t err,
                                  rd_kafka_topic_partition_list_t *offsets,
                                  void *opaque);

        rd_kafka_offset_method_t offset_store_method;
	int enable_partition_eof;

	/*
	 * Producer configuration
	 */
	int    queue_buffering_max_msgs;
	int    queue_buffering_max_kbytes;
	int    buffering_max_ms;
        int    queue_backpressure_thres;
	int    max_retries;
	int    retry_backoff_ms;
	int    batch_num_messages;
	rd_kafka_compression_t compression_codec;
	int    dr_err_only;

	/* Message delivery report callback.
	 * Called once for each produced message, either on
	 * successful and acknowledged delivery to the broker in which
	 * case 'err' is 0, or if the message could not be delivered
	 * in which case 'err' is non-zero (use rd_kafka_err2str()
	 * to obtain a human-readable error reason).
	 *
	 * If the message was produced with neither RD_KAFKA_MSG_F_FREE
	 * or RD_KAFKA_MSG_F_COPY set then 'payload' is the original
	 * pointer provided to rd_kafka_produce().
	 * rdkafka will not perform any further actions on 'payload'
	 * at this point and the application may rd_free the payload data
	 * at this point.
	 *
	 * 'opaque' is 'conf.opaque', while 'msg_opaque' is
	 * the opaque pointer provided in the rd_kafka_produce() call.
	 */
	void (*dr_cb) (rd_kafka_t *rk,
		       void *payload, size_t len,
		       rd_kafka_resp_err_t err,
		       void *opaque, void *msg_opaque);

        void (*dr_msg_cb) (rd_kafka_t *rk, const rd_kafka_message_t *rkmessage,
                           void *opaque);

        /* Consume callback */
        void (*consume_cb) (rd_kafka_message_t *rkmessage, void *opaque);

        /* Log callback */
        void (*log_cb) (const rd_kafka_t *rk, int level,
                        const char *fac, const char *buf);
        int    log_level;
        int    log_queue;
        int    log_thread_name;
        int    log_connection_close;

        /* Error callback */
	void (*error_cb) (rd_kafka_t *rk, int err,
			  const char *reason, void *opaque);

	/* Throttle callback */
	void (*throttle_cb) (rd_kafka_t *rk, const char *broker_name,
			     int32_t broker_id, int throttle_time_ms,
			     void *opaque);

	/* Stats callback */
	int (*stats_cb) (rd_kafka_t *rk,
			 char *json,
			 size_t json_len,
			 void *opaque);

        /* Socket creation callback */
        int (*socket_cb) (int domain, int type, int protocol, void *opaque);

        /* Connect callback */
        int (*connect_cb) (int sockfd,
                           const struct sockaddr *addr,
                           int addrlen,
                           const char *id,
                           void *opaque);

        /* Close socket callback */
        int (*closesocket_cb) (int sockfd, void *opaque);

		/* File open callback */
        int (*open_cb) (const char *pathname, int flags, mode_t mode,
                        void *opaque);

	/* Opaque passed to callbacks. */
	void  *opaque;

        /* For use with value-less properties. */
        int     dummy;
};

int rd_kafka_socket_cb_linux (int domain, int type, int protocol, void *opaque);
int rd_kafka_socket_cb_generic (int domain, int type, int protocol,
                                void *opaque);
#ifndef _MSC_VER
int rd_kafka_open_cb_linux (const char *pathname, int flags, mode_t mode,
                            void *opaque);
#endif
int rd_kafka_open_cb_generic (const char *pathname, int flags, mode_t mode,
                              void *opaque);



struct rd_kafka_topic_conf_s {
	int     required_acks;
	int32_t request_timeout_ms;
	int     message_timeout_ms;

	int32_t (*partitioner) (const rd_kafka_topic_t *rkt,
				const void *keydata, size_t keylen,
				int32_t partition_cnt,
				void *rkt_opaque,
				void *msg_opaque);
        char   *partitioner_str;

        int queuing_strategy; /* RD_KAFKA_QUEUE_FIFO|LIFO */
        int (*msg_order_cmp) (const void *a, const void *b);

	rd_kafka_compression_t compression_codec;
        int     produce_offset_report;

        int     consume_callback_max_msgs;
	int     auto_commit;
	int     auto_commit_interval_ms;
	int     auto_offset_reset;
	char   *offset_store_path;
	int     offset_store_sync_interval_ms;

        rd_kafka_offset_method_t offset_store_method;

	/* Application provided opaque pointer (this is rkt_opaque) */
	void   *opaque;
};



void rd_kafka_anyconf_destroy (int scope, void *conf);

#endif /* _RDKAFKA_CONF_H_ */
