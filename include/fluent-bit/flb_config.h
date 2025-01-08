/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_CONFIG_H
#define FLB_CONFIG_H

#include <time.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_task_map.h>

#include <monkey/mk_core.h>

#define FLB_CONFIG_FLUSH_SECS   1
#define FLB_CONFIG_HTTP_LISTEN  "0.0.0.0"
#define FLB_CONFIG_HTTP_PORT    "2020"
#define HC_ERRORS_COUNT_DEFAULT 5
#define HC_RETRY_FAILURE_COUNTS_DEFAULT 5
#define HEALTH_CHECK_PERIOD 60
#define FLB_CONFIG_DEFAULT_TAG  "fluent_bit"

#define FLB_CONFIG_DEFAULT_TASK_MAP_SIZE  2048
#define FLB_CONFIG_DEFAULT_TASK_MAP_SIZE_LIMIT  16384
#define FLB_CONFIG_DEFAULT_TASK_MAP_SIZE_GROWTH_SiZE 256

/* The reason behind FLB_CONFIG_DEFAULT_TASK_MAP_SIZE_LIMIT being set to 16384
 * is that this is largest unsigned number expressable with 14 bits which is
 * a limit imposed by the messaging mechanism used.
 *
 * As for FLB_CONFIG_DEFAULT_TASK_MAP_SIZE, 2048 was chosen to retain its
 * original value and FLB_CONFIG_DEFAULT_TASK_MAP_SIZE_GROWTH_SiZE is set
 * to a multiple of 8 because entries in the task map are just task
 * pointers.
 */

/* Main struct to hold the configuration of the runtime service */
struct flb_config {
    struct mk_event ch_event;

    int support_mode;         /* enterprise support mode ?      */
    int is_ingestion_active;  /* date ingestion active/allowed  */
    int is_shutting_down;     /* is the service shutting down ? */
    int is_running;           /* service running ?              */
    double flush;             /* Flush timeout                  */

    /*
     * Maximum grace time on shutdown. If set to -1, the engine will
     * shutdown when all remaining tasks are flushed
     */
    int grace;
    int grace_count;          /* Count of grace shutdown tries              */
    int grace_input;          /* Shutdown grace to keep inputs ingesting    */
    flb_pipefd_t flush_fd;    /* Timer FD associated to flush               */
    int convert_nan_to_null;  /* Convert null to nan ?                      */

    int daemon;               /* Run as a daemon ?              */
    flb_pipefd_t shutdown_fd; /* Shutdown FD, 5 seconds         */

    int verbose;           /* Verbose mode (default OFF)     */
    time_t init_time;      /* Time when Fluent Bit started   */

    /* Used in library mode */
    pthread_t worker;               /* worker tid */
    flb_pipefd_t ch_data[2];        /* pipe to communicate caller with worker */
    flb_pipefd_t ch_manager[2];     /* channel to administrate fluent bit     */
    flb_pipefd_t ch_notif[2];       /* channel to receive notifications       */

    flb_pipefd_t ch_self_events[2]; /* channel to recieve thread tasks        */

    int notification_channels_initialized;
    flb_pipefd_t notification_channels[2];
    struct mk_event notification_event;

    /* Channel event loop (just for ch_notif) */
    struct mk_event_loop *ch_evl;

    struct mk_rconf *file;

    /* main configuration */
    struct flb_cf *cf_main;
    /* command line configuration (handled by fluent-bit bin) */
    struct flb_cf *cf_opts;
    struct mk_list cf_parsers_list;

    flb_sds_t program_name;      /* argv[0] */

    /*
     * If a configuration file was used, this variable will contain the
     * absolute path for the directory that contains the file.
     */
    char *conf_path;

    /* if the configuration come from the file system, store the given path */
    flb_sds_t conf_path_file;

    /* if the external plugins come from the file system, store the given paths from command line */
    struct mk_list external_plugins;

    /* Event */
    struct mk_event event_flush;
    struct mk_event event_shutdown;
    struct mk_event event_thread_init;  /* event to initiate thread in engine */

    /* Collectors */
    pthread_mutex_t collectors_mutex;

    /* Dynamic (dso) plugins context */
    void *dso_plugins;

    /* Plugins references */
    struct mk_list processor_plugins;
    struct mk_list custom_plugins;
    struct mk_list in_plugins;
    struct mk_list parser_plugins;      /* not yet implemented */
    struct mk_list filter_plugins;
    struct mk_list out_plugins;

    /* Custom instances */
    struct mk_list customs;

    /* Inputs instances */
    struct mk_list inputs;

    /* Parsers instances */
    struct mk_list parsers;

    /* Multiline core parser definitions */
    struct mk_list multiline_parsers;
    char *multiline_buffer_limit; /* limit for multiline concatenated data */

    /* Outputs instances */
    struct mk_list outputs;             /* list of output plugins   */

    /* Filter instances */
    struct mk_list filters;

    struct mk_event_loop *evl;          /* the event loop (mk_core) */

    struct flb_bucket_queue *evl_bktq;   /* bucket queue for evl track event priority */

    /* Proxies */
    struct mk_list proxies;

    /* Kernel info */
    struct flb_kernel *kernel;

    /* Logging */
    char *log_file;
    struct flb_log *log;

    /* Parser Conf */
    char *parsers_file;

    /* Plugins config file */
    char *plugins_file;

    /* Environment */
    void *env;

    /* Working Directory */
    char *workdir;

    /* Exit status code */
    int exit_status_code;

    /* Workers: threads spawn using flb_worker_create() */
    struct mk_list workers;

    /* Metrics exporter */
#ifdef FLB_HAVE_METRICS
    void *metrics;
#endif

    /*
     * CMetric lists: a linked list to keep a reference of every
     * cmetric context created.
     */
    struct mk_list cmetrics;

    /* HTTP Server */
#ifdef FLB_HAVE_HTTP_SERVER
    int http_server;                /* HTTP Server running    */
    char *http_port;                /* HTTP Port / TCP number */
    char *http_listen;              /* Interface Address      */
    void *http_ctx;                 /* Monkey HTTP context    */
    int health_check;               /* health check enable    */
    int hc_errors_count;               /* health check error counts as unhealthy*/
    int hc_retry_failure_count;        /* health check retry failures count as unhealthy*/
    int health_check_period;           /* period by second for health status check */
#endif

    /*
     * There are two ways to use proxy in fluent-bit:
     * 1. Similar with http and datadog plugin, passing proxy directly to
     *    flb_http_client and use proxy host and port when creating upstream.
     *    HTTPS traffic is not supported this way.
     * 2. Similar with stackdriver plugin, passing http_proxy in flb_config
     *    (or by setting HTTP_PROXY env variable). HTTPS is supported this way. But
     *    proxy shouldn't be passed when calling flb_http_client().
     */
    char *http_proxy;

    /*
     * A comma-separated list of host names that shouldn't go through
     * any proxy is set in (only an asterisk, * matches all hosts).
     * As a convention (https://curl.se/docs/manual.html), this value can be set
     * and respected by `NO_PROXY` environment variable when `HTTP_PROXY` is used.
     * Example: NO_PROXY="127.0.0.1,localhost,kubernetes.default.svc"
     * Note: only `,` is allowed as seperator between URLs.
     */
    char *no_proxy;

    /* DNS */
    char *dns_mode;
    char *dns_resolver;
    int   dns_prefer_ipv4;
    int   dns_prefer_ipv6;

    /* Chunk I/O Buffering */
    void *cio;
    char *storage_path;
    void *storage_input_plugin;
    char *storage_sync;             /* sync mode */
    int   storage_metrics;          /* enable/disable storage metrics */
    int   storage_checksum;         /* checksum enabled */
    int   storage_max_chunks_up;    /* max number of chunks 'up' in memory */
    int   storage_del_bad_chunks;   /* delete irrecoverable chunks */
    char *storage_bl_mem_limit;     /* storage backlog memory limit */
    int   storage_bl_flush_on_shutdown; /* enable/disable backlog chunks flush on shutdown */
    struct flb_storage_metrics *storage_metrics_ctx; /* storage metrics context */
    int   storage_trim_files;       /* enable/disable file trimming */
    char *storage_type;             /* global storage type */
    int   storage_inherit;          /* apply storage type to inputs */

    /* Embedded SQL Database support (SQLite3) */
#ifdef FLB_HAVE_SQLDB
    struct mk_list sqldb_list;
#endif

    /* LuaJIT environment's context */
#ifdef FLB_HAVE_LUAJIT
    struct mk_list luajit_list;
#endif

    /* WASM environment's context */
#ifdef FLB_HAVE_WASM
    struct mk_list wasm_list;
#endif

#ifdef FLB_HAVE_STREAM_PROCESSOR
    char *stream_processor_file;            /* SP configuration file */
    void *stream_processor_ctx;             /* SP context */
    int  stream_processor_str_conv;         /* SP enable converting from string to number */

    /*
     * Temporal list to hold tasks defined before the SP context is created
     * by the engine. The list is passed upon start and destroyed.
     */
    struct mk_list stream_processor_tasks;
#endif

#ifdef FLB_HAVE_CHUNK_TRACE
    int enable_chunk_trace;
#endif /* FLB_HAVE_CHUNK_TRACE */

    int enable_hot_reload;
    int ensure_thread_safety_on_hot_reloading;
    unsigned int hot_reloaded_count;
    int shutdown_by_hot_reloading;
    int hot_reloading;
    int hot_reload_succeeded;
    
    int hot_reload_watchdog_timeout_seconds;

    /* Routing */
    size_t route_mask_size;
    size_t route_mask_slots;
    uint64_t *route_empty_mask;
#ifdef FLB_SYSTEM_WINDOWS
    /* maxstdio (Windows) */
    int win_maxstdio;
#endif

    /* Co-routines */
    unsigned int coro_stack_size;

    /* Upstream contexts created by plugins */
    struct mk_list upstreams;

    /* Downstream contexts created by plugins */
    struct mk_list downstreams;

    /*
     * Input table-id: table to keep a reference of thread-IDs used by the
     * input plugins.
     */
    uint16_t in_table_id[512];

    void *sched;
    unsigned int sched_cap;
    unsigned int sched_base;

    struct flb_task_map *task_map;
    size_t task_map_size;

    int json_escape_unicode;

    int dry_run;
};

#define FLB_CONFIG_LOG_LEVEL(c) (c->log->level)

struct flb_config *flb_config_init();
void flb_config_exit(struct flb_config *config);
const char *flb_config_prop_get(const char *key, struct mk_list *list);
int flb_config_set_property(struct flb_config *config,
                            const char *k, const char *v);
int flb_config_set_program_name(struct flb_config *config, char *name);
int flb_config_load_config_format(struct flb_config *config, struct flb_cf *cf);
int flb_config_task_map_resize(struct flb_config *config, size_t new_size);
int flb_config_task_map_grow(struct flb_config *config);

int set_log_level_from_env(struct flb_config *config);
#ifdef FLB_HAVE_STATIC_CONF
struct flb_cf *flb_config_static_open(const char *file);
#endif

struct flb_service_config {
    char    *key;
    int     type;
    size_t  offset;
};

enum conf_type {
    FLB_CONF_TYPE_INT,
    FLB_CONF_TYPE_DOUBLE,
    FLB_CONF_TYPE_BOOL,
    FLB_CONF_TYPE_STR,
    FLB_CONF_TYPE_OTHER,
};

#define FLB_CONF_STR_FLUSH        "Flush"
#define FLB_CONF_STR_GRACE        "Grace"
#define FLB_CONF_STR_DAEMON       "Daemon"
#define FLB_CONF_STR_LOGFILE      "Log_File"
#define FLB_CONF_STR_LOGLEVEL     "Log_Level"
#define FLB_CONF_STR_PARSERS_FILE "Parsers_File"
#define FLB_CONF_STR_PLUGINS_FILE "Plugins_File"
#define FLB_CONF_STR_STREAMS_FILE "Streams_File"
#define FLB_CONF_STR_STREAMS_STR_CONV "sp.convert_from_str_to_num"
#define FLB_CONF_STR_CONV_NAN     "json.convert_nan_to_null"

/* FLB_HAVE_HTTP_SERVER */
#ifdef FLB_HAVE_HTTP_SERVER
#define FLB_CONF_STR_HTTP_SERVER                            "HTTP_Server"
#define FLB_CONF_STR_HTTP_LISTEN                            "HTTP_Listen"
#define FLB_CONF_STR_HTTP_PORT                              "HTTP_Port"
#define FLB_CONF_STR_HEALTH_CHECK                           "Health_Check"
#define FLB_CONF_STR_HC_ERRORS_COUNT                        "HC_Errors_Count"
#define FLB_CONF_STR_HC_RETRIES_FAILURE_COUNT               "HC_Retry_Failure_Count"
#define FLB_CONF_STR_HC_PERIOD                              "HC_Period"
#endif /* !FLB_HAVE_HTTP_SERVER */

#ifdef FLB_HAVE_CHUNK_TRACE
#define FLB_CONF_STR_ENABLE_CHUNK_TRACE      "Enable_Chunk_Trace"
#endif /* FLB_HAVE_CHUNK_TRACE */

#define FLB_CONF_STR_HOT_RELOAD        "Hot_Reload"
#define FLB_CONF_STR_HOT_RELOAD_ENSURE_THREAD_SAFETY  "Hot_Reload.Ensure_Thread_Safety"
#define FLB_CONF_STR_HOT_RELOAD_TIMEOUT "Hot_Reload.Timeout"

/* Set up maxstdio (Windows) */
#define FLB_CONF_STR_WINDOWS_MAX_STDIO "windows.maxstdio"

/* DNS */
#define FLB_CONF_DNS_MODE              "dns.mode"
#define FLB_CONF_DNS_RESOLVER          "dns.resolver"
#define FLB_CONF_DNS_PREFER_IPV4       "dns.prefer_ipv4"
#define FLB_CONF_DNS_PREFER_IPV6       "dns.prefer_ipv6"

/* Proxies */
#define FLB_CONF_HTTP_PROXY            "net.http_proxy"
#define FLB_CONF_NO_PROXY              "net.no_proxy"

/* Storage / Chunk I/O */
#define FLB_CONF_STORAGE_PATH          "storage.path"
#define FLB_CONF_STORAGE_SYNC          "storage.sync"
#define FLB_CONF_STORAGE_METRICS       "storage.metrics"
#define FLB_CONF_STORAGE_CHECKSUM      "storage.checksum"
#define FLB_CONF_STORAGE_BL_MEM_LIMIT  "storage.backlog.mem_limit"
#define FLB_CONF_STORAGE_BL_FLUSH_ON_SHUTDOWN \
                                       "storage.backlog.flush_on_shutdown" 
#define FLB_CONF_STORAGE_MAX_CHUNKS_UP "storage.max_chunks_up"
#define FLB_CONF_STORAGE_DELETE_IRRECOVERABLE_CHUNKS \
                                       "storage.delete_irrecoverable_chunks"
#define FLB_CONF_STORAGE_TRIM_FILES    "storage.trim_files"
#define FLB_CONF_STORAGE_TYPE          "storage.type"
#define FLB_CONF_STORAGE_INHERIT       "storage.inherit"

/* Coroutines */
#define FLB_CONF_STR_CORO_STACK_SIZE "Coro_Stack_Size"

/* Multiline */
#define FLB_CONF_STR_MULTILINE_BUFFER_LIMIT "multiline_buffer_limit"

/* Scheduler */
#define FLB_CONF_STR_SCHED_CAP        "scheduler.cap"
#define FLB_CONF_STR_SCHED_BASE       "scheduler.base"

/* json escape */
#define FLB_CONF_UNICODE_STR_JSON_ESCAPE "json.escape_unicode"

#endif
