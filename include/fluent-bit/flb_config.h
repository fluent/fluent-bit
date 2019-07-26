/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_task_map.h>

#ifdef FLB_HAVE_TLS
#include <fluent-bit/flb_io_tls.h>
#endif

#define FLB_CONFIG_FLUSH_SECS   5
#define FLB_CONFIG_HTTP_LISTEN  "0.0.0.0"
#define FLB_CONFIG_HTTP_PORT    "2020"
#define FLB_CONFIG_DEFAULT_TAG  "fluent_bit"

/* Property configuration: key/value for an input/output instance */
struct flb_config_prop {
    char *key;
    char *val;
    struct mk_list _head;
};

/* Main struct to hold the configuration of the runtime service */
struct flb_config {
    struct mk_event ch_event;

    int support_mode;         /* enterprise support mode ?      */
    int is_running;           /* service running ?              */
    double flush;             /* Flush timeout                  */
    int grace;                /* Grace on shutdown              */
    flb_pipefd_t flush_fd;    /* Timer FD associated to flush   */

    int daemon;               /* Run as a daemon ?              */
    flb_pipefd_t shutdown_fd; /* Shutdown FD, 5 seconds         */

    int verbose;           /* Verbose mode (default OFF)     */
    time_t init_time;      /* Time when Fluent Bit started   */

    /* Used in library mode */
    pthread_t worker;            /* worker tid */
    flb_pipefd_t ch_data[2];     /* pipe to communicate caller with worker */
    flb_pipefd_t ch_manager[2];  /* channel to administrate fluent bit     */
    flb_pipefd_t ch_notif[2];    /* channel to receive notifications       */

    /* Channel event loop (just for ch_notif) */
    struct mk_event_loop *ch_evl;

    struct mk_rconf *file;

    /*
     * If a configuration file was used, this variable will contain the
     * absolute path for the directory that contains the file.
     */
    char *conf_path;

    /* Event */
    struct mk_event event_flush;
    struct mk_event event_shutdown;

    /* Collectors */
    struct mk_list collectors;

    /* Dynamic (dso) plugins context */
    void *dso_plugins;

    /* Plugins references */
    struct mk_list in_plugins;
    struct mk_list parser_plugins;      /* not yet implemented */
    struct mk_list filter_plugins;
    struct mk_list out_plugins;

    /* Inputs instances */
    struct mk_list inputs;

    /* Parsers instances */
    struct mk_list parsers;

    /* Outputs instances */
    struct mk_list outputs;             /* list of output plugins   */

    /* Filter instances */
    struct mk_list filters;

    struct mk_event_loop *evl;          /* the event loop (mk_core) */

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

    /* Workers: threads spawn using flb_worker_create() */
    struct mk_list workers;

    /* Metrics exporter */
#ifdef FLB_HAVE_METRICS
    void *metrics;
#endif

    /* HTTP Server */
#ifdef FLB_HAVE_HTTP_SERVER
    int http_server;          /* HTTP Server running    */
    char *http_port;          /* HTTP Port / TCP number */
    char *http_listen;        /* Interface Address      */
    void *http_ctx;           /* Monkey HTTP context    */
#endif

    /* Chunk I/O Buffering */
    void *cio;
    char *storage_path;
    void *storage_input_plugin;
    char *storage_sync;             /* sync mode */
    int   storage_checksum;         /* checksum enabled */
    int   storage_max_chunks_up;    /* max number of chunks 'up' in memory */
    char *storage_bl_mem_limit;     /* storage backlog memory limit */

    /* Embedded SQL Database support (SQLite3) */
#ifdef FLB_HAVE_SQLDB
    struct mk_list sqldb_list;
#endif

    /* LuaJIT environment's context */
#ifdef FLB_HAVE_LUAJIT
    struct mk_list luajit_list;
#endif

#ifdef FLB_HAVE_STREAM_PROCESSOR
    char *stream_processor_file;            /* SP configuration file */
    void *stream_processor_ctx;             /* SP context */

    /*
     * Temporal list to hold tasks defined before the SP context is created
     * by the engine. The list is passed upon start and destroyed.
     */
    struct mk_list stream_processor_tasks;
#endif

    /* Co-routines */
    unsigned int coro_stack_size;

    /*
     * Input table-id: table to keep a reference of thread-IDs used by the
     * input plugins.
     */
    uint16_t in_table_id[512];

    void *sched;

    struct flb_task_map tasks_map[2048];
};

#define FLB_CONFIG_LOG_LEVEL(c) (c->log->level)

struct flb_config *flb_config_init();
void flb_config_exit(struct flb_config *config);
const char *flb_config_prop_get(const char *key, struct mk_list *list);
int flb_config_set_property(struct flb_config *config,
                            const char *k, const char *v);
#ifdef FLB_HAVE_STATIC_CONF
struct mk_rconf *flb_config_static_open(const char *file);
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

/* FLB_HAVE_HTTP_SERVER */
#ifdef FLB_HAVE_HTTP_SERVER
#define FLB_CONF_STR_HTTP_SERVER     "HTTP_Server"
#define FLB_CONF_STR_HTTP_LISTEN     "HTTP_Listen"
#define FLB_CONF_STR_HTTP_PORT       "HTTP_Port"
#endif /* !FLB_HAVE_HTTP_SERVER */

/* Storage / Chunk I/O */
#define FLB_CONF_STORAGE_PATH          "storage.path"
#define FLB_CONF_STORAGE_SYNC          "storage.sync"
#define FLB_CONF_STORAGE_CHECKSUM      "storage.checksum"
#define FLB_CONF_STORAGE_BL_MEM_LIMIT  "storage.backlog.mem_limit"
#define FLB_CONF_STORAGE_MAX_CHUNKS_UP "storage.max_chunks_up"

/* Coroutines */
#define FLB_CONF_STR_CORO_STACK_SIZE "Coro_Stack_Size"

#endif
