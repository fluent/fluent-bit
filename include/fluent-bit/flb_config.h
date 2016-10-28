/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_task_map.h>
#include <msgpack.h>
#ifdef FLB_HAVE_TLS
#include <fluent-bit/flb_io_tls.h>
#endif

#define FLB_FLUSH_UCONTEXT      0
#define FLB_FLUSH_PTHREADS      1
#define FLB_FLUSH_LIBCO         2

#define FLB_CONFIG_FLUSH_SECS   5
#define FLB_CONFIG_HTTP_PORT    "2020"
#define FLB_CONFIG_DEFAULT_TAG  "fluent_bit"

/* Property configuration: key/value for an input/output instance */
struct flb_config_prop {
    char *key;
    char *val;
    struct mk_list _head;
};

/* reuse flb_config_prop as flb_config_user_header */
#define flb_config_user_header flb_config_prop

/* Main struct to hold the configuration of the runtime service */
struct flb_config {
    struct mk_event ch_event;

    int flush;          /* Flush timeout                  */
    int flush_fd;       /* Timer FD associated to flush   */
    int flush_method;   /* Flush method set at build time */

    int daemon;         /* Run as a daemon ?              */
    int shutdown_fd;    /* Shutdown FD, 5 seconds         */

#ifdef FLB_HAVE_STATS
    int stats_fd;       /* Stats FD, 1 second             */
    struct flb_stats *stats_ctx;
#endif

    int verbose;        /* Verbose mode (default OFF)     */
    time_t init_time;   /* Time when Fluent Bit started   */

    /* Used in library mode */
    pthread_t worker;   /* worker tid */
    int ch_data[2];     /* pipe to communicate caller with worker */
    int ch_manager[2];  /* channel to administrate fluent bit     */
    int ch_notif[2];    /* channel to receive notifications       */

    /* Channel event loop (just for ch_notif) */
    struct mk_event_loop *ch_evl;

    struct mk_rconf *file;

    /* Event */
    struct mk_event event_flush;
    struct mk_event event_shutdown;

    /* Collectors */
    struct mk_list collectors;

    /* Input and Output plugins */
    struct mk_list in_plugins;
    struct mk_list out_plugins;

    /* Inputs instances */
    struct mk_list inputs;

    /* Outputs instances */
    struct mk_list outputs;             /* list of output plugins   */
    struct flb_output_plugin *output;   /* output plugin in use     */
    struct mk_event_loop *evl;          /* the event loop (mk_core) */

    /* Header to append */
    struct mk_list user_headers;
    int    header_num;

    /* Kernel info */
    struct flb_kernel *kernel;

    /* Logging */
    char *logfile;
    struct flb_log *log;

    /* Workers: threads spawn using flb_worker_create() */
    struct mk_list workers;

    /* HTTP Server */
#ifdef FLB_HAVE_HTTP
    int http_server;
    char *http_port;
    void *http_ctx;
#endif

#ifdef FLB_HAVE_BUFFERING
    struct flb_buffer *buffer_ctx;
    int buffer_workers;
    char *buffer_path;
#endif

    /*
     * Input table-id: table to keep a reference of thread-IDs used by the
     * input plugins.
     */
    uint16_t in_table_id[512];

    struct mk_list sched_requests;
    struct flb_task_map tasks_map[2048];
};

struct flb_config *flb_config_init();
void flb_config_exit(struct flb_config *config);
char *flb_config_prop_get(char *key, struct mk_list *list);
int flb_config_set_property(struct flb_config *config,
                            char *k, char *v);
int flb_config_get_user_header_num(struct flb_config *config);
int flb_config_append_user_header(struct flb_config *config,
                                  msgpack_packer *mp_pck);
struct flb_service_config {
    char    *key;
    int     type;
    size_t  offset;
};

enum conf_type {
    FLB_CONF_TYPE_INT,
    FLB_CONF_TYPE_BOOL,
    FLB_CONF_TYPE_STR,
    FLB_CONF_TYPE_OTHER,
};

#define FLB_CONF_STR_FLUSH    "Flush"
#define FLB_CONF_STR_DAEMON   "Daemon"
#define FLB_CONF_STR_LOGFILE  "Logfile"
#define FLB_CONF_STR_LOGLEVEL "Log_Level"
#define FLB_CONF_STR_USER_HEADER "User_Header"
#ifdef FLB_HAVE_HTTP
#define FLB_CONF_STR_HTTP_MONITOR "HTTP_Monitor"
#define FLB_CONF_STR_HTTP_PORT    "HTTP_Port"
#endif /* FLB_HAVE_HTTP */
#ifdef FLB_HAVE_BUFFERING
#define FLB_CONF_STR_BUF_PATH     "Buffer_Path"
#define FLB_CONF_STR_BUF_WORKERS  "Buffer_Workers"
#endif /*FLB_HAVE_BUFFERING*/


#endif
