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

#ifdef HAVE_TLS
#include <fluent-bit/flb_io_tls.h>
#endif

#define FLB_CONFIG_FLUSH_SECS   5
#define FLB_CONFIG_DEFAULT_TAG  "fluent_bit"

/* Main struct to hold the configuration of the runtime service */
struct flb_config {
    struct mk_event ch_event;

    int flush;          /* Flush timeout                  */
    int flush_fd;       /* Timer FD associated to flush   */
    int shutdown_fd;    /* Shutdown FD, 5 seconds         */

#ifdef HAVE_STATS
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

    /* Kernel info */
    struct flb_kernel *kernel;

    /* Lib mode data */
    struct flb_lib_ctx *lib_ctx;
};

int __flb_config_verbose;

struct flb_config *flb_config_init();
void flb_config_verbose(int status);

#endif
