/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#ifdef HAVE_STATS

#ifndef FLB_STATS_H
#define FLB_STATS_H

#include <unistd.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_output.h>

#define FLB_STATS_SIZE          60  /* Datapoints buffer size */

#define FLB_STATS_USERVER        1  /* Unix socket server        */
#define FLB_STATS_USERVER_C      2  /* Unix socket server client */
#define FLB_STATS_USERVER_PRINT  3  /* Write statistics          */
#define FLB_STATS_INPUT_PLUGIN   4  /* Input plugin type         */
#define FLB_STATS_OUTPUT_PLUGIN  5  /* Output plugin type        */

#define FLB_STATS_USERVER_PATH   "/tmp/fluentbit.sock"

/*
 * Unix Socket Server: the Stats interface launch a TCP unix socket
 * domain server, for every connected client the interface will dispatch
 * a summary of statistics in JSON format every five seconds. The following
 * structures holds the server info and the connection references:
 *
 * struct flb_stats_userver:   linked from flb_stats, represents the userver
 *                             context;
 *
 * struct flb_stats_userver_c: represents a client connected to our userver.
 *
 * struct flb_stats_userver_t: the timer context to deliver data to clients.
 */

/* Unix server client context */
struct flb_stats_userver_c {
    struct mk_event event;
    int fd;
    struct mk_list _head;
};

/* Unix server timer: used to write data to clients */
struct flb_stats_userver_t {
    struct mk_event event;
    int fd;
};

/* Unix server context */
struct flb_stats_userver {
    struct mk_event event;
    int fd;

    struct mk_list clients;
    struct flb_stats_userver_t *timer;
};

struct flb_stats_datapoint {
    time_t  time;
    ssize_t events;
    ssize_t bytes;
};

/* Statistics for input plugins */
struct flb_stats_in_plugin {
    struct mk_event event;
    int pipe[2];
    int n_data;

    struct flb_stats_datapoint data[FLB_STATS_SIZE];
    struct flb_input_plugin *plugin;
    struct mk_list _head;
};

/* Statistics for output plugins */
struct flb_stats_out_plugin {
    struct mk_event event;
    int pipe[2];
    int n_data;
    struct flb_stats_datapoint data[FLB_STATS_SIZE];
    struct flb_output_plugin *plugin;
    struct mk_list _head;
};

struct flb_stats {
    struct mk_event event;

    struct mk_event_loop *evl;
    struct flb_config *config;
    pthread_t worker_tid;

    /* Unix server */
    int ch_manager[2];
    struct flb_stats_userver *userver;

    /* References to components that can deliver statistics */
    struct mk_list in_plugins;
    struct mk_list out_plugins;
};

/* Simple function to update the stats counters */
static inline void flb_stats_update(int stats_fd,
                                    ssize_t bytes, ssize_t events)
{
    struct flb_stats_datapoint d;

    d.time   = time(NULL);
    d.bytes  = bytes;
    d.events = events;

    write(stats_fd, &d, sizeof(struct flb_stats_datapoint));
}

int flb_stats_init(struct flb_config *config);
int flb_stats_exit(struct flb_config *config);
int flb_stats_collect(struct flb_config *config);
int flb_stats_register(struct mk_event_loop *evl, struct flb_config *config);

#endif /* FLB_STATS_H */
#else

/* A dummy define to avoid some macros conditions into the core */
#define flb_stats_init(a) do{} while(0)
#define flb_stats_exit(a) do{} while(0)
#define flb_stats_update(a, b, c) do {} while(0)
#define flb_stats_reset(a) do {} while(0)
#define flb_stats_register(a, b) do{} while(0)

#endif /* HAVE_STATS  */
