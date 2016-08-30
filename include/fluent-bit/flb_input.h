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

#ifndef FLB_INPUT_H
#define FLB_INPUT_H

#include <inttypes.h>
#include <msgpack.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_network.h>

#define FLB_COLLECT_TIME        1
#define FLB_COLLECT_FD_EVENT    2
#define FLB_COLLECT_FD_SERVER   4

/* Input plugin masks */
#define FLB_INPUT_NET         4  /* input address may set host and port */
#define FLB_INPUT_DYN_TAG     64 /* the plugin generate it own tags     */

struct flb_input_instance;

struct flb_input_plugin {
    int flags;

    /* The Input name */
    char *name;

    /* Plugin Description */
    char *description;

    /* Initalization */
    int (*cb_init)    (struct flb_input_instance *, struct flb_config *, void *);

    /* Pre run */
    int (*cb_pre_run) (void *, struct flb_config *);

    /*
     * Collect: every certain amount of time, Fluent Bit
     * trigger this callback.
     */
    int (*cb_collect) (struct flb_config *, void *);

    /*
     * Flush: each plugin during a collection, it does some buffering,
     * when the Flush timer takes place on the Engine, it will trigger
     * the cb_flush(...) to obtain the plugin buffer data. This data is
     * a MsgPack buffer which will be processed by the Engine and delivered
     * to the target output.
     */

    /* Flush a buffer type (raw data) */
    void *(*cb_flush_buf) (void *, size_t *);

    /* Notify that a flush have completed on the collector (buf + iov) */
    void (*cb_flush_end) (void *);

    /*
     * Optional callback that can be used from a parent caller to ingest
     * data into the engine.
     */
    int (*cb_ingest) (void *in_context, void *, size_t);

    /* Exit */
    int (*cb_exit) (void *, struct flb_config *);

    struct mk_list _head;
};

/*
 * For input plugins which adds FLB_INPUT_DYN_TAG to the registration flag,
 * they usually report a set of new records under a dynamic Tags. Internally
 * the input plugin use the API function 'flb_input_dyntag_content()' to
 * register that info. The function will look for a matchin flb_input_dyntag
 * structure node or create a new one if required.
 */
struct flb_input_dyntag {
    int busy;

    /* Tag */
    int tag_len;
    char *tag;

    /* MessagePack */
    struct msgpack_sbuffer mp_sbuf; /* msgpack sbuffer */
    struct msgpack_packer mp_pck;   /* msgpack packer  */

    /* Link to parent list on flb_input_instance */
    struct mk_list _head;

    struct flb_input_instance *in;
};

/*
 * Each initialized plugin must have an instance, same plugin may be
 * loaded more than one time.
 *
 * An instance try to contain plugin data separating what is fixed data
 * and the variable one that is generated when the plugin is invoked.
 */
struct flb_input_instance {
    int channel[2];                      /* pipe(2) channel              */
    char name[16];                       /* numbered name (cpu -> cpu.0) */
    void *context;                       /* plugin configuration context */
    struct flb_input_plugin *p;          /* original plugin              */

    /* Plugin properties */
    char *tag;                           /* Input tag for routing        */
    int tag_len;

    /*
     * Input network info:
     *
     * An input plugin can be specified just using it shortname or using the
     * complete network address format, e.g:
     *
     *  $ fluent-bit -i cpu -o plugin://hostname:port/uri
     *
     * where:
     *
     *   plugin   = the output plugin shortname
     *   name     = IP address or hostname of the target
     *   port     = target TCP port
     *   uri      = extra information that may be used by the plugin
     */
    struct flb_net_host host;

    /*
     * Optional data passed to the plugin, this info is useful when
     * running Fluent Bit in library mode and the target plugin needs
     * some specific data from it caller.
     */
    void *data;

#ifdef FLB_HAVE_STATS
    int stats_fd;
#endif

    struct mk_list _head;                /* link to config->inputs     */
    struct mk_list routes;               /* flb_router_path's list     */
    struct mk_list dyntags;              /* dyntag nodes               */
    struct mk_list properties;           /* properties / configuration   */

    /*
     * Every co-routine created by the engine when flushing data, it's
     * linked into this list header.
     */
    struct mk_list tasks;                /* engine taskslist           */
};

struct flb_input_collector {
    int type;                            /* collector type             */

    /* FLB_COLLECT_FD_EVENT */
    int fd_event;                        /* fd being watched           */

    /* FLB_COLLECT_TIME */
    int fd_timer;                        /* timer fd                   */
    time_t seconds;                      /* expire time in seconds     */
    long nanoseconds;                    /* expire nanoseconds         */

    /* Callback */
    int (*cb_collect) (struct flb_config *, void *);

    struct mk_event event;

    /* General references */
    struct flb_input_instance *instance; /* plugin instance            */
    struct mk_list _head;                /* link to list of collectors */
};

int flb_input_register_all(struct flb_config *config);
struct flb_input_instance *flb_input_new(struct flb_config *config,
                                         char *input, void *data);
int flb_input_set_property(struct flb_input_instance *in, char *k, char *v);
char *flb_input_get_property(char *key, struct flb_input_instance *i);

int flb_input_check(struct flb_config *config);
void flb_input_set_context(struct flb_input_instance *in, void *context);
int flb_input_channel_init(struct flb_input_instance *in);

int flb_input_set_collector_time(struct flb_input_instance *in,
                                 int (*cb_collect) (struct flb_config *, void *),
                                 time_t seconds,
                                 long   nanoseconds,
                                 struct flb_config *config);
int flb_input_set_collector_event(struct flb_input_instance *in,
                                  int (*cb_collect) (struct flb_config *, void *),
                                  int fd,
                                  struct flb_config *config);
int flb_input_set_collector_socket(struct flb_input_instance *in,
                                   int (*cb_new_connection) (struct flb_config *, void*),
                                   int fd,
                                   struct flb_config *config);
void flb_input_initialize_all(struct flb_config *config);
void flb_input_pre_run_all(struct flb_config *config);
void flb_input_exit_all(struct flb_config *config);

int flb_input_register_collectors(struct flb_config *config);
int flb_input_unregister_collector(struct flb_input_collector *collector,
                                   struct flb_config *config);

/* Dyntag handlers */
struct flb_input_dyntag *flb_input_dyntag_create(struct flb_input_instance *in,
                                                 char *tag, int tag_len);
int flb_input_dyntag_destroy(struct flb_input_dyntag *dt);
int flb_input_dyntag_append(struct flb_input_instance *in,
                            char *tag, size_t tag_len,
                            msgpack_object data);
void *flb_input_dyntag_flush(struct flb_input_dyntag *dt, size_t *size);
void flb_input_dyntag_exit(struct flb_input_instance *in);

#endif
