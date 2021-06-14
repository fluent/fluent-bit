/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MK_CONFIG_H
#define MK_CONFIG_H

#define _GNU_SOURCE
#include <monkey/mk_core.h>

#include <monkey/mk_info.h>
#include "../../deps/rbtree/rbtree.h"

#ifdef _WIN32
typedef uint32_t mode_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
#endif

#ifndef O_NOATIME
#define O_NOATIME       01000000
#endif

#define MK_DEFAULT_CONFIG_FILE              "monkey.conf"
#define MK_DEFAULT_MIMES_CONF_FILE          "monkey.mime"
#define MK_DEFAULT_PLUGIN_LOAD_CONF_FILE    "plugins.load"
#define MK_DEFAULT_SITES_CONF_DIR           "sites/"
#define MK_DEFAULT_PLUGINS_CONF_DIR         "plugins/"
#define MK_DEFAULT_LISTEN_ADDR              "0.0.0.0"
#define MK_DEFAULT_LISTEN_PORT              "2001"
#define MK_WORKERS_DEFAULT                  1

/* Core capabilities, used as identifiers to match plugins */
#define MK_CAP_HTTP        1

/* HTTP/2: only if enabled */
#ifdef MK_HAVE_HTTP2
#define MK_CAP_HTTP2       2
#endif

#define MK_CAP_SOCK_PLAIN  4
#define MK_CAP_SOCK_TLS    8

struct mk_config_listener
{
    char *address;                /* address to bind */
    char *port;                   /* TCP port        */
    uint32_t flags;               /* properties: http | http2 | ssl */
    struct mk_list _head;
};

/* Base struct of server */
struct mk_server
{
    int server_fd;                /* server socket file descriptor */
    int kernel_version;           /* Running Linux Kernel version */
    int kernel_features;          /* Hold different server setup status */
    int fd_limit;                 /* Limit of file descriptors */
    unsigned int server_capacity; /* total server capacity */
    short int workers;            /* number of worker threads */
    short int manual_tcp_cork;    /* If enabled it will handle TCP_CORK */

    int8_t fdt;                   /* is FDT enabled ? */
    int8_t is_daemon;
    int8_t is_seteuid;
    int8_t scheduler_mode;        /* Scheduler balancing mode */

    /* Configuration paths (absolute paths) */
    char *path_conf_root;         /* absolute path to configuration files */
    char *path_conf_pidfile;      /* absolute path to PID file */

    /* Specific names for configuration files or directories */
    char *conf_mimetype;          /* mimetype file name */
    char *conf_main;              /* name of main configuration file */
    char *conf_sites;             /* directory name for virtual host files */
    char *conf_plugin_load;       /* file name which load dynamic plugins */
    char *conf_plugins;           /* directory name for plugins conf files */
    char *conf_user_pub;          /* directory name for users public content */

    mk_ptr_t server_software;

    struct mk_list listeners;

    char *one_shot;
    char *port_override;
    char *user;
    char **request_headers_allowed;

    int timeout;                /* max time to wait for a new connection */
    int standard_port;          /* common port used in web servers (80) */
    int pid_status;
    int8_t hideversion;           /* hide version of server to clients ? */
    int8_t resume;                /* Resume (on/off) */
    int8_t symlink;               /* symbolic links */

    /* keep alive */
    int8_t keep_alive;            /* it's a persisten connection ? */
    int max_keep_alive_request; /* max persistent connections to allow */
    int keep_alive_timeout;     /* persistent connection timeout */

    /* counter of threads working */
    int thread_counter;

    /* real user */
    uid_t egid;
    gid_t euid;

    int max_request_size;

    struct mk_list *index_files;

    /* configured host quantity */
    int nhosts;
    struct mk_list hosts;

    mode_t open_flags;
    struct mk_list plugins;

    /* Safe EPOLLOUT event */
    int safe_event_write;

    /*
     * Optional reference to force a specific transport, this one
     * is used when overriding the configuration from some caller
     */
    char *transport_layer;

    /* Define the default mime type when is not possible to find the proper one */
    struct mk_list mimetype_list;
    struct rb_tree mimetype_rb_head;
    void *mimetype_default;
    char *mimetype_default_str;

    char server_signature[16];
    char server_signature_header[32];
    int  server_signature_header_len;

    /* Library  mode */
    int lib_mode;                   /* is running in Library mode ? */
    int lib_ch_manager[2];          /* lib channel manager */
    struct mk_event_loop *lib_evl;  /* lib event loop */
    struct mk_event  lib_ch_event;  /* lib channel manager event ? */

    /* Scheduler context (struct mk_sched_ctx) */
    void *sched_ctx;

    /*
     * This list head, allow to link a set of callbacks that Monkey core
     * must invoke inside each thread worker once created. This list is
     * populated from mk_lib.c:mk_config_worker_callback(..).
     */
    struct mk_list sched_worker_callbacks;

    /* source configuration from files */
    struct mk_rconf *config;

    /* FIXME: temporal map of Network Layer plugin */
    struct mk_plugin_network *network;

    /* Direct map to Stage plugins */
    struct mk_list stage10_handler;
    struct mk_list stage20_handler;
    struct mk_list stage30_handler;
    struct mk_list stage40_handler;
    struct mk_list stage50_handler;
};

/* Functions */
struct mk_server_config *mk_config_init();
void mk_config_start_configure(struct mk_server *server);
void mk_config_signature(struct mk_server *server);
void mk_config_add_index(char *indexname);
void mk_config_set_init_values(struct mk_server *config);
int mk_config_listen_parse(char *value, struct mk_server *server);

/* config helpers */
void mk_config_error(const char *path, int line, const char *msg);
struct mk_config_listener *mk_config_listener_add(char *address,
                                                  char *port, int flags,
                                                  struct mk_server *server);
int mk_config_listen_check_busy();
void mk_config_listeners_free();

int mk_config_get_bool(char *value);
void mk_config_read_hosts(char *path);
void mk_config_sanity_check(struct mk_server *server);
void mk_config_free_all(struct mk_server *server);

#endif
