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

#ifndef MK_PLUGIN_H
#define MK_PLUGIN_H

#include <monkey/monkey.h>
#include <monkey/mk_kernel.h>
#include <monkey/mk_config.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_header.h>
#include <monkey/mk_http_status.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_info.h>
#include <monkey/mk_plugin_net.h>
#include <monkey/mk_core.h>

#define MK_PLUGIN_ERROR -1      /* plugin execution error */
#define MK_PLUGIN_

/* Plugin: Stages */
#define MK_PLUGIN_STAGE_10 (4)    /* Connection just accept()ed */
#define MK_PLUGIN_STAGE_20 (8)    /* HTTP Request arrived */
#define MK_PLUGIN_STAGE_30 (16)   /* Object handler  */
#define MK_PLUGIN_STAGE_40 (32)   /* Content served */
#define MK_PLUGIN_STAGE_50 (64)   /* Conection ended */

/* Plugin: Network type */
#define MK_PLUGIN_NETWORK_LAYER (128)
#define MK_PLUGIN_STAGE         (256)

/* Return values */
#define MK_PLUGIN_RET_NOT_ME -1
#define MK_PLUGIN_RET_CONTINUE 100
#define MK_PLUGIN_RET_END 200
#define MK_PLUGIN_RET_CLOSE_CONX 300
#define MK_PLUGIN_HEADER_EXTRA_ROWS  18

/* Plugin types */
#define MK_PLUGIN_STATIC     0   /* built-in into core */
#define MK_PLUGIN_DYNAMIC    1   /* shared library     */

/* Plugin Flags */
#define MK_PLUGIN_THREAD     1   /* It runs in a Monkey coroutine/thread */

/*
 * Event return values
 * -------------------
 * Any plugin can hook to any socket event, when a worker thread receives
 * a socket event through epoll(), it will check first the plugins hooks
 * before return the control to Monkey core.
 */

 /* The plugin request to the caller to continue invoking next plugins */
#define MK_PLUGIN_RET_EVENT_NEXT -300

/* The plugin has taken some action and no other plugin should go
 * over the event in question, return as soon as possible
 */
#define MK_PLUGIN_RET_EVENT_OWNED -400

/* The plugin request to finalize the session request */
#define MK_PLUGIN_RET_EVENT_CLOSE -500

/* The plugin request to the caller skip event hooks */
#define MK_PLUGIN_RET_EVENT_CONTINUE -600

struct mk_plugin;

/* API functions exported to plugins */
struct plugin_api
{
    /* socket functions */
    int (*socket_cork_flag) (int, int);
    int (*socket_reset) (int);
    int (*socket_set_tcp_fastopen) (int);
    int (*socket_set_tcp_nodelay) (int);
    int (*socket_set_tcp_reuseport) (int);
    int (*socket_connect) (char *, int, int);
    int (*socket_open) (char *, int);
    int (*socket_set_nonblocking) (int);
    int (*socket_create) ();
    int (*socket_close) (int);
    int (*socket_read) (int, void *, int);
    int (*socket_send_file) (int, int, off_t *, size_t);
    int (*socket_ip_str) (int, char **, int, unsigned long *);

    /* Async Network */
    struct mk_net_connection *(*net_conn_create) (char *, int);

    struct mk_server_config *config;
    struct mk_list *plugins;

    /* Error helper */
    void (*_error) (int, const char *, ...) PRINTF_WARNINGS(2,3);

    /* HTTP request function */
    int   (*http_request_end) (struct mk_plugin *plugin,
                               struct mk_http_session *cs, int close);
    int   (*http_request_error) (int, struct mk_http_session *,
                                 struct mk_http_request *, struct mk_plugin *);

    /* memory functions */
    void *(*mem_alloc) (const size_t size);
    void *(*mem_alloc_z) (const size_t size);
    void *(*mem_realloc) (void *, const size_t size);
    void  (*mem_free) (void *);
    void  (*pointer_set) (mk_ptr_t *, char *);
    void  (*pointer_print) (mk_ptr_t);
    char *(*pointer_to_buf) (mk_ptr_t);

    /* string functions */
    int   (*str_itop) (uint64_t, mk_ptr_t *);
    int   (*str_search) (const char *, const char *, int);
    int   (*str_search_n) (const char *, const char *, int, int);
    int   (*str_char_search) (const char *, int, int);

    char *(*str_build) (char **, unsigned long *, const char *, ...) PRINTF_WARNINGS(3,4);
    char *(*str_dup) (const char *);
    char *(*str_copy_substr) (const char *, int, int);
    struct mk_list *(*str_split_line) (const char *);
    void  (*str_split_free) (struct mk_list *);

    /* file functions */
    char *(*file_to_buffer) (const char *);
    int  (*file_get_info) (const char *, struct file_info *, int);

    /* header */
    int  (*header_prepare) (struct mk_plugin *,
                            struct mk_http_session *,
                            struct mk_http_request *);
    struct mk_http_header *(*header_get) (int, struct mk_http_request *,
                                          const char *, unsigned int);
    int  (*header_add) (struct mk_http_request *, char *row, int len);
    void (*header_set_http_status) (struct mk_http_request *, int);

    /* channel / stream handling */
    struct mk_stream *(*stream_new) (int, struct mk_channel *, void *, size_t,
                                void *,
                                void (*) (struct mk_stream *),
                                void (*) (struct mk_stream *, long),
                                void (*) (struct mk_stream *, int));
    struct mk_channel *(*channel_new) (int, int);
    int (*channel_flush) (struct mk_channel *);
    int (*channel_write) (struct mk_channel *, size_t *);
    void (*channel_append_stream) (struct mk_channel *, struct mk_stream *stream);
    void (*stream_set) (struct mk_stream *, int, struct mk_channel *, void *, size_t,
                        void *,
                        void (*) (struct mk_stream *),
                        void (*) (struct mk_stream *, long),
                        void (*) (struct mk_stream *, int));

    /* iov functions */
    struct mk_iov *(*iov_create) (int, int);
    struct mk_iov *(*iov_realloc) (struct mk_iov *, int);
    void (*iov_free) (struct mk_iov *);
    void (*iov_free_marked) (struct mk_iov *);
    int (*iov_add) (struct mk_iov *, void *, int, int);
    int (*iov_set_entry) (struct mk_iov *, void *, int, int, int);
    ssize_t (*iov_send) (int, struct mk_iov *);
    void (*iov_print) (struct mk_iov *);

    /* plugin functions */
    void *(*plugin_load_symbol) (void *, const char *);

    /* core events mechanism */
    struct mk_event_loop *(*ev_loop_create) (int);
    struct mk_event_fdt *(*ev_get_fdt) ();
    int (*ev_add) (struct mk_event_loop *, int, int, uint32_t, void *);
    int (*ev_del) (struct mk_event_loop *, struct mk_event *);
    int (*ev_timeout_create) (struct mk_event_loop *, time_t, long, void *);
    int (*ev_channel_create) (struct mk_event_loop *, int *, int *, void *);
    int (*ev_wait) (struct mk_event_loop *);
    char *(*ev_backend) ();

    /* Mime type */
    struct mk_mimetype *(*mimetype_lookup) (struct mk_server *, char *);

    /* configuration reader functions */
    struct mk_rconf *(*config_open) (const char *);
    struct mk_rconf *(*config_create) (const char *);
    void (*config_free) (struct mk_rconf *);
    struct mk_rconf_section *(*config_section_get) (struct mk_rconf *,
                                                    const char *);
    void *(*config_section_get_key) (struct mk_rconf_section *, char *, int);

    /* Scheduler */
    struct mk_event_loop *(*sched_loop)();
    int (*sched_remove_client) (int, struct mk_server *);
    struct mk_sched_conn *(*sched_get_connection)(struct mk_sched_worker *,
                                                  int);
    void (*sched_event_free) (struct mk_event *);
    struct mk_sched_worker *(*sched_worker_info)();

    /* worker's functions */
    int (*worker_spawn) (void (*func) (void *), void *, pthread_t *);
    int (*worker_rename) (const char *);

    /* event's functions */
    int (*event_add) (int, int, struct mk_plugin *, unsigned int);
    int (*event_del) (int);
    struct plugin_event *(*event_get) (int);

    int (*event_socket_change_mode) (int, int, unsigned int);

    /* Time utils functions */
    int (*time_unix) ();
    int (*time_to_gmt) (char **, time_t);
    mk_ptr_t *(*time_human) ();

#ifdef TRACE
    void (*trace)(const char *, int, const char *, char *, int, const char *, ...);
    int (*errno_print) (int);
#endif
    void (*stacktrace)(void);

    /* kernel interfaces */
    int (*kernel_version) ();
    int (*kernel_features_print) (char *, size_t, struct mk_server *);

    /* Handler */
    struct mk_vhost_handler_param *(*handler_param_get)(int, struct mk_list *);

#ifdef JEMALLOC_STATS
    int (*je_mallctl) (const char *, void *, size_t *, void *, size_t);
#endif
};

extern struct plugin_api *api;

struct mk_plugin_event
{
    struct mk_event event;        /* event loop context   */
    struct mk_plugin *handler;    /* plugin owner/handler */
};

struct mk_plugin_stage;

/* Info: used to register a plugin */
struct mk_plugin {
    int flags;

    /* Identification */
    const char *shortname;
    const char *name;
    const char *version;

    /* Hooks and capabilities */
    unsigned int hooks;
    char capabilities;

    struct plugin_api *api;

    /* Init / Exit */
    int (*init_plugin) (struct mk_plugin *, char *);
    int (*exit_plugin) (struct mk_plugin *);

    /* Init Levels */
    int  (*master_init) (struct mk_server *);
    void (*worker_init) ();

    /* Callback references for plugin type */
    struct mk_plugin_network *network;        /* MK_NETWORK_LAYER   */
    struct mk_plugin_stage   *stage;          /* MK_PLUGIN_STAGE    */

    /* Internal use variables */
    void *handler;                 /* DSO handler                  */
    char *path;                    /* Path for dynamic plugin      */
    pthread_key_t *thread_key;     /* Worker thread key            */
    struct mk_list _head;          /* Link to config->plugins list */
    struct mk_list stage_list;     /* Stages head list             */

    /* Load type: MK_PLUGIN_STATIC / MK_PLUGIN_DYNAMIC */
    int load_type;

    /* Sever context */
    struct mk_server *server_ctx;
};

struct mk_plugin_stage {
    int (*stage10) (int);
    int (*stage20) (struct mk_http_session *, struct mk_http_request *);
    int (*stage30) (struct mk_plugin *, struct mk_http_session *,
                    struct mk_http_request *, int, struct mk_list *);
    void (*stage30_thread) (struct mk_plugin *, struct mk_http_session *,
                            struct mk_http_request *, int, struct mk_list *);
    int (*stage30_hangup) (struct mk_plugin *, struct mk_http_session *,
                           struct mk_http_request *);
    int (*stage40) (struct mk_http_session *, struct mk_http_request *);
    int (*stage50) (int);

    /* Just a reference to the parent plugin */
    struct mk_plugin *plugin;

    /* Only used when doing direct mapping from config->stageN_handler; */
    struct mk_list _head;

    struct mk_list _parent_head;
};


void mk_plugin_api_init(struct mk_server *server);
void mk_plugin_load_all(struct mk_server *server);
void mk_plugin_exit_all(struct mk_server *server);
void mk_plugin_exit_worker();

void mk_plugin_event_init_list();

int mk_plugin_stage_run(unsigned int stage,
                        unsigned int socket,
                        struct mk_sched_conn *conx,
                        struct mk_http_session *cs, struct mk_http_request *sr);

void mk_plugin_core_process(struct mk_server *server);
void mk_plugin_core_thread();

void mk_plugin_preworker_calls(struct mk_server *server);

/* Plugins events interface */
int mk_plugin_event_add(int socket, int mode,
                        struct mk_plugin *handler,
                        unsigned int behavior);
int mk_plugin_event_del(int socket);
struct plugin_event *mk_plugin_event_get(int socket);

int mk_plugin_event_socket_change_mode(int socket, int mode, unsigned int behavior);

struct mk_plugin *mk_plugin_load(int type, const char *shortname,
                                 void *data, struct mk_server *server);

void *mk_plugin_load_symbol(void *handler, const char *symbol);
int mk_plugin_http_error(int http_status, struct mk_http_session *cs,
                         struct mk_http_request *sr,
                         struct mk_plugin *plugin);
int mk_plugin_http_request_end(struct mk_plugin *plugin,
                               struct mk_http_session *cs, int close);

/* Register functions */
struct plugin *mk_plugin_register(struct plugin *p);
void mk_plugin_unregister(struct mk_plugin *p);

struct plugin *mk_plugin_alloc(void *handler, const char *path);
void mk_plugin_free(struct mk_plugin *p);

int mk_plugin_time_now_unix(struct mk_server *server);
mk_ptr_t *mk_plugin_time_now_human(struct mk_server *server);

int mk_plugin_sched_remove_client(int socket, struct mk_server *server);


int mk_plugin_header_prepare(struct mk_plugin *plugin,
                             struct mk_http_session *cs,
                             struct mk_http_request *sr);

int mk_plugin_header_add(struct mk_http_request *sr, char *row, int len);
int mk_plugin_header_get(struct mk_http_request *sr,
                         mk_ptr_t query,
                         mk_ptr_t *result);

struct mk_sched_worker *mk_plugin_sched_get_thread_conf();
struct mk_plugin *mk_plugin_cap(char cap, struct mk_server *server);
struct mk_plugin *mk_plugin_lookup(char *shortname, struct mk_server *server);

void mk_plugin_load_static(struct mk_server *server);
struct mk_vhost_handler_param *mk_handler_param_get(int id,
                                                    struct mk_list *params);

#endif
