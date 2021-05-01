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

#include <monkey/monkey.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_http.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_mimetype.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_static_plugins.h>
#include <monkey/mk_plugin_stage.h>
#include <monkey/mk_core.h>
#include <monkey/mk_net.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <err.h>
#endif

enum {
    bufsize = 256
};

static struct plugin_stagemap *plg_stagemap;
struct plugin_network_io *plg_netiomap;
struct plugin_api *api;

struct mk_plugin *mk_plugin_lookup(char *shortname, struct mk_server *server)
{
    struct mk_list *head;
    struct mk_plugin *p = NULL;

    mk_list_foreach(head, &server->plugins) {
        p = mk_list_entry(head, struct mk_plugin, _head);
        if (strcmp(p->shortname, shortname) == 0){
            return p;
        }
    }

    return NULL;
}

void *mk_plugin_load_dynamic(const char *path)
{
    void *handle;

#ifdef _WIN32
    handle = (void *) LoadLibraryA(path);
#else
    handle = dlopen(path, RTLD_LAZY);

    if (!handle) {
        mk_warn("dlopen() %s", dlerror());
    }
#endif

    return handle;
}

void *mk_plugin_load_symbol(void *handler, const char *symbol)
{
    void *s;

#ifdef _WIN32
    s = GetProcAddress((HMODULE)handler, symbol);
#else
    dlerror();
    s = dlsym(handler, symbol);
    if (dlerror() != NULL) {
        return NULL;
    }
#endif

    return s;
}

/* Initialize a plugin, trigger the init_plugin callback */
static int mk_plugin_init(struct plugin_api *api, struct mk_plugin *plugin,
                          struct mk_server *server)
{
    int ret;
    unsigned long len;
    char path[1024];
    char *conf_dir = NULL;
    struct file_info f_info;

    MK_TRACE("Load Plugin: '%s'", plugin->shortname);

    snprintf(path, 1024, "%s/%s",
             server->path_conf_root, server->conf_plugins);
    ret = mk_file_get_info(path, &f_info, MK_FILE_READ);
    if (ret == -1 || f_info.is_directory == MK_FALSE) {
        snprintf(path, 1024, "%s", server->conf_plugins);
    }

    /* Build plugin configuration path */
    mk_string_build(&conf_dir,
                    &len,
                    "%s/%s/",
                    path, plugin->shortname);

    /* Init plugin */
    plugin->server_ctx = server;
    ret = plugin->init_plugin(&api, conf_dir);
    mk_mem_free(conf_dir);

    return ret;
}


/*
 * Load a plugin into Monkey core, 'type' defines if it's a MK_PLUGIN_STATIC or
 * a MK_PLUGIN_DYNAMIC. 'shortname' is mandatory and 'path' is only used when
 * MK_PLUGIN_DYNAMIC is set and represents the absolute path of the shared
 * library.
 */
struct mk_plugin *mk_plugin_load(int type, const char *shortname,
                                 void *data, struct mk_server *server)
{
    char *path;
    char symbol[64];
    void *handler;
    struct mk_list *head;
    struct mk_plugin *tmp;
    struct mk_plugin *plugin = NULL;
    struct mk_plugin_stage *stage;

    /* Set main struct name to reference */
    if (type == MK_PLUGIN_DYNAMIC) {
        path = (char *) data;
        handler = mk_plugin_load_dynamic(path);
        if (!handler) {
            return NULL;
        }

        snprintf(symbol, sizeof(symbol) - 1, "mk_plugin_%s", shortname);
        plugin  = mk_plugin_load_symbol(handler, symbol);
        if (!plugin) {
            mk_warn("Plugin '%s' is not registering properly", path);
#ifdef _WIN32
            FreeLibrary((HMODULE)handler);
#else
            dlclose(handler);
#endif
            return NULL;
        }

        /* Make sure this is not loaded twice (ref #218) */
        mk_list_foreach(head, &server->plugins) {
            tmp = mk_list_entry(head, struct mk_plugin, _head);
            if (tmp->load_type == MK_PLUGIN_STATIC &&
                strcmp(tmp->name, plugin->name) == 0){
                mk_warn("Plugin '%s' have been built-in.",
                        tmp->shortname);
#ifdef _WIN32
                FreeLibrary((HMODULE)handler);
#else
                dlclose(handler);
#endif
                return NULL;
            }
        }

        plugin->load_type = MK_PLUGIN_DYNAMIC;
        plugin->handler   = handler;
        plugin->path      = mk_string_dup(path);
    }
    else if (type == MK_PLUGIN_STATIC) {
        plugin = (struct mk_plugin *) data;
        plugin->load_type = MK_PLUGIN_STATIC;
    }

    if (!plugin) {
        return NULL;
    }

    /* Validate all callbacks are set */
    if (!plugin->shortname || !plugin->name || !plugin->version ||
        !plugin->init_plugin || !plugin->exit_plugin) {
        mk_warn("Plugin '%s' is not registering all fields properly",
                shortname);
        return NULL;
    }

    if (plugin->hooks & MK_PLUGIN_NETWORK_LAYER) {
        mk_bug(!plugin->network);
    }

    mk_list_init(&plugin->stage_list);
    if (plugin->hooks & MK_PLUGIN_STAGE) {
        struct mk_plugin_stage *st;

        stage = plugin->stage;
        if (stage->stage10) {
            st = mk_mem_alloc(sizeof(struct mk_plugin_stage));
            st->stage10 = stage->stage10;
            st->plugin  = plugin;
            mk_list_add(&st->_head, &server->stage10_handler);
            mk_list_add(&st->_parent_head, &plugin->stage_list);
        }
        if (stage->stage20) {
            st = mk_mem_alloc(sizeof(struct mk_plugin_stage));
            st->stage20 = stage->stage20;
            st->plugin  = plugin;
            mk_list_add(&st->_head, &server->stage20_handler);
            mk_list_add(&st->_parent_head, &plugin->stage_list);
        }
        if (stage->stage30) {
            st = mk_mem_alloc(sizeof(struct mk_plugin_stage));
            st->stage30 = stage->stage30;
            st->plugin  = plugin;
            mk_list_add(&st->_head, &server->stage30_handler);
            mk_list_add(&st->_parent_head, &plugin->stage_list);
        }
        if (stage->stage40) {
            st = mk_mem_alloc(sizeof(struct mk_plugin_stage));
            st->stage40 = stage->stage40;
            st->plugin  = plugin;
            mk_list_add(&st->_head, &server->stage40_handler);
            mk_list_add(&st->_parent_head, &plugin->stage_list);
        }
        if (stage->stage50) {
            st = mk_mem_alloc(sizeof(struct mk_plugin_stage));
            st->stage50 = stage->stage50;
            st->plugin  = plugin;
            mk_list_add(&st->_head, &server->stage50_handler);
            mk_list_add(&st->_parent_head, &plugin->stage_list);
        }
    }

    if (type == MK_PLUGIN_DYNAMIC) {
        /* Add Plugin to the end of the list */
        mk_list_add(&plugin->_head, &server->plugins);
    }

    return plugin;
}

void mk_plugin_unregister(struct mk_plugin *p)
{
    mk_mem_free(p->path);
    mk_list_del(&p->_head);
    if (p->load_type == MK_PLUGIN_DYNAMIC) {
#ifdef _WIN32
        FreeLibrary((HMODULE)p->handler);
#else
        dlclose(p->handler);
#endif
    }

}

void mk_plugin_api_init(struct mk_server *server)
{
    /* Create an instance of the API */
    api = mk_mem_alloc_z(sizeof(struct plugin_api));

#ifndef _WIN32
    __builtin_prefetch(api);
#endif

    /* Setup and connections list */
    /* FIXME: api->config = server; */

    /* API plugins funcions */

    /* Error helper */
    api->_error = mk_print;

    /* HTTP callbacks */
    api->http_request_end = mk_plugin_http_request_end;
    api->http_request_error = mk_plugin_http_error;

    /* Memory callbacks */
    api->pointer_set = mk_ptr_set;
    api->pointer_print = mk_ptr_print;
    api->pointer_to_buf = mk_ptr_to_buf;
    api->plugin_load_symbol = mk_plugin_load_symbol;
    api->mem_alloc = mk_mem_alloc;
    api->mem_alloc_z = mk_mem_alloc_z;
    api->mem_realloc = mk_mem_realloc;
    api->mem_free = mk_mem_free;

    /* String Callbacks */
    api->str_build = mk_string_build;
    api->str_dup = mk_string_dup;
    api->str_search = mk_string_search;
    api->str_search_n = mk_string_search_n;
    api->str_char_search = mk_string_char_search;
    api->str_copy_substr = mk_string_copy_substr;
    api->str_itop = mk_string_itop;
    api->str_split_line = mk_string_split_line;
    api->str_split_free = mk_string_split_free;

    /* File Callbacks */
    api->file_to_buffer = mk_file_to_buffer;
    api->file_get_info = mk_file_get_info;

    /* HTTP Callbacks */
    api->header_prepare = mk_plugin_header_prepare;
    api->header_add = mk_plugin_header_add;
    api->header_get = mk_http_header_get;
    api->header_set_http_status = mk_header_set_http_status;

    /* Channels / Streams */
    api->channel_new   = mk_channel_new;
    api->channel_flush = mk_channel_flush;
    api->channel_write = mk_channel_write;
    api->channel_append_stream = mk_channel_append_stream;

    /* IOV callbacks */
    api->iov_create  = mk_iov_create;
    api->iov_realloc = mk_iov_realloc;
    api->iov_free = mk_iov_free;
    api->iov_free_marked = mk_iov_free_marked;
    api->iov_add =  mk_iov_add;
    api->iov_set_entry =  mk_iov_set_entry;
    api->iov_send =  mk_iov_send;
    api->iov_print =  mk_iov_print;

    /* events mechanism */
    api->ev_loop_create = mk_event_loop_create;
    api->ev_add = mk_event_add;
    api->ev_del = mk_event_del;
    api->ev_timeout_create = mk_event_timeout_create;
    api->ev_channel_create = mk_event_channel_create;
    api->ev_wait = mk_event_wait;
    api->ev_backend = mk_event_backend;

    /* Mimetype */
    api->mimetype_lookup = mk_mimetype_lookup;

    /* Socket callbacks */
    api->socket_cork_flag = mk_socket_set_cork_flag;
    api->socket_connect = mk_socket_connect;
    api->socket_open = mk_socket_open;
    api->socket_reset = mk_socket_reset;
    api->socket_set_tcp_fastopen = mk_socket_set_tcp_fastopen;
    api->socket_set_tcp_reuseport = mk_socket_set_tcp_reuseport;
    api->socket_set_tcp_nodelay = mk_socket_set_tcp_nodelay;
    api->socket_set_nonblocking = mk_socket_set_nonblocking;
    api->socket_create = mk_socket_create;
    api->socket_ip_str = mk_socket_ip_str;

    /* Async network */
    api->net_conn_create = mk_net_conn_create;

    /* Config Callbacks */
    api->config_create = mk_rconf_create;
    api->config_open = mk_rconf_open;
    api->config_free = mk_rconf_free;
    api->config_section_get = mk_rconf_section_get;
    api->config_section_get_key = mk_rconf_section_get_key;

    /* Scheduler and Event callbacks */
    api->sched_loop           = mk_sched_loop;
    api->sched_get_connection = mk_sched_get_connection;
    api->sched_event_free     = mk_sched_event_free;
    api->sched_remove_client  = mk_plugin_sched_remove_client;
    api->sched_worker_info    = mk_plugin_sched_get_thread_conf;

    /* Worker functions */
    api->worker_spawn = mk_utils_worker_spawn;
    api->worker_rename = mk_utils_worker_rename;

    /* Time functions */
    api->time_unix   = mk_plugin_time_now_unix;
    api->time_to_gmt = mk_utils_utime2gmt;
    api->time_human  = mk_plugin_time_now_human;

    api->stacktrace = (void *) mk_utils_stacktrace;
    api->kernel_version = mk_kernel_version;
    api->kernel_features_print = mk_kernel_features_print;
    api->plugins = &server->plugins;

    /* handler */
    api->handler_param_get = mk_handler_param_get;
}

void mk_plugin_load_static(struct mk_server *server)
{
    /* Load static plugins */
    mk_list_init(&server->plugins);
    mk_static_plugins(&server->plugins);
}

void mk_plugin_load_all(struct mk_server *server)
{
    int ret;
    char *tmp;
    char *path;
    char shortname[64];
    struct mk_plugin *p;
    struct mk_rconf *cnf;
    struct mk_rconf_section *section;
    struct mk_rconf_entry *entry;
    struct mk_list *head;
    struct mk_list *htmp;
    struct file_info f_info;

    mk_plugin_load_static(server);
    mk_list_foreach_safe(head, htmp, &server->plugins) {
        p = mk_list_entry(head, struct mk_plugin, _head);

        /* Load the static plugin */
        p = mk_plugin_load(MK_PLUGIN_STATIC,
                           p->shortname,
                           (void *) p,
                           server);
        if (!p) {
            continue;
        }
        ret = mk_plugin_init(api, p, server);
        if (ret == -1) {
            /* Free plugin, do not register, error initializing */
            mk_warn("Plugin initialization failed: %s", p->shortname);
            mk_plugin_unregister(p);
            continue;
        }
        else if (ret == -2) {
            /* Do not register, just skip it */
            mk_plugin_unregister(p);
            continue;
        }
    }

    /* In case there are not dynamic plugins */
    if (!server->conf_plugin_load) {
        return;
    }

    /* Read configuration file */
    path = mk_mem_alloc_z(1024);
    snprintf(path, 1024, "%s/%s", server->path_conf_root,
             server->conf_plugin_load);
    ret = mk_file_get_info(path, &f_info, MK_FILE_READ);
    if (ret == -1 || f_info.is_file == MK_FALSE) {
        snprintf(path, 1024, "%s", server->conf_plugin_load);
    }

    cnf = mk_rconf_open(path);
    if (!cnf) {
        mk_warn("No dynamic plugins loaded.");
        mk_mem_free(path);
        return;
    }

    /* Read section 'PLUGINS' */
    section = mk_rconf_section_get(cnf, "PLUGINS");
    if (!section) {
        exit(EXIT_FAILURE);
    }

    /* Read key entries */
    mk_list_foreach_safe(head, htmp, &section->entries) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);
        if (strcasecmp(entry->key, "Load") == 0) {

            /* Get plugin 'shortname' */
            tmp = memrchr(entry->val, '-', strlen(entry->val));
            ++tmp;
            memset(shortname, '\0', sizeof(shortname) - 1);
            strncpy(shortname, tmp, strlen(tmp) - 3);

            /* Load the dynamic plugin */
            p = mk_plugin_load(MK_PLUGIN_DYNAMIC,
                               shortname,
                               entry->val,
                               server);
            if (!p) {
                mk_warn("Invalid plugin '%s'", entry->val);
                continue;
            }

            ret = mk_plugin_init(api, p, server);
            if (ret < 0) {
                /* Free plugin, do not register */
                MK_TRACE("Unregister plugin '%s'", p->shortname);
                mk_plugin_unregister(p);
                continue;
            }
        }
    }

    /* Look for plugins thread key data */
    mk_plugin_preworker_calls(server);
    mk_vhost_map_handlers(server);
    mk_mem_free(path);
    mk_rconf_free(cnf);
}

static void mk_plugin_exit_stages(struct mk_plugin *p)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_plugin_stage *st;

    mk_list_foreach_safe(head, tmp, &p->stage_list) {
        st = mk_list_entry(head, struct mk_plugin_stage, _parent_head);

        /* remove from direct config->stageN head list */
        mk_list_del(&st->_head);

        /* remove from plugin->stage_lists */
        mk_list_del(&st->_parent_head);
        mk_mem_free(st);
    }
}

/* Invoke all plugins 'exit' hook and free resources by the plugin interface */
void mk_plugin_exit_all(struct mk_server *server)
{
    struct mk_plugin *plugin;
    struct mk_list *head, *tmp;

    /* Plugins */
    mk_list_foreach(head, &server->plugins) {
        plugin = mk_list_entry(head, struct mk_plugin, _head);
        plugin->exit_plugin();
    }

    /* Plugin interface it self */
    mk_list_foreach_safe(head, tmp, &server->plugins) {
        plugin = mk_list_entry(head, struct mk_plugin, _head);
        mk_list_del(&plugin->_head);
        mk_plugin_exit_stages(plugin);

        if (plugin->load_type == MK_PLUGIN_DYNAMIC) {
            mk_mem_free(plugin->path);
#ifdef _WIN32
            FreeLibrary((HMODULE)plugin->handler);
#else
            dlclose(plugin ->handler);
#endif
        }
    }
    mk_mem_free(api);
    mk_mem_free(plg_stagemap);
}

/*
 * When a worker is exiting, it invokes this function to release any plugin
 * associated data.
 */
void mk_plugin_exit_worker()
{
}

/* This function is called by every created worker
 * for plugins which need to set some data under a thread
 * context
 */
void mk_plugin_core_process(struct mk_server *server)
{
    struct mk_plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, &server->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);

        /* Init plugin */
        if (node->master_init) {
            node->master_init(server);
        }
    }
}

/* This function is called by every created worker
 * for plugins which need to set some data under a thread
 * context
 */
void mk_plugin_core_thread(struct mk_server *server)
{

    struct mk_plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, &server->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);

        /* Init plugin thread context */
        if (node->worker_init) {
            node->worker_init(server);
        }
    }
}

/* This function is called by Monkey *outside* of the
 * thread context for plugins, so here's the right
 * place to set pthread keys or similar
 */
void mk_plugin_preworker_calls(struct mk_server *server)
{
    int ret;
    struct mk_plugin *node;
    struct mk_list *head;

    mk_list_foreach(head, &server->plugins) {
        node = mk_list_entry(head, struct mk_plugin, _head);

        /* Init pthread keys */
        if (node->thread_key) {
            MK_TRACE("[%s] Set thread key", node->shortname);

            ret = pthread_key_create(node->thread_key, NULL);
            if (ret != 0) {
                mk_err("Plugin Error: could not create key for %s",
                       node->shortname);
            }
        }
    }
}

int mk_plugin_http_error(int http_status, struct mk_http_session *cs,
                         struct mk_http_request *sr,
                         struct mk_plugin *plugin)
{
    return mk_http_error(http_status, cs, sr, plugin->server_ctx);
}


int mk_plugin_http_request_end(struct mk_plugin *plugin,
                               struct mk_http_session *cs, int close)
{
    int ret;
    int con;
    struct mk_http_request *sr;
    struct mk_server *server = plugin->server_ctx;

    MK_TRACE("[FD %i] PLUGIN HTTP REQUEST END", cs->socket);

    cs->status = MK_REQUEST_STATUS_INCOMPLETE;
    if (mk_list_is_empty(&cs->request_list) == 0) {
        MK_TRACE("[FD %i] Tried to end non-existing request.", cs->socket);
        return -1;
    }

    sr = mk_list_entry_last(&cs->request_list, struct mk_http_request, _head);
    mk_plugin_stage_run_40(cs, sr, server);

    if (close == MK_TRUE) {
        cs->close_now = MK_TRUE;
    }

    /* Let's check if we should ask to finalize the connection or not */
    ret = mk_http_request_end(cs, server);
    MK_TRACE("[FD %i] HTTP session end = %i", cs->socket, ret);
    if (ret < 0) {
        con = mk_sched_event_close(cs->conn, mk_sched_get_thread_conf(),
                                   MK_EP_SOCKET_DONE, server);
        if (con != 0) {
            return con;
        }
        else {
            return -1;
        }
    }

    return ret;
}

/* Plugin epoll event handlers
 * ---------------------------
 * this functions are called by connection.c functions as mk_conn_read(),
 * mk_conn_write(),mk_conn_error(), mk_conn_close() and mk_conn_timeout().
 *
 * Return Values:
 * -------------
 *    MK_PLUGIN_RET_EVENT_NOT_ME: There's no plugin hook associated
 */

void mk_plugin_event_bad_return(const char *hook, int ret)
{
    mk_err("[%s] Not allowed return value %i", hook, ret);
}

int mk_plugin_time_now_unix()
{
    return log_current_utime;
}

mk_ptr_t *mk_plugin_time_now_human()
{
    return &log_current_time;
}

int mk_plugin_sched_remove_client(int socket, struct mk_server *server)
{
    struct mk_sched_conn *conn;
    struct mk_sched_worker *sched;

    MK_TRACE("[FD %i] remove client", socket);

    sched = mk_sched_get_thread_conf();
    conn  = mk_sched_get_connection(sched, socket);
    if (!conn) {
        return -1;
    }

    return mk_sched_remove_client(conn, sched, server);
}

int mk_plugin_header_prepare(struct mk_plugin *plugin,
                             struct mk_http_session *cs,
                             struct mk_http_request *sr)
{
    return mk_header_prepare(cs, sr, plugin->server_ctx);
}


int mk_plugin_header_add(struct mk_http_request *sr, char *row, int len)
{
    mk_bug(!sr);

    if (!sr->headers._extra_rows) {
        /*
         * We allocate space for a fixed number of IOV entries:
         *
         *   MK_PLUGIN_HEADER_EXTRA_ROWS = X
         *
         *  we use (MK_PLUGIN_HEADER_EXTRA_ROWS * 2) thinking in an ending CRLF
         */
        sr->headers._extra_rows = mk_iov_create(MK_PLUGIN_HEADER_EXTRA_ROWS * 2, 0);
        mk_bug(!sr->headers._extra_rows);
    }

    mk_iov_add(sr->headers._extra_rows, row, len,
               MK_FALSE);
    mk_iov_add(sr->headers._extra_rows,
               mk_iov_crlf.data, mk_iov_crlf.len,
               MK_FALSE);
    return 0;
}

struct mk_sched_worker *mk_plugin_sched_get_thread_conf()
{
    return MK_TLS_GET(mk_tls_sched_worker_node);
}

struct mk_plugin *mk_plugin_cap(char cap, struct mk_server *server)
{
    struct mk_list *head;
    struct mk_plugin *plugin;

    mk_list_foreach(head, &server->plugins) {
        plugin = mk_list_entry(head, struct mk_plugin, _head);
        if (plugin->capabilities & cap) {
            return plugin;
        }
    }

    return NULL;
}

struct mk_vhost_handler_param *mk_handler_param_get(int id,
                                                    struct mk_list *params)
{
    int i = 0;
    struct mk_list *head;

    mk_list_foreach(head, params) {
        if (i == id) {
            return mk_list_entry(head, struct mk_vhost_handler_param, _head);
        }
        i++;
    }

    return NULL;
}
