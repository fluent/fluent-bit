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
#include <monkey/mk_kernel.h>
#include <monkey/mk_config.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_mimetype.h>
#include <monkey/mk_info.h>
#include <monkey/mk_core.h>
#include <monkey/mk_server.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_mimetype.h>
#include <monkey/mk_info.h>

#include <ctype.h>
#include <limits.h>
#include <mk_core/mk_dirent.h>
#include <sys/stat.h>

struct mk_server_config *mk_config;

static int mk_config_key_have(struct mk_list *list, const char *value)
{
    struct mk_list *head;
    struct mk_string_line *entry;

    mk_list_foreach(head, list) {
        entry = mk_list_entry(head, struct mk_string_line, _head);
        if (strcasecmp(entry->val, value) == 0) {
            return MK_TRUE;
        }
    }
    return MK_FALSE;
}

void mk_config_listeners_free(struct mk_server *server)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_config_listener *l;

    mk_list_foreach_safe(head, tmp, &server->listeners) {
        l = mk_list_entry(head, struct mk_config_listener, _head);
        mk_list_del(&l->_head);
        mk_mem_free(l->address);
        mk_mem_free(l->port);
        mk_mem_free(l);
    }
}

void mk_config_free_all(struct mk_server *server)
{
    mk_vhost_free_all(server);
    mk_mimetype_free_all(server);

    if (server->config) {
        mk_rconf_free(server->config);
    }

    if (server->path_conf_root) {
        mk_mem_free(server->path_conf_root);
    }

    if (server->path_conf_pidfile) {
        mk_mem_free(server->path_conf_pidfile);
    }

    if (server->conf_user_pub) {
        mk_mem_free(server->conf_user_pub);
    }

    /* free config->index_files */
    if (server->index_files) {
        mk_string_split_free(server->index_files);
    }

    if (server->user) {
        mk_mem_free(server->user);
    }

    if (server->transport_layer) {
        mk_mem_free(server->transport_layer);
    }

    mk_config_listeners_free(server);

    mk_ptr_free(&server->server_software);
    mk_mem_free(server);
}

/* Print a specific error */
static void mk_config_print_error_msg(char *variable, char *path)
{
    mk_err("[config] %s at %s has an invalid value",
           variable, path);
    mk_mem_free(path);
    exit(EXIT_FAILURE);
}

/*
 * Check if at least one of the Listen interfaces are being used by another
 * process.
 */
int mk_config_listen_check_busy(struct mk_server *server)
{
    int fd;
    struct mk_list *head;
    struct mk_plugin *p;
    struct mk_config_listener *listen;

    p = mk_plugin_cap(MK_CAP_SOCK_PLAIN, server);
    if (!p) {
        mk_warn("Listen check: consider build monkey with basic socket handling!");
        return MK_FALSE;
    }

    mk_list_foreach(head, &server->listeners) {
        listen = mk_list_entry(head, struct mk_config_listener, _head);

        fd = mk_socket_connect(listen->address, atol(listen->port), MK_FALSE);
        if (fd != -1) {
            close(fd);
            return MK_TRUE;
        }
    }

    return MK_FALSE;
}

int mk_config_listen_parse(char *value, struct mk_server *server)
{
    int ret = -1;
    int flags = 0;
    long port_num;
    char *address = NULL;
    char *port = NULL;
    char *divider;
    struct mk_list *list = NULL;
    struct mk_string_line *listener;

    list = mk_string_split_line(value);
    if (!list) {
        goto error;
    }

    if (mk_list_is_empty(list) == 0) {
        goto error;
    }

    /* Parse the listener interface */
    listener = mk_list_entry_first(list, struct mk_string_line, _head);
    if (listener->val[0] == '[') {
        /* IPv6 address */
        divider = strchr(listener->val, ']');
        if (divider == NULL) {
            mk_err("[config] Expected closing ']' in IPv6 address.");
            goto error;
        }
        if (divider[1] != ':' || divider[2] == '\0') {
            mk_err("[config] Expected ':port' after IPv6 address.");
            goto error;
        }

        address = mk_string_copy_substr(listener->val + 1, 0,
                                        divider - listener->val - 1);
        port = mk_string_dup(divider + 2);
    }
    else if (strchr(listener->val, ':') != NULL) {
        /* IPv4 address */
        divider = strrchr(listener->val, ':');
        if (divider == NULL || divider[1] == '\0') {
            mk_err("[config] Expected ':port' after IPv4 address.");
            goto error;
        }

        address = mk_string_copy_substr(listener->val, 0,
                                        divider - listener->val);
        port = mk_string_dup(divider + 1);
    }
    else {
        /* Port only */
        address = NULL;
        port = mk_string_dup(listener->val);
    }

    errno = 0;
    port_num = strtol(port, NULL, 10);
    if (errno != 0 || port_num == LONG_MAX || port_num == LONG_MIN) {
        mk_warn("Using defaults, could not understand \"Listen %s\"",
                listener->val);
        port = NULL;
    }

    /* Check extra properties of the listener */
    flags = MK_CAP_HTTP;
    if (mk_config_key_have(list, "!http")) {
        flags |= ~MK_CAP_HTTP;
    }

#ifdef MK_HAVE_HTTP2
    if (mk_config_key_have(list, "h2")) {
        flags |= (MK_CAP_HTTP2 | MK_CAP_SOCK_TLS);
    }

    if (mk_config_key_have(list, "h2c")) {
        flags |= MK_CAP_HTTP2;
    }
#endif

    if (mk_config_key_have(list, "tls")) {
        flags |= MK_CAP_SOCK_TLS;
    }

    /* register the new listener */
    mk_config_listener_add(address, port, flags, server);
    mk_string_split_free(list);
    list = NULL;
    ret = 0;

error:
    if (address) {
        mk_mem_free(address);
    }
    if (port) {
        mk_mem_free(port);
    }
    if (list) {
        mk_string_split_free(list);
    }

    return ret;
}

static int mk_config_listen_read(struct mk_rconf_section *section,
                                 struct mk_server *server)
{
    int ret;
    struct mk_list *cur;
    struct mk_rconf_entry *entry;

    mk_list_foreach(cur, &section->entries) {
        entry = mk_list_entry(cur, struct mk_rconf_entry, _head);
        if (strcasecmp(entry->key, "Listen")) {
            continue;
        }

        ret = mk_config_listen_parse(entry->val, server);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

/* Read configuration files */
static int mk_config_read_files(char *path_conf, char *file_conf,
                                struct mk_server *server)
{
    unsigned long len;
    char *tmp = NULL;
    struct stat checkdir;
    struct mk_rconf *cnf;
    struct mk_rconf_section *section;

    if (!path_conf) {
        return -1;
    }

    if (!file_conf) {
        file_conf = "monkey.conf";
    }

    server->path_conf_root = mk_string_dup(path_conf);

    if (stat(server->path_conf_root, &checkdir) == -1) {
        mk_err("ERROR: Cannot find/open '%s'", server->path_conf_root);
        return -1;
    }

    mk_string_build(&tmp, &len, "%s/%s", path_conf, file_conf);
    cnf = mk_rconf_open(tmp);
    if (!cnf) {
        mk_mem_free(tmp);
        mk_err("Cannot read '%s'", server->conf_main);
        return -1;
    }
    section = mk_rconf_section_get(cnf, "SERVER");
    if (!section) {
        mk_err("ERROR: No 'SERVER' section defined");
        return -1;
    }

    /* Map source configuration */
    server->config = cnf;

    /* Listen */
    if (!server->port_override) {
        /* Process each Listen entry */
        if (mk_config_listen_read(section, server)) {
            mk_err("[config] Failed to read listen sections.");
        }
        if (mk_list_is_empty(&server->listeners) == 0) {
            mk_warn("[config] No valid Listen entries found, set default");
            mk_config_listener_add(NULL, NULL, MK_CAP_HTTP, server);
        }
    }
    else {
        mk_config_listener_add(NULL, server->port_override,
                               MK_CAP_HTTP, server);
    }

    /* Number of thread workers */
    if (server->workers == -1) {
        server->workers = (size_t) mk_rconf_section_get_key(section,
                                                               "Workers",
                                                               MK_RCONF_NUM);
    }

    if (server->workers < 1) {
        server->workers = mk_utils_get_system_core_count();

        if (server->workers < 1) {
            mk_config_print_error_msg("Workers", tmp);
        }
    }

    /* Timeout */
    server->timeout = (size_t) mk_rconf_section_get_key(section,
                                                           "Timeout", MK_RCONF_NUM);
    if (server->timeout < 1) {
        mk_config_print_error_msg("Timeout", tmp);
    }

    /* KeepAlive */
    server->keep_alive = (size_t) mk_rconf_section_get_key(section,
                                                              "KeepAlive",
                                                              MK_RCONF_BOOL);
    if (server->keep_alive == MK_ERROR) {
        mk_config_print_error_msg("KeepAlive", tmp);
    }

    /* MaxKeepAliveRequest */
    server->max_keep_alive_request = (size_t)
        mk_rconf_section_get_key(section,
                                 "MaxKeepAliveRequest",
                                 MK_RCONF_NUM);

    if (server->max_keep_alive_request == 0) {
        mk_config_print_error_msg("MaxKeepAliveRequest", tmp);
    }

    /* KeepAliveTimeout */
    server->keep_alive_timeout = (size_t) mk_rconf_section_get_key(section,
                                                                      "KeepAliveTimeout",
                                                                      MK_RCONF_NUM);
    if (server->keep_alive_timeout == 0) {
        mk_config_print_error_msg("KeepAliveTimeout", tmp);
    }

    /* Pid File */
    if (!server->path_conf_pidfile) {
        server->path_conf_pidfile = mk_rconf_section_get_key(section,
                                                                "PidFile",
                                                                MK_RCONF_STR);
    }

    /* Home user's directory /~ */
    server->conf_user_pub = mk_rconf_section_get_key(section,
                                                        "UserDir",
                                                        MK_RCONF_STR);

    /* Index files */
    server->index_files = mk_rconf_section_get_key(section,
                                                      "Indexfile", MK_RCONF_LIST);

    /* HideVersion Variable */
    server->hideversion = (size_t) mk_rconf_section_get_key(section,
                                                         "HideVersion",
                                                         MK_RCONF_BOOL);
    if (server->hideversion == MK_ERROR) {
        mk_config_print_error_msg("HideVersion", tmp);
    }

    /* User Variable */
    server->user = mk_rconf_section_get_key(section, "User", MK_RCONF_STR);

    /* Resume */
    server->resume = (size_t) mk_rconf_section_get_key(section,
                                                          "Resume", MK_RCONF_BOOL);
    if (server->resume == MK_ERROR) {
        mk_config_print_error_msg("Resume", tmp);
    }

    /* Max Request Size */
    server->max_request_size = (size_t) mk_rconf_section_get_key(section,
                                                              "MaxRequestSize",
                                                              MK_RCONF_NUM);
    if (server->max_request_size <= 0) {
        mk_config_print_error_msg("MaxRequestSize", tmp);
    }
    else {
        server->max_request_size *= 1024;
    }

    /* Symbolic Links */
    server->symlink = (size_t) mk_rconf_section_get_key(section,
                                                     "SymLink", MK_RCONF_BOOL);
    if (server->symlink == MK_ERROR) {
        mk_config_print_error_msg("SymLink", tmp);
    }

    /* Transport Layer plugin */
    if (!server->transport_layer) {
        server->transport_layer = mk_rconf_section_get_key(section,
                                                              "TransportLayer",
                                                              MK_RCONF_STR);
    }

    /* Default Mimetype */
    mk_mem_free(tmp);
    tmp = mk_rconf_section_get_key(section, "DefaultMimeType", MK_RCONF_STR);
    if (tmp) {
        mk_string_build(&server->mimetype_default_str, &len, "%s\r\n", tmp);
    }

    /* File Descriptor Table (FDT) */
    server->fdt = (size_t) mk_rconf_section_get_key(section,
                                                    "FDT",
                                                    MK_RCONF_BOOL);

    /* FIXME: Overcapacity not ready */
    server->fd_limit = (size_t) mk_rconf_section_get_key(section,
                                                           "FDLimit",
                                                           MK_RCONF_NUM);
    /* Get each worker clients capacity based on FDs system limits */
    server->server_capacity = mk_server_capacity(server);


    if (!server->one_shot) {
        mk_vhost_init(path_conf, server);
    }
    else {
        mk_vhost_set_single(server->one_shot, server);
    }

    mk_mem_free(tmp);
    return 0;
}

void mk_config_signature(struct mk_server *server)
{
    unsigned long len;

    /* Server Signature */
    if (server->hideversion == MK_FALSE) {
        snprintf(server->server_signature,
                 sizeof(server->server_signature) - 1,
                 "Monkey/%s", MK_VERSION_STR);
    }
    else {
        snprintf(server->server_signature,
                 sizeof(server->server_signature) - 1,
                 "Monkey");
    }
    len = snprintf(server->server_signature_header,
                   sizeof(server->server_signature_header) - 1,
                   "Server: %s\r\n", server->server_signature);
    server->server_signature_header_len = len;
}

/* read main configuration from monkey.conf */
void mk_config_start_configure(struct mk_server *server)
{
    int ret;
    unsigned long len;

    ret = mk_config_read_files(server->path_conf_root,
                               server->conf_main, server);
    if (ret != 0) {
        return;
    }

    /* Load mimes */
    mk_mimetype_read_config(server);

    mk_ptr_reset(&server->server_software);

    /* Basic server information */
    if (server->hideversion == MK_FALSE) {
        mk_string_build(&server->server_software.data,
                        &len, "Monkey/%s (%s)", MK_VERSION_STR, MK_BUILD_OS);
        server->server_software.len = len;
    }
    else {
        mk_string_build(&server->server_software.data, &len, "Monkey Server");
        server->server_software.len = len;
    }
}

/* Register a new listener into the main configuration */
struct mk_config_listener *mk_config_listener_add(char *address,
                                                  char *port, int flags,
                                                  struct mk_server *server)
{
    struct mk_list *head;
    struct mk_config_listener *check;
    struct mk_config_listener *listen = NULL;

    listen = mk_mem_alloc(sizeof(struct mk_config_listener));
    if (!listen) {
        mk_err("[listen_add] malloc() failed");
        return NULL;
    }

    if (!address) {
        listen->address = mk_string_dup(MK_DEFAULT_LISTEN_ADDR);
    }
    else {
        listen->address = mk_string_dup(address);
    }

    /* Set the port */
    if (!port) {
        mk_err("[listen_add] TCP port not defined");
        exit(EXIT_FAILURE);
    }

    listen->port = mk_string_dup(port);
    listen->flags = flags;

    /* Before to add a new listener, lets make sure it's not a duplicated */
    mk_list_foreach(head, &server->listeners) {
        check = mk_list_entry(head, struct mk_config_listener, _head);
        if (strcmp(listen->address, check->address) == 0 &&
            strcmp(listen->port, check->port) == 0) {
            mk_warn("Listener: duplicated %s:%s, skip.",
                    listen->address, listen->port);

            /* free resources */
            mk_mem_free(listen->address);
            mk_mem_free(listen->port);
            mk_mem_free(listen);
            return NULL;
        }
    }

    mk_list_add(&listen->_head, &server->listeners);
    return listen;
}

void mk_config_set_init_values(struct mk_server *server)
{
    /* Init values */
    server->is_seteuid = MK_FALSE;
    server->timeout = 15;
    server->hideversion = MK_FALSE;
    server->keep_alive = MK_TRUE;
    server->keep_alive_timeout = 15;
    server->max_keep_alive_request = 50;
    server->resume = MK_TRUE;
    server->standard_port = 80;
    server->symlink = MK_FALSE;
    server->nhosts = 0;
    mk_list_init(&server->hosts);
    server->user = NULL;
    server->open_flags = O_RDONLY; /* The only place this is effectively used (other than the sanity check) 
                                    * is mk_http.c where it's used to test for file existence and the fd is apparently leaked */
    server->index_files = NULL;
    server->conf_user_pub = NULL;
    server->workers = 1;

    /* TCP REUSEPORT: available on Linux >= 3.9 */
    if (server->scheduler_mode == -1) {
        if (server->kernel_features & MK_KERNEL_SO_REUSEPORT) {
            server->scheduler_mode = MK_SCHEDULER_REUSEPORT;
        }
        else {
            server->scheduler_mode = MK_SCHEDULER_FAIR_BALANCING;
        }
    }

    /* Max request buffer size allowed
     * right now, every chunk size is 4KB (4096 bytes),
     * so we are setting a maximum request size to 32 KB */
    server->max_request_size = MK_REQUEST_CHUNK * 8;

    /* Internals */
    server->safe_event_write = MK_FALSE;

    /* Init plugin list */
    mk_list_init(&server->plugins);

    /* Init listeners */
    mk_list_init(&server->listeners);
}

void mk_config_sanity_check(struct mk_server *server)
{
    /* Check O_NOATIME for current user, flag will just be used
     * if running user is allowed to.
     */
    int fd;
    int flags;

    if (!server->path_conf_root) {
        return;
    }

    flags = server->open_flags;
    flags |= O_NOATIME;
    fd = open(server->path_conf_root, flags);

    if (fd > -1) {
        server->open_flags = flags;
        close(fd);
    }
}
