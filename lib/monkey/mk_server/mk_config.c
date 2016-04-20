/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/stat.h>

struct mk_server_config *mk_config;
gid_t EGID;
gid_t EUID;

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

struct mk_server_config *mk_config_init()
{
    struct mk_server_config *config;

    config = mk_mem_malloc_z(sizeof(struct mk_server_config));
    mk_list_init(&config->stage10_handler);
    mk_list_init(&config->stage20_handler);
    mk_list_init(&config->stage30_handler);
    mk_list_init(&config->stage40_handler);
    mk_list_init(&config->stage50_handler);

    config->scheduler_mode = -1;

    return config;
}

void mk_config_listeners_free()
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_config_listener *l;

    mk_list_foreach_safe(head, tmp, &mk_config->listeners) {
        l = mk_list_entry(head, struct mk_config_listener, _head);
        mk_list_del(&l->_head);
        mk_mem_free(l->address);
        mk_mem_free(l->port);
        mk_mem_free(l);
    }
}

void mk_config_free_all()
{
    mk_vhost_free_all();
    mk_mimetype_free_all();

    if (mk_config->config) {
        mk_rconf_free(mk_config->config);
    }

    if (mk_config->serverconf) {
        mk_mem_free(mk_config->serverconf);
    }

    if (mk_config->pid_file_path) {
        mk_mem_free(mk_config->pid_file_path);
    }

    if (mk_config->user_dir) {
        mk_mem_free(mk_config->user_dir);
    }

    /* free config->index_files */
    if (mk_config->index_files) {
        mk_string_split_free(mk_config->index_files);
    }

    if (mk_config->user) {
        mk_mem_free(mk_config->user);
    }

    if (mk_config->transport_layer) {
        mk_mem_free(mk_config->transport_layer);
    }

    mk_config_listeners_free();

    mk_ptr_free(&mk_config->server_software);
    mk_mem_free(mk_config);
}

/* Print a specific error */
static void mk_config_print_error_msg(char *variable, char *path)
{
    mk_err("Error in %s variable under %s, has an invalid value",
           variable, path);
    mk_mem_free(path);
    exit(EXIT_FAILURE);
}

/*
 * Check if at least one of the Listen interfaces are being used by another
 * process.
 */
int mk_config_listen_check_busy(struct mk_server_config *config)
{
    int fd;
    struct mk_list *head;
    struct mk_plugin *p;
    struct mk_config_listener *listen;

    p = mk_plugin_cap(MK_CAP_SOCK_PLAIN, config);
    if (!p) {
        mk_warn("Listen check: consider build monkey with basic socket handling!");
        return MK_FALSE;
    }

    mk_list_foreach(head, &mk_config->listeners) {
        listen = mk_list_entry(head, struct mk_config_listener, _head);

        fd = mk_socket_connect(listen->address, atol(listen->port), MK_FALSE);
        if (fd != -1) {
            close(fd);
            return MK_TRUE;
        }
    }

    return MK_FALSE;
}

static int mk_config_listen_read(struct mk_rconf_section *section)
{
    int flags = 0;
    long port_num;
    char *address = NULL;
    char *port = NULL;
    char *divider;
    struct mk_list *list = NULL;
    struct mk_list *cur;
    struct mk_string_line *listener;
    struct mk_rconf_entry *entry;

    mk_list_foreach(cur, &section->entries) {
        entry = mk_list_entry(cur, struct mk_rconf_entry, _head);
        if (strcasecmp(entry->key, "Listen")) {
            continue;
        }

        list = mk_string_split_line(entry->val);
        if (!list) {
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

        if (mk_config_key_have(list, "h2")) {
            flags |= (MK_CAP_HTTP2 | MK_CAP_SOCK_TLS);
        }

        if (mk_config_key_have(list, "h2c")) {
            flags |= MK_CAP_HTTP2;
        }

        if (mk_config_key_have(list, "tls")) {
            flags |= MK_CAP_SOCK_TLS;
        }

        /* register the new listener */
        mk_config_listener_add(address, port, flags);
        mk_string_split_free(list);
        list = NULL;
    }

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

    if (mk_list_is_empty(&mk_config->listeners) == 0) {
        mk_warn("[config] No valid Listen entries found, set default");
        mk_config_listener_add(NULL, NULL, MK_CAP_HTTP);
    }

    return 0;
}

/* Read configuration files */
static void mk_config_read_files(char *path_conf, char *file_conf)
{
    unsigned long len;
    char *tmp = NULL;
    struct stat checkdir;
    struct mk_rconf *cnf;
    struct mk_rconf_section *section;

    mk_config->serverconf = mk_string_dup(path_conf);

    if (stat(mk_config->serverconf, &checkdir) == -1) {
        mk_err("ERROR: Cannot find/open '%s'", mk_config->serverconf);
        exit(EXIT_FAILURE);
    }

    mk_string_build(&tmp, &len, "%s/%s", path_conf, file_conf);
    cnf = mk_rconf_open(tmp);
    if (!cnf) {
        mk_mem_free(tmp);
        mk_err("Cannot read '%s'", mk_config->server_conf_file);
        exit(EXIT_FAILURE);
    }
    section = mk_rconf_section_get(cnf, "SERVER");
    if (!section) {
        mk_err("ERROR: No 'SERVER' section defined");
        exit(EXIT_FAILURE);
    }

    /* Map source configuration */
    mk_config->config = cnf;

    /* Listen */
    if (!mk_config->port_override) {
        if (mk_config_listen_read(section)) {
            mk_err("[config] Failed to read listen sections.");
        }
    }
    else {
        mk_config_listener_add(NULL, mk_config->port_override, MK_CAP_HTTP);
    }

    /* Number of thread workers */
    if (mk_config->workers == -1) {
        mk_config->workers = (size_t) mk_rconf_section_get_key(section,
                                                               "Workers",
                                                               MK_RCONF_NUM);
    }

    if (mk_config->workers < 1) {
        mk_config->workers = sysconf(_SC_NPROCESSORS_ONLN);
        if (mk_config->workers < 1) {
            mk_config_print_error_msg("Workers", tmp);
        }
    }

    /* Timeout */
    mk_config->timeout = (size_t) mk_rconf_section_get_key(section,
                                                           "Timeout", MK_RCONF_NUM);
    if (mk_config->timeout < 1) {
        mk_config_print_error_msg("Timeout", tmp);
    }

    /* KeepAlive */
    mk_config->keep_alive = (size_t) mk_rconf_section_get_key(section,
                                                              "KeepAlive",
                                                              MK_RCONF_BOOL);
    if (mk_config->keep_alive == MK_ERROR) {
        mk_config_print_error_msg("KeepAlive", tmp);
    }

    /* MaxKeepAliveRequest */
    mk_config->max_keep_alive_request = (size_t)
        mk_rconf_section_get_key(section,
                                 "MaxKeepAliveRequest",
                                 MK_RCONF_NUM);

    if (mk_config->max_keep_alive_request == 0) {
        mk_config_print_error_msg("MaxKeepAliveRequest", tmp);
    }

    /* KeepAliveTimeout */
    mk_config->keep_alive_timeout = (size_t) mk_rconf_section_get_key(section,
                                                                      "KeepAliveTimeout",
                                                                      MK_RCONF_NUM);
    if (mk_config->keep_alive_timeout == 0) {
        mk_config_print_error_msg("KeepAliveTimeout", tmp);
    }

    /* Pid File */
    if (!mk_config->pid_file_path) {
        mk_config->pid_file_path = mk_rconf_section_get_key(section,
                                                            "PidFile",
                                                            MK_RCONF_STR);
    }

    /* Home user's directory /~ */
    mk_config->user_dir = mk_rconf_section_get_key(section,
                                                   "UserDir", MK_RCONF_STR);

    /* Index files */
    mk_config->index_files = mk_rconf_section_get_key(section,
                                                      "Indexfile", MK_RCONF_LIST);

    /* HideVersion Variable */
    mk_config->hideversion = (size_t) mk_rconf_section_get_key(section,
                                                         "HideVersion",
                                                         MK_RCONF_BOOL);
    if (mk_config->hideversion == MK_ERROR) {
        mk_config_print_error_msg("HideVersion", tmp);
    }

    /* User Variable */
    mk_config->user = mk_rconf_section_get_key(section, "User", MK_RCONF_STR);

    /* Resume */
    mk_config->resume = (size_t) mk_rconf_section_get_key(section,
                                                          "Resume", MK_RCONF_BOOL);
    if (mk_config->resume == MK_ERROR) {
        mk_config_print_error_msg("Resume", tmp);
    }

    /* Max Request Size */
    mk_config->max_request_size = (size_t) mk_rconf_section_get_key(section,
                                                              "MaxRequestSize",
                                                              MK_RCONF_NUM);
    if (mk_config->max_request_size <= 0) {
        mk_config_print_error_msg("MaxRequestSize", tmp);
    }
    else {
        mk_config->max_request_size *= 1024;
    }

    /* Symbolic Links */
    mk_config->symlink = (size_t) mk_rconf_section_get_key(section,
                                                     "SymLink", MK_RCONF_BOOL);
    if (mk_config->symlink == MK_ERROR) {
        mk_config_print_error_msg("SymLink", tmp);
    }

    /* Transport Layer plugin */
    if (!mk_config->transport_layer) {
        mk_config->transport_layer = mk_rconf_section_get_key(section,
                                                              "TransportLayer",
                                                              MK_RCONF_STR);
    }

    /* Default Mimetype */
    mk_mem_free(tmp);
    tmp = mk_rconf_section_get_key(section, "DefaultMimeType", MK_RCONF_STR);
    if (!tmp) {
        mk_config->default_mimetype = mk_string_dup(MIMETYPE_DEFAULT_TYPE);
    }
    else {
        mk_string_build(&mk_config->default_mimetype, &len, "%s\r\n", tmp);
    }

    /* File Descriptor Table (FDT) */
    mk_config->fdt = (size_t) mk_rconf_section_get_key(section,
                                                    "FDT",
                                                    MK_RCONF_BOOL);

    /* FIXME: Overcapacity not ready */
    mk_config->fd_limit = (size_t) mk_rconf_section_get_key(section,
                                                           "FDLimit",
                                                           MK_RCONF_NUM);
    /* Get each worker clients capacity based on FDs system limits */
    mk_config->server_capacity = mk_server_capacity();


    if (!mk_config->one_shot) {
        mk_vhost_init(path_conf);
    }
    else {
        mk_vhost_set_single(mk_config->one_shot);
    }

    /* Server Signature */
    if (mk_config->hideversion == MK_FALSE) {
        snprintf(mk_config->server_signature,
                 sizeof(mk_config->server_signature) - 1,
                 "Monkey/%s", MK_VERSION_STR);
    }
    else {
        snprintf(mk_config->server_signature,
                 sizeof(mk_config->server_signature) - 1,
                 "Monkey");
    }
    len = snprintf(mk_config->server_signature_header,
                   sizeof(mk_config->server_signature_header) - 1,
                   "Server: %s\r\n", mk_config->server_signature);
    mk_config->server_signature_header_len = len;

    mk_mem_free(tmp);
}

/* read main configuration from monkey.conf */
void mk_config_start_configure(void)
{
    unsigned long len;

    mk_config_set_init_values();
    mk_config_read_files(mk_config->path_config, mk_config->server_conf_file);

    /* Load mimes */
    mk_mimetype_read_config();

    mk_ptr_reset(&mk_config->server_software);

    /* Basic server information */
    if (mk_config->hideversion == MK_FALSE) {
        mk_string_build(&mk_config->server_software.data,
                        &len, "Monkey/%s (%s)", MK_VERSION_STR, MK_BUILD_OS);
        mk_config->server_software.len = len;
    }
    else {
        mk_string_build(&mk_config->server_software.data, &len, "Monkey Server");
        mk_config->server_software.len = len;
    }
}

/* Register a new listener into the main configuration */
struct mk_config_listener *mk_config_listener_add(char *address,
                                                  char *port, int flags)
{
    struct mk_list *head;
    struct mk_config_listener *check;
    struct mk_config_listener *listen = NULL;

    listen = mk_mem_malloc(sizeof(struct mk_config_listener));
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
    mk_list_foreach(head, &mk_config->listeners) {
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

    mk_list_add(&listen->_head, &mk_config->listeners);
    return listen;
}

void mk_config_set_init_values(void)
{
    /* Init values */
    mk_config->is_seteuid = MK_FALSE;
    mk_config->timeout = 15;
    mk_config->hideversion = MK_FALSE;
    mk_config->keep_alive = MK_TRUE;
    mk_config->keep_alive_timeout = 15;
    mk_config->max_keep_alive_request = 50;
    mk_config->resume = MK_TRUE;
    mk_config->standard_port = 80;
    mk_config->symlink = MK_FALSE;
    mk_config->nhosts = 0;
    mk_list_init(&mk_config->hosts);
    mk_config->user = NULL;
    mk_config->open_flags = O_RDONLY | O_NONBLOCK;
    mk_config->index_files = NULL;
    mk_config->user_dir = NULL;

    /* TCP REUSEPORT: available on Linux >= 3.9 */
    if (mk_config->scheduler_mode == -1) {
        if (mk_config->kernel_features & MK_KERNEL_SO_REUSEPORT) {
            mk_config->scheduler_mode = MK_SCHEDULER_REUSEPORT;
        }
        else {
            mk_config->scheduler_mode = MK_SCHEDULER_FAIR_BALANCING;
        }
    }

    /* Max request buffer size allowed
     * right now, every chunk size is 4KB (4096 bytes),
     * so we are setting a maximum request size to 32 KB */
    mk_config->max_request_size = MK_REQUEST_CHUNK * 8;

    /* Internals */
    mk_config->safe_event_write = MK_FALSE;

    /* Init plugin list */
    mk_list_init(&mk_config->plugins);

    /* Init listeners */
    mk_list_init(&mk_config->listeners);
}


void mk_config_sanity_check()
{
    /* Check O_NOATIME for current user, flag will just be used
     * if running user is allowed to.
     */
    int fd, flags = mk_config->open_flags;

    flags |= O_NOATIME;
    fd = open(mk_config->path_config, flags);

    if (fd > -1) {
        mk_config->open_flags = flags;
        close(fd);
    }
}
