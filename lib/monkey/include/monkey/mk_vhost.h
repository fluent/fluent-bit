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

#ifndef MK_VHOST_H
#define MK_VHOST_H

#include <monkey/mk_core.h>
#include <monkey/mk_config.h>
#include <monkey/mk_http.h>

#include <regex.h>

/* Custom error page */
struct error_page {
    short int status;
    char *file;
    char *real_path;
    struct mk_list _head;
};

struct mk_handler_param {
    mk_ptr_t p;
    struct mk_list _head;
};

struct mk_host_handler {
    /* we only support a regex match for now */
    regex_t match;

    /* plugin handler */
    char *name;

    int n_params;
    struct mk_list params;
    struct mk_plugin *handler;
    struct mk_list _head;
};

struct host
{
    char *file;                   /* configuration file */
    struct mk_list server_names;  /* host names (a b c...) */

    mk_ptr_t documentroot;
    mk_ptr_t header_redirect;

    /* source configuration */
    struct mk_rconf *config;

    /* custom error pages */
    struct mk_list error_pages;

    /* content handlers */
    struct mk_list handlers;

    /* link node */
    struct mk_list _head;
};

struct host_alias
{
    char *name;
    unsigned int len;

    struct mk_list _head;
};


#define VHOST_FDT_HASHTABLE_SIZE   64
#define VHOST_FDT_HASHTABLE_CHAINS  8

struct vhost_fdt_hash_chain {
    int fd;
    int readers;
    unsigned int hash;
};

struct vhost_fdt_hash_table {
    int av_slots;
    struct vhost_fdt_hash_chain chain[VHOST_FDT_HASHTABLE_CHAINS];
};

struct vhost_fdt_host {
    struct host *host;
    struct vhost_fdt_hash_table hash_table[VHOST_FDT_HASHTABLE_SIZE];
    struct mk_list _head;
};

//pthread_key_t mk_vhost_fdt_key;
pthread_mutex_t mk_vhost_fdt_mutex;

struct host *mk_vhost_read(char *path);
int mk_vhost_get(mk_ptr_t host, struct host **vhost, struct host_alias **alias);
void mk_vhost_set_single(char *path);
void mk_vhost_init(char *path);
int mk_vhost_fdt_worker_init();
int mk_vhost_fdt_worker_exit();
int mk_vhost_open(struct mk_http_request *sr);
int mk_vhost_close(struct mk_http_request *sr);
void mk_vhost_free_all();
int mk_vhost_map_handlers();

#endif
