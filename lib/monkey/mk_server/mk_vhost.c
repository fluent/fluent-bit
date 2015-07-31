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
#include <monkey/mk_core.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_http_status.h>
#include <monkey/mk_info.h>

#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>

/* Initialize Virtual Host FDT mutex */
pthread_mutex_t mk_vhost_fdt_mutex = PTHREAD_MUTEX_INITIALIZER;

static __thread struct mk_list *mk_vhost_fdt_key;

static int str_to_regex(char *str, regex_t *reg)
{
    int ret;
    char tmp[80];
    char *p = str;

    while (*p) {
        if (*p == ' ') *p = '|';
        p++;
    }

    ret = regcomp(reg, str, REG_EXTENDED|REG_ICASE|REG_NOSUB);
    if (ret) {
        regerror(ret, reg, tmp, sizeof(tmp));
        mk_err("Handler config: Failed to compile regex: %s", tmp);
        return -1;
    }

    return 0;
}

/*
 * This function is triggered upon thread creation (inside the thread
 * context), here we configure per-thread data.
 */
int mk_vhost_fdt_worker_init()
{
    int i;
    int j;
    struct host *h;
    struct mk_list *list;
    struct mk_list *head;
    struct vhost_fdt_host *fdt;
    struct vhost_fdt_hash_table *ht;
    struct vhost_fdt_hash_chain *hc;

    if (mk_config->fdt == MK_FALSE) {
        return -1;
    }

    /*
     * We are under a thread context and the main configuration is
     * already in place. Now for every existent virtual host we are
     * going to create the File Descriptor Table (FDT) which aims to
     * hold references of 'open and shared' file descriptors under
     * the Virtual Host context.
     */

    /*
     * Under an initialization context we need to protect this critical
     * section
     */
    pthread_mutex_lock(&mk_vhost_fdt_mutex);

    /*
     * Initialize the thread FDT/Hosts list and create an entry per
     * existent virtual host
     */
    list = mk_mem_malloc_z(sizeof(struct mk_list));
    mk_list_init(list);

    mk_list_foreach(head, &mk_config->hosts) {
        h = mk_list_entry(head, struct host, _head);

        fdt = mk_mem_malloc(sizeof(struct vhost_fdt_host));
        fdt->host = h;

        /* Initialize hash table */
        for (i = 0; i < VHOST_FDT_HASHTABLE_SIZE; i++) {
            ht = &fdt->hash_table[i];
            ht->av_slots = VHOST_FDT_HASHTABLE_CHAINS;

            /* for each chain under the hash table, set the fd */
            for (j = 0; j < VHOST_FDT_HASHTABLE_CHAINS; j++) {
                hc = &ht->chain[j];
                hc->fd      = -1;
                hc->hash    =  0;
                hc->readers =  0;
            }
        }
        mk_list_add(&fdt->_head, list);
    }

    mk_vhost_fdt_key = list;
    pthread_mutex_unlock(&mk_vhost_fdt_mutex);

    return 0;
}

int mk_vhost_fdt_worker_exit()
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct vhost_fdt_host *fdt;

    if (mk_config->fdt == MK_FALSE) {
        return -1;
    }

    mk_list_foreach_safe(head, tmp, mk_vhost_fdt_key) {
        fdt = mk_list_entry(head, struct vhost_fdt_host, _head);
        mk_list_del(&fdt->_head);
        mk_mem_free(fdt);
    }

    mk_mem_free(mk_vhost_fdt_key);
    return 0;
}


static inline
struct vhost_fdt_hash_table *mk_vhost_fdt_table_lookup(int id, struct host *host)
{
    struct mk_list *head;
    struct mk_list *vhost_list;
    struct vhost_fdt_host *fdt_host;
    struct vhost_fdt_hash_table *ht = NULL;

    vhost_list = mk_vhost_fdt_key;
    mk_list_foreach(head, vhost_list) {
        fdt_host = mk_list_entry(head, struct vhost_fdt_host, _head);
        if (fdt_host->host == host) {
            ht = &fdt_host->hash_table[id];
            return ht;
        }
    }

    return ht;
}

static inline
struct vhost_fdt_hash_chain
*mk_vhost_fdt_chain_lookup(unsigned int hash, struct vhost_fdt_hash_table *ht)
{
    int i;
    struct vhost_fdt_hash_chain *hc = NULL;

    for (i = 0; i < VHOST_FDT_HASHTABLE_CHAINS; i++) {
        hc = &ht->chain[i];
        if (hc->hash == hash) {
            return hc;
        }
    }

    return NULL;
}


static inline int mk_vhost_fdt_open(int id, unsigned int hash,
                                    struct mk_http_request *sr)
{
    int i;
    int fd = -1;
    struct vhost_fdt_hash_table *ht = NULL;
    struct vhost_fdt_hash_chain *hc;

    if (mk_config->fdt == MK_FALSE) {
        return open(sr->real_path.data, sr->file_info.flags_read_only);
    }

    ht = mk_vhost_fdt_table_lookup(id, sr->host_conf);
    if (mk_unlikely(!ht)) {
        return open(sr->real_path.data, sr->file_info.flags_read_only);
    }

    /* We got the hash table, now look around the chains array */
    hc = mk_vhost_fdt_chain_lookup(hash, ht);
    if (hc) {
        /* Increment the readers and return the shared FD */
        hc->readers++;
        sr->vhost_fdt_id      = id;
        sr->vhost_fdt_hash    = hash;
        sr->vhost_fdt_enabled = MK_TRUE;
        return hc->fd;
    }

    /*
     * Get here means that no entry exists in the hash table for the
     * requested file descriptor and hash, we must try to open the file
     * and register the entry in the table.
     */
    fd = open(sr->real_path.data, sr->file_info.flags_read_only);
    if (fd == -1) {
        return -1;
    }

    /* If chains are full, just return the new FD, bad luck... */
    if (ht->av_slots <= 0) {
        return fd;
    }

    /* Register the new entry in an available slot */
    for (i = 0; i < VHOST_FDT_HASHTABLE_CHAINS; i++) {
        hc = &ht->chain[i];
        if (hc->fd == -1) {
            hc->fd   = fd;
            hc->hash = hash;
            hc->readers++;
            ht->av_slots--;

            sr->vhost_fdt_id      = id;
            sr->vhost_fdt_hash    = hash;
            sr->vhost_fdt_enabled = MK_TRUE;

            return fd;
        }
    }

    return fd;
}

static inline int mk_vhost_fdt_close(struct mk_http_request *sr)
{
    int id;
    unsigned int hash;
    struct vhost_fdt_hash_table *ht = NULL;
    struct vhost_fdt_hash_chain *hc;

    if (mk_config->fdt == MK_FALSE || sr->vhost_fdt_enabled == MK_FALSE) {
        if (sr->file_stream.fd > 0) {
            return close(sr->file_stream.fd);
        }
        return -1;
    }

    id   = sr->vhost_fdt_id;
    hash = sr->vhost_fdt_hash;

    ht = mk_vhost_fdt_table_lookup(id, sr->host_conf);
    if (mk_unlikely(!ht)) {
        return close(sr->file_stream.fd);
    }

    /* We got the hash table, now look around the chains array */
    hc = mk_vhost_fdt_chain_lookup(hash, ht);
    if (hc) {
        /* Increment the readers and check if we should close */
        hc->readers--;
        sr->vhost_fdt_enabled = MK_FALSE;

        if (hc->readers == 0) {
            hc->fd   = -1;
            hc->hash = 0;
            ht->av_slots++;
            return close(sr->file_stream.fd);
        }
        else {
            return 0;
        }
    }
    return close(sr->file_stream.fd);
}


int mk_vhost_open(struct mk_http_request *sr)
{
    int id;
    int off;
    unsigned int hash;

    off = sr->host_conf->documentroot.len;
    hash = mk_utils_gen_hash(sr->real_path.data + off,
                             sr->real_path.len - off);
    id   = (hash % VHOST_FDT_HASHTABLE_SIZE);

    return mk_vhost_fdt_open(id, hash, sr);
}

int mk_vhost_close(struct mk_http_request *sr)
{
    return mk_vhost_fdt_close(sr);
}

/*
 * Open a virtual host configuration file and return a structure with
 * definitions.
 */
struct host *mk_vhost_read(char *path)
{
    int ret;
    char *tmp;
    char *host_low;
    struct stat checkdir;
    struct host *host;
    struct host_alias *new_alias;
    struct error_page *err_page;
    struct mk_rconf *cnf;
    struct mk_rconf_section *section_host;
    struct mk_rconf_section *section_ep;
    struct mk_rconf_section *section_handlers;
    struct mk_rconf_entry *entry_ep;
    struct mk_string_line *entry;
    struct mk_list *head, *list, *line;
    struct mk_host_handler *h_handler;
    struct mk_handler_param *h_param;

    /* Read configuration file */
    cnf = mk_rconf_create(path);
    if (!cnf) {
        mk_err("Configuration error, aborting.");
        exit(EXIT_FAILURE);
    }

    /* Read 'HOST' section */
    section_host = mk_rconf_section_get(cnf, "HOST");
    if (!section_host) {
        mk_err("Invalid config file %s", path);
        return NULL;
    }

    /* Alloc configuration node */
    host = mk_mem_malloc_z(sizeof(struct host));
    host->config = cnf;
    host->file = mk_string_dup(path);

    /* Init list for host name aliases */
    mk_list_init(&host->server_names);

    /* Init list for custom error pages */
    mk_list_init(&host->error_pages);

    /* Init list for content handlers */
    mk_list_init(&host->handlers);

    /* Lookup Servername */
    list = mk_rconf_section_get_key(section_host, "Servername", MK_RCONF_LIST);
    if (!list) {
        mk_err("Hostname does not contain a Servername");
        exit(EXIT_FAILURE);
    }

    mk_list_foreach(head, list) {
        entry = mk_list_entry(head, struct mk_string_line, _head);
        if (entry->len > MK_HOSTNAME_LEN - 1) {
            continue;
        }

        /* Hostname to lowercase */
        host_low = mk_string_tolower(entry->val);

        /* Alloc node */
        new_alias = mk_mem_malloc_z(sizeof(struct host_alias));
        new_alias->name = mk_mem_malloc_z(entry->len + 1);
        strncpy(new_alias->name, host_low, entry->len);
        mk_mem_free(host_low);

        new_alias->len = entry->len;

        mk_list_add(&new_alias->_head, &host->server_names);
    }
    mk_string_split_free(list);

    /* Lookup document root handled by a mk_ptr_t */
    host->documentroot.data = mk_rconf_section_get_key(section_host,
                                                       "DocumentRoot",
                                                       MK_RCONF_STR);
    if (!host->documentroot.data) {
        mk_err("Missing DocumentRoot entry on %s file", path);
        mk_rconf_free(cnf);
        mk_mem_free(host->file);
        mk_mem_free(host);
        return NULL;
    }

    host->documentroot.len = strlen(host->documentroot.data);

    /* Validate document root configured */
    if (stat(host->documentroot.data, &checkdir) == -1) {
        mk_err("Invalid path to DocumentRoot in %s", path);
    }
    else if (!(checkdir.st_mode & S_IFDIR)) {
        mk_err("DocumentRoot variable in %s has an invalid directory path", path);
    }

    if (mk_list_is_empty(&host->server_names) == 0) {
        mk_rconf_free(cnf);
        mk_mem_free(host->file);
        mk_mem_free(host);
        return NULL;
    }

    /* Check Virtual Host redirection */
    host->header_redirect.data = NULL;
    host->header_redirect.len  = 0;

    tmp = mk_rconf_section_get_key(section_host,
                                   "Redirect",
                                   MK_RCONF_STR);
    if (tmp) {
        host->header_redirect.data = mk_string_dup(tmp);
        host->header_redirect.len  = strlen(tmp);
        mk_mem_free(tmp);
    }

    /* Error Pages */
    section_ep = mk_rconf_section_get(cnf, "ERROR_PAGES");
    if (section_ep) {
        mk_list_foreach(head, &section_ep->entries) {
            entry_ep = mk_list_entry(head, struct mk_rconf_entry, _head);

            int ep_status = -1;
            char *ep_file = NULL;
            unsigned long len;

            ep_status = atoi(entry_ep->key);
            ep_file   = entry_ep->val;

            /* Validate input values */
            if (ep_status < MK_CLIENT_BAD_REQUEST ||
                ep_status > MK_SERVER_HTTP_VERSION_UNSUP ||
                ep_file == NULL) {
                continue;
            }

            /* Alloc error page node */
            err_page = mk_mem_malloc_z(sizeof(struct error_page));
            err_page->status = ep_status;
            err_page->file   = mk_string_dup(ep_file);
            err_page->real_path = NULL;
            mk_string_build(&err_page->real_path, &len, "%s/%s",
                            host->documentroot.data, err_page->file);

            MK_TRACE("Map error page: status %i -> %s", err_page->status, err_page->file);

            /* Link page to the error page list */
            mk_list_add(&err_page->_head, &host->error_pages);
        }
    }

    /* Handlers */
    int i;
    int params;
    struct mk_list *head_line;

    section_handlers = mk_rconf_section_get(cnf, "HANDLERS");
    if (!section_handlers) {
        return host;
    }
    mk_list_foreach(head, &section_handlers->entries) {
        entry_ep = mk_list_entry(head, struct mk_rconf_entry, _head);
        if (strncasecmp(entry_ep->key, "Match", strlen(entry_ep->key)) == 0) {
            line = mk_string_split_line(entry_ep->val);
            if (!line) {
                continue;
            }
            h_handler = mk_mem_malloc(sizeof(struct mk_host_handler));
            if (!h_handler) {
                exit(EXIT_FAILURE);
            }
            mk_list_init(&h_handler->params);

            i = 0;
            params = 0;
            mk_list_foreach(head_line, line) {
                entry = mk_list_entry(head_line, struct mk_string_line, _head);
                switch (i) {
                case 0:
                    ret = str_to_regex(entry->val, &h_handler->match);
                    if (ret == -1) {
                        exit(EXIT_FAILURE);
                    }
                    break;
                case 1:
                    h_handler->name = mk_string_dup(entry->val);
                    break;
                default:
                    /* link parameters */
                    h_param = mk_mem_malloc(sizeof(struct mk_handler_param));
                    h_param->p.data = mk_string_dup(entry->val);
                    h_param->p.len  = entry->len;
                    mk_list_add(&h_param->_head, &h_handler->params);
                    params++;
                };
                i++;
            }
            h_handler->n_params = params;

            if (i < 2) {
                mk_err("[Host Handlers] invalid Match value\n");
                exit(EXIT_FAILURE);
            }
            mk_list_add(&h_handler->_head, &host->handlers);
        }
    }


    return host;
}

int mk_vhost_map_handlers()
{
    int n = 0;
    struct mk_list *head;
    struct mk_list *head_handler;
    struct host *host;
    struct mk_host_handler *h_handler;
    struct mk_plugin *p;

    mk_list_foreach(head, &mk_config->hosts) {
        host = mk_list_entry(head, struct host, _head);
        mk_list_foreach(head_handler, &host->handlers) {
            h_handler = mk_list_entry(head_handler, struct mk_host_handler, _head);

            /* Lookup plugin by name */
            p = mk_plugin_lookup(h_handler->name);
            if (!p) {
                mk_err("Plugin '%s' was not loaded", h_handler->name);
                exit(EXIT_FAILURE);
            }

            if (p->hooks != MK_PLUGIN_STAGE) {
                mk_err("Plugin '%s' is not a handler", h_handler->name);
                exit(EXIT_FAILURE);
            }

            h_handler->handler = p;
            n++;
        }
    }

    return n;
}

void mk_vhost_set_single(char *path)
{
    struct host *host;
    struct host_alias *halias;
    struct stat checkdir;

    /* Set the default host */
    host = mk_mem_malloc_z(sizeof(struct host));
    mk_list_init(&host->error_pages);
    mk_list_init(&host->server_names);

    /* Prepare the unique alias */
    halias = mk_mem_malloc_z(sizeof(struct host_alias));
    halias->name = mk_string_dup("127.0.0.1");
    mk_list_add(&halias->_head, &host->server_names);

    host->documentroot.data = mk_string_dup(path);
    host->documentroot.len = strlen(path);
    host->header_redirect.data = NULL;

    /* Validate document root configured */
    if (stat(host->documentroot.data, &checkdir) == -1) {
        mk_err("Invalid path to DocumentRoot in %s", path);
        exit(EXIT_FAILURE);
    }
    else if (!(checkdir.st_mode & S_IFDIR)) {
        mk_err("DocumentRoot variable in %s has an invalid directory path", path);
        exit(EXIT_FAILURE);
    }
    mk_list_add(&host->_head, &mk_config->hosts);
}

/* Given a configuration directory, start reading the virtual host entries */
void mk_vhost_init(char *path)
{
    DIR *dir;
    unsigned long len;
    char *buf = 0;
    char *sites = 0;
    char *file;
    struct host *p_host;     /* debug */
    struct dirent *ent;
    struct file_info f_info;
    int ret;

    /* Read default virtual host file */
    mk_string_build(&sites, &len, "%s/%s/", path, mk_config->sites_conf_dir);
    ret = mk_file_get_info(sites, &f_info, MK_FILE_EXISTS);
    if (ret == -1 || f_info.is_directory == MK_FALSE) {
        mk_mem_free(sites);
        sites = mk_config->sites_conf_dir;
    }

    mk_string_build(&buf, &len, "%s/default", sites);

    p_host = mk_vhost_read(buf);
    if (!p_host) {
        mk_err("Error parsing main configuration file 'default'");
    }
    mk_list_add(&p_host->_head, &mk_config->hosts);
    mk_config->nhosts++;
    mk_mem_free(buf);
    buf = NULL;


    /* Read all virtual hosts defined in sites/ */
    if (!(dir = opendir(sites))) {
        mk_mem_free(sites);
        mk_err("Could not open %s", sites);
        exit(EXIT_FAILURE);
    }

    /* Reading content */
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        if (strcmp((char *) ent->d_name, "..") == 0) {
            continue;
        }
        if (ent->d_name[strlen(ent->d_name) - 1] ==  '~') {
            continue;
        }
        if (strcasecmp((char *) ent->d_name, "default") == 0) {
            continue;
        }
        file = NULL;
        mk_string_build(&file, &len, "%s/%s", sites, ent->d_name);

        p_host = mk_vhost_read(file);
        mk_mem_free(file);
        if (!p_host) {
            continue;
        }
        else {
            mk_list_add(&p_host->_head, &mk_config->hosts);
            mk_config->nhosts++;
        }
    }
    closedir(dir);
    mk_mem_free(sites);
}


/* Lookup a registered virtual host based on the given 'host' input */
int mk_vhost_get(mk_ptr_t host, struct host **vhost, struct host_alias **alias)
{
    struct host *entry_host;
    struct host_alias *entry_alias;
    struct mk_list *head_vhost, *head_alias;

    mk_list_foreach(head_vhost, &mk_config->hosts) {
        entry_host = mk_list_entry(head_vhost, struct host, _head);
        mk_list_foreach(head_alias, &entry_host->server_names) {
            entry_alias = mk_list_entry(head_alias, struct host_alias, _head);
            if (entry_alias->len == host.len &&
                strncmp(entry_alias->name, host.data, host.len) == 0) {
                *vhost = entry_host;
                *alias = entry_alias;
                return 0;
            }
        }
    }

    return -1;
}

void mk_vhost_free_all()
{
    struct host *host;
    struct host_alias *host_alias;
    struct error_page *ep;
    struct mk_list *head_host;
    struct mk_list *head_alias;
    struct mk_list *head_error;
    struct mk_list *tmp1, *tmp2;

    mk_list_foreach_safe(head_host, tmp1, &mk_config->hosts) {
        host = mk_list_entry(head_host, struct host, _head);
        mk_list_del(&host->_head);

        mk_mem_free(host->file);

        /* Free aliases or servernames */
        mk_list_foreach_safe(head_alias, tmp2, &host->server_names) {
            host_alias = mk_list_entry(head_alias, struct host_alias, _head);
            mk_list_del(&host_alias->_head);
            mk_mem_free(host_alias->name);
            mk_mem_free(host_alias);
        }

        /* Free error pages */
        mk_list_foreach_safe(head_error, tmp2, &host->error_pages) {
            ep = mk_list_entry(head_error, struct error_page, _head);
            mk_list_del(&ep->_head);
            mk_mem_free(ep->file);
            mk_mem_free(ep->real_path);
            mk_mem_free(ep);
        }

        mk_ptr_free(&host->documentroot);

        /* Free source configuration */
        if (host->config) mk_rconf_free(host->config);
        mk_mem_free(host);
    }
}
