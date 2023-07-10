/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
 *  Copyright 2012, Sonny Karlsson
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

/* Monkey API */
#include <monkey/mk_api.h>


/* system */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "mandril.h"

static struct mk_rconf *conf;

/* Read database configuration parameters */
static int mk_security_conf(struct mk_plugin *plugin, char *confdir)
{
    int n;
    int ret = 0;
    unsigned long len;
    char *conf_path = NULL;
    char *_net, *_mask;

    struct mk_secure_ip_t *new_ip;
    struct mk_secure_url_t *new_url;
    struct mk_secure_deny_hotlink_t *new_deny_hotlink;

    struct mk_rconf_section *section;
    struct mk_rconf_entry *entry;
    struct mk_list *head;

    /* Read configuration */
    plugin->api->str_build(&conf_path, &len, "%s/mandril.conf", confdir);
    conf = plugin->api->config_open(conf_path);
    if (!conf) {
        return -1;
    }

    section = plugin->api->config_section_get(conf, "RULES");
    if (!section) {
        return -1;
    }

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);

        /* Passing to internal struct */
        if (strcasecmp(entry->key, "IP") == 0) {
            new_ip = plugin->api->mem_alloc(sizeof(struct mk_secure_ip_t));
            n = plugin->api->str_search(entry->val, "/", 1);

            /* subnet */
            if (n > 0) {
                /* split network addr and netmask */
                _net  = plugin->api->str_copy_substr(entry->val, 0, n);
                _mask = plugin->api->str_copy_substr(entry->val,
                                                     n + 1,
                                                     strlen(entry->val));

                /* validations... */
                if (!_net ||  !_mask) {
                    mk_warn_ex(plugin->api,
                               "Mandril: cannot parse entry '%s' in RULES section",
                               entry->val);
                    goto ip_next;
                }

                /* convert ip string to network address */
                if (inet_aton(_net, &new_ip->ip) == 0) {
                    mk_warn_ex(plugin->api,
                               "Mandril: invalid ip address '%s' in RULES section",
                               entry->val);
                    goto ip_next;
                }

                /* parse mask */
                new_ip->netmask = strtol(_mask, (char **) NULL, 10);
                if (new_ip->netmask <= 0 || new_ip->netmask >= 32) {
                    mk_warn_ex(plugin->api,
                               "Mandril: invalid mask value '%s' in RULES section",
                               entry->val);
                    goto ip_next;
                }

                /* complete struct data */
                new_ip->is_subnet = MK_TRUE;
                new_ip->network = MK_NET_NETWORK(new_ip->ip.s_addr, new_ip->netmask);
                new_ip->hostmin = MK_NET_HOSTMIN(new_ip->ip.s_addr, new_ip->netmask);
                new_ip->hostmax = MK_NET_HOSTMAX(new_ip->ip.s_addr, new_ip->netmask);

                /* link node with main list */
                mk_list_add(&new_ip->_head, &mk_secure_ip);

            /*
             * I know, you were instructed to hate 'goto' statements!, ok, show this
             * code to your teacher and let him blame :P
             */
            ip_next:
                if (_net) {
                    plugin->api->mem_free(_net);
                }
                if (_mask) {
                    plugin->api->mem_free(_mask);
                }
            }
            else { /* normal IP address */

                /* convert ip string to network address */
                if (inet_aton(entry->val, &new_ip->ip) == 0) {
                    mk_warn_ex(plugin->api,
                               "Mandril: invalid ip address '%s' in RULES section",
                               entry->val);
                }
                else {
                    new_ip->is_subnet = MK_FALSE;
                    mk_list_add(&new_ip->_head, &mk_secure_ip);
                }
            }
        }
        else if (strcasecmp(entry->key, "URL") == 0) {
            /* simple allcotion and data association */
            new_url = plugin->api->mem_alloc(sizeof(struct mk_secure_url_t));
            new_url->criteria = entry->val;

            /* link node with main list */
            mk_list_add(&new_url->_head, &mk_secure_url);
        }
        else if (strcasecmp(entry->key, "deny_hotlink") == 0) {
            new_deny_hotlink = plugin->api->mem_alloc(sizeof(*new_deny_hotlink));
            new_deny_hotlink->criteria = entry->val;

            mk_list_add(&new_deny_hotlink->_head, &mk_secure_deny_hotlink);
        }
    }

    plugin->api->mem_free(conf_path);

    return ret;
}

static int mk_security_check_ip(int socket)
{
    int network;
    struct mk_secure_ip_t *entry;
    struct mk_list *head;
    struct in_addr *addr;
    struct sockaddr_in addr_t = {0};
    socklen_t len = sizeof(addr_t);

    if (getpeername(socket, (struct sockaddr *) &addr_t, &len) != 0) {
        perror("getpeername");
        return -1;
    }

    addr = &(addr_t).sin_addr;

    PLUGIN_TRACE("[FD %i] Mandril validating IP address", socket);
    mk_list_foreach(head, &mk_secure_ip) {
        entry = mk_list_entry(head, struct mk_secure_ip_t, _head);

        if (entry->is_subnet == MK_TRUE) {
            /* Validate network */
            network = MK_NET_NETWORK(addr->s_addr, entry->netmask);
            if (network != entry->network) {
                continue;
            }
            /* Validate host range */
            if (addr->s_addr <= entry->hostmax && addr->s_addr >= entry->hostmin) {
                PLUGIN_TRACE("[FD %i] Mandril closing by rule in ranges", socket);
                return -1;
            }
        }
        else {
            if (addr->s_addr == entry->ip.s_addr) {
                PLUGIN_TRACE("[FD %i] Mandril closing by rule in IP match", socket);
                return -1;
            }
        }
    }
    return 0;
}

/* Check if the incoming URL is restricted for some rule */
static int mk_security_check_url(struct mk_plugin *plugin, mk_ptr_t url)
{
    int n;
    struct mk_list *head;
    struct mk_secure_url_t *entry;

    mk_list_foreach(head, &mk_secure_url) {
        entry = mk_list_entry(head, struct mk_secure_url_t, _head);
        n = plugin->api->str_search_n(url.data, entry->criteria, MK_STR_INSENSITIVE, url.len);
        if (n >= 0) {
            return -1;
        }
    }

    return 0;
}

mk_ptr_t parse_referer_host(struct mk_http_header *header)
{
    unsigned int i, beginHost, endHost;
    mk_ptr_t host;

    host.data = NULL;
    host.len = 0;

    // Find end of "protocol://"
    for (i = 0; i < header->val.len && !(header->val.data[i] == '/' && header->val.data[i+1] == '/'); i++);
    if (i == header->val.len) {
        goto error;
    }
    beginHost = i + 2;

    // Find end of any "user:password@"
    for (; i < header->val.len && header->val.data[i] != '@'; i++);
    if (i < header->val.len) {
        beginHost = i + 1;
    }

    // Find end of "host", (beginning of :port or /path)
    for (i = beginHost; i < header->val.len && header->val.data[i] != ':' && header->val.data[i] != '/'; i++);
    endHost = i;

    host.data = header->val.data + beginHost;
    host.len = endHost - beginHost;
    return host;
error:
    host.data = NULL;
    host.len = 0;
    return host;
}

static int mk_security_check_hotlink(struct mk_plugin *plugin,
                                     mk_ptr_t url, mk_ptr_t host,
                                     struct mk_http_header *referer)
{
    mk_ptr_t ref_host = parse_referer_host(referer);
    unsigned int domains_matched = 0;
    int i = 0;
    const char *curA, *curB;
    struct mk_list *head;
    struct mk_secure_deny_hotlink_t *entry;

    if (ref_host.data == NULL) {
        return 0;
    }
    else if (host.data == NULL) {
        mk_err_ex(plugin->api, "No host data.");
        return -1;
    }

    mk_list_foreach(head, &mk_secure_url) {
        entry = mk_list_entry(head, struct mk_secure_deny_hotlink_t, _head);
        i = plugin->api->str_search_n(url.data, entry->criteria, MK_STR_INSENSITIVE, url.len);
        if (i >= 0) {
            break;
        }
    }
    if (i < 0) {
        return 0;
    }

    curA = host.data + host.len;
    curB = ref_host.data + ref_host.len;

    // Match backwards from root domain.
    while (curA > host.data && curB > ref_host.data) {
        i++;
        curA--;
        curB--;

        if ((*curA == '.' && *curB == '.') ||
                curA == host.data || curB == ref_host.data) {
            if (i < 1) {
                break;
            }
            else if (curA == host.data &&
                    !(curB == ref_host.data || *(curB - 1) == '.')) {
                break;
            }
            else if (curB == ref_host.data &&
                    !(curA == host.data || *(curA - 1) == '.')) {
                break;
            }
            else if (strncasecmp(curA, curB, i)) {
                break;
            }
            domains_matched += 1;
            i = 0;
        }
    }

    // Block connection if none or only top domain matched.
    return domains_matched >= 2 ? 0 : -1;
}

int mk_mandril_plugin_init(struct mk_plugin *plugin, char *confdir)
{
    /* Init security lists */
    mk_list_init(&mk_secure_ip);
    mk_list_init(&mk_secure_url);
    mk_list_init(&mk_secure_deny_hotlink);

    /* Read configuration */
    mk_security_conf(plugin, confdir);

    return 0;
}

int mk_mandril_plugin_exit()
{
    return 0;
}

int mk_mandril_stage10(int socket)
{
    /* Validate ip address with Mandril rules */
    if (mk_security_check_ip(socket) != 0) {
        PLUGIN_TRACE("[FD %i] Mandril close connection", socket);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_mandril_stage30(struct mk_plugin *p,
                       struct mk_http_session *cs,
                       struct mk_http_request *sr,
                       int n_params,
                       struct mk_list *params)
{
    (void) p;
    (void) cs;
    (void) n_params;
    (void) params;

    struct mk_http_header *header;

    PLUGIN_TRACE("[FD %i] Mandril validating URL", cs->socket);

    if (mk_security_check_url(p, sr->uri_processed) < 0) {
        PLUGIN_TRACE("[FD %i] Close connection, blocked URL", cs->socket);
        p->api->header_set_http_status(sr, MK_CLIENT_FORBIDDEN);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    PLUGIN_TRACE("[FD %d] Mandril validating hotlinking", cs->socket);

    header = p->api->header_get(MK_HEADER_REFERER, sr, NULL, 0);
    if (mk_security_check_hotlink(p, sr->uri_processed, sr->host, header) < 0) {
        PLUGIN_TRACE("[FD %i] Close connection, deny hotlinking.", cs->socket);
        p->api->header_set_http_status(sr, MK_CLIENT_FORBIDDEN);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    return MK_PLUGIN_RET_NOT_ME;
}

struct mk_plugin_stage mk_plugin_stage_mandril = {
    .stage10      = &mk_mandril_stage10,
    .stage30      = &mk_mandril_stage30
};

struct mk_plugin mk_plugin_mandril = {
    /* Identification */
    .shortname     = "mandril",
    .name          = "Mandril Security",
    .version       = MK_VERSION_STR,
    .hooks         = MK_PLUGIN_STAGE,

    /* Init / Exit */
    .init_plugin   = mk_mandril_plugin_init,
    .exit_plugin   = mk_mandril_plugin_exit,

    /* Init Levels */
    .master_init   = NULL,
    .worker_init   = NULL,

    /* Type */
    .stage         = &mk_plugin_stage_mandril
};
