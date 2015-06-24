/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
 *  Copyright (C) 2012-2013, Lauri Kasanen
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

#include "cgi.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>

int swrite(const int fd, const void *buf, const size_t count)
{
    ssize_t pos = count, ret = 0;

    while (pos > 0 && ret >= 0) {
        ret = write(fd, buf, pos);

        if (ret < 0)
            return ret;

        pos -= ret;
        buf += ret;
    }

    return count;
}

static void cgi_write_post(void *p)
{
    const struct post_t * const in = p;

    swrite(in->fd, in->buf, in->len);
    close(in->fd);
}

static int do_cgi(const char *const __restrict__ file,
                  const char *const __restrict__ url,
                  struct mk_http_request *const sr,
                  struct mk_http_session *const cs,
                  struct cgi_match_t *match,
                  struct mk_plugin *const plugin)
{
    int ret;
    const int socket = cs->socket;
    struct file_info finfo;

    char *env[30];

    /* Unchanging env vars */
    env[0] = "PATH_INFO=";
    env[1] = "GATEWAY_INTERFACE=CGI/1.1";
    env[2] = "REDIRECT_STATUS=200";
    const int env_start = 3;

    /* Dynamic env vars */

    unsigned short envpos = env_start;

    char method[SHORTLEN];
    char *query = NULL;
    char request_uri[PATHLEN];
    char script_filename[PATHLEN];
    char script_name[PATHLEN];
    char query_string[PATHLEN];
    char remote_addr[INET6_ADDRSTRLEN+SHORTLEN];
    char tmpaddr[INET6_ADDRSTRLEN], *ptr = tmpaddr;
    char remote_port[SHORTLEN];
    char content_length[SHORTLEN];
    char content_type[SHORTLEN];
    char server_software[SHORTLEN];
    char server_protocol[SHORTLEN];
    char http_host[SHORTLEN];

    /* Check the interpreter exists */
    if (match->bin) {
        ret = mk_api->file_get_info(match->bin, &finfo, MK_FILE_EXEC);

        if (ret == -1 ||
            (finfo.is_file == MK_FALSE && finfo.is_link == MK_FALSE) ||
            finfo.exec_access == MK_FALSE) {
            return 500;
        }
    }

    snprintf(method, SHORTLEN, "REQUEST_METHOD=%.*s", (int) sr->method_p.len, sr->method_p.data);
    env[envpos++] = method;

    snprintf(server_software, SHORTLEN, "SERVER_SOFTWARE=%s",
             mk_api->config->server_signature);
    env[envpos++] = server_software;

    snprintf(http_host, SHORTLEN, "HTTP_HOST=%.*s", (int) sr->host.len, sr->host.data);
    env[envpos++] = http_host;

    char *protocol;
    if (sr->protocol == MK_HTTP_PROTOCOL_11)
        protocol = MK_HTTP_PROTOCOL_11_STR;
    else
        protocol = MK_HTTP_PROTOCOL_10_STR;

    snprintf(server_protocol, SHORTLEN, "SERVER_PROTOCOL=%s", protocol);
    env[envpos++] = server_protocol;

    if (sr->query_string.len) {
        query = mk_api->mem_alloc_z(sr->query_string.len + 1);
        memcpy(query, sr->query_string.data, sr->query_string.len);
        snprintf(request_uri, PATHLEN, "REQUEST_URI=%s?%s", url, query);
    }
    else {
        snprintf(request_uri, PATHLEN, "REQUEST_URI=%s", url);
    }
    env[envpos++] = request_uri;

    snprintf(script_filename, PATHLEN, "SCRIPT_FILENAME=%s", file);
    env[envpos++] = script_filename;

    snprintf(script_name, PATHLEN, "SCRIPT_NAME=%s", url);
    env[envpos++] = script_name;

    if (query) {
        snprintf(query_string, PATHLEN, "QUERY_STRING=%s", query);
        env[envpos++] = query_string;
        mk_api->mem_free(query);
    }

    unsigned long len;
    if (mk_api->socket_ip_str(socket, &ptr, INET6_ADDRSTRLEN, &len) < 0)
        tmpaddr[0] = '\0';
    snprintf(remote_addr, INET6_ADDRSTRLEN+SHORTLEN, "REMOTE_ADDR=%s", tmpaddr);
    env[envpos++] = remote_addr;

    snprintf(remote_port, SHORTLEN, "REMOTE_PORT=%ld", sr->port);
    env[envpos++] = remote_port;

    if (sr->data.len) {
        snprintf(content_length, SHORTLEN, "CONTENT_LENGTH=%lu", sr->data.len);
        env[envpos++] = content_length;
    }

    if (sr->content_type.len) {
        snprintf(content_type, SHORTLEN, "CONTENT_TYPE=%.*s", (int)sr->content_type.len, sr->content_type.data);
        env[envpos++] = content_type;
    }


    /* Must be NULL-terminated */
    env[envpos] = NULL;

    /* pipes, from monkey's POV */
    int writepipe[2], readpipe[2];
    if (pipe(writepipe) || pipe(readpipe)) {
        mk_err("Failed to create pipe");
        return 403;
    }

    pid_t pid = vfork();
    if (pid < 0) {
        mk_err("Failed to fork");
        return 403;
    }

    /* Child */
    if (pid == 0) {
        close(writepipe[1]);
        close(readpipe[0]);

        /* Our stdin is the read end of monkey's writing */
        if (dup2(writepipe[0], 0) < 0) {
            mk_err("dup2 failed");
            _exit(1);
        }
        close(writepipe[0]);

        /* Our stdout is the write end of monkey's reading */
        if (dup2(readpipe[1], 1) < 0) {
            mk_err("dup2 failed");
            _exit(1);
        }
        close(readpipe[1]);

        /* Our stderr goes to /dev/null */
        const int devnull = open("/dev/null", O_WRONLY);
        if (dup2(devnull, 2) < 0) {
            mk_err("dup2 failed");
            _exit(1);
        }
        close(devnull);

        char *argv[3] = { NULL };

        char *tmp = mk_api->str_dup(file);
        if (chdir(dirname(tmp)))
            _exit(1);

        char *tmp2 = mk_api->str_dup(file);
        argv[0] = basename(tmp2);

        /* Restore signals for the child */
        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        if (!match->bin) {
            execve(file, argv, env);
        }
        else {
            argv[0] = basename(match->bin);
            argv[1] = (char *) file;
            execve(match->bin, argv, env);
        }

        /* Exec failed, return */
        _exit(1);
    }

    /* Yay me */
    close(writepipe[0]);
    close(readpipe[1]);

    /* If we have POST data to write, spawn a thread to do that */
    if (sr->data.len) {
        struct post_t p;
        p.fd = writepipe[1];
        p.buf = sr->data.data;
        p.len = sr->data.len;

        mk_api->worker_spawn(cgi_write_post, &p);
    }
    else {
        close(writepipe[1]);
    }


    struct cgi_request *r = cgi_req_create(readpipe[0], socket, sr, cs);
    if (!r) return 403;

    if (r->sr->protocol >= MK_HTTP_PROTOCOL_11 &&
        (r->sr->headers.status < MK_REDIR_MULTIPLE ||
         r->sr->headers.status > MK_REDIR_USE_PROXY))
    {
        r->sr->headers.transfer_encoding = MK_HEADER_TE_TYPE_CHUNKED;
        r->chunked = 1;
    }


    cgi_req_add(r);
    mk_api->event_add(readpipe[0], MK_EVENT_READ, plugin, -1);

    /* XXX Fixme: this needs to be atomic */
    requests_by_socket[socket] = r;

    /* We have nothing to write yet */
    mk_api->event_socket_change_mode(socket, MK_EVENT_SLEEP, -1);

    return 200;
}

static void str_to_regex(char *str, regex_t *reg)
{
    char *p = str;
    while (*p) {
        if (*p == ' ') *p = '|';
        p++;
    }

    int ret = regcomp(reg, str, REG_EXTENDED|REG_ICASE|REG_NOSUB);
    if (ret) {
        char tmp[80];
        regerror(ret, reg, tmp, 80);
        mk_err("CGI: Failed to compile regex: %s", tmp);
    }
}

static int cgi_link_matches(struct mk_config_section *section, struct mk_list *list)
{
    int i;
    int n = 0;
    struct mk_list *head;
    struct mk_list *line;
    struct mk_list *head_match;
    struct mk_config_entry *entry;
    struct mk_string_line *entry_match;
    struct cgi_match_t *match_line = NULL;

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_config_entry, _head);
        if (strncasecmp(entry->key, "Match", strlen(entry->key)) == 0) {
            line = mk_api->str_split_line(entry->val);
            if (!line) {
                continue;
            }

            /*
             * The variable 'i' represent the position of each string
             * component found in the Match configuration line:
             *
             *   0 = Regex expression
             *   1 = Interpreter path
             *   2 = Mime type
             */
            i = 0;
            match_line = mk_api->mem_alloc_z(sizeof(struct cgi_match_t));
            mk_list_add(&match_line->_head, list);

            mk_list_foreach(head_match, line) {
                entry_match = mk_list_entry(head_match,
                                            struct mk_string_line,
                                            _head);
                if (!entry_match) {
                    mk_err("CGI: Invalid configuration key");
                    exit(EXIT_FAILURE);
                }

                switch (i) {
                case 0: /* regex */
                    str_to_regex(entry_match->val, &match_line->match);
                    break;
                case 1: /* interpreter */
                    match_line->bin = mk_api->str_dup(entry_match->val);
                    break;
                case 2: /* mime type */
                    match_line->content_type.data = mk_api->str_dup(entry_match->val);
                    match_line->content_type.len = entry_match->len;
                    break;
                };

                i++;
            }
            n++;
        }
    }

    return n;
}

static void cgi_read_config(const char * const path)
{
    char *file = NULL;
    unsigned long len;
    struct mk_config *conf;
    struct mk_config_section *section;

    mk_api->str_build(&file, &len, "%scgi.conf", path);
    conf = mk_api->config_create(file);
    section = mk_api->config_section_get(conf, "CGI");

    if (section) {
        cgi_link_matches(section, &cgi_global_matches);
    }

    mk_api->mem_free(file);
    mk_api->config_free(conf);

    // Plugin config done. Then check for virtual hosts

    struct mk_list *hosts = &mk_api->config->hosts;
    struct mk_list *head_host;
    struct host *entry_host;
    unsigned short vhosts = 0;

    mk_list_foreach(head_host, hosts) {
        entry_host = mk_list_entry(head_host, struct host, _head);
        section = mk_api->config_section_get(entry_host->config, "CGI");
        if (section) vhosts++;
    }

//    printf("Found %hu vhosts with CGI section\n", vhosts);

    if (vhosts < 1) return;

    // NULL-terminated linear cache
    cgi_vhosts = mk_api->mem_alloc_z((vhosts + 1) * sizeof(struct cgi_vhost_t));

    vhosts = 0;
    mk_list_foreach(head_host, hosts) {
        entry_host = mk_list_entry(head_host, struct host, _head);
        section = mk_api->config_section_get(entry_host->config, "CGI");

        if (!section) {
            continue;
        }

        /* Set the host for this entry */
        cgi_vhosts[vhosts].host = entry_host;
        mk_list_init(&cgi_vhosts[vhosts].matches);

        /*
         * For each section found on every virtual host, lookup all 'Match'
         * keys and populate the list of scripting rules
         */
        cgi_link_matches(section, &cgi_vhosts[vhosts].matches);
        vhosts++;
    }
}

int mk_cgi_plugin_init(struct plugin_api **api, char *confdir)
{
    mk_api = *api;

    mk_list_init(&cgi_global_matches);
    cgi_read_config(confdir);
    pthread_key_create(&cgi_request_list, NULL);

    struct rlimit lim;
    getrlimit(RLIMIT_NOFILE, &lim);
    requests_by_socket = mk_api->mem_alloc_z(sizeof(struct cgi_request *) * lim.rlim_cur);

    /* Make sure we act good if the child dies */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    return 0;
}

int mk_cgi_plugin_exit()
{
    regfree(&match_regex);
    mk_api->mem_free(requests_by_socket);

    return 0;
}

int mk_cgi_stage30(struct mk_plugin *plugin,
                   struct mk_http_session *cs,
                   struct mk_http_request *sr)
{
    unsigned int i;
    char url[PATHLEN];
    struct cgi_match_t *match_rule;
    struct mk_list *head_matches;

    if (sr->uri.len + 1 > PATHLEN)
        return MK_PLUGIN_RET_NOT_ME;

    memcpy(url, sr->uri.data, sr->uri.len);
    url[sr->uri.len] = '\0';

    const char *const file = sr->real_path.data;

    if (!sr->file_info.is_file) {
        return MK_PLUGIN_RET_NOT_ME;
    }

    /* Go around each global CGI Match entry and check if one of them applies */
    mk_list_foreach(head_matches, &cgi_global_matches) {
        match_rule = mk_list_entry(head_matches, struct cgi_match_t,  _head);
        if (regexec(&match_rule->match, url, 0, NULL, 0) == 0) {
            goto run_cgi;
        }
    }

    /* Now check the rules under the proper virtual host */
    if (!cgi_vhosts) {
        return MK_PLUGIN_RET_NOT_ME;
    }

    for (i = 0; cgi_vhosts[i].host; i++) {
        if (sr->host_conf == cgi_vhosts[i].host) {
            break;
        }
    }

    /* No vhost matched */
    if (!cgi_vhosts[i].host) {
        return MK_PLUGIN_RET_NOT_ME;
    }

    /* A vhost was found, check if its regex matches */
    mk_list_foreach(head_matches, &cgi_vhosts[i].matches) {
        match_rule = mk_list_entry(head_matches, struct cgi_match_t,  _head);
        if (regexec(&match_rule->match, url, 0, NULL, 0) == 0) {
            goto run_cgi;
        }
    }

    /* If we reach this line means that not matches was found */
    return MK_PLUGIN_RET_NOT_ME;


 run_cgi:
    /* start running the CGI */
    if (cgi_req_get(cs->socket)) {
        printf("Error, someone tried to retry\n");
        return MK_PLUGIN_RET_CONTINUE;
    }

    int status = do_cgi(file, url, sr, cs, match_rule, plugin);

    /* These are just for the other plugins, such as logger; bogus data */
    mk_api->header_set_http_status(sr, status);

    if (status != 200)
        return MK_PLUGIN_RET_CLOSE_CONX;

    sr->headers.cgi = SH_CGI;

    return MK_PLUGIN_RET_CONTINUE;
}

void mk_cgi_worker_init()
{
    struct mk_list *list = mk_api->mem_alloc_z(sizeof(struct mk_list));

    mk_list_init(list);
    pthread_setspecific(cgi_request_list, (void *) list);
}


struct mk_plugin_stage mk_plugin_stage_cgi = {
    .stage30      = &mk_cgi_stage30
};

struct mk_plugin mk_plugin_cgi = {
    /* Identification */
    .shortname     = "cgi",
    .name          = "Common Gateway Interface",
    .version       = MK_VERSION_STR,
    .hooks         = MK_PLUGIN_STAGE,

    /* Init / Exit */
    .init_plugin   = mk_cgi_plugin_init,
    .exit_plugin   = mk_cgi_plugin_exit,

    /* Init Levels */
    .master_init   = NULL,
    .worker_init   = mk_cgi_worker_init,

    /* Type */
    .stage         = &mk_plugin_stage_cgi
};
