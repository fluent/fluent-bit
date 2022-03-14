/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#include <monkey/mk_stream.h>
#include "cgi.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>

void cgi_finish(struct cgi_request *r)
{
    /*
     * Unregister & close the CGI child process pipe reader fd from the
     * thread event loop, otherwise we may get unexpected notifications.
     */
    mk_api->ev_del(mk_api->sched_loop(), (struct mk_event *) r);
    close(r->fd);
    if (r->chunked && r->active == MK_TRUE) {
        PLUGIN_TRACE("CGI sending Chunked EOF");
        channel_write(r, "0\r\n\r\n", 5);
    }

    /* Try to kill any child process */
    if (r->child > 0) {
        kill(r->child, SIGKILL);
        r->child = 0;
    }

    /* Invalidte our socket handler */
    requests_by_socket[r->socket] = NULL;
    if (r->active == MK_TRUE) {
        mk_api->http_request_end(r->plugin, r->cs, r->hangup);
    }
    cgi_req_del(r);
}

int swrite(const int fd, const void *buf, const size_t count)
{
    ssize_t pos = count, ret = 0;

    while (pos > 0 && ret >= 0) {
        ret = write(fd, buf, pos);
        if (ret < 0) {
            return ret;
        }

        pos -= ret;
        buf += ret;
    }
    return count;
}

int channel_write(struct cgi_request *r, void *buf, size_t count)
{
    int ret;

    if (r->active == MK_FALSE) {
        return -1;
    }

    MK_TRACE("channel write: %d bytes", count);
    mk_stream_in_raw(&r->sr->stream,
                      NULL,
                      buf, count,
                      NULL, NULL);

    ret = mk_api->channel_flush(r->sr->session->channel);
    if (ret & MK_CHANNEL_ERROR) {
        r->active = MK_FALSE;
        cgi_finish(r);
    }
    return 0;
}

static void cgi_write_post(void *p)
{
    const struct post_t * const in = p;

    swrite(in->fd, in->buf, in->len);
    close(in->fd);
}

static int do_cgi(const char *const __restrict__ file,
                  const char *const __restrict__ url,
                  struct mk_http_request *sr,
                  struct mk_http_session *cs,
                  struct mk_plugin *plugin,
                  char *interpreter,
                  char *mimetype)
{
    int ret;
    int devnull;
    const int socket = cs->socket;
    struct file_info finfo;
    struct cgi_request *r = NULL;
    struct mk_event *event;
    char *env[30];
    int writepipe[2], readpipe[2];
    (void) plugin;

    /* Unchanging env vars */
    env[0] = "PATH_INFO=";
    env[1] = "GATEWAY_INTERFACE=CGI/1.1";
    env[2] = "REDIRECT_STATUS=200";
    const int env_start = 3;
    char *protocol;
    unsigned long len;

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
    if (interpreter) {
        ret = mk_api->file_get_info(interpreter, &finfo, MK_FILE_EXEC);
        if (ret == -1 ||
            (finfo.is_file == MK_FALSE && finfo.is_link == MK_FALSE) ||
            finfo.exec_access == MK_FALSE) {
            return 500;
        }
    }

    if (mimetype) {
        sr->content_type.data = mimetype;
        sr->content_type.len  = strlen(mimetype);
    }

    snprintf(method, SHORTLEN, "REQUEST_METHOD=%.*s", (int) sr->method_p.len, sr->method_p.data);
    env[envpos++] = method;

    snprintf(server_software, SHORTLEN, "SERVER_SOFTWARE=%s",
             mk_api->config->server_signature);
    env[envpos++] = server_software;

    snprintf(http_host, SHORTLEN, "HTTP_HOST=%.*s", (int) sr->host.len, sr->host.data);
    env[envpos++] = http_host;

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
        devnull = open("/dev/null", O_WRONLY);
        if (devnull == -1) {
            perror("open");
            _exit(1);
        }

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

        if (!interpreter) {
            execve(file, argv, env);
        }
        else {
            argv[0] = basename(interpreter);
            argv[1] = (char *) file;
            execve(interpreter, argv, env);
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
        pthread_t tid;

        p.fd = writepipe[1];
        p.buf = sr->data.data;
        p.len = sr->data.len;

        ret = mk_api->worker_spawn(cgi_write_post, &p, &tid);
        if (ret != 0) {
            return 403;
        }
    }
    else {
        close(writepipe[1]);
    }

    r = cgi_req_create(readpipe[0], socket, plugin, sr, cs);
    if (!r) {
        return 403;
    }
    r->child = pid;

    /*
     * Hang up?: by default Monkey assumes the CGI scripts generate
     * content dynamically (no Content-Length header), so for such HTTP/1.0
     * clients we should close the connection as KeepAlive is not supported
     * by specification, only on HTTP/1.1 where the Chunked Transfer encoding
     * exists.
     */
    if (r->sr->protocol >= MK_HTTP_PROTOCOL_11) {
        r->hangup = MK_FALSE;
    }

    /* Set transfer encoding */
    if (r->sr->protocol >= MK_HTTP_PROTOCOL_11 &&
        (r->sr->headers.status < MK_REDIR_MULTIPLE ||
         r->sr->headers.status > MK_REDIR_USE_PROXY)) {
        r->sr->headers.transfer_encoding = MK_HEADER_TE_TYPE_CHUNKED;
        r->chunked = 1;
    }

    /* Register the 'request' context */
    cgi_req_add(r);

    /* Prepare the built-in event structure */
    event = &r->event;
    event->fd      = readpipe[0];
    event->type    = MK_EVENT_CUSTOM;
    event->mask    = MK_EVENT_EMPTY;
    event->data    = r;
    event->handler = cb_cgi_read;

    /* Register the event into the worker event-loop */
    ret = mk_api->ev_add(mk_api->sched_loop(),
                         readpipe[0],
                         MK_EVENT_CUSTOM, MK_EVENT_READ, r);
    if (ret != 0) {
        return 403;
    }


    /* XXX Fixme: this needs to be atomic */
    requests_by_socket[socket] = r;
    return 200;
}

int mk_cgi_plugin_init(struct plugin_api **api, char *confdir)
{
    struct rlimit lim;
    (void) confdir;

    mk_api = *api;
    mk_list_init(&cgi_global_matches);
    pthread_key_create(&cgi_request_list, NULL);

    /*
     * We try to perform some quick lookup over the list of CGI
     * instances. We do this with a fixed length array, if you use CGI
     * you don't care too much about performance anyways.
     */
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
                   struct mk_http_request *sr,
                   int n_params,
                   struct mk_list *params)
{
    char *interpreter = NULL;
    char *mimetype = NULL;
    struct mk_vhost_handler_param *param;
    (void) plugin;

    const char *const file = sr->real_path.data;

    if (!sr->file_info.is_file) {
        return MK_PLUGIN_RET_NOT_ME;
    }

     /* start running the CGI */
    if (cgi_req_get(cs->socket)) {
        PLUGIN_TRACE("Error, someone tried to retry\n");
        return MK_PLUGIN_RET_CONTINUE;
    }

    if (n_params > 0) {
        /* Interpreter */
        param = mk_api->handler_param_get(0, params);
        if (param) {
            interpreter = param->p.data;
        }

        /* Mimetype */
        param = mk_api->handler_param_get(0, params);
        if (param) {
            mimetype = param->p.data;
        }
    }

    int status = do_cgi(file, sr->uri_processed.data,
                        sr, cs, plugin, interpreter, mimetype);

    /* These are just for the other plugins, such as logger; bogus data */
    mk_api->header_set_http_status(sr, status);
    if (status != 200) {
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    sr->headers.cgi = SH_CGI;
    return MK_PLUGIN_RET_CONTINUE;
}

/*
 * Invoked everytime a remote client drop the active connection, this
 * callback is triggered by the Monkey Scheduler
 */
int mk_cgi_stage30_hangup(struct mk_plugin *plugin,
                          struct mk_http_session *cs,
                          struct mk_http_request *sr)
{
    struct cgi_request *r;
    (void) sr;
    (void) plugin;

    PLUGIN_TRACE("CGI / Parent connection closed (hangup)");
    r = requests_by_socket[cs->socket];
    if (!r) {
        return -1;
    }

    r->active = MK_FALSE;
    cgi_finish(r);
    return 0;
}

void mk_cgi_worker_init()
{
    struct mk_list *list = mk_api->mem_alloc_z(sizeof(struct mk_list));

    mk_list_init(list);
    pthread_setspecific(cgi_request_list, (void *) list);
}


struct mk_plugin_stage mk_plugin_stage_cgi = {
    .stage30        = &mk_cgi_stage30,
    .stage30_hangup = &mk_cgi_stage30_hangup
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
