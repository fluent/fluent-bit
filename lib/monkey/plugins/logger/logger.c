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

#define _GNU_SOURCE

#include <monkey/mk_api.h>

/* System Headers */
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Local Headers */
#include "logger.h"
#include "pointers.h"

struct status_response {
    int   i_status;
    char *s_status;
};

static struct status_response response_codes[] = {
    /* Common matches first */
    {200, "200"}, {404, "404"},

    {100, "100"}, {101, "101"},
    {201, "201"}, {202, "202"}, {203, "203"}, {204, "204"},
    {205, "205"}, {206, "206"},
    {300, "300"}, {301, "301"}, {302, "302"}, {303, "303"}, {304, "304"},
    {305, "305"},
    {400, "400"}, {401, "401"}, {402, "402"}, {403, "403"},
    {405, "405"}, {406, "406"}, {407, "407"}, {408, "408"}, {409, "409"},
    {410, "410"}, {411, "411"}, {412, "412"}, {413, "413"}, {414, "414"},
    {415, "415"},
    {500, "500"}, {501, "501"}, {502, "502"}, {503, "503"}, {504, "504"},
    {505, "505"},
};

static struct log_target *mk_logger_match_by_host(struct mk_vhost *host, int is_ok)
{
    struct mk_list *head;
    struct log_target *entry;

    mk_list_foreach(head, &targets_list) {
        entry = mk_list_entry(head, struct log_target, _head);
        if (entry->host == host && entry->is_ok == is_ok) {
            return entry;
        }
    }

    return NULL;
}

static struct iov *mk_logger_get_cache()
{
    return pthread_getspecific(cache_iov);
}

static ssize_t _mk_logger_append(int pipe_fd_in,
        int file_fd_out,
        size_t bytes)
{
    ssize_t ret;
#ifdef MK_HAVE_SPLICE
    ret = splice(pipe_fd_in, NULL, file_fd_out,
            NULL, bytes, SPLICE_F_MOVE);
    return ret;
#else
    unsigned char buffer[4096];
    ssize_t buffer_used;
    size_t bytes_written = 0;

    while (bytes_written < bytes) {
        ret = read(pipe_fd_in, buffer, sizeof(buffer));
        if (ret < 0) {
            break;
        }
        buffer_used = ret;
        ret = write(file_fd_out, buffer, buffer_used);
        if (ret < 0) {
            break;
        }
        bytes_written += ret;
    }
    if (ret < 0 && bytes_written == 0)
        return -1;
    else
        return bytes_written;
#endif
}

static void mk_logger_start_worker(void *args)
{
    int fd;
    int bytes, err;
    int max_events = mk_api->config->nhosts;
    int flog;
    int clk;
    long slen;
    int timeout;
    char *target;
    (void) args;
    struct mk_list *head;
    struct log_target *entry;
    struct mk_event *event;
    struct mk_event_loop *evl;

    /* pipe_size:
     * ----------
     * Linux set a pipe size usingto the PAGE_SIZE,
     * check linux/include/pipe_fs_i.h for details:
     *
     *       #define PIPE_SIZE               PAGE_SIZE
     *
     * In the same header file we can found that every
     * pipe has 16 pages, so our real memory allocation
     * is: (PAGE_SIZE*PIPE_BUFFERS)
     */
    long pipe_size;

    /* buffer_limit:
     * -------------
     * it means the maximum data that a monkey log pipe can contain.
     */
    long buffer_limit;

    mk_api->worker_rename("monkey: logger");

    /* Monkey allow just 75% of a pipe capacity */
    pipe_size = sysconf(_SC_PAGESIZE) * 16;
    buffer_limit = (pipe_size * MK_LOGGER_PIPE_LIMIT);

    /* Creating poll */
    evl = mk_api->ev_loop_create(max_events);

    /* Registering targets for virtualhosts */
    mk_list_foreach(head, &targets_list) {
        entry = mk_list_entry(head, struct log_target, _head);
        event = &entry->event;
        event->mask  = MK_EVENT_EMPTY;
        event->data  = entry;
        event->handler = NULL;
        event->status = MK_EVENT_NONE;

        /* Add access log file */
        if (entry->pipe[0] > 0) {
            event->fd = entry->pipe[0];
            mk_api->ev_add(evl, entry->pipe[0],
                           MK_EVENT_CONNECTION, MK_EVENT_READ, entry);
        }
    }

    /* Set initial timeout */
    timeout = time(NULL) + mk_logger_timeout;

    /* Reading pipe buffer */
    while (1) {
        usleep(1200);

        /* wait for events */
        mk_api->ev_wait(evl);

        /* get current time */
        clk = mk_api->time_unix();

        /* translate the backend events triggered */
        mk_event_foreach(event, evl) {
            entry = (struct log_target *) event;
            target = entry->file;
            fd = entry->pipe[0];

            err = ioctl(fd, FIONREAD, &bytes);
            if (mk_unlikely(err == -1)){
                perror("ioctl");
            }

            if (bytes < buffer_limit && clk <= timeout) {
                continue;
            }

            timeout = clk + mk_logger_timeout;

            flog = open(target, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
            if (mk_unlikely(flog == -1)) {
                mk_warn("Could not open logfile '%s' (%s)", target, strerror(errno));

                int consumed = 0;
                char buf[255];
                do {
                    slen = read(fd, buf, 255);
                    if (slen > 0) {
                        consumed += slen;
                    }
                    else {
                        break;
                    }
                } while (consumed < bytes);

                continue;
            }

            lseek(flog, 0, SEEK_END);
            slen = _mk_logger_append(fd, flog, bytes);
            if (mk_unlikely(slen == -1)) {
                mk_warn("Could not write to log file: splice() = %ld", slen);
            }

            MK_TRACE("written %i bytes", bytes);
            close(flog);
        }
    }
}

static int mk_logger_read_config(char *path)
{
    int timeout;
    char *logfilename = NULL;
    unsigned long len;
    char *default_file = NULL;
    struct mk_rconf *conf;
    struct mk_rconf_section *section;

    mk_api->str_build(&default_file, &len, "%slogger.conf", path);
    conf = mk_api->config_open(default_file);
    if (!conf) {
        return -1;
    }

    section = mk_api->config_section_get(conf, "LOGGER");
    if (section) {

        /* FlushTimeout */
        timeout = (size_t) mk_api->config_section_get_key(section,
                                                          "FlushTimeout",
                                                          MK_RCONF_NUM);
        if (timeout <= 0) {
            mk_err("FlushTimeout does not have a proper value");
            exit(EXIT_FAILURE);
        }
        mk_logger_timeout = timeout;
        MK_TRACE("FlushTimeout %i seconds", mk_logger_timeout);

        /* MasterLog */
        logfilename = mk_api->config_section_get_key(section,
                                                     "MasterLog",
                                                     MK_RCONF_STR);
        if (logfilename == NULL) {
            mk_err("MasterLog does not have a proper value");
            exit(EXIT_FAILURE);
        }

        mk_logger_master_path = logfilename;
        MK_TRACE("MasterLog '%s'", mk_logger_master_path);
    }

    mk_api->mem_free(default_file);
    mk_api->config_free(conf);

    return 0;
}

static void mk_logger_print_listeners()
{
    struct mk_list *head;
    struct mk_config_listener *listener;

    mk_list_foreach(head, &mk_api->config->listeners) {
        listener = mk_list_entry(head, struct mk_config_listener, _head);
        printf("    listen on %s:%s\n",
               listener->address,
               listener->port);
    }
}

static void mk_logger_print_details(void)
{
    time_t now;
    struct tm *current;

    now = time(NULL);
    current = localtime(&now);
    printf("[%i/%02i/%02i %02i:%02i:%02i] Monkey Started\n",
           current->tm_year + 1900,
           current->tm_mon + 1,
           current->tm_mday,
           current->tm_hour,
           current->tm_min,
           current->tm_sec);
    printf("   version          : %s\n", MK_VERSION_STR);
    printf("   number of workers: %i\n", mk_api->config->workers);
    mk_logger_print_listeners();
    fflush(stdout);
}

int mk_logger_plugin_init(struct plugin_api **api, char *confdir)
{
    int fd;
    mk_api = *api;

    /* Specific thread key */
    pthread_key_create(&cache_iov, NULL);
    pthread_key_create(&cache_content_length, NULL);
    pthread_key_create(&cache_status, NULL);
    pthread_key_create(&cache_ip_str, NULL);

    /* Global configuration */
    mk_logger_timeout = MK_LOGGER_TIMEOUT_DEFAULT;
    mk_logger_master_path = NULL;
    mk_logger_read_config(confdir);

    /* Check masterlog */
    if (mk_logger_master_path) {
        fd = open(mk_logger_master_path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (fd == -1) {
            mk_err("Could not open/create master logfile %s", mk_logger_master_path);
            exit(EXIT_FAILURE);

        }
        else {
            /* Close test FD for MasterLog */
            close(fd);
        }
    }

    return 0;
}

int mk_logger_plugin_exit()
{
    struct mk_list *head, *tmp;
    struct log_target *entry;

    mk_list_foreach_safe(head, tmp, &targets_list) {
        entry = mk_list_entry(head, struct log_target, _head);
        mk_list_del(&entry->_head);
        if (entry->pipe[0] > 0) close(entry->pipe[0]);
        if (entry->pipe[1] > 0) close(entry->pipe[1]);
        mk_api->mem_free(entry->file);
        mk_api->mem_free(entry);
    }

    mk_api->mem_free(mk_logger_master_path);

    return 0;
}

int mk_logger_master_init(struct mk_server_config *config)
{
    int ret;
    struct log_target *new;
    struct mk_vhost *entry_host;
    struct mk_list *hosts = &mk_api->config->hosts;
    struct mk_list *head_host;
    struct mk_rconf_section *section;
    char *access_file_name = NULL;
    char *error_file_name = NULL;
    pthread_t tid;
    (void) config;

    /* Restore STDOUT if we are in background mode */
    if (mk_logger_master_path != NULL && mk_api->config->is_daemon == MK_TRUE) {
        mk_logger_master_stdout = freopen(mk_logger_master_path, "ae", stdout);
        mk_logger_master_stderr = freopen(mk_logger_master_path, "ae", stderr);
        mk_logger_print_details();
    }

    MK_TRACE("Reading virtual hosts");

    mk_list_init(&targets_list);

    mk_list_foreach(head_host, hosts) {
        entry_host = mk_list_entry(head_host, struct mk_vhost, _head);

        /* Read logger section from virtual host configuration */
        section = mk_api->config_section_get(entry_host->config, "LOGGER");
        if (section) {
            /* Read configuration entries */
            access_file_name = (char *) mk_api->config_section_get_key(section,
                                                                       "AccessLog",
                                                                       MK_RCONF_STR);
            error_file_name = (char *) mk_api->config_section_get_key(section,
                                                                      "ErrorLog",
                                                                      MK_RCONF_STR);

            if (access_file_name) {
                new = mk_api->mem_alloc(sizeof(struct log_target));
                new->is_ok = MK_TRUE;

                /* Set access pipe */
                if (pipe(new->pipe) < 0) {
                    mk_err("Could not create pipe");
                    exit(EXIT_FAILURE);
                }
                if (fcntl(new->pipe[1], F_SETFL, O_NONBLOCK) == -1) {
                    perror("fcntl");
                }
                if (fcntl(new->pipe[0], F_SETFD, FD_CLOEXEC) == -1) {
                    perror("fcntl");
                }
                if (fcntl(new->pipe[1], F_SETFD, FD_CLOEXEC) == -1) {
                    perror("fcntl");
                }
                new->file = access_file_name;
                new->host = entry_host;
                mk_list_add(&new->_head, &targets_list);
            }

            /* Set error pipe */
            if (error_file_name) {
                new = mk_api->mem_alloc(sizeof(struct log_target));
                new->is_ok = MK_FALSE;

                if (pipe(new->pipe) < 0) {
                    mk_err("Could not create pipe");
                    exit(EXIT_FAILURE);
                }
                if (fcntl(new->pipe[1], F_SETFL, O_NONBLOCK) == -1) {
                    perror("fcntl");
                }
                if (fcntl(new->pipe[0], F_SETFD, FD_CLOEXEC) == -1) {
                    perror("fcntl");
                }
                if (fcntl(new->pipe[1], F_SETFD, FD_CLOEXEC) == -1 ){
                    perror("fcntl");
                }
                new->file = error_file_name;
                new->host = entry_host;
                mk_list_add(&new->_head, &targets_list);

            }
        }
    }

    ret = mk_api->worker_spawn((void *) mk_logger_start_worker, NULL, &tid);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

void mk_logger_worker_init()
{
    struct mk_iov *iov_log;
    mk_ptr_t *content_length;
    mk_ptr_t *status;
    mk_ptr_t *ip_str;


    MK_TRACE("Creating thread cache");

    /* Cache iov log struct */
    iov_log = mk_api->iov_create(15, 0);
    pthread_setspecific(cache_iov, (void *) iov_log);

    /* Cache content length */
    content_length = mk_api->mem_alloc_z(sizeof(mk_ptr_t));
    content_length->data = mk_api->mem_alloc_z(MK_UTILS_INT2MKP_BUFFER_LEN);
    content_length->len = -1;
    pthread_setspecific(cache_content_length, (void *) content_length);

    /* Cahe status */
    status = mk_api->mem_alloc_z(sizeof(mk_ptr_t));
    status->data = mk_api->mem_alloc_z(MK_UTILS_INT2MKP_BUFFER_LEN);
    status->len = -1;
    pthread_setspecific(cache_status, (void *) status);

    /* Cache IP address */
    ip_str = mk_api->mem_alloc_z(sizeof(mk_ptr_t));
    ip_str->data = mk_api->mem_alloc_z(INET6_ADDRSTRLEN + 1);
    ip_str->len  = -1;
    pthread_setspecific(cache_ip_str, (void *) ip_str);
}

int mk_logger_stage40(struct mk_http_session *cs, struct mk_http_request *sr)
{
    int i, http_status, ret, tmp;
    int array_len = ARRAY_SIZE(response_codes);
    int access;
    struct log_target *target;
    struct mk_iov *iov;
    mk_ptr_t *date;
    mk_ptr_t *content_length;
    mk_ptr_t *ip_str;
    mk_ptr_t status;

    /* Set response status */
    http_status = sr->headers.status;

    if (http_status < 400) {
        access = MK_TRUE;
    }
    else {
        access = MK_FALSE;
    }

    /* Look for target log file */
    target = mk_logger_match_by_host(sr->host_conf, access);
    if (!target) {
        MK_TRACE("No target found");
        return 0;
    }

    /* Get iov cache struct and reset indexes */
    iov = (struct mk_iov *) mk_logger_get_cache();
    iov->iov_idx = 0;
    iov->buf_idx = 0;
    iov->total_len = 0;

    /* Format IP string */
    ip_str = pthread_getspecific(cache_ip_str);
    ret = mk_api->socket_ip_str(cs->socket,
                                &ip_str->data,
                                INET6_ADDRSTRLEN + 1,
                                &ip_str->len);
    /*
     * If the socket is not longer available ip_str can be null,
     * so we must check this condition and return
     */
    if (mk_unlikely(ret < 0)) {
        return 0;
    }

    /* Add IP to IOV */
    mk_api->iov_add(iov,
                    ip_str->data, ip_str->len,
                    MK_FALSE);
    mk_api->iov_add(iov,
                    mk_logger_iov_dash.data,
                    mk_logger_iov_dash.len,
                    MK_FALSE);

    /* Date/time when object was requested */
    date = mk_api->time_human(cs->server);
    mk_api->iov_add(iov,
                    date->data, date->len,
                    MK_FALSE);
    mk_api->iov_add(iov,
                    mk_logger_iov_space.data,
                    mk_logger_iov_space.len,
                    MK_FALSE);

    /* Access Log */
    if (http_status < 400) {
        /* No access file defined */
        if (!target->file) {
            return 0;
        }

        /* HTTP Method */
        mk_api->iov_add(iov,
                        sr->method_p.data,
                        sr->method_p.len,
                        MK_FALSE);
        mk_api->iov_add(iov,
                        mk_logger_iov_space.data,
                        mk_logger_iov_space.len,
                        MK_FALSE);

        /* HTTP URI required */
        mk_api->iov_add(iov,
                        sr->uri.data, sr->uri.len,
                        MK_FALSE);
        mk_api->iov_add(iov,
                        mk_logger_iov_space.data,
                        mk_logger_iov_space.len,
                        MK_FALSE);

        /* HTTP Protocol */
        mk_api->iov_add(iov,
                        sr->protocol_p.data, sr->protocol_p.len,
                        MK_FALSE);
        mk_api->iov_add(iov,
                        mk_logger_iov_space.data,
                        mk_logger_iov_space.len,
                        MK_FALSE);

        /* HTTP Status code response */
        for (i=0; i < array_len; i++) {
            if (response_codes[i].i_status == http_status) {
                break;
            }
        }

        if (array_len == i) {
            mk_api->str_itop(http_status, &status);
            status.len -= 2;
        }
        else {
            status.data = response_codes[i].s_status;
            status.len  = 3;
        }
        mk_api->iov_add(iov,
                        status.data,
                        status.len,
                        MK_FALSE);
        mk_api->iov_add(iov,
                        mk_logger_iov_space.data,
                        mk_logger_iov_space.len,
                        MK_FALSE);

        /* Content Length */
        if (sr->method != MK_METHOD_HEAD) {
            /* Int to mk_ptr_t */
            content_length = pthread_getspecific(cache_content_length);

            tmp = sr->headers.content_length;
            if (tmp < 0) {
                tmp = 0;
            }

            mk_api->str_itop(tmp, content_length);

            mk_api->iov_add(iov,
                            content_length->data, content_length->len - 2,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
        }
        else {
            mk_api->iov_add(iov,
                            mk_logger_iov_empty.data,
                            mk_logger_iov_empty.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
        }

        /* Write iov array to pipe */
        mk_api->iov_send(target->pipe[1], iov);
    }
    else {
        if (mk_unlikely(!target->file)) {
            return 0;
        }

        /* For unknown errors. Needs to exist until iov_send. */
        char err_str[80];

        switch (http_status) {
        case MK_CLIENT_BAD_REQUEST:
            mk_api->iov_add(iov,
                            error_msg_400.data,
                            error_msg_400.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
            break;
        case MK_CLIENT_FORBIDDEN:
            mk_api->iov_add(iov,
                            error_msg_403.data,
                            error_msg_403.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_space.data,
                            mk_logger_iov_space.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            sr->uri.data,
                            sr->uri.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);

            break;
        case MK_CLIENT_NOT_FOUND:
            mk_api->iov_add(iov,
                            error_msg_404.data,
                            error_msg_404.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_space.data,
                            mk_logger_iov_space.len,
                            MK_FALSE);

            mk_api->iov_add(iov,
                            sr->uri.data,
                            sr->uri.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);

            break;
        case MK_CLIENT_METHOD_NOT_ALLOWED:
            mk_api->iov_add(iov,
                            error_msg_405.data,
                            error_msg_405.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_space.data,
                            mk_logger_iov_space.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            sr->method_p.data,
                            sr->method_p.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
            break;
        case MK_CLIENT_REQUEST_TIMEOUT:
            mk_api->iov_add(iov,
                            error_msg_408.data,
                            error_msg_408.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
            break;
        case MK_CLIENT_LENGTH_REQUIRED:
            mk_api->iov_add(iov,
                            error_msg_411.data,
                            error_msg_411.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
            break;
        case MK_CLIENT_REQUEST_ENTITY_TOO_LARGE:
            mk_api->iov_add(iov,
                            error_msg_413.data,
                            error_msg_413.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
            break;
        case MK_SERVER_NOT_IMPLEMENTED:
            mk_api->iov_add(iov,
                            error_msg_501.data,
                            error_msg_501.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_space.data,
                            mk_logger_iov_space.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            sr->method_p.data,
                            sr->method_p.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
            break;
        case MK_SERVER_INTERNAL_ERROR:
            mk_api->iov_add(iov,
                            error_msg_500.data,
                            error_msg_500.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_space.data,
                            mk_logger_iov_space.len,
                            MK_FALSE);
            break;
        case MK_SERVER_HTTP_VERSION_UNSUP:
            mk_api->iov_add(iov,
                            error_msg_505.data,
                            error_msg_505.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
            break;
        default:
            {
            int len = snprintf(err_str, 80, "[error %u] (no description)", http_status);
            err_str[79] = '\0';
            if (len > 79) len = 79;

            mk_api->iov_add(iov,
                            err_str,
                            len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_space.data,
                            mk_logger_iov_space.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            sr->uri.data,
                            sr->uri.len,
                            MK_FALSE);
            mk_api->iov_add(iov,
                            mk_logger_iov_lf.data,
                            mk_logger_iov_lf.len,
                            MK_FALSE);
            }
            break;
        }


        /* Write iov array to pipe */
        mk_api->iov_send(target->pipe[1], iov);
    }

    return 0;
}

struct mk_plugin_stage mk_plugin_stage_logger = {
    .stage40      = &mk_logger_stage40
};

struct mk_plugin mk_plugin_logger = {
    /* Identification */
    .shortname     = "logger",
    .name          = "Log Writer",
    .version       = MK_VERSION_STR,
    .hooks         = MK_PLUGIN_STAGE,

    /* Init / Exit */
    .init_plugin   = mk_logger_plugin_init,
    .exit_plugin   = mk_logger_plugin_exit,

    /* Init Levels */
    .master_init   = mk_logger_master_init,
    .worker_init   = mk_logger_worker_init,

    /* Type */
    .stage         = &mk_plugin_stage_logger
};
