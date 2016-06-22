/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_plugins.h>
#include <fluent-bit/flb_io_tls.h>
#include <fluent-bit/flb_kernel.h>

struct flb_config *flb_config_init()
{
    struct flb_config *config;

    config = calloc(1, sizeof(struct flb_config));
    if (!config) {
        perror("malloc");
        return NULL;
    }

    /* Flush */
    config->flush        = FLB_CONFIG_FLUSH_SECS;
#ifdef FLB_HAVE_FLUSH_UCONTEXT
    config->flush_method = FLB_FLUSH_UCONTEXT;
#elif defined FLB_HAVE_FLUSH_PTHREADS
    config->flush_method = FLB_FLUSH_PTHREADS;
#endif
    config->daemon       = FLB_FALSE;
    config->init_time    = time(NULL);
    config->kernel       = flb_kernel_info();
    config->verbose      = 3;

#ifdef FLB_HAVE_HTTP
    config->http_server  = FLB_FALSE;
    config->http_port    = FLB_CONFIG_HTTP_PORT;
#endif

#ifdef FLB_HAVE_BUFFERING
    config->buffer_ctx     = NULL;
    config->buffer_path    = NULL;
    config->buffer_workers = 0;
#endif

    mk_list_init(&config->collectors);
    mk_list_init(&config->in_plugins);
    mk_list_init(&config->out_plugins);
    mk_list_init(&config->inputs);
    mk_list_init(&config->outputs);

    /* Register plugins */
    flb_register_plugins(config);

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    return config;
}

void flb_config_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_collector *collector;

    if (config->log) {
        free(config->log);
    }

    if (config->kernel) {
        free(config->kernel->s_version.data);
        free(config->kernel);
    }

        /* release resources */
    if (config->ch_event.fd) {
        close(config->ch_event.fd);
    }

    /* Pipe */
    if (config->ch_data[0]) {
        close(config->ch_data[0]);
        close(config->ch_data[1]);
    }

    /* Channel manager */
    if (config->ch_manager[0] > 0) {
        close(config->ch_manager[0]);
        if (config->ch_manager[0] != config->ch_manager[1]) {
            close(config->ch_manager[1]);
        }
    }

    /* Channel notifications */
    if (config->ch_notif[0] > 0) {
        close(config->ch_notif[0]);
        if (config->ch_notif[0] != config->ch_notif[1]) {
            close(config->ch_notif[1]);
        }
    }

    /* Collectors */
    mk_list_foreach_safe(head, tmp, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        mk_event_del(config->evl, &collector->event);

        if (collector->type == FLB_COLLECT_TIME) {
            close(collector->fd_timer);
        }

        mk_list_del(&collector->_head);
        free(collector);
    }

    /* Event flush */
    mk_event_del(config->evl, &config->event_flush);
    close(config->flush_fd);

#ifdef FLB_HAVE_STATS
    flb_stats_exit(config);
#endif

#ifdef FLB_HAVE_BUFFERING
    free(config->buffer_path);
#endif

    mk_event_loop_destroy(config->evl);
    free(config);
}

char *flb_config_prop_get(char *key, struct mk_list *list)
{
    struct mk_list *head;
    struct flb_config_prop *p;

    mk_list_foreach(head, list) {
        p = mk_list_entry(head, struct flb_config_prop, _head);
        if (strcasecmp(key, p->key) == 0) {
            return p->val;
        }
    }

    return NULL;
}
