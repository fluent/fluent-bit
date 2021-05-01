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

#include <mk_core/mk_pthread.h>
#include <mk_core/mk_event.h>

#include <monkey/mk_scheduler.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_mimetype.h>

void mk_server_info(struct mk_server *server)
{
    struct mk_list *head;
    struct mk_plugin *p;
    struct mk_config_listener *l;

#ifdef _WIN32
    printf(MK_BANNER_ENTRY "Process ID is %ld\n", (long)GetCurrentProcessId());
#else
    printf(MK_BANNER_ENTRY "Process ID is %ld\n", (long) getpid());
#endif
    mk_list_foreach(head, &server->listeners) {
        l = mk_list_entry(head, struct mk_config_listener, _head);
        printf(MK_BANNER_ENTRY "Server listening on %s:%s\n",
               l->address, l->port);
    }
    printf(MK_BANNER_ENTRY
           "%i threads, may handle up to %i client connections\n",
           server->workers, server->server_capacity);

    /* List loaded plugins */
    printf(MK_BANNER_ENTRY "Loaded Plugins: ");
    mk_list_foreach(head, &server->plugins) {
        p = mk_list_entry(head, struct mk_plugin, _head);
        printf("%s ", p->shortname);
    }
    printf("\n");

#ifdef __linux__
    char tmp[64];

    if (mk_kernel_features_print(tmp, sizeof(tmp), server) > 0) {
        printf(MK_BANNER_ENTRY "Linux Features: %s\n", tmp);
    }
#endif

    fflush(stdout);
}

/* Initialize Monkey Server */
struct mk_server *mk_server_create()
{
    int ret;
    int kern_version;
    int kern_features;
    struct mk_server *server;

    server = mk_mem_alloc_z(sizeof(struct mk_server));
    if (!server) {
        return NULL;
    }

    /* I'll try to leave both initializations here because 
     * it should be possible to run in windows using the accept
     * backend in which case it doesn't make sense to tie the net stack
     * initialization to libevent.
     */
    mk_net_init();
    mk_event_init();

    /* Library mode: event loop */
    server->lib_mode = MK_TRUE;
    server->lib_evl = mk_event_loop_create(8);
    if (!server->lib_evl) {
        mk_mem_free(server);
        return NULL;
    }


    /* Library mode: channel manager */

    /* This code causes a memory corruption because it interprets the mk_server structure 
     * pointer as a mk_event structure pointer but the mk_server structure doesn't start
     * with a mk_event member, however, so I added an event to that structure to fix the 
     * issue, however, I could be wrong so some input on this would be great.
     */

    memset(&server->lib_ch_event, 0, sizeof(struct mk_event));

    ret = mk_event_channel_create(server->lib_evl,
        &server->lib_ch_manager[0],
        &server->lib_ch_manager[1],
        &server->lib_ch_event);
/*
    ret = mk_event_channel_create(server->lib_evl,
                                  &server->lib_ch_manager[0],
                                  &server->lib_ch_manager[1],
                                  server);
*/

    if (ret != 0) {
        mk_event_loop_destroy(server->lib_evl);
        mk_mem_free(server);
        return NULL;
    }

    /* Initialize linked list heads */
    mk_list_init(&server->plugins);
    mk_list_init(&server->sched_worker_callbacks);
    mk_list_init(&server->stage10_handler);
    mk_list_init(&server->stage20_handler);
    mk_list_init(&server->stage30_handler);
    mk_list_init(&server->stage40_handler);
    mk_list_init(&server->stage50_handler);
    server->scheduler_mode = -1;

    mk_core_init();

    /* Init Kernel version data */
    kern_version = mk_kernel_version();
    kern_features = mk_kernel_features(kern_version);

    server->kernel_version = kern_version;
    server->kernel_features = kern_features;

#ifdef MK_HAVE_TRACE
    MK_TRACE("Monkey TRACE is enabled");
    //pthread_mutex_init(&mutex_trace, (pthread_mutexattr_t *) NULL);
#endif

#ifdef LINUX_TRACE
    mk_info("Linux Trace enabled");
#endif

    mk_config_set_init_values(server);

    mk_mimetype_init(server);

    return server;
}

int mk_server_setup(struct mk_server *server)
{
    int ret;
    pthread_t tid;

    /* Core and Scheduler setup */
    mk_config_start_configure(server);
    mk_config_signature(server);

    mk_sched_init(server);

    /* Clock init that must happen before starting threads */
    mk_clock_sequential_init(server);

    /* Load plugins */
    mk_plugin_api_init();
    mk_plugin_load_all(server);

    /* Workers: logger and clock */
    ret = mk_utils_worker_spawn((void *) mk_clock_worker_init, server, &tid);
    if (ret != 0) {
        return -1;
    }

    /* Init thread keys */
    mk_thread_keys_init();

    /* Configuration sanity check */
    mk_config_sanity_check(server);

    /* Invoke Plugin PRCTX hooks */
    mk_plugin_core_process(server);

    /* Launch monkey http workers */
    MK_TLS_INIT();
    mk_server_launch_workers(server);

    return 0;
}


void mk_thread_keys_init(void)
{
    /* Create thread keys */
    pthread_key_create(&mk_utils_error_key, NULL);
}


void mk_exit_all(struct mk_server *server)
{
    uint64_t val;

    /* Distribute worker signals to stop working */
    val = MK_SCHED_SIGNAL_FREE_ALL;
    mk_sched_send_signal(server, val);

    /* Wait for all workers to finish */
    mk_sched_workers_join(server);

    /* Continue exiting */
    mk_plugin_exit_all(server);
    mk_clock_exit();

    mk_sched_exit(server);
    mk_config_free_all(server);
}
