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

#define _GNU_SOURCE

#include <pthread.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_clock.h>

void mk_server_info()
{
    struct mk_list *head;
    struct mk_plugin *p;
    struct mk_config_listener *l;

    printf(MK_BANNER_ENTRY "Process ID is %i\n", getpid());
    mk_list_foreach(head, &mk_config->listeners) {
        l = mk_list_entry(head, struct mk_config_listener, _head);
        printf(MK_BANNER_ENTRY "Server listening on %s:%s\n",
               l->address, l->port);
    }
    printf(MK_BANNER_ENTRY
           "%i threads, may handle up to %i client connections\n",
           mk_config->workers, mk_config->server_capacity);

    /* List loaded plugins */
    printf(MK_BANNER_ENTRY "Loaded Plugins: ");
    mk_list_foreach(head, &mk_config->plugins) {
        p = mk_list_entry(head, struct mk_plugin, _head);
        printf("%s ", p->shortname);
    }
    printf("\n");

#ifdef __linux__
    char tmp[64];

    if (mk_kernel_features_print(tmp, sizeof(tmp)) > 0) {
        printf(MK_BANNER_ENTRY "Linux Features: %s\n", tmp);
    }
#endif

    fflush(stdout);
}

/* Initialize Monkey Server */
struct mk_server_config *mk_server_init()
{
    /* setup basic configurations */
    mk_config = mk_config_init();

#ifdef TRACE
    mk_core_init();
#endif

    /* Init Kernel version data */
    mk_kernel_init();
    mk_kernel_features();

#ifdef TRACE
    MK_TRACE("Monkey TRACE is enabled");
    env_trace_filter = getenv("MK_TRACE_FILTER");
    pthread_mutex_init(&mutex_trace, (pthread_mutexattr_t *) NULL);
#endif
    pthread_mutex_init(&mutex_port_init, (pthread_mutexattr_t *) NULL);

#ifdef LINUX_TRACE
    mk_info("Linux Trace enabled");
#endif

    return mk_config;
}

int mk_server_setup()
{
    /* Core and Scheduler setup */
    mk_config_start_configure();
    mk_sched_init();

    /* Clock init that must happen before starting threads */
    mk_clock_sequential_init();

    /* Load plugins */
    mk_plugin_api_init();
    mk_plugin_load_all();

    /* Workers: logger and clock */
    mk_utils_worker_spawn((void *) mk_clock_worker_init, NULL);

    /* Init thread keys */
    mk_thread_keys_init();

    /* Configuration sanity check */
    mk_config_sanity_check();

    /* Invoke Plugin PRCTX hooks */
    mk_plugin_core_process();

    /* Launch monkey http workers */
    MK_TLS_INIT();
    mk_server_launch_workers();

    return 0;
}


void mk_thread_keys_init(void)
{
    /* Create thread keys */
    pthread_key_create(&mk_utils_error_key, NULL);
}


void mk_exit_all()
{
    int i;
    int n;
    uint64_t val;

    /* Distribute worker signals to stop working */
    val = MK_SCHED_SIGNAL_FREE_ALL;
    for (i = 0; i < mk_config->workers; i++) {
        n = write(sched_list[i].signal_channel_w, &val, sizeof(val));
        if (n < 0) {
            perror("write");
        }
    }

    /* Wait for workers to finish */
    for (i = 0; i < mk_config->workers; i++) {
        pthread_join(sched_list[i].tid, NULL);
    }

    mk_plugin_exit_all();
    mk_config_free_all();
    mk_mem_free(sched_list);
    mk_clock_exit();
}
