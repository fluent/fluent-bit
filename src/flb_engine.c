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
#include <sys/time.h>
#include <sys/uio.h>

#include <mk_core.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_http_server.h>

#ifdef HAVE_STATS
#include <fluent-bit/flb_stats.h>
#endif

static int flb_engine_destroy_threads(struct mk_list *threads)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_thread *th;

    mk_list_foreach_safe(head, tmp, threads) {
        th = mk_list_entry(head, struct flb_thread, _head);
        flb_thread_destroy(th);
        c++;
    }

    return c;
}

int flb_engine_destroy_tasks(struct mk_list *tasks)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_engine_task *task;

    mk_list_foreach_safe(head, tmp, tasks) {
        task = mk_list_entry(head, struct flb_engine_task, _head);
        flb_engine_task_destroy(task);
        c++;
    }

    return c;
}

int flb_engine_flush(struct flb_config *config,
                     struct flb_input_plugin *in_force)
{
    size_t size;
    char *buf;
    struct flb_input_instance *in;
    struct flb_input_plugin *p;
    struct mk_list *head;
    struct mk_list *r_head;
    struct flb_thread *th;
    struct flb_output_instance *o_ins;
    struct flb_router_path *path;
    struct flb_engine_task *task;

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        p = in->p;

        if (in_force != NULL && p != in_force) {
            continue;
        }

        if (p->cb_flush_buf) {
            buf = p->cb_flush_buf(in->context, &size);
            if (!buf) {
                goto flush_done;
            }
            if (size == 0) {
                flb_warn("[engine] no input data");
                continue;
            }

            /*
             * Create an engine task, the task will hold the buffer reference
             * and the co-routines associated to the output instance plugins
             * that needs to handle the data.
             */
            task = flb_engine_task_create(buf, size, in, NULL);
            if (!task) {
                free(buf);
                continue;
            }

            /* Create a thread context for an output plugin call */
            mk_list_foreach(r_head, &in->routes) {
                path = mk_list_entry(r_head, struct flb_router_path, _head);
                o_ins = path->ins;

                th = flb_output_thread(task,
                                       in,
                                       o_ins,
                                       config,
                                       buf, size,
                                       in->tag,
                                       in->tag_len);
                flb_engine_task_add(&th->_head, task);
                flb_thread_resume(th);
            }

            /* Sometimes a task finish right away, lets check */
            if (task->deleted == FLB_TRUE) {
                flb_engine_destroy_threads(&task->threads);
                flb_engine_task_destroy(task);
            }

            continue;
        }
        else if (p->flags & FLB_INPUT_DYN_TAG) {
            /*
             * FIXME> Testing iteration from dynamic tag buffers
             * =====
             */
            struct mk_list *d_head, *tmp;
            struct flb_input_dyntag *dt;
            struct flb_output_instance *o_ins;
            mk_list_foreach_safe(d_head, tmp, &in->dyntags) {
                int matches = 0;
                struct mk_list *o_head;
                dt = mk_list_entry(d_head, struct flb_input_dyntag, _head);
                flb_trace("[dyntag %s] %p tag=%s", dt->in->name, dt, dt->tag);

                /* There is a match, get the buffer */
                buf = flb_input_dyntag_flush(dt, &size);
                if (size == 0 || !buf) {
                    continue;
                }

                task = flb_engine_task_create(buf, size, dt->in, dt);
                if (!task) {
                    free(buf);
                    continue;
                }

                /* FIXME: Testing static tags match first */
                mk_list_foreach(o_head, &config->outputs) {
                    o_ins = mk_list_entry(o_head,
                                          struct flb_output_instance, _head);

                    if (flb_router_match(dt->tag, o_ins->match)) {
                        flb_trace("[dyntag %s] [%p] match rule %s:%s",
                                  dt->in->name, dt, dt->tag, o_ins->match);

                        flb_trace("[dyntag buf] size=%lu buf=%p",
                                  size, buf);

                        th = flb_output_thread(task,
                                               dt->in,
                                               o_ins,
                                               config,
                                               buf, size,
                                               dt->tag, dt->tag_len);
                        flb_engine_task_add(&th->_head, task);
                        flb_thread_resume(th);

                        matches++;
                    }
                }
                if (matches == 0) {
                    flb_input_dyntag_destroy(dt);
                }

                if (task->deleted == FLB_TRUE) {
                    flb_engine_destroy_threads(&task->threads);
                    flb_engine_task_destroy(task);
                }
            }
        }

    flush_done:
        if (p->cb_flush_end) {
            p->cb_flush_end(in->context);
        }
    }

    return 0;
}

static inline int consume_byte(int fd)
{
    int ret;
    uint64_t val;

    /* We need to consume the byte */
    ret = read(fd, &val, sizeof(val));
    if (ret <= 0) {
        perror("read");
        return -1;
    }

    return 0;
}

static inline int flb_engine_manager(int fd, struct flb_config *config)
{
    int bytes;
    uint64_t val;

    bytes = read(fd, &val, sizeof(uint64_t));
    if (bytes == -1) {
        perror("read");
        return -1;
    }

    /* Flush all remaining data */
    if (val == FLB_ENGINE_STOP) {
        flb_trace("[engine] flush enqueued data");
        flb_engine_flush(config, NULL);
        return FLB_ENGINE_STOP;
    }
#ifdef HAVE_STATS
    else if (val == FLB_ENGINE_STATS) {
        flb_trace("[engine] collect stats");
        //flb_stats_collect(config);
        return FLB_ENGINE_STATS;
    }
#endif

    return 0;
}

static FLB_INLINE int flb_engine_handle_event(int fd, int mask,
                                              struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct flb_input_collector *collector;

    if (mask & MK_EVENT_READ) {
        /* Check if we need to flush */
        if (config->flush_fd == fd) {
            consume_byte(fd);
            flb_engine_flush(config, NULL);
            return 0;
        }
        else if (config->shutdown_fd == fd) {
            return FLB_ENGINE_SHUTDOWN;
        }
#ifdef HAVE_STATS
        else if (config->stats_fd == fd) {
            consume_byte(fd);
            return FLB_ENGINE_STATS;
        }
#endif
        else if (config->ch_manager[0] == fd) {
            ret = flb_engine_manager(fd, config);
            if (ret == FLB_ENGINE_STOP) {
                return FLB_ENGINE_STOP;
            }
        }

        /* Determinate what is this file descriptor */
        mk_list_foreach(head, &config->collectors) {
            collector = mk_list_entry(head, struct flb_input_collector, _head);
            if (collector->fd_event == fd) {
                return collector->cb_collect(config,
                                             collector->instance->context);
            }
            else if (collector->fd_timer == fd) {
                consume_byte(fd);
                return collector->cb_collect(config,
                                             collector->instance->context);
            }
        }
    }

    return 0;
}

static int flb_engine_started(struct flb_config *config)
{
    uint64_t val;

    /* Check the channel is valid (enabled by library mode) */
    if (config->ch_notif[1] <= 0) {
        return -1;
    }

    val = FLB_ENGINE_STARTED;
    return write(config->ch_notif[1], &val, sizeof(uint64_t));
}

int flb_engine_start(struct flb_config *config)
{
    int fd;
    int ret;
    struct mk_list *head;
    struct mk_event *event;
    struct mk_event_loop *evl;
    struct flb_input_collector *collector;
    struct flb_upstream_conn *u_conn;
    struct flb_thread *th;
    struct flb_engine_task *task;

#ifdef HAVE_HTTP
    if (config->http_server == FLB_TRUE) {
        flb_http_server_start(config);
    }
#endif

    flb_info("starting engine");
    pthread_key_create(&flb_thread_key, NULL);

    /* Create the event loop and set it in the global configuration */
    evl = mk_event_loop_create(256);
    if (!evl) {
        return -1;
    }
    config->evl = evl;

    /*
     * Create a communication channel: this routine creates a channel to
     * signal the Engine event loop. It's useful to stop the event loop
     * or to instruct anything else without break.
     */
    ret = mk_event_channel_create(config->evl,
                                  &config->ch_manager[0],
                                  &config->ch_manager[1],
                                  config);
    if (ret != 0) {
        flb_error("[engine] could not create manager channels");
        exit(EXIT_FAILURE);
    }

    /* Initialize input plugins */
    flb_input_initialize_all(config);

    /* Inputs pre-run */
    flb_input_pre_run_all(config);

    /* Outputs pre-run */
    ret = flb_output_init(config);
    if (ret == -1) {
        flb_engine_shutdown(config);
        return -1;
    }

    flb_output_pre_run(config);


    /* Create and register the timer fd for flush procedure */
    event = &config->event_flush;
    event->mask = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;

    config->flush_fd = mk_event_timeout_create(evl, config->flush, 0, event);
    if (config->flush_fd == -1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH_CREATE);
    }

    /* Initialize the stats interface (just if HAVE_STATS is defined) */
    flb_stats_init(config);

    /* For each Collector, register the event into the main loop */
    mk_list_foreach(head, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        event = &collector->event;

        if (collector->type == FLB_COLLECT_TIME) {
            event->mask = MK_EVENT_EMPTY;
            event->status = MK_EVENT_NONE;
            fd = mk_event_timeout_create(evl, collector->seconds,
                                         collector->nanoseconds, event);
            if (fd == -1) {
                continue;
            }
            collector->fd_timer = fd;
        }
        else if (collector->type & (FLB_COLLECT_FD_EVENT | FLB_COLLECT_FD_SERVER)) {
            event->fd     = collector->fd_event;
            event->mask   = MK_EVENT_EMPTY;
            event->status = MK_EVENT_NONE;

            ret = mk_event_add(evl,
                               collector->fd_event,
                               FLB_ENGINE_EV_CORE,
                               MK_EVENT_READ, event);
            if (ret == -1) {
                close(collector->fd_event);
                continue;
            }
        }
    }

    /* Prepare routing paths */
    ret = flb_router_io_set(config);
    if (ret == -1) {
        return -1;
    }

    /* Signal that we have started */
    flb_engine_started(config);
    while (1) {
        mk_event_wait(evl);
        mk_event_foreach(event, evl) {
            if (event->type == FLB_ENGINE_EV_CORE) {
                ret = flb_engine_handle_event(event->fd, event->mask, config);
                if (ret == FLB_ENGINE_STOP) {
                    /*
                     * We are preparing to shutdown, we give a graceful time
                     * of 5 seconds to process any pending event.
                     */
                    event = &config->event_shutdown;
                    event->mask = MK_EVENT_EMPTY;
                    event->status = MK_EVENT_NONE;
                    config->shutdown_fd = mk_event_timeout_create(evl, 5, 0, event);
                    flb_warn("[engine] service will stop in 5 seconds");
                }
                else if (ret == FLB_ENGINE_SHUTDOWN) {
                    flb_info("[engine] service stopped");
                    return flb_engine_shutdown(config);
                }
#ifdef HAVE_STATS
                else if (ret == FLB_ENGINE_STATS) {
                    //flb_stats_collect(config);
                }
#endif
            }
            else if (event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
            else if (event->type == FLB_ENGINE_EV_THREAD) {
                /*
                 * Check if we have some co-routine associated to this event,
                 * if so, resume the co-routine
                 */
                u_conn = (struct flb_upstream_conn *) event;
                th = u_conn->thread;
                task = th->task;

                flb_trace("[engine] resuming thread: %i", u_conn->event.fd);
                flb_thread_resume(th);

                if (task->deleted == FLB_TRUE) {
                    flb_engine_destroy_threads(&task->threads);
                    flb_engine_task_destroy(task);
                }
            }
        }
    }
}

/* Release all resources associated to the engine */
int flb_engine_shutdown(struct flb_config *config)
{
    /* router */
    flb_router_exit(config);

    /* cleanup plugins */
    flb_input_exit_all(config);
    flb_output_exit(config);

    flb_config_exit(config);

    return 0;
}
