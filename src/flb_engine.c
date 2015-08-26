/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <mk_core/mk_core.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine.h>

int flb_engine_flush(struct flb_config *config,
                     struct flb_input_plugin *in_force)
{
    int fd;
    int size;
    int len;
    int bytes;
    char *buf;
    struct flb_input_plugin *in;
    struct iovec *iov;
    struct mk_list *head;

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);

        if (in_force != NULL && in != in_force) {
            continue;
        }

        if (in->active == FLB_TRUE) {
            if (in->cb_flush_buf) {
                buf = in->cb_flush_buf(in->in_context, &size);
                if (!buf) {
                    goto flush_done;
                }
                if (size == 0) {
                    flb_warn("No input data");
                    continue;
                }

                bytes = config->output->cb_flush(buf, size,
                                                 config->output->out_context,
                                                 config);
                if (bytes <= 0) {
                    flb_error("Error flushing data");
                }
                else {
                    flb_info("Flush buf %i bytes", bytes);
                }
                free(buf);
            }

            if (in->cb_flush_iov) {
                iov = in->cb_flush_iov(in->in_context, &len);
                if (len <= 0) {
                    goto flush_done;
                }

                bytes = writev(fd, iov, len);
                if (bytes <= 0) {
                    perror("writev");
                }
                else {
                    flb_info("Flush iov %i bytes (%i entries)", bytes, len);
                }
            }

        flush_done:
            if (in->cb_flush_end) {
                in->cb_flush_end(in->in_context);
            }
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

static inline int flb_engine_handle_event(int fd, int mask,
                                          struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_collector *collector;

    if (mask & MK_EVENT_READ) {
        /* Check if we need to flush */
        if (config->flush_fd == fd) {
            consume_byte(fd);
            flb_engine_flush(config, NULL);
            return 0;
        }

        /* Determinate what is this file descriptor */
        mk_list_foreach(head, &config->collectors) {
            collector = mk_list_entry(head, struct flb_input_collector, _head);
            if (collector->fd_event == fd) {
                return collector->cb_collect(config,
                                             collector->plugin->in_context);
            }
            else if (collector->fd_timer == fd) {
                consume_byte(fd);
                return collector->cb_collect(config,
                                             collector->plugin->in_context);
            }
        }
    }

    return -1;
}

static int flb_engine_manager(struct mk_event *event)
{
    int fd = event->fd;
    int bytes;
    uint64_t val;
    struct flb_config *config = (struct flb_config *) event;

    bytes = read(fd, &val, sizeof(uint64_t));
    if (bytes == -1) {
        perror("read");
        return -1;
    }

    /* Flush all remaining data */
    if (val == FLB_ENGINE_STOP) {
        flb_debug("[engine] flush enqueued data");
        flb_engine_flush(config, NULL);
        return -1;
    }

    return 0;
}

static int flb_engine_started(struct flb_config *config)
{
    uint64_t val;

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

    flb_info("starting engine");

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
    flb_output_init(config);
    flb_output_pre_run(config);

    /* Create and register the timer fd for flush procedure */
    event = malloc(sizeof(struct mk_event));
    event->mask = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;
    config->flush_fd = mk_event_timeout_create(evl, config->flush, event);
    if (config->flush_fd == -1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH_CREATE);
    }

    /* For each Collector, register the event into the main loop */
    mk_list_foreach(head, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        if (collector->type == FLB_COLLECT_TIME) {
            event = malloc(sizeof(struct mk_event));
            event->mask = MK_EVENT_EMPTY;
            event->status = MK_EVENT_NONE;
            fd = mk_event_timeout_create(evl, collector->seconds, event);
            if (fd == -1) {
                continue;
            }
            collector->fd_timer = fd;
        }
        else if (collector->type & (FLB_COLLECT_FD_EVENT | FLB_COLLECT_FD_SERVER)) {
            event = malloc(sizeof(struct mk_event));
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

    /* Signal that we have started */
    flb_engine_started(config);

    while (1) {
        mk_event_wait(evl);
        mk_event_foreach(event, evl) {
            if (event->type == FLB_ENGINE_EV_CORE) {
                flb_engine_handle_event(event->fd, event->mask, config);
            }
            else if (event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
            else if (event->type == MK_EVENT_NOTIFICATION) {
                ret = flb_engine_manager(event);
                if (ret == -1) {
                    flb_debug("[manager] stopping Fluent Bit");
                    return 0;
                }
            }
        }
    }
}
