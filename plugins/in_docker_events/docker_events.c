/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "docker_events.h"
#include "docker_events_config.h"


/**
 * Creates the connection to docker's unix socket and sends the
 * HTTP GET /events
 *
 * @param ctx  Pointer to flb_in_de_config
 *
 * @return int 0 on success, -1 on failure
 */
static int de_unix_create(struct flb_in_de_config *ctx)
{
    ssize_t bytes;
    unsigned long len;
    size_t address_length;
    struct sockaddr_un address;
    char request[512];

    ctx->fd = flb_net_socket_create(AF_UNIX, FLB_FALSE);
    if (ctx->fd == -1) {
        return -1;
    }

    /* Prepare the unix socket path */
    len = strlen(ctx->unix_path);
    address.sun_family = AF_UNIX;
    sprintf(address.sun_path, "%s", ctx->unix_path);
    address_length = sizeof(address.sun_family) + len + 1;
    if (connect(ctx->fd, (struct sockaddr *)&address, address_length) == -1) {
        flb_errno();
        close(ctx->fd);
        return -1;
    }

    strcpy(request, "GET /events HTTP/1.0\r\n\r\n");
    flb_plg_trace(ctx->ins, "writing to socket %s", request);
    write(ctx->fd, request, strlen(request));

    /* Read the initial http response */
    bytes = read(ctx->fd, ctx->buf, ctx->buf_size - 1);
    if (bytes == -1) {
        flb_errno();
    }
    flb_plg_debug(ctx->ins, "read %zu bytes from socket", bytes);

    return 0;
}

static int in_de_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context);

static int reconnect_docker_sock(struct flb_input_instance *ins,
                                 struct flb_config *config,
                                 struct flb_in_de_config *ctx)
{
    int ret;

    /* remove old socket collector */
    if (ctx->coll_id >= 0) {
        ret = flb_input_collector_delete(ctx->coll_id, ins);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "failed to pause event");
            return -1;
        }
        ctx->coll_id = -1;
    }
    if (ctx->fd > 0) {
        flb_plg_debug(ctx->ins, "close socket fd=%d", ctx->fd);
        close(ctx->fd);
        ctx->fd = -1;
    }

    /* create socket again */
    if (de_unix_create(ctx) < 0) {
        flb_plg_error(ctx->ins, "failed to re-initialize socket");
        if (ctx->fd > 0) {
            flb_plg_debug(ctx->ins, "close socket fd=%d", ctx->fd);
            close(ctx->fd);
            ctx->fd = -1;
        }
        return -1;
    }
    /* set event */
    ctx->coll_id = flb_input_set_collector_event(ins,
                                                 in_de_collect,
                                                 ctx->fd, config);
    if (ctx->coll_id < 0) {
        flb_plg_error(ctx->ins,
                      "could not set collector for IN_DOCKER_EVENTS plugin");
        close(ctx->fd);
        ctx->fd = -1;
        return -1;
    }
    ret = flb_input_collector_start(ctx->coll_id, ins);
    if (ret < 0) {
        flb_plg_error(ctx->ins,
                      "could not start collector for IN_DOCKER_EVENTS plugin");
        flb_input_collector_delete(ctx->coll_id, ins);
        close(ctx->fd);
        ctx->coll_id = -1;
        ctx->fd = -1;
        return -1;
    }

    flb_plg_info(ctx->ins, "Reconnect successful");
    return 0;
}

static int cb_reconnect(struct flb_input_instance *ins,
                       struct flb_config *config,
                       void *in_context)
{
    struct flb_in_de_config *ctx = in_context;
    int ret;

    flb_plg_info(ctx->ins, "Retry(%d/%d)",
                 ctx->current_retries, ctx->reconnect_retry_limits);
    ret = reconnect_docker_sock(ins, config, ctx);
    if (ret < 0) {
        /* Failed to reconnect */
        ctx->current_retries++;
        if (ctx->current_retries > ctx->reconnect_retry_limits) {
            /* give up */
            flb_plg_error(ctx->ins, "Failed to retry. Giving up...");
            goto cb_reconnect_end;
        }
        flb_plg_info(ctx->ins, "Failed. Waiting for next retry..");
        return 0;
    }

 cb_reconnect_end:
    if(flb_input_collector_delete(ctx->retry_coll_id, ins) < 0) {
        flb_plg_error(ctx->ins, "failed to delete timer event");
    }
    ctx->current_retries = 0;
    ctx->retry_coll_id = -1;
    return ret;
}

static int create_reconnect_event(struct flb_input_instance *ins,
                                  struct flb_config *config,
                                  struct flb_in_de_config *ctx)
{
    int ret;

    if (ctx->retry_coll_id >= 0) {
        flb_plg_debug(ctx->ins, "already retring ?");
        return 0;
    }

    /* try before creating event to stop incoming event */
    ret = reconnect_docker_sock(ins, config, ctx);
    if (ret == 0) {        
        return 0;
    }

    ctx->current_retries = 1;
    ctx->retry_coll_id = flb_input_set_collector_time(ins,
                                                      cb_reconnect,
                                                      ctx->reconnect_retry_interval,
                                                      0,
                                                      config);
    if (ctx->retry_coll_id < 0) {
        flb_plg_error(ctx->ins, "failed to create timer event");
        return -1;
    }
    ret = flb_input_collector_start(ctx->retry_coll_id, ins);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "failed to start timer event");
        flb_input_collector_delete(ctx->retry_coll_id, ins);
        ctx->retry_coll_id = -1;
        return -1;
    }
    flb_plg_info(ctx->ins, "create reconnect event. interval=%d second",
                 ctx->reconnect_retry_interval);

    return 0;
}

static int is_recoverable_error(int error)
{
    /* ENOTTY: 
          It reports on Docker in Docker mode.
          https://github.com/fluent/fluent-bit/issues/3439#issuecomment-831424674
     */
    if (error == ENOTTY || error == EBADF) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}


/**
 * Callback function to process events recieved on the unix
 * socket.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to
 *                      flb_in_de_config
 *
 * @return int Always returns success
 */
static int in_de_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int ret = 0;
    int error;
    size_t str_len = 0;
    struct flb_in_de_config *ctx = in_context;

    /* variables for parser */
    int parser_ret = -1;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;

    ret = read(ctx->fd, ctx->buf, ctx->buf_size - 1);

    if (ret > 0) {
        str_len = ret;
        ctx->buf[str_len] = '\0';

        ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

        if (!ctx->parser) {
            /* Initialize local msgpack buffer */
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_set_current_timestamp(
                        &ctx->log_encoder);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_values(
                        &ctx->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE(ctx->key),
                        FLB_LOG_EVENT_STRING_VALUE(ctx->buf, str_len));
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                flb_input_log_append(ins, NULL, 0,
                                     ctx->log_encoder.output_buffer,
                                     ctx->log_encoder.output_length);

            }
            else {
                flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
            }
        }
        else {
            flb_time_get(&out_time);

            parser_ret = flb_parser_do(ctx->parser, ctx->buf, str_len - 1,
                                       &out_buf, &out_size, &out_time);
            if (parser_ret >= 0) {
                if (flb_time_to_nanosec(&out_time) == 0L) {
                    flb_time_get(&out_time);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_set_timestamp(
                            &ctx->log_encoder,
                            &out_time);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                            &ctx->log_encoder,
                            out_buf,
                            out_size);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    flb_input_log_append(ins, NULL, 0,
                                         ctx->log_encoder.output_buffer,
                                         ctx->log_encoder.output_length);

                }
                else {
                    flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
                }


                flb_free(out_buf);
            }
            else {
                flb_plg_trace(ctx->ins, "tried to parse: %s", ctx->buf);
                flb_plg_trace(ctx->ins, "buf_size %zu", ctx->buf_size);
                flb_plg_error(ctx->ins, "parser returned an error: %d",
                              parser_ret);
            }
        }

        flb_log_event_encoder_reset(&ctx->log_encoder);
    }
    else if (ret == 0) {
        /* EOF */

        /* docker service may be restarted */
        flb_plg_info(ctx->ins, "EOF detected. Re-initialize");
        if (ctx->reconnect_retry_limits > 0) {
            ret = create_reconnect_event(ins, config, ctx);
            if (ret < 0) {
                return ret;
            }
        }
    }
    else {
        error = errno;
        flb_plg_error(ctx->ins, "read returned error: %d, %s", error,
                      strerror(error));
        if (is_recoverable_error(error)) {
            if (ctx->reconnect_retry_limits > 0) {
                ret = create_reconnect_event(ins, config, ctx);
                if (ret < 0) {
                    return ret;
                }
            }
        }
    }

    return 0;
}

/**
 * Callback function to initialize docker events plugin
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 * @param data    Unused
 *
 * @return int 0 on success, -1 on failure
 */
static int in_de_init(struct flb_input_instance *ins,
                      struct flb_config *config, void *data)
{
    struct flb_in_de_config *ctx = NULL;
    (void) data;

    /* Allocate space for the configuration */
    ctx = de_config_init(ins, config);
    if (!ctx) {
        return -1;
    }
    ctx->ins = ins;
    ctx->retry_coll_id = -1;
    ctx->current_retries = 0;

    /* Set the context */
    flb_input_set_context(ins, ctx);

    if (de_unix_create(ctx) != 0) {
        flb_plg_error(ctx->ins, "could not listen on unix://%s",
                      ctx->unix_path);
        de_config_destroy(ctx);
        return -1;
    }

    ctx->coll_id = flb_input_set_collector_event(ins, in_de_collect,
                                                 ctx->fd, config);
    if(ctx->coll_id < 0){
        flb_plg_error(ctx->ins,
                      "could not set collector for IN_DOCKER_EVENTS plugin");
        de_config_destroy(ctx);
        return -1;
    }

    flb_plg_info(ctx->ins, "listening for events on %s", ctx->unix_path);
    return 0;
}

/**
 * Callback exit function to cleanup plugin
 *
 * @param data    Pointer cast to flb_in_de_config
 * @param config  Unused
 *
 * @return int    Always returns 0
 */
static int in_de_exit(void *data, struct flb_config *config)
{
    (void) config;
    struct flb_in_de_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    de_config_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "unix_path", DEFAULT_UNIX_SOCKET_PATH,
     0, FLB_TRUE, offsetof(struct flb_in_de_config, unix_path),
     "Define Docker unix socket path to read events"
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_size", "8k",
     0, FLB_TRUE, offsetof(struct flb_in_de_config, buf_size),
     "Set buffer size to read events"
    },
    {
     FLB_CONFIG_MAP_STR, "parser", NULL,
      0, FLB_FALSE, 0,
     "Optional parser for records, if not set, records are packages under 'key'"
    },
    {
     FLB_CONFIG_MAP_STR, "key", DEFAULT_FIELD_NAME,
     0, FLB_TRUE, offsetof(struct flb_in_de_config, key),
     "Set the key name to store unparsed Docker events"
    },
    {
     FLB_CONFIG_MAP_INT, "reconnect.retry_limits", "5",
     0, FLB_TRUE, offsetof(struct flb_in_de_config, reconnect_retry_limits),
     "Maximum number to retry to connect docker socket"
    },
    {
     FLB_CONFIG_MAP_INT, "reconnect.retry_interval", "1",
     0, FLB_TRUE, offsetof(struct flb_in_de_config, reconnect_retry_interval),
     "Retry interval to connect docker socket"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_docker_events_plugin = {
    .name         = "docker_events",
    .description  = "Docker events",
    .cb_init      = in_de_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_de_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_de_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET
};
