/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 *  Copyright (C) 2005-2017 The Android Open Source Project
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

#include "in_logcat.h"
#include "logprint.h"
#include "entities.h"

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>

#include <msgpack.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <stdarg.h>

static int output_log_entry(const AndroidLogEntry * logEntry,
                            struct flb_logcat *ctx);
static int connect_to_logd_read_socket(struct flb_input_instance *in,
                                       struct flb_config *config,
                                       struct flb_logcat *ctx);
static int input_collector_delete(int coll_id, struct flb_input_instance *in);
static struct flb_input_collector *get_collector(int id,
                                                 struct flb_input_instance
                                                 *in);

int output_error_as_log(struct flb_logcat *ctx, const char *fmt, ...)
{
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    AndroidLogEntry entry;
    entry.message = buf;
    entry.tag = "in_logcat";
    entry.tagLen = 10;
    entry.messageLen = strlen(buf);
    entry.pid = getpid();
    entry.uid = 0;
    entry.priority = ANDROID_LOG_ERROR;
    entry.tid = getpid();

    time_t t = time(NULL);
    entry.tv_sec = t;
    entry.tv_nsec = t * NS_PER_SEC;

    output_log_entry(&entry, ctx);
    return 0;
}

static int output_log_entry(const AndroidLogEntry * logEntry,
                            struct flb_logcat *ctx)
{
    char buf[4096];
    size_t line_length;
    bool ext_buf_used = false;
    char *line = formatLogLine(buf, sizeof(buf), logEntry, &line_length);
    if (!line) {
        flb_plg_error(ctx->ins, "line formatting has failed");

        /*
         * We can't use report_error here because we don't want to get stuck in recursion
         * loop. So we construct simple error string ourselves so that it will be reported
         * to flb engine instead of original failed string.
         */
        line = "[in_logcat] line formatting has failed!";
    }
    else {
        if (line != buf) {
            ext_buf_used = true;
        }
    }

    flb_plg_info(ctx->ins, "line read: %d %s", line_length, line);

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, 2);

    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "Data", 4);
    msgpack_pack_str(&mp_pck, line_length);
    msgpack_pack_str_body(&mp_pck, line, line_length);

    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "Path", 4);
    const int path_len = strlen(ctx->path);
    msgpack_pack_str(&mp_pck, path_len);
    msgpack_pack_str_body(&mp_pck, ctx->path, path_len);

    int ret =
        flb_input_chunk_append_raw(ctx->ins, NULL, 0, mp_sbuf.data,
                                   mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (ext_buf_used) {
        free(line);
    }

    return ret;
}

static int in_logcat_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    struct flb_logcat *ctx = in_context;

    struct log_msg log_msg;
    int ret;
    int delay = MIN_DELAY_SEC;
    while ((ret =
            TEMP_FAILURE_RETRY(recv
                               (ctx->server_fd, &log_msg,
                                LOGGER_ENTRY_MAX_LEN, 0))) <= 0) {
        report_error(ctx,
                     "failed to read from socket. Wait %d seconds before reconnect...",
                     delay);
        if (ctx->collector_id >= 0) {
            if (input_collector_delete(ctx->collector_id, ins) < 0) {
                report_error(ctx,
                             "Failed to remove previous event collector");
            }
        }

        sleep(delay);
        if (delay < MAX_DELAY_SEC) {
            delay *= DELAY_AMPLIFY;
            if (delay > MAX_DELAY_SEC) {
                delay = MAX_DELAY_SEC;
            }
        }
        connect_to_logd_read_socket(ins, config, ctx);
    }

    flb_plg_info(ctx->ins,
                 "ret=%d, sizeof(entry)=%d, entry.hdr_size=%d, entry.len=%d",
                 ret, sizeof(log_msg.entry), log_msg.entry.hdr_size,
                 log_msg.entry.len);

    AndroidLogEntry parsed;
    int result = parseLogEntry(&log_msg, ret, &parsed, ctx->ins);
    if (result < 0) {
        report_error(ctx, "failed to parse log entry");
        return -1;
    }

    return output_log_entry(&parsed, ctx);
}

static int config_destroy(struct flb_logcat *ctx)
{
    if (ctx->server_fd >= 0) {
        close(ctx->server_fd);
    }

    if (ctx->path != NULL) {
        flb_free(ctx->path);
    }

    if (ctx->socket_path) {
        flb_free(ctx->socket_path);
    }

    flb_free(ctx);
    return 0;
}

static control_command_result send_control_command(struct flb_logcat *ctx,
                                                   int fd, const char *cmd)
{
    int ret = TEMP_FAILURE_RETRY(write(fd, cmd, strlen(cmd) + 1));
    if (ret <= 0) {
        report_error(ctx, "failed to write to logd control socket");
        return INTERNAL_ERROR;
    }

    flb_plg_info(ctx->ins, "send command '%s'", cmd);

    char response[MAX_COMMAND_RESPONSE_LEN];
    ret = TEMP_FAILURE_RETRY(recv(fd, response, MAX_COMMAND_RESPONSE_LEN, 0));
    if (ret < 0) {
        report_error(ctx, "failed to read from control socket");
        return INTERNAL_ERROR;
    }

    if (strncmp(response, "success", 7) == 0) {
        return SUCCESS;
    }

    flb_plg_warn(ctx->ins, "non-success response from control socket: %s",
                 response);

    if (strncmp(response, "Permission Denied", 17) == 0) {
        return PERMISSION_DENIED;
    }

    flb_plg_warn(ctx->ins, "unknown response type");
    return INTERNAL_ERROR;
}

static int configure_logd(struct flb_logcat *ctx)
{
    struct sockaddr_un address;
    address.sun_family = AF_LOCAL;
    strncpy(address.sun_path, ctx->control_socket_path,
            sizeof(address.sun_path) - 1);
    int control_fd = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (control_fd < 0) {
        report_error(ctx, "failed to create control socket");
        return -1;
    }

    if (connect(control_fd, &address, sizeof(address)) == -1) {
        report_error(ctx, "failed to connect to control logd socket");
        close(control_fd);
        return -1;
    }

    /* Logcat defaults */
    const int lids[] = { LOG_ID_MAIN, LOG_ID_SYSTEM, LOG_ID_CRASH };

    int i;
    for (i = 0; i < sizeof(lids) / sizeof(lids[0]); i++) {
        char buf[MAX_COMMAND_LEN];
        snprintf(buf, sizeof(buf), "setLogSize %d %d", lids[i],
                 ctx->log_buffer_size);
        int ret = send_control_command(ctx, control_fd, buf);
        if (ret != SUCCESS && ret != PERMISSION_DENIED) {
            report_error(ctx, "failed to set log buffer size");
            close(control_fd);
            return -1;
        }
    }
    close(control_fd);
    return 0;
}

static int connect_to_logd_read_socket(struct flb_input_instance *in,
                                       struct flb_config *config,
                                       struct flb_logcat *ctx)
{
    struct sockaddr_un address;
    address.sun_family = AF_LOCAL;
    strncpy(address.sun_path, ctx->socket_path, sizeof(address.sun_path) - 1);
    int fd = socket(AF_LOCAL, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        report_error(ctx, "failed to create socket");
        return -1;
    }

    ctx->server_fd = fd;

    if (connect(fd, &address, sizeof(address)) == -1) {
        report_error(ctx, "failed to connect to logd read socket");
        return -1;
    }

    const char *cmd = "stream lids=0,3,4";
    int ret = TEMP_FAILURE_RETRY(write(fd, cmd, strlen(cmd)));
    if (ret <= 0) {
        report_error(ctx, "failed to write to logd read socket");
        return -1;
    }

    flb_plg_info(ctx->ins, "connected to logd read socket succesfully");

    flb_input_set_context(in, ctx);

    ret = flb_input_set_collector_event(in, in_logcat_collect, fd, config);
    if (ret < 0) {
        report_error(ctx, "could not set collector for logcat input plugin");
        return -1;
    }

    ctx->collector_id = ret;
    flb_input_collector_start(ctx->collector_id, in);

    return 0;
}

static struct flb_input_collector *get_collector(int id,
                                                 struct flb_input_instance
                                                 *in)
{
    struct mk_list *head;
    struct flb_input_collector *coll;

    mk_list_foreach(head, &in->collectors) {
        coll = mk_list_entry(head, struct flb_input_collector, _head_ins);
        if (coll->id == id) {
            return coll;
        }
    }

    return NULL;
}

static int input_collector_delete(int coll_id, struct flb_input_instance *in)
{
    struct flb_input_collector *coll;

    coll = get_collector(coll_id, in);
    if (!coll) {
        return -1;
    }
    if (flb_input_collector_pause(coll_id, in) < 0) {
        return -1;
    }

    mk_list_del(&coll->_head);
    mk_list_del(&coll->_head_ins);
    flb_free(coll);
    return 0;
}

static int in_logcat_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_logcat *ctx = NULL;
    ctx = flb_malloc(sizeof(struct flb_logcat));
    if (ctx == NULL) {
        return -1;
    }
    ctx->ins = in;
    ctx->path = NULL;
    ctx->socket_path = NULL;
    ctx->server_fd = -1;
    ctx->collector_id = -1;

    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to initialize config map");
        config_destroy(ctx);
        return -1;
    }

    if (configure_logd(ctx) < 0) {
        config_destroy(ctx);
        return -1;
    }

    if (connect_to_logd_read_socket(in, config, ctx) < 0) {
        config_destroy(ctx);
        return -1;
    }

    return 0;
}

static int in_logcat_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_logcat *ctx = data;

    config_destroy(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {FLB_CONFIG_MAP_STR, "Path", "logcat",
     0, FLB_TRUE, offsetof(struct flb_logcat, path),
     "set the path for output messages."},
    {FLB_CONFIG_MAP_STR, "Socket_Path", DEFAULT_SOCKET_PATH,
     0, FLB_TRUE, offsetof(struct flb_logcat, socket_path),
     "Socket path for reading logs from."},
    {FLB_CONFIG_MAP_STR, "Control_Socket_Path", DEFAULT_CONTROL_SOCKET_PATH,
     0, FLB_TRUE, offsetof(struct flb_logcat, control_socket_path),
     "Socket path for transmitting control commands."},
    {FLB_CONFIG_MAP_INT, "Log_Buffer_Size", DEFAULT_LOG_BUFFER_SIZE,
     0, FLB_TRUE, offsetof(struct flb_logcat, log_buffer_size),
     "Log buffer size for logd. Log lines that do not fit into this buffer will be skipped."},
    {0}
};

struct flb_input_plugin in_logcat_plugin = {
    .name = "logcat",
    .description = "Reads logcat",
    .cb_init = in_logcat_init,
    .cb_pre_run = NULL,
    .cb_collect = in_logcat_collect,
    .cb_flush_buf = NULL,
    .cb_exit = in_logcat_exit,
    .config_map = config_map
};
