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

#include <errno.h>
#include <glob.h>
#include <netinet/in.h>
#include <poll.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>

#include "flb_tests_runtime.h"

static int listen_loopback(int *port)
{
    int fd;
    socklen_t length;
    struct sockaddr_in address;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *) &address, sizeof(address)) == -1 ||
        listen(fd, 2) == -1) {
        close(fd);
        return -1;
    }

    length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *) &address, &length) == -1) {
        close(fd);
        return -1;
    }

    *port = ntohs(address.sin_port);
    return fd;
}

static int wait_readable(int fd)
{
    int ret;
    struct pollfd descriptor;

    descriptor.fd = fd;
    descriptor.events = POLLIN;
    do {
        ret = poll(&descriptor, 1, 20000);
    } while (ret == -1 && errno == EINTR);

    return ret == 1 && (descriptor.revents & POLLIN);
}

static int receive_upload(int listener, const char *operation, const char *payload)
{
    int fd;
    int ret = -1;
    ssize_t bytes;
    size_t length = 0;
    size_t sent = 0;
    size_t body_length;
    char request[4096];
    char *body;
    char *content_length;
    const char response[] = "HTTP/1.1 201 Created\r\n"
                            "Content-Length: 0\r\nConnection: close\r\n\r\n";

    if (!wait_readable(listener)) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    if (fd == -1) {
        return -1;
    }

    while (length < sizeof(request) - 1 && wait_readable(fd)) {
        bytes = recv(fd, request + length, sizeof(request) - length - 1, 0);
        if (bytes <= 0) {
            break;
        }
        length += bytes;
        request[length] = '\0';
        body = strstr(request, "\r\n\r\n");
        if (body == NULL) {
            continue;
        }
        content_length = strstr(request, "\r\n");
        while (content_length != NULL && content_length < body &&
               strncasecmp(content_length + 2, "Content-Length:", 15) != 0) {
            content_length = strstr(content_length + 2, "\r\n");
        }
        if (content_length == NULL || content_length >= body) {
            break;
        }
        body += 4;
        body_length = strtoul(content_length + strlen("\r\nContent-Length:"), NULL, 10);
        if (length - (body - request) < body_length) {
            continue;
        }

        TEST_CHECK(strncmp(request, "PUT /container/", 15) == 0);
        TEST_CHECK(strstr(request, operation) != NULL);
        TEST_CHECK(strstr(body, payload) != NULL);

        while (sent < sizeof(response) - 1) {
            bytes = send(fd, response + sent, sizeof(response) - 1 - sent, 0);
            if (bytes <= 0) {
                break;
            }
            sent += bytes;
        }
        ret = sent == sizeof(response) - 1 ? 0 : -1;
        break;
    }

    close(fd);
    return ret;
}

static void test_buffered_upload(void)
{
    int listener;
    int port;
    int input;
    int output;
    int ret;
    int attempt;
    int started = FLB_FALSE;
    char endpoint[64];
    char pattern[1024];
    /* The store appends its key within a 64-byte root buffer. */
    char store_dir[] = "/tmp/flb-azb-XXXXXX";
    char *buffer_path = NULL;
    char *separator;
    glob_t files;
    flb_ctx_t *ctx = NULL;
    const char record[] = "[12345678, {\"message\":\"buffered-upload\"}]";

    listener = listen_loopback(&port);
    if (!TEST_CHECK(listener >= 0)) {
        return;
    }
    if (!TEST_CHECK(mkdtemp(store_dir) != NULL)) {
        close(listener);
        return;
    }

    ctx = flb_create();
    if (!TEST_CHECK(ctx != NULL)) {
        goto cleanup;
    }
    ret = flb_service_set(ctx, "flush", "0.1", "grace", "1", "log_level", "debug", NULL);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }
    input = flb_input(ctx, "lib", NULL);
    output = flb_output(ctx, "azure_blob", NULL);
    if (!TEST_CHECK(input >= 0 && output >= 0)) {
        goto cleanup;
    }
    ret = flb_input_set(ctx, input, "tag", "buffered", NULL);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }
    snprintf(endpoint, sizeof(endpoint), "http://127.0.0.1:%d", port);
    ret = flb_output_set(ctx, output,
                         "match", "*",
                         "account_name", "test",
                         "container_name", "container",
                         "auth_type", "sas",
                         "sas_token", "sig=test",
                         "endpoint", endpoint,
                         "auto_create_container", "off",
                         "blob_type", "blockblob",
                         "buffering_enabled", "on",
                         "buffer_file_delete_early", "off",
                         "buffer_dir", store_dir,
                         "upload_timeout", "6s",
                         "io_timeout", "2s",
                         "scheduler_max_retries", "1",
                         "workers", "1",
                         NULL);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }
    if (!TEST_CHECK(flb_start(ctx) == 0)) {
        goto cleanup;
    }
    started = FLB_TRUE;
    ret = flb_lib_push(ctx, input, record, sizeof(record) - 1);
    if (!TEST_CHECK(ret == sizeof(record) - 1)) {
        goto cleanup;
    }

    snprintf(pattern, sizeof(pattern), "%s/key/*/*", store_dir);
    for (attempt = 0; attempt < 100; attempt++) {
        memset(&files, 0, sizeof(files));
        ret = glob(pattern, 0, NULL, &files);
        if (ret == 0 && files.gl_pathc == 1) {
            buffer_path = flb_strdup(files.gl_pathv[0]);
        }
        globfree(&files);
        if (buffer_path != NULL) {
            break;
        }
        flb_time_msleep(100);
    }
    if (!TEST_CHECK(buffer_path != NULL)) {
        goto cleanup;
    }

    if (!TEST_CHECK(receive_upload(listener, "&comp=block&", "\"message\":\"buffered-upload\"") == 0)) {
        goto cleanup;
    }
    if (!TEST_CHECK(receive_upload(listener, "?comp=blocklist&", "<Latest>") == 0)) {
        goto cleanup;
    }

    /* The timer must delete the buffer before shutdown can flush it. */
    for (attempt = 0; attempt < 100; attempt++) {
        ret = access(buffer_path, F_OK);
        if (ret == -1 && errno == ENOENT) {
            break;
        }
        flb_time_msleep(100);
    }
    TEST_CHECK(ret == -1 && errno == ENOENT);

cleanup:
    close(listener);
    if (started) {
        TEST_CHECK(flb_stop(ctx) == 0);
    }
    if (ctx != NULL) {
        flb_destroy(ctx);
    }
    if (buffer_path != NULL) {
        unlink(buffer_path);
        separator = strrchr(buffer_path, '/');
        *separator = '\0';
        rmdir(buffer_path);
        flb_free(buffer_path);
    }
    snprintf(pattern, sizeof(pattern), "%s/key", store_dir);
    rmdir(pattern);
    TEST_CHECK(rmdir(store_dir) == 0);
}

TEST_LIST = {
    {"buffered_upload", test_buffered_upload},
    {0}
};
