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

#include <fluent-bit.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <strings.h>
#include <unistd.h>

#include "flb_tests_runtime.h"

struct blob_test {
    flb_ctx_t *ctx;
    flb_sockfd_t listener;
    int input;
    int output;
    char directory[64];
    char buffer_dir[128];
};

struct request {
    char target[2048];
    char body[8192];
    size_t size;
};

struct buffer_snapshot {
    char path[PATH_MAX];
    char *data;
    size_t size;
};

static int64_t milliseconds(void)
{
    struct timespec now;

    TEST_ASSERT(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (int64_t) now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int readable(flb_sockfd_t fd, int timeout_ms)
{
    fd_set fds;
    struct timeval timeout;
    int ret;

    do {
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        ret = select(fd + 1, &fds, NULL, NULL, &timeout);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

static flb_sockfd_t accept_request(struct blob_test *test)
{
    flb_sockfd_t fd;

    if (!TEST_CHECK(readable(test->listener, 15000) == 1)) {
        return FLB_INVALID_SOCKET;
    }
    fd = accept(test->listener, NULL, NULL);
    TEST_CHECK(fd != FLB_INVALID_SOCKET);
    return fd;
}

static void send_bytes(flb_sockfd_t fd, const char *data, size_t size)
{
    ssize_t written;
    size_t offset = 0;

    while (offset < size) {
        written = send(fd, data + offset, size - offset, 0);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        TEST_ASSERT(written > 0);
        offset += written;
    }
}

static void respond(flb_sockfd_t fd, int status, const char *body, int keepalive)
{
    char header[256];
    int length;

    length = snprintf(header, sizeof(header),
                      "HTTP/1.1 %d Test\r\nContent-Length: %zu\r\n"
                      "Connection: %s\r\n\r\n",
                      status, strlen(body), keepalive ? "keep-alive" : "close");
    TEST_ASSERT(length > 0 && length < sizeof(header));
    send_bytes(fd, header, length);
    send_bytes(fd, body, strlen(body));
    if (!keepalive) {
        flb_socket_close(fd);
    }
}

/* Reading headers byte by byte leaves the next keepalive request in the socket. */
static void read_request(flb_sockfd_t fd, struct request *request)
{
    char header[8192];
    char *line;
    char *length;
    char *end;
    size_t used = 0;
    size_t content_length;
    ssize_t received;
    int64_t deadline = milliseconds() + 5000;
    int remaining;

    header[0] = '\0';
    while (strstr(header, "\r\n\r\n") == NULL) {
        remaining = deadline - milliseconds();
        TEST_ASSERT(remaining > 0);
        TEST_ASSERT(used + 1 < sizeof(header));
        TEST_ASSERT(readable(fd, remaining) == 1);
        received = recv(fd, header + used, 1, 0);
        TEST_ASSERT(received == 1);
        header[++used] = '\0';
    }
    TEST_ASSERT(sscanf(header, "PUT %2047s HTTP/1.1", request->target) == 1);
    length = NULL;
    line = strstr(header, "\r\n") + 2;
    while (*line != '\r') {
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            length = line + 15;
        }
        line = strstr(line, "\r\n") + 2;
    }
    TEST_ASSERT(length != NULL);
    content_length = strtoul(length, &end, 10);
    TEST_ASSERT(end != length && *end == '\r');
    TEST_ASSERT(content_length < sizeof(request->body));
    used = 0;
    while (used < content_length) {
        remaining = deadline - milliseconds();
        TEST_ASSERT(remaining > 0);
        TEST_ASSERT(readable(fd, remaining) == 1);
        received = recv(fd, request->body + used, content_length - used, 0);
        TEST_ASSERT(received > 0);
        used += received;
    }
    request->size = content_length;
    request->body[used] = '\0';
}

static void query_value(const char *target, const char *name,
                        char *value, size_t capacity)
{
    const char *query = strchr(target, '?');
    const char *end;
    size_t length;
    size_t used = 0;
    unsigned int byte;

    TEST_ASSERT(query != NULL);
    query++;
    while (*query) {
        end = strchr(query, '&');
        if (!end) {
            end = query + strlen(query);
        }
        length = strlen(name);
        if ((size_t) (end - query) > length &&
            strncmp(query, name, length) == 0 && query[length] == '=') {
            query += length + 1;
            while (query < end) {
                TEST_ASSERT(used + 1 < capacity);
                if (*query == '%') {
                    TEST_ASSERT(end - query >= 3);
                    TEST_ASSERT(sscanf(query + 1, "%2x", &byte) == 1);
                    value[used++] = byte;
                    query += 3;
                }
                else {
                    value[used++] = *query++;
                }
            }
            value[used] = '\0';
            return;
        }
        query = *end ? end + 1 : end;
    }
    TEST_ASSERT_(0, "missing %s in %s", name, target);
}

static void check_block(const struct request *block)
{
    char operation[32];

    query_value(block->target, "comp", operation, sizeof(operation));
    TEST_CHECK(strcmp(operation, "block") == 0);
    TEST_CHECK(block->size > 0);
}

static void check_commit(const struct request *block,
                         const struct request *commit)
{
    char operation[32];
    char block_id[512];
    char expected[640];
    const char *block_query = strchr(block->target, '?');
    const char *commit_query = strchr(commit->target, '?');
    const char *reference;
    size_t object_length;

    query_value(commit->target, "comp", operation, sizeof(operation));
    TEST_CHECK(strcmp(operation, "blocklist") == 0);
    query_value(block->target, "blockid", block_id, sizeof(block_id));
    snprintf(expected, sizeof(expected), "<Latest>%s</Latest>", block_id);
    reference = strstr(commit->body, "<Latest>");
    TEST_ASSERT(reference != NULL);
    TEST_ASSERT(strncmp(reference, expected, strlen(expected)) == 0);
    TEST_CHECK(strstr(reference + strlen(expected), "<Latest>") == NULL);
    TEST_CHECK(strstr(commit->body, "<Uncommitted>") == NULL);
    TEST_CHECK(strstr(commit->body, "<Committed>") == NULL);
    TEST_ASSERT(block_query != NULL && commit_query != NULL);
    object_length = block_query - block->target;
    TEST_CHECK(object_length == (size_t) (commit_query - commit->target));
    TEST_CHECK(strncmp(block->target, commit->target, object_length) == 0);
}

static void remove_directory(const char *path)
{
    DIR *directory;
    struct dirent *entry;
    struct stat info;
    char child[PATH_MAX];

    directory = opendir(path);
    TEST_ASSERT(directory != NULL);
    while ((entry = readdir(directory))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        TEST_ASSERT(snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) <
                    sizeof(child));
        TEST_ASSERT(lstat(child, &info) == 0);
        if (S_ISDIR(info.st_mode)) {
            remove_directory(child);
        }
        else {
            TEST_CHECK(unlink(child) == 0);
        }
    }
    closedir(directory);
    TEST_CHECK(rmdir(path) == 0);
}

static struct blob_test create_test(int buffered, int keepalive)
{
    struct blob_test test = {0};
    struct sockaddr_in address;
    socklen_t address_size = sizeof(address);
    char endpoint[128];

    strcpy(test.directory, "/tmp/flb-azb-XXXXXX");
    TEST_ASSERT(mkdtemp(test.directory) != NULL);
    snprintf(test.buffer_dir, sizeof(test.buffer_dir), "%s/buffer", test.directory);
    test.listener = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(test.listener != FLB_INVALID_SOCKET);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    TEST_ASSERT(bind(test.listener, (struct sockaddr *) &address, sizeof(address)) == 0);
    TEST_ASSERT(listen(test.listener, 8) == 0);
    TEST_ASSERT(getsockname(test.listener, (struct sockaddr *) &address,
                           &address_size) == 0);
    snprintf(endpoint, sizeof(endpoint), "http://127.0.0.1:%u", ntohs(address.sin_port));

    test.ctx = flb_create();
    TEST_ASSERT(test.ctx != NULL);
    TEST_ASSERT(flb_service_set(test.ctx, "flush", "0.05", "grace", "1",
                                "log_level", "error", "scheduler.base", "1",
                                "scheduler.cap", "1", NULL) == 0);
    test.input = flb_input(test.ctx, "lib", NULL);
    TEST_ASSERT(test.input >= 0);
    TEST_ASSERT(flb_input_set(test.ctx, test.input, "tag", "commit", NULL) == 0);
    test.output = flb_output(test.ctx, "azure_blob", NULL);
    TEST_ASSERT(test.output >= 0);
    TEST_ASSERT(flb_output_set(test.ctx, test.output, "match", "commit", "account_name",
                               "fixture", "container_name", "logs", "endpoint", endpoint,
                               "auth_type", "sas", "sas_token", "sig=fixture",
                               "blob_type", "blockblob", "auto_create_container", "false",
                               "buffering_enabled", buffered ? "true" : "false",
                               "workers", "1", "retry_limit", "3", "net.keepalive",
                               keepalive ? "on" : "off", "net.connect_timeout", "2",
                               "net.io_timeout", "2", NULL) == 0);
    if (keepalive) {
        TEST_ASSERT(flb_output_set(test.ctx, test.output,
                                   "net.max_worker_connections", "1", NULL) == 0);
    }
    if (buffered) {
        TEST_ASSERT(flb_output_set(test.ctx, test.output,
                                   "buffer_dir", test.buffer_dir,
                                   "azure_blob_buffer_key", "commit",
                                   "upload_timeout", "6s",
                                   "buffer_file_delete_early", "off",
                                   "delete_on_max_upload_error", "off",
                                   "scheduler_max_retries", "2", NULL) == 0);
    }
    return test;
}

static void stop_test(struct blob_test *test)
{
    flb_socket_close(test->listener);
    flb_stop(test->ctx);
    flb_destroy(test->ctx);
}

static void push_record(struct blob_test *test)
{
    const char record[] = "[1,{\"record_id\":\"azure-commit\"}]";

    TEST_ASSERT(flb_lib_push(test->ctx, test->input, record, sizeof(record) - 1) ==
                sizeof(record) - 1);
}

static int find_buffer(const char *path, char *file, size_t capacity)
{
    DIR *directory;
    struct dirent *entry;
    struct stat info;
    char child[PATH_MAX];
    int count = 0;
    int ret;

    directory = opendir(path);
    TEST_ASSERT(directory != NULL);
    while ((entry = readdir(directory))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        TEST_ASSERT(snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) <
                    sizeof(child));
        ret = lstat(child, &info);
        /* The uploader can remove committed buffers during this scan. */
        if (ret == -1 && errno == ENOENT) {
            continue;
        }
        TEST_ASSERT(ret == 0);
        if (S_ISDIR(info.st_mode)) {
            count += find_buffer(child, file, capacity);
        }
        else {
            TEST_ASSERT(S_ISREG(info.st_mode));
            TEST_ASSERT(strlen(child) < capacity);
            strcpy(file, child);
            count++;
        }
    }
    closedir(directory);
    return count;
}

static int check_buffer(struct blob_test *test, struct buffer_snapshot *snapshot)
{
    char path[PATH_MAX];
    char *data;
    size_t size;
    int matches;

    if (!TEST_CHECK(find_buffer(test->buffer_dir, path, sizeof(path)) == 1)) {
        return 0;
    }
    TEST_ASSERT(flb_utils_read_file(path, &data, &size) == 0);
    if (snapshot->data == NULL) {
        strcpy(snapshot->path, path);
        snapshot->data = data;
        snapshot->size = size;
        return 1;
    }
    matches = strcmp(path, snapshot->path) == 0 && size == snapshot->size &&
              memcmp(data, snapshot->data, size) == 0;
    TEST_CHECK_(matches, "buffer file and bytes remain unchanged before HTTP 201");
    flb_free(data);
    return matches;
}

static flb_sockfd_t stage_block(struct blob_test *test, struct request *block,
                                struct request *commit)
{
    flb_sockfd_t fd = accept_request(test);

    if (fd == FLB_INVALID_SOCKET) {
        return fd;
    }
    read_request(fd, block);
    check_block(block);
    respond(fd, 201, "", 0);
    fd = accept_request(test);
    if (fd != FLB_INVALID_SOCKET) {
        read_request(fd, commit);
        check_commit(block, commit);
    }
    return fd;
}

static void buffered_commit(int rejection, const char *body)
{
    struct blob_test test = create_test(1, 0);
    struct buffer_snapshot snapshot = {0};
    struct request first;
    struct request retry;
    struct request commit;
    char path[PATH_MAX];
    flb_sockfd_t fd;
    int count;
    int64_t deadline;

    TEST_ASSERT(flb_start(test.ctx) == 0);
    push_record(&test);
    fd = stage_block(&test, &first, &commit);
    if (fd == FLB_INVALID_SOCKET) {
        goto cleanup;
    }
    TEST_CHECK(strstr(first.body, "\"record_id\":\"azure-commit\"") != NULL);
    if (!check_buffer(&test, &snapshot)) {
        respond(fd, 201, "", 0);
        goto cleanup;
    }
    if (rejection != 201) {
        respond(fd, rejection, body, 0);
        fd = stage_block(&test, &retry, &commit);
        if (fd == FLB_INVALID_SOCKET) {
            check_buffer(&test, &snapshot);
            goto cleanup;
        }
        TEST_CHECK(first.size == retry.size);
        TEST_CHECK(first.size == retry.size &&
                   memcmp(first.body, retry.body, first.size) == 0);
        if (!check_buffer(&test, &snapshot)) {
            respond(fd, 201, "", 0);
            goto cleanup;
        }
    }
    respond(fd, 201, "", 0);
    deadline = milliseconds() + 3000;
    do {
        count = find_buffer(test.buffer_dir, path, sizeof(path));
        if (count == 0) {
            break;
        }
        flb_time_msleep(10);
    } while (milliseconds() < deadline);
    TEST_CHECK_(count == 0, "buffer removed after the accepted commit");
    TEST_CHECK(readable(test.listener, 100) == 0);

cleanup:
    stop_test(&test);
    flb_free(snapshot.data);
    remove_directory(test.directory);
}

static void test_commit_201(void)
{
    buffered_commit(201, "");
}

static void test_commit_403(void)
{
    buffered_commit(403, "<Error><Code>AuthorizationFailure</Code></Error>");
}

static void test_commit_500_empty(void)
{
    buffered_commit(500, "");
}

static void test_commit_200(void)
{
    buffered_commit(200, "");
}

static void test_malformed_commit(void)
{
    const char malformed[] =
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n-1\r\n";
    struct blob_test test = create_test(0, 1);
    struct request first;
    struct request retry;
    struct request commit;
    flb_sockfd_t failed = FLB_INVALID_SOCKET;
    flb_sockfd_t replacement = FLB_INVALID_SOCKET;
    char byte;

    TEST_ASSERT(flb_start(test.ctx) == 0);
    push_record(&test);
    failed = accept_request(&test);
    if (failed == FLB_INVALID_SOCKET) {
        goto cleanup;
    }
    read_request(failed, &first);
    check_block(&first);
    respond(failed, 201, "", 1);
    read_request(failed, &commit);
    check_commit(&first, &commit);
    send_bytes(failed, malformed, sizeof(malformed) - 1);

    /* Peer EOF proves this connection was discarded, even if an fd is reused. */
    if (!TEST_CHECK(readable(failed, 5000) == 1) ||
        !TEST_CHECK(recv(failed, &byte, 1, 0) == 0)) {
        goto cleanup;
    }
    replacement = accept_request(&test);
    if (replacement == FLB_INVALID_SOCKET) {
        goto cleanup;
    }
    read_request(replacement, &retry);
    check_block(&retry);
    TEST_CHECK(first.size == retry.size &&
               memcmp(first.body, retry.body, first.size) == 0);
    respond(replacement, 201, "", 1);
    read_request(replacement, &commit);
    check_commit(&retry, &commit);
    respond(replacement, 201, "", 1);
    TEST_CHECK(readable(replacement, 250) == 0);

cleanup:
    if (failed != FLB_INVALID_SOCKET) {
        flb_socket_close(failed);
    }
    if (replacement != FLB_INVALID_SOCKET) {
        flb_socket_close(replacement);
    }
    stop_test(&test);
    remove_directory(test.directory);
}
TEST_LIST = {
    {"commit_201", test_commit_201},
    {"commit_403", test_commit_403},
    {"commit_500_empty", test_commit_500_empty},
    {"commit_200", test_commit_200},
    {"malformed_commit", test_malformed_commit},
    {NULL, NULL}
};
