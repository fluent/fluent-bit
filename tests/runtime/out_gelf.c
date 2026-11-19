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

#include <fluent-bit.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include "../../plugins/out_gelf/gelf.h"
#include "flb_tests_runtime.h"

static void test_udp_recovery(int compress, int chunked, int workers, int oversized)
{
    flb_ctx_t *ctx;
    struct flb_output_instance *ins;
    struct flb_out_gelf_config *gelf;
    struct sockaddr_in address = {0};
    struct sockaddr disconnected = {0};
    struct timeval timeout = {10, 0};
    socklen_t address_size = sizeof(address);
    int receiver;
    int input;
    int output;
    int ret;
    int sequence;
    int count = 1;
    int index;
    unsigned int random_state = 12345;
    char *batch = NULL;
    char large_message[20001];
    ssize_t received;
    size_t length = 0;
    size_t decoded_size;
    void *decoded = NULL;
    char port[16];
    unsigned char packet[2048];
    unsigned char message_id[8];
    char payload[4096];
    char *record = "[1448403340,{\"host\":\"test-host\","
                   "\"short_message\":\"UDP socket recovery\"}]";

    receiver = socket(AF_INET, SOCK_DGRAM, 0);
    if (!TEST_CHECK(receiver >= 0)) {
        return;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ret = bind(receiver, (struct sockaddr *) &address, sizeof(address));
    if (!TEST_CHECK(ret == 0)) {
        goto close_receiver;
    }
    ret = getsockname(receiver, (struct sockaddr *) &address, &address_size);
    if (!TEST_CHECK(ret == 0)) {
        goto close_receiver;
    }
    ret = setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (!TEST_CHECK(ret == 0)) {
        goto close_receiver;
    }
    snprintf(port, sizeof(port), "%u", ntohs(address.sin_port));

    ctx = flb_create();
    if (!TEST_CHECK(ctx != NULL)) {
        goto close_receiver;
    }
    TEST_CHECK(flb_service_set(ctx, "flush", "0.1", "grace", "1",
                              "scheduler.base", "1", "scheduler.cap", "1", NULL) == 0);
    input = flb_input(ctx, "lib", NULL);
    TEST_CHECK(input >= 0);
    TEST_CHECK(flb_input_set(ctx, input, "tag", "test", NULL) == 0);
    output = flb_output(ctx, "gelf", NULL);
    TEST_CHECK(output >= 0);
    TEST_CHECK(flb_output_set(ctx, output, "match", "*", "host", "127.0.0.1",
                             "port", port, "mode", "udp", "retry_limit", "false",
                             "compress", compress ? "true" : "false",
                             "packet_size", chunked ? "32" : "1420",
                             "workers", workers ? "2" : "0", NULL) == 0);
    if (!TEST_CHECK(flb_start(ctx) == 0)) {
        goto destroy;
    }

    /* No records are queued yet, so the engine cannot be using this socket. */
    ins = flb_output_get_instance(ctx->config, output);
    if (!TEST_CHECK(ins != NULL && ins->context != NULL)) {
        goto stop;
    }
    gelf = ins->context;
    if (oversized) {
        /* Incompressible enough to exceed 128 packets of 32 bytes. */
        for (index = 0; index < sizeof(large_message) - 1; index++) {
            random_state = random_state * 1664525u + 1013904223u;
            large_message[index] = 'a' + ((random_state >> 16) % 26);
        }
        large_message[index] = '\0';
        batch = flb_malloc(sizeof(large_message) + strlen(record) + 128);
        if (!TEST_CHECK(batch != NULL)) {
            goto stop;
        }
        sprintf(batch, "[1448403340,{\"host\":\"test-host\",\"short_message\":\"%s\"}]%s",
                large_message, record);
        ret = flb_lib_push(ctx, input, batch, strlen(batch));
        TEST_CHECK(ret == strlen(batch));
        flb_free(batch);
    }
    else if (workers) {
        /* A worker must not recreate the socket while the instance lock is held. */
        pthread_mutex_lock(&gelf->udp_mutex);
        flb_socket_close(gelf->fd);
        gelf->fd = FLB_INVALID_SOCKET;
        ret = flb_lib_push(ctx, input, record, strlen(record));
        TEST_CHECK(ret == strlen(record));
        flb_time_msleep(500);
        TEST_CHECK(gelf->fd == FLB_INVALID_SOCKET);
        pthread_mutex_unlock(&gelf->udp_mutex);
    }
    else {
        disconnected.sa_family = AF_UNSPEC;
        ret = connect(gelf->fd, &disconnected, sizeof(disconnected));
        if (!TEST_CHECK(ret == 0)) {
            goto stop;
        }

        /* Verify the actual kernel failure without replacing or closing the fd. */
        ret = send(gelf->fd, "probe", 5, 0);
        if (!TEST_CHECK(ret == -1 && errno == EDESTADDRREQ)) {
            goto stop;
        }
        ret = flb_lib_push(ctx, input, record, strlen(record));
        if (!TEST_CHECK(ret == strlen(record))) {
            goto stop;
        }
    }

    /* Reassemble and validate the deliverable record. */
    for (sequence = 0; sequence < count; sequence++) {
        received = recv(receiver, packet, sizeof(packet), 0);
        if (!TEST_CHECK(received > 0)) {
            TEST_MSG("Timed out waiting for GELF delivery after UDP disconnection");
            goto stop;
        }
        if (chunked) {
            if (!TEST_CHECK(received > 12 && packet[0] == 0x1e && packet[1] == 0x0f)) {
                goto stop;
            }
            if (sequence == 0) {
                count = packet[11];
                memcpy(message_id, packet + 2, sizeof(message_id));
            }
            if (!TEST_CHECK(count > 1 && count <= 128 && packet[10] == sequence &&
                            packet[11] == count &&
                            memcmp(message_id, packet + 2, sizeof(message_id)) == 0 &&
                            length + received - 12 < sizeof(payload))) {
                goto stop;
            }
            memcpy(payload + length, packet + 12, received - 12);
            length += received - 12;
        }
        else {
            memcpy(payload, packet, received);
            length = received;
        }
    }

    if (compress) {
        ret = flb_gzip_uncompress(payload, length, &decoded, &decoded_size);
        if (!TEST_CHECK(ret == 0)) {
            goto stop;
        }
        if (!TEST_CHECK(decoded_size < sizeof(payload))) {
            flb_free(decoded);
            goto stop;
        }
        memcpy(payload, decoded, decoded_size);
        length = decoded_size;
        flb_free(decoded);
    }
    payload[length] = '\0';
    TEST_CHECK(strstr(payload, "UDP socket recovery") != NULL);
    TEST_CHECK(strstr(payload, "test-host") != NULL);

stop:
    flb_stop(ctx);
destroy:
    flb_destroy(ctx);
close_receiver:
    flb_socket_close(receiver);
}

static void test_udp_uncompressed_recovery(void)
{
    test_udp_recovery(FLB_FALSE, FLB_FALSE, 0, 0);
}

static void test_udp_compressed_recovery(void)
{
    test_udp_recovery(FLB_TRUE, FLB_FALSE, 0, 0);
}

static void test_udp_chunked_recovery(void)
{
    test_udp_recovery(FLB_TRUE, FLB_TRUE, 0, 0);
}

static void test_udp_workers_serialized(void)
{
    test_udp_recovery(FLB_TRUE, FLB_TRUE, 2, 0);
}

static void test_udp_oversized_record(void)
{
    test_udp_recovery(FLB_TRUE, FLB_TRUE, 2, 1);
}

TEST_LIST = {
    {"udp_uncompressed_recovery", test_udp_uncompressed_recovery},
    {"udp_compressed_recovery", test_udp_compressed_recovery},
    {"udp_chunked_recovery", test_udp_chunked_recovery},
    {"udp_workers_serialized", test_udp_workers_serialized},
    {"udp_oversized_record", test_udp_oversized_record},
    {NULL, NULL}
};
