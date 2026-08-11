/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2022, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "test.h"

#include "rdkafka.h"

#ifndef _WIN32
#include <netdb.h>
#else
#define WIN32_MEAN_AND_LEAN
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#endif

/**
 * @name Test a custom address resolution callback.
 *
 * The test sets bogus bootstrap.servers, uses the resolution callback to
 * resolve to a bogus address, and then verifies that the address is passed
 * to the connect callback. If the resolution callback is not invoked, or if the
 * connect callback is not invoked with the output of the resolution callback,
 * the test will fail.
 */

/**
 * Stage of the test:
 *   0: expecting resolve_cb to be invoked with TESTING_RESOLVE_CB:1234
 *   1: expecting resolve_cb to be invoked with NULL, NULL
 *   2: expecting connect_cb to invoked with socket address 127.1.2.3:57616
 *   3: done
 */
static rd_atomic32_t stage;

/** Exposes current test struct (in TLS) to callbacks. */
static struct test *this_test;

static int resolve_cb(const char *node,
                      const char *service,
                      const struct addrinfo *hints,
                      struct addrinfo **res,
                      void *opaque) {

        int32_t cnt;

        test_curr = this_test;

        cnt = rd_atomic32_get(&stage);

        TEST_SAY("resolve_cb invoked: node=%s service=%s stage=%d\n", node,
                 service, cnt);

        if (cnt == 0) {
                /* Stage 0: return a bogus address. */

                struct sockaddr_in *addr;

                TEST_ASSERT(node != NULL);
                TEST_ASSERT(strcmp(node, "TESTING_RESOLVE_CB") == 0,
                            "unexpected node: %s", node);
                TEST_ASSERT(service != NULL);
                TEST_ASSERT(strcmp(service, "1234") == 0,
                            "unexpected service: %s", service);

                addr                  = calloc(1, sizeof(struct sockaddr_in));
                addr->sin_family      = AF_INET;
                addr->sin_port        = htons(4321);
                addr->sin_addr.s_addr = htonl(0x7f010203) /* 127.1.2.3 */;

                *res                = calloc(1, sizeof(struct addrinfo));
                (*res)->ai_family   = AF_INET;
                (*res)->ai_socktype = SOCK_STREAM;
                (*res)->ai_protocol = IPPROTO_TCP;
                (*res)->ai_addrlen  = sizeof(struct sockaddr_in);
                (*res)->ai_addr     = (struct sockaddr *)addr;
        } else if (cnt == 1) {
                /* Stage 1: free the bogus address returned in stage 0. */

                TEST_ASSERT(node == NULL);
                TEST_ASSERT(service == NULL);
                TEST_ASSERT(hints == NULL);
                free((*res)->ai_addr);
                free(*res);
        } else {
                /* Stage 2+: irrelevant, simply fail to resolve. */

                return -1;
        }

        rd_atomic32_add(&stage, 1);
        return 0;
}

static int connect_cb(int s,
                      const struct sockaddr *addr,
                      int addrlen,
                      const char *id,
                      void *opaque) {
        /* Stage 3: assert address is expected bogus. */

        int32_t cnt;
        struct sockaddr_in *addr_in;

        test_curr = this_test;

        cnt = rd_atomic32_get(&stage);

        TEST_SAY("connect_cb invoked: stage=%d\n", cnt);

        TEST_ASSERT(cnt == 2, "connect_cb invoked in unexpected stage: %d",
                    cnt);

        TEST_ASSERT(addr->sa_family == AF_INET,
                    "address has unexpected type: %d", addr->sa_family);

        addr_in = (struct sockaddr_in *)(void *)addr;

        TEST_ASSERT(addr_in->sin_port == htons(4321),
                    "address has unexpected port: %d",
                    ntohs(addr_in->sin_port));
        TEST_ASSERT(addr_in->sin_addr.s_addr == htonl(0x7f010203),
                    "address has unexpected host: 0x%x",
                    ntohl(addr_in->sin_addr.s_addr));

        rd_atomic32_add(&stage, 1);

        /* The test has succeeded. Just report the connection as faile
         * for simplicity. */
        return -1;
}

int main_0136_resolve_cb(int argc, char **argv) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;

        this_test = test_curr;

        rd_atomic32_init(&stage, 0);

        test_conf_init(&conf, NULL, 0);
        rd_kafka_conf_set_resolve_cb(conf, resolve_cb);
        rd_kafka_conf_set_connect_cb(conf, connect_cb);

        TEST_SAY("Setting bogus broker list\n");
        test_conf_set(conf, "bootstrap.servers", "TESTING_RESOLVE_CB:1234");

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        while (rd_atomic32_get(&stage) != 3)
                rd_sleep(1);

        rd_kafka_destroy(rk);

        return 0;
}
