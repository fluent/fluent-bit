/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
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
#include <unistd.h>
#include <sys/wait.h>
#endif

/**
 * @brief Forking a threaded process will not transfer threads (such as
 *        librdkafka's background threads) to the child process.
 *        There is no way such a forked client instance will work
 *        in the child process, but it should not crash on destruction: #1674
 */

int main_0079_fork (int argc, char **argv) {

#if __SANITIZE_ADDRESS__
        TEST_SKIP("AddressSanitizer is enabled: this test leaks memory (due to fork())\n");
        return 0;
#endif
#ifdef _WIN32
        TEST_SKIP("No fork() support on Windows");
        return 0;
#else
        pid_t pid;
        rd_kafka_t *rk;
        int status;

        rk = test_create_producer();

        rd_kafka_producev(rk,
                          RD_KAFKA_V_TOPIC("atopic"),
                          RD_KAFKA_V_VALUE("hi", 2),
                          RD_KAFKA_V_END);

        pid = fork();
        TEST_ASSERT(pid != 1, "fork() failed: %s", strerror(errno));

        if (pid == 0) {
                /* Child process */

                /* This call will enqueue the message on a queue
                 * which is not served by any thread, but it should not crash */
                rd_kafka_producev(rk,
                                  RD_KAFKA_V_TOPIC("atopic"),
                                  RD_KAFKA_V_VALUE("hello", 5),
                                  RD_KAFKA_V_END);

                /* Don't crash on us */
                rd_kafka_destroy(rk);

                exit(0);
        }

        /* Parent process, wait for child to exit cleanly. */
        if (waitpid(pid, &status, 0) == -1)
                TEST_FAIL("waitpid(%d) failed: %s", (int)pid, strerror(errno));

        if (!WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
                TEST_FAIL("child exited with status %d", WEXITSTATUS(status));

        rd_kafka_destroy(rk);

        return 0;
#endif
}
