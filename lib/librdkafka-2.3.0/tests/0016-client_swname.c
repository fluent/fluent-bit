/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020-2022, Magnus Edenhill
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

/**
 * @name Verify KIP-511, client.software.name and client.software.version
 *
 */
static char jmx_cmd[512];

/**
 * @brief Verify that the expected software name and version is reported
 *        in JMX metrics.
 */
static void jmx_verify(const char *exp_swname, const char *exp_swversion) {
#if _WIN32
        return;
#else
        int r;
        char cmd[512 + 256];

        if (!*jmx_cmd)
                return;

        rd_snprintf(cmd, sizeof(cmd),
                    "%s | "
                    "grep -F 'clientSoftwareName=%s,clientSoftwareVersion=%s'",
                    jmx_cmd, exp_swname, exp_swversion ? exp_swversion : "");
        r = system(cmd);
        if (WEXITSTATUS(r) == 1)
                TEST_FAIL(
                    "Expected software name and version not found in "
                    "JMX metrics with command \"%s\"",
                    cmd);
        else if (r == -1 || WIFSIGNALED(r) || WEXITSTATUS(r))
                TEST_FAIL(
                    "Failed to execute JmxTool command \"%s\": "
                    "exit code %d",
                    cmd, r);

        TEST_SAY(
            "Expected software name \"%s\" and version \"%s\" "
            "found in JMX metrics\n",
            exp_swname, exp_swversion);
#endif /* !_WIN32 */
}


static void do_test_swname(const char *broker,
                           const char *swname,
                           const char *swversion,
                           const char *exp_swname,
                           const char *exp_swversion) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        const rd_kafka_metadata_t *md;
        rd_kafka_resp_err_t err;

        TEST_SAY(_C_MAG
                 "[ Test client.software.name=%s, "
                 "client.software.version=%s ]\n",
                 swname ? swname : "NULL", swversion ? swversion : "NULL");

        test_conf_init(&conf, NULL, 30 /* jmxtool is severely slow */);
        if (broker)
                test_conf_set(conf, "bootstrap.servers", broker);
        if (swname)
                test_conf_set(conf, "client.software.name", swname);
        if (swversion)
                test_conf_set(conf, "client.software.version", swversion);
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* Trigger a metadata request so we know we're connected. */
        err = rd_kafka_metadata(rk, 0, NULL, &md, tmout_multip(5000));
        TEST_ASSERT(!err, "metadata() failed: %s", rd_kafka_err2str(err));
        rd_kafka_metadata_destroy(md);

        /* Verify JMX metrics, if possible */
        jmx_verify(exp_swname, exp_swversion);

        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN
                 "[ Test client.software.name=%s, "
                 "client.software.version=%s: PASS ]\n",
                 swname ? swname : "NULL", swversion ? swversion : "NULL");
}

int main_0016_client_swname(int argc, char **argv) {
        const char *broker;
        const char *kafka_path;
        const char *jmx_port;
        const char *reason = NULL;

        /* If available, use the Kafka JmxTool to query software name
         * in broker JMX metrics */
        if (!(broker = test_getenv("BROKER_ADDRESS_2", NULL)))
                reason =
                    "Env var BROKER_ADDRESS_2 missing "
                    "(not running in trivup or trivup too old?)";
        else if (test_broker_version < TEST_BRKVER(2, 5, 0, 0))
                reason =
                    "Client software JMX metrics not exposed prior to "
                    "Apache Kafka 2.5.0.0";
        else if (!(kafka_path = test_getenv("KAFKA_PATH", NULL)))
                reason = "Env var KAFKA_PATH missing (not running in trivup?)";
        else if (!(jmx_port = test_getenv("BROKER_JMX_PORT_2", NULL)))
                reason =
                    "Env var BROKER_JMX_PORT_2 missing "
                    "(not running in trivup or trivup too old?)";
        else
                rd_snprintf(jmx_cmd, sizeof(jmx_cmd),
                            "%s/bin/kafka-run-class.sh kafka.tools.JmxTool "
                            "--jmx-url "
                            "service:jmx:rmi:///jndi/rmi://:%s/jmxrmi "
                            "--attributes connections --one-time true | "
                            "grep clientSoftware",
                            kafka_path, jmx_port);

        if (reason)
                TEST_WARN("Will not be able to verify JMX metrics: %s\n",
                          reason);

        /* Default values, the version is not checked since the
         * built librdkafka may not use the same string, and additionally we
         * don't want to perform the string mangling here to make the string
         * protocol safe. */
        do_test_swname(broker, NULL, NULL, "librdkafka", NULL);
        /* Properly formatted */
        do_test_swname(broker, "my-little-version", "1.2.3.4",
                       "my-little-version", "1.2.3.4");
        /* Containing invalid characters, verify that safing the strings works
         */
        do_test_swname(broker, "?1?this needs! ESCAPING?", "--v99.11 ~b~",
                       "1-this-needs--ESCAPING", "v99.11--b");

        return 0;
}
