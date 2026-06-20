/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2016-2022, Magnus Edenhill
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

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


/**
 * Issue #606: test that api.version.request=true works or reverts to
 *             fallback within reasonable amount of time.
 * Brokers 0.9.0 and 0.9.0.1 had a regression (wouldnt close the connection)
 * which caused these requests to time out (slowly) in librdkafka.
 */


int main_0035_api_version(int argc, char **argv) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        const struct rd_kafka_metadata *metadata;
        rd_kafka_resp_err_t err;
        test_timing_t t_meta;

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "socket.timeout.ms", "12000");
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("Querying for metadata\n");
        TIMING_START(&t_meta, "metadata()");
        err = rd_kafka_metadata(rk, 0, NULL, &metadata, tmout_multip(5 * 1000));
        TIMING_STOP(&t_meta);
        if (err)
                TEST_FAIL("metadata() failed: %s", rd_kafka_err2str(err));

        if (TIMING_DURATION(&t_meta) / 1000 > 15 * 1000)
                TEST_FAIL("metadata() took too long: %.3fms",
                          (float)TIMING_DURATION(&t_meta) / 1000.0f);

        rd_kafka_metadata_destroy(metadata);

        TEST_SAY("Metadata succeeded\n");

        rd_kafka_destroy(rk);

        return 0;
}
