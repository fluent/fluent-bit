/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2017-2022, Magnus Edenhill
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


/**
 * @brief Plugin test library
 */

#include <stdio.h>
#include <assert.h>

/* typical include path outside tests is <librdkafka/rdkafka.h> */
#include "rdkafka.h"



static void *my_opaque = (void *)0x5678;
/*
 * Common methods
 */
rd_kafka_resp_err_t conf_init(rd_kafka_conf_t *conf,
                              void **plug_opaquep,
                              char *errstr,
                              size_t errstr_size) {
        printf("plugin conf_init called!\n");
        *plug_opaquep = my_opaque;
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

void conf_destroy(const rd_kafka_conf_t *conf, void *plug_opaque) {
        assert(plug_opaque == plug_opaque);
        printf("plugin destroy called\n");
}
