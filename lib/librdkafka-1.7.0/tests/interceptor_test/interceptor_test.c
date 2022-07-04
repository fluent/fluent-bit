/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2017 Magnus Edenhill
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
 * @brief Interceptor plugin test library
 *
 * Interceptors can be implemented in the app itself and use
 * the direct API to set the interceptors methods, or be implemented
 * as an external plugin library that uses the direct APIs.
 *
 * This file implements the latter, an interceptor plugin library.
 */

#define _CRT_SECURE_NO_WARNINGS /* Silence MSVC nonsense */

#include "../test.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

/* typical include path outside tests is <librdkafka/rdkafka.h> */
#include "rdkafka.h"

#include "interceptor_test.h"

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

/**
 * @brief Interceptor instance.
 *
 * An interceptor instance is created for each intercepted configuration
 * object (triggered through conf_init() which is the plugin loader,
 * or by conf_dup() which is a copying of a conf previously seen by conf_init())
 */
struct ici {
        rd_kafka_conf_t *conf;  /**< Interceptor config */
        char *config1;          /**< Interceptor-specific config */
        char *config2;

        int on_new_cnt;
        int on_conf_destroy_cnt;
};

static char *my_interceptor_plug_opaque = "my_interceptor_plug_opaque";



/* Producer methods */
rd_kafka_resp_err_t on_send (rd_kafka_t *rk,
                             rd_kafka_message_t *rkmessage,
                             void *ic_opaque) {
        struct ici *ici = ic_opaque;
        printf("on_send: %p\n", ici);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


rd_kafka_resp_err_t on_acknowledgement (rd_kafka_t *rk,
                                        rd_kafka_message_t *rkmessage,
                                        void *ic_opaque) {
        struct ici *ici = ic_opaque;
        printf("on_acknowledgement: %p: err %d, partition %"PRId32"\n",
               ici, rkmessage->err, rkmessage->partition);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/* Consumer methods */
rd_kafka_resp_err_t on_consume (rd_kafka_t *rk,
                                rd_kafka_message_t *rkmessage,
                                void *ic_opaque) {
        struct ici *ici = ic_opaque;
        printf("on_consume: %p: partition %"PRId32" @ %"PRId64"\n",
               ici, rkmessage->partition, rkmessage->offset);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

rd_kafka_resp_err_t on_commit (rd_kafka_t *rk,
                               const rd_kafka_topic_partition_list_t *offsets,
                               rd_kafka_resp_err_t err, void *ic_opaque) {
        struct ici *ici = ic_opaque;
        printf("on_commit: %p: err %d\n", ici, err);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static void ici_destroy (struct ici *ici) {
        if (ici->conf)
                rd_kafka_conf_destroy(ici->conf);
        if (ici->config1)
                free(ici->config1);
        if (ici->config2)
                free(ici->config2);
        free(ici);
}

rd_kafka_resp_err_t on_destroy (rd_kafka_t *rk, void *ic_opaque) {
        struct ici *ici = ic_opaque;
        printf("on_destroy: %p\n", ici);
        /* the ici is freed from on_conf_destroy() */
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Called from rd_kafka_new(). We use it to set up interceptors.
 */
static rd_kafka_resp_err_t on_new (rd_kafka_t *rk, const rd_kafka_conf_t *conf,
                                   void *ic_opaque,
                                   char *errstr, size_t errstr_size) {
        struct ici *ici = ic_opaque;

        ictest.on_new.cnt++;
        ici->on_new_cnt++;

        TEST_SAY("on_new(rk %p, conf %p, ici->conf %p): %p: #%d\n",
                 rk, conf, ici->conf, ici, ictest.on_new.cnt);

        ICTEST_CNT_CHECK(on_new);
        TEST_ASSERT(ici->on_new_cnt == 1);

        TEST_ASSERT(!ictest.session_timeout_ms);
        TEST_ASSERT(!ictest.socket_timeout_ms);
        /* Extract some well known config properties from the interceptor's
         * configuration. */
        ictest.session_timeout_ms = rd_strdup(test_conf_get(ici->conf, "session.timeout.ms"));
        ictest.socket_timeout_ms  = rd_strdup(test_conf_get(ici->conf, "socket.timeout.ms"));
        ictest.config1 = rd_strdup(ici->config1);
        ictest.config2 = rd_strdup(ici->config2);

        rd_kafka_interceptor_add_on_send(rk, __FILE__, on_send, ici);
        rd_kafka_interceptor_add_on_acknowledgement(rk, __FILE__,
                                                    on_acknowledgement, ici);
        rd_kafka_interceptor_add_on_consume(rk, __FILE__, on_consume, ici);
        rd_kafka_interceptor_add_on_commit(rk, __FILE__, on_commit, ici);
        rd_kafka_interceptor_add_on_destroy(rk, __FILE__, on_destroy, ici);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Configuration set handler
 */
static rd_kafka_conf_res_t on_conf_set (rd_kafka_conf_t *conf,
                                        const char *name, const char *val,
                                        char *errstr, size_t errstr_size,
                                        void *ic_opaque) {
        struct ici *ici = ic_opaque;
        int level = 3;

        if (!strcmp(name, "session.timeout.ms") ||
            !strcmp(name, "socket.timeout.ms") ||
            !strncmp(name, "interceptor_test", strlen("interceptor_test")))
                level = 2;

        TEST_SAYL(level, "on_conf_set(conf %p, \"%s\", \"%s\"): %p\n",
                  conf, name, val, ici);

        if (!strcmp(name, "interceptor_test.good"))
                return RD_KAFKA_CONF_OK;
        else if (!strcmp(name, "interceptor_test.bad")) {
                strncpy(errstr, "on_conf_set failed deliberately",
                        errstr_size-1);
                errstr[errstr_size-1] = '\0';
                return RD_KAFKA_CONF_INVALID;
        } else if (!strcmp(name, "interceptor_test.config1")) {
                if (ici->config1) {
                        free(ici->config1);
                        ici->config1 = NULL;
                }
                if (val)
                        ici->config1 = rd_strdup(val);
                TEST_SAY("on_conf_set(conf %p, %s, %s): %p\n",
                         conf, name, val, ici);
                return RD_KAFKA_CONF_OK;
        } else if (!strcmp(name, "interceptor_test.config2")) {
                if (ici->config2) {
                        free(ici->config2);
                        ici->config2 = NULL;
                }
                if (val)
                        ici->config2 = rd_strdup(val);
                return RD_KAFKA_CONF_OK;
        } else {
                /* Apply intercepted client's config properties on
                 * interceptor config. */
                rd_kafka_conf_set(ici->conf, name, val,
                                  errstr, errstr_size);
                /* UNKNOWN makes the conf_set() call continue with
                 * other interceptors and finally the librdkafka properties. */
                return RD_KAFKA_CONF_UNKNOWN;
        }

        return RD_KAFKA_CONF_UNKNOWN;
}

static void conf_init0 (rd_kafka_conf_t *conf);


/**
 * @brief Set up new configuration on copy.
 */
static rd_kafka_resp_err_t on_conf_dup (rd_kafka_conf_t *new_conf,
                                        const rd_kafka_conf_t *old_conf,
                                        size_t filter_cnt, const char **filter,
                                        void *ic_opaque) {
        struct ici *ici = ic_opaque;
        TEST_SAY("on_conf_dup(new_conf %p, old_conf %p, filter_cnt %"PRIusz
                 ", ici %p)\n",
                 new_conf, old_conf, filter_cnt, ici);
        conf_init0(new_conf);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static rd_kafka_resp_err_t on_conf_destroy (void *ic_opaque) {
        struct ici *ici = ic_opaque;
        ici->on_conf_destroy_cnt++;
        printf("conf_destroy called (opaque %p vs %p) ici %p\n",
               ic_opaque, my_interceptor_plug_opaque, ici);
        TEST_ASSERT(ici->on_conf_destroy_cnt == 1);
        ici_destroy(ici);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}



/**
 * @brief Configuration init is intercepted both from plugin.library.paths
 *        as well as rd_kafka_conf_dup().
 *        This internal method serves both cases.
 */
static void conf_init0 (rd_kafka_conf_t *conf) {
        struct ici *ici;
        const char *filter[] = { "plugin.library.paths",
                                 "interceptor_test." };
        size_t filter_cnt = sizeof(filter) / sizeof(*filter);

        /* Create new interceptor instance */
        ici = calloc(1, sizeof(*ici));

        ictest.conf_init.cnt++;
        ICTEST_CNT_CHECK(conf_init);

        /* Create own copy of configuration, after filtering out what
         * brought us here (plugins and our own interceptor config). */
        ici->conf = rd_kafka_conf_dup_filter(conf, filter_cnt, filter);
        TEST_SAY("conf_init0(conf %p) for ici %p with ici->conf %p\n",
                 conf, ici, ici->conf);


        /* Add interceptor methods */
        rd_kafka_conf_interceptor_add_on_new(conf, __FILE__, on_new, ici);

        rd_kafka_conf_interceptor_add_on_conf_set(conf, __FILE__, on_conf_set,
                                                  ici);
        rd_kafka_conf_interceptor_add_on_conf_dup(conf, __FILE__, on_conf_dup,
                                                  ici);
        rd_kafka_conf_interceptor_add_on_conf_destroy(conf, __FILE__,
                                                      on_conf_destroy, ici);
}

/**
 * @brief Plugin conf initializer called when plugin.library.paths is set.
 */
DLL_EXPORT
rd_kafka_resp_err_t conf_init (rd_kafka_conf_t *conf,
                               void **plug_opaquep,
                               char *errstr, size_t errstr_size) {
        *plug_opaquep = (void *)my_interceptor_plug_opaque;

        TEST_SAY("conf_init(conf %p) called (setting opaque to %p)\n",
                 conf, *plug_opaquep);

        conf_init0(conf);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


