/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2013, Magnus Edenhill
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
 * Tests various config related things
 */


#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"  /* for Kafka driver */



static void dr_cb (rd_kafka_t *rk, void *payload, size_t len,
		   rd_kafka_resp_err_t err, void *opaque, void *msg_opaque) {
}

static void error_cb (rd_kafka_t *rk, int err, const char *reason,
		      void *opaque) {

}


static int32_t partitioner (const rd_kafka_topic_t *rkt,
			    const void *keydata,
			    size_t keylen,
			    int32_t partition_cnt,
			    void *rkt_opaque,
			    void *msg_opaque) {
	return 0;
}


static void conf_verify (int line,
			 const char **arr, size_t cnt, const char **confs) {
	int i, j;


	for (i = 0 ; confs[i] ; i += 2) {
		for (j = 0 ; j < (int)cnt ; j += 2) {
			if (!strcmp(confs[i], arr[j])) {
				if (strcmp(confs[i+1], arr[j+1]))
					TEST_FAIL("%i: Property %s mismatch: "
						  "expected %s != retrieved %s",
						  line,
						  confs[i],
						  confs[i+1], arr[j+1]);
			}
			if (j == (int)cnt)
				TEST_FAIL("%i: "
					  "Property %s not found in config\n",
					  line,
					  confs[i]);
		}
	}
}


static void conf_cmp (const char *desc,
		      const char **a, size_t acnt,
		      const char **b, size_t bcnt) {
	int i;

	if (acnt != bcnt)
		TEST_FAIL("%s config compare: count %"PRIusz" != %"PRIusz" mismatch",
			  desc, acnt, bcnt);

	for (i = 0 ; i < (int)acnt ; i += 2) {
		if (strcmp(a[i], b[i]))
			TEST_FAIL("%s conf mismatch: %s != %s",
				  desc, a[i], b[i]);
		else if (strcmp(a[i+1], b[i+1])) {
                        /* The default_topic_conf will be auto-created
                         * when global->topic fallthru is used, so its
                         * value will not match here. */
                        if (!strcmp(a[i], "default_topic_conf"))
                                continue;
                        TEST_FAIL("%s conf value mismatch for %s: %s != %s",
                                  desc, a[i], a[i+1], b[i+1]);
                }
	}
}


/**
 * @brief Not called, just used for config
 */
static int on_new_call_cnt;
static rd_kafka_resp_err_t my_on_new (rd_kafka_t *rk,
                                      const rd_kafka_conf_t *conf,
                                      void *ic_opaque,
                                      char *errstr, size_t errstr_size) {
        TEST_SAY("%s: on_new() called\n", rd_kafka_name(rk));
        on_new_call_cnt++;
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}



/**
 * @brief When rd_kafka_new() succeeds it takes ownership of the config object,
 *        but when it fails the config object remains in application custody.
 *        These tests makes sure that's the case (preferably run with valgrind)
 */
static void do_test_kafka_new_failures (void) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        char errstr[512];

        conf = rd_kafka_conf_new();

        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(rk, "kafka_new() failed: %s", errstr);
        rd_kafka_destroy(rk);

        /* Set an erroneous configuration value that is not checked
         * by conf_set() but by rd_kafka_new() */
        conf = rd_kafka_conf_new();
        if (rd_kafka_conf_set(conf, "partition.assignment.strategy",
                              "range,thiswillfail", errstr, sizeof(errstr)) !=
            RD_KAFKA_CONF_OK)
                TEST_FAIL("%s", errstr);

        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(!rk, "kafka_new() should have failed");

        /* config object should still belong to us,
         * correct the erroneous config and try again. */
        if (rd_kafka_conf_set(conf, "partition.assignment.strategy", NULL,
                              errstr, sizeof(errstr)) !=
            RD_KAFKA_CONF_OK)
                TEST_FAIL("%s", errstr);

        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(rk, "kafka_new() failed: %s", errstr);
        rd_kafka_destroy(rk);

        /* set conflicting properties */
        conf = rd_kafka_conf_new();
        test_conf_set(conf, "acks", "1");
        test_conf_set(conf, "enable.idempotence", "true");
        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(!rk, "kafka_new() should have failed");
        rd_kafka_conf_destroy(conf);
        TEST_SAY(_C_GRN "Ok: %s\n", errstr);
}


/**
 * @brief Verify that INVALID properties (such as for Java SSL properties)
 *        work, as well as INTERNAL properties.
 */
static void do_test_special_invalid_conf (void) {
        rd_kafka_conf_t *conf;
        char errstr[512];
        rd_kafka_conf_res_t res;

        conf = rd_kafka_conf_new();

        res = rd_kafka_conf_set(conf, "ssl.truststore.location", "abc",
                                errstr, sizeof(errstr));
        /* Existing apps might not print the error string when conf_set
         * returns UNKNOWN, only on INVALID, so make sure that is
         * what is being returned. */
        TEST_ASSERT(res == RD_KAFKA_CONF_INVALID,
                    "expected ssl.truststore.location to fail with INVALID, "
                    "not %d", res);
        /* Make sure there is a link to documentation */
        TEST_ASSERT(strstr(errstr, "http"),
                    "expected ssl.truststore.location to provide link to "
                    "documentation, not \"%s\"", errstr);
        TEST_SAY(_C_GRN "Ok: %s\n" _C_CLR, errstr);


        res = rd_kafka_conf_set(conf, "sasl.jaas.config", "abc",
                                errstr, sizeof(errstr));
        /* Existing apps might not print the error string when conf_set
         * returns UNKNOWN, only on INVALID, so make sure that is
         * what is being returned. */
        TEST_ASSERT(res == RD_KAFKA_CONF_INVALID,
                    "expected sasl.jaas.config to fail with INVALID, "
                    "not %d", res);
        /* Make sure there is a link to documentation */
        TEST_ASSERT(strstr(errstr, "http"),
                    "expected sasl.jaas.config to provide link to "
                    "documentation, not \"%s\"", errstr);
        TEST_SAY(_C_GRN "Ok: %s\n" _C_CLR, errstr);


        res = rd_kafka_conf_set(conf, "interceptors", "1",
                                errstr, sizeof(errstr));
        TEST_ASSERT(res == RD_KAFKA_CONF_INVALID,
                    "expected interceptors to fail with INVALID, "
                    "not %d", res);
        TEST_SAY(_C_GRN "Ok: %s\n" _C_CLR, errstr);

        rd_kafka_conf_destroy(conf);
}


/**
 * @brief Verify idempotence configuration constraints
 */
static void do_test_idempotence_conf (void) {
        static const struct {
                const char *prop;
                const char *val;
                rd_bool_t topic_conf;
                rd_bool_t exp_rk_fail;
                rd_bool_t exp_rkt_fail;
        } check[] = {
                { "acks", "1", rd_true, rd_false, rd_true },
                { "acks", "all", rd_true, rd_false, rd_false },
                { "queuing.strategy", "lifo", rd_true, rd_false, rd_true },
                { NULL }
        };
        int i;

        for (i = 0 ; check[i].prop ; i++) {
                int j;

                for (j = 0 ; j < 1 + (check[i].topic_conf ? 1 : 0) ; j++) {
                        /* j = 0: set on global config
                        *  j = 1: set on topic config */
                        rd_kafka_conf_t *conf;
                        rd_kafka_topic_conf_t *tconf = NULL;
                        rd_kafka_t *rk;
                        rd_kafka_topic_t *rkt;
                        char errstr[512];

                        conf = rd_kafka_conf_new();
                        test_conf_set(conf, "enable.idempotence", "true");

                        if (j == 0)
                                test_conf_set(conf, check[i].prop, check[i].val);


                        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf,
                                          errstr, sizeof(errstr));

                        if (!rk) {
                                /* default topic config (j=0) will fail. */
                                TEST_ASSERT(check[i].exp_rk_fail ||
                                            (j == 0 && check[i].exp_rkt_fail &&
                                             check[i].topic_conf),
                                            "Did not expect config #%d.%d "
                                            "to fail: %s",
                                            i, j, errstr);

                                rd_kafka_conf_destroy(conf);
                                continue;

                        } else {
                                TEST_ASSERT(!check[i].exp_rk_fail,
                                            "Expect config #%d.%d to fail",
                                            i, j);
                        }

                        if (j == 1) {
                                tconf = rd_kafka_topic_conf_new();
                                test_topic_conf_set(tconf, check[i].prop,
                                                    check[i].val);
                        }

                        rkt = rd_kafka_topic_new(rk, "mytopic", tconf);
                        if (!rkt) {
                                TEST_ASSERT(check[i].exp_rkt_fail,
                                            "Did not expect topic config "
                                            "#%d.%d to fail: %s",
                                            i, j,
                                            rd_kafka_err2str(
                                                    rd_kafka_last_error()));


                        } else {
                                TEST_ASSERT(!check[i].exp_rkt_fail,
                                            "Expect topic config "
                                            "#%d.%d to fail", i, j);
                                rd_kafka_topic_destroy(rkt);
                        }

                        rd_kafka_destroy(rk);
                }
        }
}


/**
 * @brief Verify that configuration properties can be extract
 *        from the instance config object.
 */
static void do_test_instance_conf (void) {
        rd_kafka_conf_t *conf;
        const rd_kafka_conf_t *iconf;
        rd_kafka_t *rk;
        rd_kafka_conf_res_t res;
        static const char *props[] = {
                "linger.ms", "123",
                "group.id", "test1",
                "enable.auto.commit", "false",
                NULL,
        };
        const char **p;

        conf = rd_kafka_conf_new();

        for (p = props ; *p ; p += 2) {
                res = rd_kafka_conf_set(conf, *p, *(p+1), NULL, 0);
                TEST_ASSERT(res == RD_KAFKA_CONF_OK, "failed to set %s", *p);
        }

        rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, NULL, 0);
        TEST_ASSERT(rk, "failed to create consumer");

        iconf = rd_kafka_conf(rk);
        TEST_ASSERT(conf, "failed to get instance config");

        for (p = props ; *p ; p += 2) {
                char dest[512];
                size_t destsz = sizeof(dest);

                res = rd_kafka_conf_get(iconf, *p, dest, &destsz);
                TEST_ASSERT(res == RD_KAFKA_CONF_OK,
                            "failed to get %s: result %d", *p, res);

                TEST_SAY("Instance config %s=%s\n", *p, dest);
                TEST_ASSERT(!strcmp(*(p+1), dest),
                            "Expected %s=%s, not %s",
                            *p, *(p+1), dest);
        }

        rd_kafka_destroy(rk);
}


int main_0004_conf (int argc, char **argv) {
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	rd_kafka_conf_t *ignore_conf, *conf, *conf2;
	rd_kafka_topic_conf_t *ignore_topic_conf, *tconf, *tconf2;
	char errstr[512];
        rd_kafka_resp_err_t err;
	const char **arr_orig, **arr_dup;
	size_t cnt_orig, cnt_dup;
	int i;
        const char *topic;
	static const char *gconfs[] = {
		"message.max.bytes", "12345", /* int property */
		"client.id", "my id", /* string property */
		"debug", "topic,metadata,interceptor", /* S2F property */
		"topic.blacklist", "__.*", /* #778 */
                "auto.offset.reset", "earliest", /* Global->Topic fallthru */
#if WITH_ZLIB
		"compression.codec", "gzip", /* S2I property */
#endif
		NULL
	};
	static const char *tconfs[] = {
		"request.required.acks", "-1", /* int */
		"auto.commit.enable", "false", /* bool */
		"auto.offset.reset", "error",  /* S2I */
		"offset.store.path", "my/path", /* string */
		NULL
	};

	test_conf_init(&ignore_conf, &ignore_topic_conf, 10);
	rd_kafka_conf_destroy(ignore_conf);
	rd_kafka_topic_conf_destroy(ignore_topic_conf);

        topic = test_mk_topic_name("0004", 0);

	/* Set up a global config object */
	conf = rd_kafka_conf_new();

        for (i = 0 ; gconfs[i] ; i += 2) {
                if (rd_kafka_conf_set(conf, gconfs[i], gconfs[i+1],
                                      errstr, sizeof(errstr)) !=
                    RD_KAFKA_CONF_OK)
                        TEST_FAIL("%s\n", errstr);
        }

	rd_kafka_conf_set_dr_cb(conf, dr_cb);
	rd_kafka_conf_set_error_cb(conf, error_cb);
        /* interceptor configs are not exposed as strings or in dumps
         * so the dump verification step will not cover them, but valgrind
         * will help track down memory leaks/use-after-free etc. */
        err = rd_kafka_conf_interceptor_add_on_new(conf, "testic",
                                                   my_on_new, NULL);
        TEST_ASSERT(!err, "add_on_new() failed: %s", rd_kafka_err2str(err));

	/* Set up a topic config object */
	tconf = rd_kafka_topic_conf_new();

	rd_kafka_topic_conf_set_partitioner_cb(tconf, partitioner);
	rd_kafka_topic_conf_set_opaque(tconf, (void *)0xbeef);

	for (i = 0 ; tconfs[i] ; i += 2) {
		if (rd_kafka_topic_conf_set(tconf, tconfs[i], tconfs[i+1],
				      errstr, sizeof(errstr)) !=
		    RD_KAFKA_CONF_OK)
			TEST_FAIL("%s\n", errstr);
	}


	/* Verify global config */
	arr_orig = rd_kafka_conf_dump(conf, &cnt_orig);
	conf_verify(__LINE__, arr_orig, cnt_orig, gconfs);

	/* Verify copied global config */
	conf2 = rd_kafka_conf_dup(conf);
	arr_dup = rd_kafka_conf_dump(conf2, &cnt_dup);
	conf_verify(__LINE__, arr_dup, cnt_dup, gconfs);
	conf_cmp("global", arr_orig, cnt_orig, arr_dup, cnt_dup);
	rd_kafka_conf_dump_free(arr_orig, cnt_orig);
	rd_kafka_conf_dump_free(arr_dup, cnt_dup);

	/* Verify topic config */
	arr_orig = rd_kafka_topic_conf_dump(tconf, &cnt_orig);
	conf_verify(__LINE__, arr_orig, cnt_orig, tconfs);

	/* Verify copied topic config */
	tconf2 = rd_kafka_topic_conf_dup(tconf);
	arr_dup = rd_kafka_topic_conf_dump(tconf2, &cnt_dup);
	conf_verify(__LINE__, arr_dup, cnt_dup, tconfs);
	conf_cmp("topic", arr_orig, cnt_orig, arr_dup, cnt_dup);
	rd_kafka_conf_dump_free(arr_orig, cnt_orig);
	rd_kafka_conf_dump_free(arr_dup, cnt_dup);


	/*
	 * Create kafka instances using original and copied confs
	 */

	/* original */
        TEST_ASSERT(on_new_call_cnt == 0, "expected 0 on_new call, not %d",
                    on_new_call_cnt);
        on_new_call_cnt = 0;
	rk = test_create_handle(RD_KAFKA_PRODUCER, conf);
        TEST_ASSERT(on_new_call_cnt == 1, "expected 1 on_new call, not %d",
                on_new_call_cnt);

	rkt = rd_kafka_topic_new(rk, topic, tconf);
	if (!rkt)
		TEST_FAIL("Failed to create topic: %s\n",
			  rd_strerror(errno));

	rd_kafka_topic_destroy(rkt);
	rd_kafka_destroy(rk);

	/* copied */
        on_new_call_cnt = 0; /* interceptors are not copied. */
	rk = test_create_handle(RD_KAFKA_PRODUCER, conf2);
        TEST_ASSERT(on_new_call_cnt == 0, "expected 0 on_new call, not %d",
                on_new_call_cnt);

	rkt = rd_kafka_topic_new(rk, topic, tconf2);
	if (!rkt)
		TEST_FAIL("Failed to create topic: %s\n",
			  rd_strerror(errno));
	rd_kafka_topic_destroy(rkt);
	rd_kafka_destroy(rk);


	/* Incremental S2F property.
	 * NOTE: The order of fields returned in get() is hardcoded here. */
	{
		static const char *s2fs[] = {
			"generic,broker,queue,cgrp",
			"generic,broker,queue,cgrp",

			"-broker,+queue,topic",
			"generic,topic,queue,cgrp",

			"-all,security,-fetch,+metadata",
			"metadata,security",

			NULL
		};

		TEST_SAY("Incremental S2F tests\n");
		conf = rd_kafka_conf_new();

		for (i = 0 ; s2fs[i] ; i += 2) {
			const char *val;

			TEST_SAY("  Set: %s\n", s2fs[i]);
			test_conf_set(conf, "debug", s2fs[i]);
			val = test_conf_get(conf, "debug");
			TEST_SAY("  Now: %s\n", val);

			if (strcmp(val, s2fs[i+1]))
				TEST_FAIL_LATER("\n"
						"Expected: %s\n"
						"     Got: %s",
						s2fs[i+1], val);
		}
		rd_kafka_conf_destroy(conf);
	}

        {
                rd_kafka_conf_res_t res;

                TEST_SAY("Error reporting for S2F properties\n");
                conf = rd_kafka_conf_new();

                res = rd_kafka_conf_set(conf, "debug",
                        "cgrp,invalid-value,topic", errstr, sizeof(errstr));

                TEST_ASSERT(res == RD_KAFKA_CONF_INVALID,
                        "expected 'debug=invalid-value' to fail with INVALID, "
                        "not %d", res);
                TEST_ASSERT(strstr(errstr, "invalid-value"),
                        "expected invalid value to be mentioned in error, "
                        "not \"%s\"", errstr);
                TEST_ASSERT(
                        !strstr(errstr, "cgrp") && !strstr(errstr, "topic"),
                        "expected only invalid value to be mentioned, "
                        "not \"%s\"", errstr);
                TEST_SAY(_C_GRN "Ok: %s\n" _C_CLR, errstr);

                rd_kafka_conf_destroy(conf);
        }

	/* Canonical int values, aliases, s2i-verified strings, doubles */
	{
		static const struct {
			const char *prop;
			const char *val;
			const char *exp;
			int is_global;
		} props[] = {
			{ "request.required.acks", "0", "0" },
			{ "request.required.acks", "-1", "-1" },
			{ "request.required.acks", "1", "1" },
			{ "acks", "3", "3" }, /* alias test */
			{ "request.required.acks", "393", "393" },
			{ "request.required.acks", "bad", NULL },
			{ "request.required.acks", "all", "-1" },
                        { "request.required.acks", "all", "-1", 1/*fallthru*/ },
			{ "acks", "0", "0" }, /* alias test */
#if WITH_SASL
			{ "sasl.mechanisms", "GSSAPI", "GSSAPI", 1 },
			{ "sasl.mechanisms", "PLAIN", "PLAIN", 1  },
			{ "sasl.mechanisms", "GSSAPI,PLAIN", NULL, 1  },
			{ "sasl.mechanisms", "", NULL, 1  },
#endif
                        { "linger.ms", "12555.3", "12555.3", 1 },
                        { "linger.ms", "1500.000", "1500", 1 },
                        { "linger.ms", "0.0001", "0.0001", 1 },
			{ NULL }
		};

		TEST_SAY("Canonical tests\n");
		tconf = rd_kafka_topic_conf_new();
		conf = rd_kafka_conf_new();

		for (i = 0 ; props[i].prop ; i++) {
			char dest[64];
			size_t destsz;
			rd_kafka_conf_res_t res;

			TEST_SAY("  Set: %s=%s expect %s (%s)\n",
				 props[i].prop, props[i].val, props[i].exp,
                                 props[i].is_global ? "global":"topic");


			/* Set value */
			if (props[i].is_global)
				res = rd_kafka_conf_set(conf,
						      props[i].prop,
						      props[i].val,
						      errstr, sizeof(errstr));
			else
				res = rd_kafka_topic_conf_set(tconf,
							      props[i].prop,
							      props[i].val,
							      errstr,
							      sizeof(errstr));
			if ((res == RD_KAFKA_CONF_OK ? 1:0) !=
			    (props[i].exp ? 1:0))
				TEST_FAIL("Expected %s, got %s",
					  props[i].exp ? "success" : "failure",
					  (res == RD_KAFKA_CONF_OK ? "OK" :
					   (res == RD_KAFKA_CONF_INVALID ? "INVALID" :
					    "UNKNOWN")));

			if (!props[i].exp)
				continue;

			/* Get value and compare to expected result */
			destsz = sizeof(dest);
			if (props[i].is_global)
				res = rd_kafka_conf_get(conf,
							props[i].prop,
							dest, &destsz);
			else
				res = rd_kafka_topic_conf_get(tconf,
							      props[i].prop,
							      dest, &destsz);
			TEST_ASSERT(res == RD_KAFKA_CONF_OK,
				    ".._conf_get(%s) returned %d",
                                    props[i].prop, res);

			TEST_ASSERT(!strcmp(props[i].exp, dest),
				    "Expected \"%s\", got \"%s\"",
				    props[i].exp, dest);
		}
		rd_kafka_topic_conf_destroy(tconf);
		rd_kafka_conf_destroy(conf);
	}

        do_test_kafka_new_failures();

        do_test_special_invalid_conf();

        do_test_idempotence_conf();

        do_test_instance_conf();

	return 0;
}
