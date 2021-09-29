/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012, Magnus Edenhill
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
 * Apache Kafka consumer & producer example programs
 * using the Kafka driver from librdkafka
 * (https://github.com/edenhill/librdkafka)
 */

#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>
#include <getopt.h>

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is builtin from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"  /* for Kafka driver */


static volatile sig_atomic_t run = 1;
static rd_kafka_t *rk;
static int exit_eof = 0;
static int quiet = 0;
static 	enum {
	OUTPUT_HEXDUMP,
	OUTPUT_RAW,
} output = OUTPUT_HEXDUMP;

static void stop (int sig) {
	run = 0;
	fclose(stdin); /* abort fgets() */
}


static void hexdump (FILE *fp, const char *name, const void *ptr, size_t len) {
	const char *p = (const char *)ptr;
	size_t of = 0;


	if (name)
		fprintf(fp, "%s hexdump (%zd bytes):\n", name, len);

	for (of = 0 ; of < len ; of += 16) {
		char hexen[16*3+1];
		char charen[16+1];
		int hof = 0;

		int cof = 0;
		int i;

		for (i = of ; i < (int)of + 16 && i < (int)len ; i++) {
			hof += sprintf(hexen+hof, "%02x ", p[i] & 0xff);
			cof += sprintf(charen+cof, "%c",
				       isprint((int)p[i]) ? p[i] : '.');
		}
		fprintf(fp, "%08zx: %-48s %-16s\n",
			of, hexen, charen);
	}
}

/**
 * Kafka logger callback (optional)
 */
static void logger (const rd_kafka_t *rk, int level,
		    const char *fac, const char *buf) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	fprintf(stderr, "%u.%03u RDKAFKA-%i-%s: %s: %s\n",
		(int)tv.tv_sec, (int)(tv.tv_usec / 1000),
		level, fac, rk ? rd_kafka_name(rk) : NULL, buf);
}


/**
 * Message delivery report callback using the richer rd_kafka_message_t object.
 */
static void msg_delivered (rd_kafka_t *rk,
                           const rd_kafka_message_t *rkmessage, void *opaque) {
        if (rkmessage->err)
                fprintf(stderr,
                        "%% Message delivery failed (broker %"PRId32"): %s\n",
                        rd_kafka_message_broker_id(rkmessage),
                        rd_kafka_err2str(rkmessage->err));
        else if (!quiet)
                fprintf(stderr,
                        "%% Message delivered (%zd bytes, offset %"PRId64", "
                        "partition %"PRId32", broker %"PRId32"): %.*s\n",
                        rkmessage->len, rkmessage->offset,
                        rkmessage->partition,
                        rd_kafka_message_broker_id(rkmessage),
                        (int)rkmessage->len, (const char *)rkmessage->payload);
}


static void msg_consume (rd_kafka_message_t *rkmessage,
			 void *opaque) {
	if (rkmessage->err) {
		if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
			fprintf(stderr,
				"%% Consumer reached end of %s [%"PRId32"] "
			       "message queue at offset %"PRId64"\n",
			       rd_kafka_topic_name(rkmessage->rkt),
			       rkmessage->partition, rkmessage->offset);

			if (exit_eof)
				run = 0;

			return;
		}

		fprintf(stderr, "%% Consume error for topic \"%s\" [%"PRId32"] "
		       "offset %"PRId64": %s\n",
		       rd_kafka_topic_name(rkmessage->rkt),
		       rkmessage->partition,
		       rkmessage->offset,
		       rd_kafka_message_errstr(rkmessage));

                if (rkmessage->err == RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION ||
                    rkmessage->err == RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC)
                        run = 0;
		return;
	}

	if (!quiet) {
		rd_kafka_timestamp_type_t tstype;
		int64_t timestamp;
                rd_kafka_headers_t *hdrs;

                fprintf(stdout,
                        "%% Message (offset %"PRId64", %zd bytes, "
                        "broker %"PRId32"):\n",
                        rkmessage->offset, rkmessage->len,
                        rd_kafka_message_broker_id(rkmessage));

		timestamp = rd_kafka_message_timestamp(rkmessage, &tstype);
		if (tstype != RD_KAFKA_TIMESTAMP_NOT_AVAILABLE) {
			const char *tsname = "?";
			if (tstype == RD_KAFKA_TIMESTAMP_CREATE_TIME)
				tsname = "create time";
			else if (tstype == RD_KAFKA_TIMESTAMP_LOG_APPEND_TIME)
				tsname = "log append time";

			fprintf(stdout, "%% Message timestamp: %s %"PRId64
				" (%ds ago)\n",
				tsname, timestamp,
				!timestamp ? 0 :
				(int)time(NULL) - (int)(timestamp/1000));
		}

                if (!rd_kafka_message_headers(rkmessage, &hdrs)) {
                        size_t idx = 0;
                        const char *name;
                        const void *val;
                        size_t size;

                        fprintf(stdout, "%% Headers:");

                        while (!rd_kafka_header_get_all(hdrs, idx++,
                                                        &name, &val, &size)) {
                                fprintf(stdout, "%s%s=",
                                        idx == 1 ? " " : ", ", name);
                                if (val)
                                        fprintf(stdout, "\"%.*s\"",
                                                (int)size, (const char *)val);
                                else
                                        fprintf(stdout, "NULL");
                        }
                        fprintf(stdout, "\n");
                }
	}

	if (rkmessage->key_len) {
		if (output == OUTPUT_HEXDUMP)
			hexdump(stdout, "Message Key",
				rkmessage->key, rkmessage->key_len);
		else
			printf("Key: %.*s\n",
			       (int)rkmessage->key_len, (char *)rkmessage->key);
	}

	if (output == OUTPUT_HEXDUMP)
		hexdump(stdout, "Message Payload",
			rkmessage->payload, rkmessage->len);
	else
		printf("%.*s\n",
		       (int)rkmessage->len, (char *)rkmessage->payload);
}


static void metadata_print (const char *topic,
                            const struct rd_kafka_metadata *metadata) {
        int i, j, k;
        int32_t controllerid;

        printf("Metadata for %s (from broker %"PRId32": %s):\n",
               topic ? : "all topics",
               metadata->orig_broker_id,
               metadata->orig_broker_name);

        controllerid = rd_kafka_controllerid(rk, 0);


        /* Iterate brokers */
        printf(" %i brokers:\n", metadata->broker_cnt);
        for (i = 0 ; i < metadata->broker_cnt ; i++)
                printf("  broker %"PRId32" at %s:%i%s\n",
                       metadata->brokers[i].id,
                       metadata->brokers[i].host,
                       metadata->brokers[i].port,
                       controllerid == metadata->brokers[i].id ?
                       " (controller)" : "");

        /* Iterate topics */
        printf(" %i topics:\n", metadata->topic_cnt);
        for (i = 0 ; i < metadata->topic_cnt ; i++) {
                const struct rd_kafka_metadata_topic *t = &metadata->topics[i];
                printf("  topic \"%s\" with %i partitions:",
                       t->topic,
                       t->partition_cnt);
                if (t->err) {
                        printf(" %s", rd_kafka_err2str(t->err));
                        if (t->err == RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE)
                                printf(" (try again)");
                }
                printf("\n");

                /* Iterate topic's partitions */
                for (j = 0 ; j < t->partition_cnt ; j++) {
                        const struct rd_kafka_metadata_partition *p;
                        p = &t->partitions[j];
                        printf("    partition %"PRId32", "
                               "leader %"PRId32", replicas: ",
                               p->id, p->leader);

                        /* Iterate partition's replicas */
                        for (k = 0 ; k < p->replica_cnt ; k++)
                                printf("%s%"PRId32,
                                       k > 0 ? ",":"", p->replicas[k]);

                        /* Iterate partition's ISRs */
                        printf(", isrs: ");
                        for (k = 0 ; k < p->isr_cnt ; k++)
                                printf("%s%"PRId32,
                                       k > 0 ? ",":"", p->isrs[k]);
                        if (p->err)
                                printf(", %s\n", rd_kafka_err2str(p->err));
                        else
                                printf("\n");
                }
        }
}


static void sig_usr1 (int sig) {
	rd_kafka_dump(stdout, rk);
}

int main (int argc, char **argv) {
	rd_kafka_topic_t *rkt;
	char *brokers = "localhost:9092";
	char mode = 'C';
	char *topic = NULL;
	int partition = RD_KAFKA_PARTITION_UA;
	int opt;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;
	char errstr[512];
	int64_t start_offset = 0;
	int do_conf_dump = 0;
	char tmp[16];
        int64_t seek_offset = 0;
        int64_t tmp_offset = 0;
	int get_wmarks = 0;
        rd_kafka_headers_t *hdrs = NULL;
        rd_kafka_resp_err_t err;

	/* Kafka configuration */
	conf = rd_kafka_conf_new();

        /* Set logger */
        rd_kafka_conf_set_log_cb(conf, logger);

	/* Quick termination */
	snprintf(tmp, sizeof(tmp), "%i", SIGIO);
	rd_kafka_conf_set(conf, "internal.termination.signal", tmp, NULL, 0);

	/* Topic configuration */
	topic_conf = rd_kafka_topic_conf_new();

	while ((opt = getopt(argc, argv, "PCLt:p:b:z:qd:o:eX:As:H:")) != -1) {
		switch (opt) {
		case 'P':
		case 'C':
                case 'L':
			mode = opt;
			break;
		case 't':
			topic = optarg;
			break;
		case 'p':
			partition = atoi(optarg);
			break;
		case 'b':
			brokers = optarg;
			break;
		case 'z':
			if (rd_kafka_conf_set(conf, "compression.codec",
					      optarg,
					      errstr, sizeof(errstr)) !=
			    RD_KAFKA_CONF_OK) {
				fprintf(stderr, "%% %s\n", errstr);
				exit(1);
			}
			break;
		case 'o':
                case 's':
			if (!strcmp(optarg, "end"))
				tmp_offset = RD_KAFKA_OFFSET_END;
			else if (!strcmp(optarg, "beginning"))
				tmp_offset = RD_KAFKA_OFFSET_BEGINNING;
			else if (!strcmp(optarg, "stored"))
				tmp_offset = RD_KAFKA_OFFSET_STORED;
			else if (!strcmp(optarg, "wmark"))
				get_wmarks = 1;
			else {
				tmp_offset = strtoll(optarg, NULL, 10);

				if (tmp_offset < 0)
					tmp_offset = RD_KAFKA_OFFSET_TAIL(-tmp_offset);
			}

                        if (opt == 'o')
                                start_offset = tmp_offset;
                        else if (opt == 's')
                                seek_offset = tmp_offset;
			break;
		case 'e':
			exit_eof = 1;
			break;
		case 'd':
			if (rd_kafka_conf_set(conf, "debug", optarg,
					      errstr, sizeof(errstr)) !=
			    RD_KAFKA_CONF_OK) {
				fprintf(stderr,
					"%% Debug configuration failed: "
					"%s: %s\n",
					errstr, optarg);
				exit(1);
			}
			break;
		case 'q':
			quiet = 1;
			break;
		case 'A':
			output = OUTPUT_RAW;
			break;
                case 'H':
                {
                        char *name, *val;
                        size_t name_sz = -1;

                        name = optarg;
                        val = strchr(name, '=');
                        if (val) {
                                name_sz = (size_t)(val-name);
                                val++; /* past the '=' */
                        }

                        if (!hdrs)
                                hdrs = rd_kafka_headers_new(8);

                        err = rd_kafka_header_add(hdrs, name, name_sz, val, -1);
                        if (err) {
                                fprintf(stderr,
                                        "%% Failed to add header %s: %s\n",
                                        name, rd_kafka_err2str(err));
                                exit(1);
                        }
                }
                break;

		case 'X':
		{
			char *name, *val;
			rd_kafka_conf_res_t res;

			if (!strcmp(optarg, "list") ||
			    !strcmp(optarg, "help")) {
				rd_kafka_conf_properties_show(stdout);
				exit(0);
			}

			if (!strcmp(optarg, "dump")) {
				do_conf_dump = 1;
				continue;
			}

			name = optarg;
			if (!(val = strchr(name, '='))) {
				char dest[512];
				size_t dest_size = sizeof(dest);
				/* Return current value for property. */

				res = RD_KAFKA_CONF_UNKNOWN;
				if (!strncmp(name, "topic.", strlen("topic.")))
					res = rd_kafka_topic_conf_get(
						topic_conf,
						name+strlen("topic."),
						dest, &dest_size);
				if (res == RD_KAFKA_CONF_UNKNOWN)
					res = rd_kafka_conf_get(
						conf, name, dest, &dest_size);

				if (res == RD_KAFKA_CONF_OK) {
					printf("%s = %s\n", name, dest);
					exit(0);
				} else {
					fprintf(stderr,
						"%% %s property\n",
						res == RD_KAFKA_CONF_UNKNOWN ?
						"Unknown" : "Invalid");
					exit(1);
				}
			}

			*val = '\0';
			val++;

			res = RD_KAFKA_CONF_UNKNOWN;
			/* Try "topic." prefixed properties on topic
			 * conf first, and then fall through to global if
			 * it didnt match a topic configuration property. */
			if (!strncmp(name, "topic.", strlen("topic.")))
				res = rd_kafka_topic_conf_set(topic_conf,
							      name+
							      strlen("topic."),
							      val,
							      errstr,
							      sizeof(errstr));

			if (res == RD_KAFKA_CONF_UNKNOWN)
				res = rd_kafka_conf_set(conf, name, val,
							errstr, sizeof(errstr));

			if (res != RD_KAFKA_CONF_OK) {
				fprintf(stderr, "%% %s\n", errstr);
				exit(1);
			}
		}
		break;

		default:
			goto usage;
		}
	}


	if (do_conf_dump) {
		const char **arr;
		size_t cnt;
		int pass;

		for (pass = 0 ; pass < 2 ; pass++) {
			int i;

			if (pass == 0) {
				arr = rd_kafka_conf_dump(conf, &cnt);
				printf("# Global config\n");
			} else {
				printf("# Topic config\n");
				arr = rd_kafka_topic_conf_dump(topic_conf,
							       &cnt);
			}

			for (i = 0 ; i < (int)cnt ; i += 2)
				printf("%s = %s\n",
				       arr[i], arr[i+1]);

			printf("\n");

			rd_kafka_conf_dump_free(arr, cnt);
		}

		exit(0);
	}


	if (optind != argc || (mode != 'L' && !topic)) {
	usage:
		fprintf(stderr,
			"Usage: %s -C|-P|-L -t <topic> "
			"[-p <partition>] [-b <host1:port1,host2:port2,..>]\n"
			"\n"
			"librdkafka version %s (0x%08x)\n"
			"\n"
			" Options:\n"
			"  -C | -P         Consumer or Producer mode\n"
                        "  -L              Metadata list mode\n"
			"  -t <topic>      Topic to fetch / produce\n"
			"  -p <num>        Partition (random partitioner)\n"
			"  -b <brokers>    Broker address (localhost:9092)\n"
			"  -z <codec>      Enable compression:\n"
			"                  none|gzip|snappy|lz4|zstd\n"
			"  -o <offset>     Start offset (consumer):\n"
			"                  beginning, end, NNNNN or -NNNNN\n"
			"                  wmark returns the current hi&lo "
			"watermarks.\n"
			"  -e              Exit consumer when last message\n"
			"                  in partition has been received.\n"
			"  -d [facs..]     Enable debugging contexts:\n"
			"                  %s\n"
			"  -q              Be quiet\n"
			"  -A              Raw payload output (consumer)\n"
                        "  -H <name[=value]> Add header to message (producer)\n"
			"  -X <prop=name>  Set arbitrary librdkafka "
			"configuration property\n"
			"                  Properties prefixed with \"topic.\" "
			"will be set on topic object.\n"
			"  -X list         Show full list of supported "
			"properties.\n"
			"  -X dump         Show configuration\n"
			"  -X <prop>       Get single property value\n"
			"\n"
			" In Consumer mode:\n"
			"  writes fetched messages to stdout\n"
			" In Producer mode:\n"
			"  reads messages from stdin and sends to broker\n"
                        " In List mode:\n"
                        "  queries broker for metadata information, "
                        "topic is optional.\n"
			"\n"
			"\n"
			"\n",
			argv[0],
			rd_kafka_version_str(), rd_kafka_version(),
			RD_KAFKA_DEBUG_CONTEXTS);
		exit(1);
	}

	if ((mode == 'C' && !isatty(STDIN_FILENO)) ||
	    (mode != 'C' && !isatty(STDOUT_FILENO)))
		quiet = 1;


	signal(SIGINT, stop);
	signal(SIGUSR1, sig_usr1);

        /* Set bootstrap servers */
        if (brokers &&
            rd_kafka_conf_set(conf, "bootstrap.servers", brokers,
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%% %s\n", errstr);
                exit(1);
        }

	if (mode == 'P') {
		/*
		 * Producer
		 */
		char buf[2048];
		int sendcnt = 0;

		/* Set up a message delivery report callback.
		 * It will be called once for each message, either on successful
		 * delivery to broker, or upon failure to deliver to broker. */
                rd_kafka_conf_set_dr_msg_cb(conf, msg_delivered);

		/* Create Kafka handle */
		if (!(rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf,
					errstr, sizeof(errstr)))) {
			fprintf(stderr,
				"%% Failed to create new producer: %s\n",
				errstr);
			exit(1);
		}

		/* Create topic */
		rkt = rd_kafka_topic_new(rk, topic, topic_conf);
                topic_conf = NULL; /* Now owned by topic */

		if (!quiet)
			fprintf(stderr,
				"%% Type stuff and hit enter to send\n");

		while (run && fgets(buf, sizeof(buf), stdin)) {
			size_t len = strlen(buf);
			if (buf[len-1] == '\n')
				buf[--len] = '\0';

                        err = RD_KAFKA_RESP_ERR_NO_ERROR;

			/* Send/Produce message. */
                        if (hdrs) {
                                rd_kafka_headers_t *hdrs_copy;

                                hdrs_copy = rd_kafka_headers_copy(hdrs);

                                err = rd_kafka_producev(
                                        rk,
                                        RD_KAFKA_V_RKT(rkt),
                                        RD_KAFKA_V_PARTITION(partition),
                                        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                        RD_KAFKA_V_VALUE(buf, len),
                                        RD_KAFKA_V_HEADERS(hdrs_copy),
                                        RD_KAFKA_V_END);

                                if (err)
                                        rd_kafka_headers_destroy(hdrs_copy);

                        } else {
                                if (rd_kafka_produce(
                                            rkt, partition,
                                            RD_KAFKA_MSG_F_COPY,
                                            /* Payload and length */
                                            buf, len,
                                            /* Optional key and its length */
                                            NULL, 0,
                                            /* Message opaque, provided in
                                             * delivery report callback as
                                             * msg_opaque. */
                                            NULL) == -1) {
                                        err = rd_kafka_last_error();
                                }
                        }

                        if (err) {
                                fprintf(stderr,
                                        "%% Failed to produce to topic %s "
					"partition %i: %s\n",
					rd_kafka_topic_name(rkt), partition,
					rd_kafka_err2str(err));

				/* Poll to handle delivery reports */
				rd_kafka_poll(rk, 0);
				continue;
			}

			if (!quiet)
				fprintf(stderr, "%% Sent %zd bytes to topic "
					"%s partition %i\n",
				len, rd_kafka_topic_name(rkt), partition);
			sendcnt++;
			/* Poll to handle delivery reports */
			rd_kafka_poll(rk, 0);
		}

		/* Poll to handle delivery reports */
		rd_kafka_poll(rk, 0);

		/* Wait for messages to be delivered */
		while (run && rd_kafka_outq_len(rk) > 0)
			rd_kafka_poll(rk, 100);

		/* Destroy topic */
		rd_kafka_topic_destroy(rkt);

		/* Destroy the handle */
		rd_kafka_destroy(rk);

	} else if (mode == 'C') {
		/*
		 * Consumer
		 */

                rd_kafka_conf_set(conf, "enable.partition.eof", "true",
                                  NULL, 0);

		/* Create Kafka handle */
		if (!(rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf,
					errstr, sizeof(errstr)))) {
			fprintf(stderr,
				"%% Failed to create new consumer: %s\n",
				errstr);
			exit(1);
		}

		if (get_wmarks) {
			int64_t lo, hi;

			/* Only query for hi&lo partition watermarks */

			if ((err = rd_kafka_query_watermark_offsets(
				     rk, topic, partition, &lo, &hi, 5000))) {
				fprintf(stderr, "%% query_watermark_offsets() "
					"failed: %s\n",
					rd_kafka_err2str(err));
				exit(1);
			}

			printf("%s [%d]: low - high offsets: "
			       "%"PRId64" - %"PRId64"\n",
			       topic, partition, lo, hi);

			rd_kafka_destroy(rk);
			exit(0);
		}


		/* Create topic */
		rkt = rd_kafka_topic_new(rk, topic, topic_conf);
                topic_conf = NULL; /* Now owned by topic */

		/* Start consuming */
		if (rd_kafka_consume_start(rkt, partition, start_offset) == -1){
			err = rd_kafka_last_error();
			fprintf(stderr, "%% Failed to start consuming: %s\n",
				rd_kafka_err2str(err));
                        if (err == RD_KAFKA_RESP_ERR__INVALID_ARG)
                                fprintf(stderr,
                                        "%% Broker based offset storage "
                                        "requires a group.id, "
                                        "add: -X group.id=yourGroup\n");
			exit(1);
		}

		while (run) {
			rd_kafka_message_t *rkmessage;

                        /* Poll for errors, etc. */
                        rd_kafka_poll(rk, 0);

			/* Consume single message.
			 * See rdkafka_performance.c for high speed
			 * consuming of messages. */
			rkmessage = rd_kafka_consume(rkt, partition, 1000);
			if (!rkmessage) /* timeout */
				continue;

			msg_consume(rkmessage, NULL);

			/* Return message to rdkafka */
			rd_kafka_message_destroy(rkmessage);

                        if (seek_offset) {
                                err = rd_kafka_seek(rkt, partition, seek_offset,
                                                    2000);
                                if (err)
                                        printf("Seek failed: %s\n",
                                               rd_kafka_err2str(err));
                                else
                                        printf("Seeked to %"PRId64"\n",
                                               seek_offset);
                                seek_offset = 0;
                        }
		}

		/* Stop consuming */
		rd_kafka_consume_stop(rkt, partition);

                while (rd_kafka_outq_len(rk) > 0)
                        rd_kafka_poll(rk, 10);

		/* Destroy topic */
		rd_kafka_topic_destroy(rkt);

		/* Destroy handle */
		rd_kafka_destroy(rk);

        } else if (mode == 'L') {
                err = RD_KAFKA_RESP_ERR_NO_ERROR;

		/* Create Kafka handle */
		if (!(rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf,
					errstr, sizeof(errstr)))) {
			fprintf(stderr,
				"%% Failed to create new producer: %s\n",
				errstr);
			exit(1);
		}

                /* Create topic */
                if (topic) {
                        rkt = rd_kafka_topic_new(rk, topic, topic_conf);
                        topic_conf = NULL; /* Now owned by topic */
                } else
                        rkt = NULL;

                while (run) {
                        const struct rd_kafka_metadata *metadata;

                        /* Fetch metadata */
                        err = rd_kafka_metadata(rk, rkt ? 0 : 1, rkt,
                                                &metadata, 5000);
                        if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
                                fprintf(stderr,
                                        "%% Failed to acquire metadata: %s\n",
                                        rd_kafka_err2str(err));
                                run = 0;
                                break;
                        }

                        metadata_print(topic, metadata);

                        rd_kafka_metadata_destroy(metadata);
                        run = 0;
                }

		/* Destroy topic */
		if (rkt)
			rd_kafka_topic_destroy(rkt);

		/* Destroy the handle */
		rd_kafka_destroy(rk);

                if (topic_conf)
                        rd_kafka_topic_conf_destroy(topic_conf);


                /* Exit right away, dont wait for background cleanup, we haven't
                 * done anything important anyway. */
                exit(err ? 2 : 0);
        }

        if (hdrs)
                rd_kafka_headers_destroy(hdrs);

        if (topic_conf)
                rd_kafka_topic_conf_destroy(topic_conf);

	/* Let background threads clean up and terminate cleanly. */
	run = 5;
	while (run-- > 0 && rd_kafka_wait_destroyed(1000) == -1)
		printf("Waiting for librdkafka to decommission\n");
	if (run <= 0)
		rd_kafka_dump(stdout, rk);

	return 0;
}
