/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2015, Magnus Edenhill
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
 * Apache Kafka high level consumer example program
 * using the Kafka driver from librdkafka
 * (https://github.com/edenhill/librdkafka)
 */

#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/time.h>
#include <errno.h>
#include <getopt.h>

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is builtin from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


static volatile sig_atomic_t run = 1;
static rd_kafka_t *rk;
static int exit_eof = 0;
static int wait_eof = 0; /* number of partitions awaiting EOF */
static int quiet    = 0;
static enum {
        OUTPUT_HEXDUMP,
        OUTPUT_RAW,
} output = OUTPUT_HEXDUMP;

static void stop(int sig) {
        if (!run)
                exit(1);
        run = 0;
        fclose(stdin); /* abort fgets() */
}


static void hexdump(FILE *fp, const char *name, const void *ptr, size_t len) {
        const char *p   = (const char *)ptr;
        unsigned int of = 0;


        if (name)
                fprintf(fp, "%s hexdump (%zd bytes):\n", name, len);

        for (of = 0; of < len; of += 16) {
                char hexen[16 * 3 + 1];
                char charen[16 + 1];
                int hof = 0;

                int cof = 0;
                int i;

                for (i = of; i < (int)of + 16 && i < (int)len; i++) {
                        hof += sprintf(hexen + hof, "%02x ", p[i] & 0xff);
                        cof += sprintf(charen + cof, "%c",
                                       isprint((int)p[i]) ? p[i] : '.');
                }
                fprintf(fp, "%08x: %-48s %-16s\n", of, hexen, charen);
        }
}

/**
 * Kafka logger callback (optional)
 */
static void
logger(const rd_kafka_t *rk, int level, const char *fac, const char *buf) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        fprintf(stdout, "%u.%03u RDKAFKA-%i-%s: %s: %s\n", (int)tv.tv_sec,
                (int)(tv.tv_usec / 1000), level, fac, rd_kafka_name(rk), buf);
}



/**
 * Handle and print a consumed message.
 * Internally crafted messages are also used to propagate state from
 * librdkafka to the application. The application needs to check
 * the `rkmessage->err` field for this purpose.
 */
static void msg_consume(rd_kafka_message_t *rkmessage) {
        if (rkmessage->err) {
                if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                        fprintf(stderr,
                                "%% Consumer reached end of %s [%" PRId32
                                "] "
                                "message queue at offset %" PRId64 "\n",
                                rd_kafka_topic_name(rkmessage->rkt),
                                rkmessage->partition, rkmessage->offset);

                        if (exit_eof && --wait_eof == 0) {
                                fprintf(stderr,
                                        "%% All partition(s) reached EOF: "
                                        "exiting\n");
                                run = 0;
                        }

                        return;
                }

                if (rkmessage->rkt)
                        fprintf(stderr,
                                "%% Consume error for "
                                "topic \"%s\" [%" PRId32
                                "] "
                                "offset %" PRId64 ": %s\n",
                                rd_kafka_topic_name(rkmessage->rkt),
                                rkmessage->partition, rkmessage->offset,
                                rd_kafka_message_errstr(rkmessage));
                else
                        fprintf(stderr, "%% Consumer error: %s: %s\n",
                                rd_kafka_err2str(rkmessage->err),
                                rd_kafka_message_errstr(rkmessage));

                if (rkmessage->err == RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION ||
                    rkmessage->err == RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC)
                        run = 0;
                return;
        }

        if (!quiet)
                fprintf(stdout,
                        "%% Message (topic %s [%" PRId32
                        "], "
                        "offset %" PRId64 ", %zd bytes):\n",
                        rd_kafka_topic_name(rkmessage->rkt),
                        rkmessage->partition, rkmessage->offset,
                        rkmessage->len);

        if (rkmessage->key_len) {
                if (output == OUTPUT_HEXDUMP)
                        hexdump(stdout, "Message Key", rkmessage->key,
                                rkmessage->key_len);
                else
                        printf("Key: %.*s\n", (int)rkmessage->key_len,
                               (char *)rkmessage->key);
        }

        if (output == OUTPUT_HEXDUMP)
                hexdump(stdout, "Message Payload", rkmessage->payload,
                        rkmessage->len);
        else
                printf("%.*s\n", (int)rkmessage->len,
                       (char *)rkmessage->payload);
}


static void
print_partition_list(FILE *fp,
                     const rd_kafka_topic_partition_list_t *partitions) {
        int i;
        for (i = 0; i < partitions->cnt; i++) {
                fprintf(fp, "%s %s [%" PRId32 "] offset %" PRId64,
                        i > 0 ? "," : "", partitions->elems[i].topic,
                        partitions->elems[i].partition,
                        partitions->elems[i].offset);
        }
        fprintf(fp, "\n");
}
static void rebalance_cb(rd_kafka_t *rk,
                         rd_kafka_resp_err_t err,
                         rd_kafka_topic_partition_list_t *partitions,
                         void *opaque) {
        rd_kafka_error_t *error     = NULL;
        rd_kafka_resp_err_t ret_err = RD_KAFKA_RESP_ERR_NO_ERROR;

        fprintf(stderr, "%% Consumer group rebalanced: ");

        switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                fprintf(stderr, "assigned (%s):\n",
                        rd_kafka_rebalance_protocol(rk));
                print_partition_list(stderr, partitions);

                if (!strcmp(rd_kafka_rebalance_protocol(rk), "COOPERATIVE"))
                        error = rd_kafka_incremental_assign(rk, partitions);
                else
                        ret_err = rd_kafka_assign(rk, partitions);
                wait_eof += partitions->cnt;
                break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                fprintf(stderr, "revoked (%s):\n",
                        rd_kafka_rebalance_protocol(rk));
                print_partition_list(stderr, partitions);

                if (!strcmp(rd_kafka_rebalance_protocol(rk), "COOPERATIVE")) {
                        error = rd_kafka_incremental_unassign(rk, partitions);
                        wait_eof -= partitions->cnt;
                } else {
                        ret_err  = rd_kafka_assign(rk, NULL);
                        wait_eof = 0;
                }
                break;

        default:
                fprintf(stderr, "failed: %s\n", rd_kafka_err2str(err));
                rd_kafka_assign(rk, NULL);
                break;
        }

        if (error) {
                fprintf(stderr, "incremental assign failure: %s\n",
                        rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
        } else if (ret_err) {
                fprintf(stderr, "assign failure: %s\n",
                        rd_kafka_err2str(ret_err));
        }
}


static int describe_groups(rd_kafka_t *rk, const char *group) {
        rd_kafka_resp_err_t err;
        const struct rd_kafka_group_list *grplist;
        int i;

        err = rd_kafka_list_groups(rk, group, &grplist, 10000);

        if (err) {
                fprintf(stderr, "%% Failed to acquire group list: %s\n",
                        rd_kafka_err2str(err));
                return -1;
        }

        for (i = 0; i < grplist->group_cnt; i++) {
                const struct rd_kafka_group_info *gi = &grplist->groups[i];
                int j;

                printf("Group \"%s\" in state %s on broker %d (%s:%d)\n",
                       gi->group, gi->state, gi->broker.id, gi->broker.host,
                       gi->broker.port);
                if (gi->err)
                        printf(" Error: %s\n", rd_kafka_err2str(gi->err));
                printf(
                    " Protocol type \"%s\", protocol \"%s\", "
                    "with %d member(s):\n",
                    gi->protocol_type, gi->protocol, gi->member_cnt);

                for (j = 0; j < gi->member_cnt; j++) {
                        const struct rd_kafka_group_member_info *mi;
                        mi = &gi->members[j];

                        printf("  \"%s\", client id \"%s\" on host %s\n",
                               mi->member_id, mi->client_id, mi->client_host);
                        printf("    metadata: %d bytes\n",
                               mi->member_metadata_size);
                        printf("    assignment: %d bytes\n",
                               mi->member_assignment_size);
                }
                printf("\n");
        }

        if (group && !grplist->group_cnt)
                fprintf(stderr, "%% No matching group (%s)\n", group);

        rd_kafka_group_list_destroy(grplist);

        return 0;
}



static void sig_usr1(int sig) {
        rd_kafka_dump(stdout, rk);
}

int main(int argc, char **argv) {
        char mode     = 'C';
        char *brokers = "localhost:9092";
        int opt;
        rd_kafka_conf_t *conf;
        char errstr[512];
        const char *debug = NULL;
        int do_conf_dump  = 0;
        char tmp[16];
        rd_kafka_resp_err_t err;
        char *group = NULL;
        rd_kafka_topic_partition_list_t *topics;
        int is_subscription;
        int i;

        quiet = !isatty(STDIN_FILENO);

        /* Kafka configuration */
        conf = rd_kafka_conf_new();

        /* Set logger */
        rd_kafka_conf_set_log_cb(conf, logger);

        /* Quick termination */
        snprintf(tmp, sizeof(tmp), "%i", SIGIO);
        rd_kafka_conf_set(conf, "internal.termination.signal", tmp, NULL, 0);

        while ((opt = getopt(argc, argv, "g:b:qd:eX:ADO")) != -1) {
                switch (opt) {
                case 'b':
                        brokers = optarg;
                        break;
                case 'g':
                        group = optarg;
                        break;
                case 'e':
                        exit_eof = 1;
                        break;
                case 'd':
                        debug = optarg;
                        break;
                case 'q':
                        quiet = 1;
                        break;
                case 'A':
                        output = OUTPUT_RAW;
                        break;
                case 'X': {
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
                                fprintf(stderr,
                                        "%% Expected "
                                        "-X property=value, not %s\n",
                                        name);
                                exit(1);
                        }

                        *val = '\0';
                        val++;

                        res = rd_kafka_conf_set(conf, name, val, errstr,
                                                sizeof(errstr));

                        if (res != RD_KAFKA_CONF_OK) {
                                fprintf(stderr, "%% %s\n", errstr);
                                exit(1);
                        }
                } break;

                case 'D':
                case 'O':
                        mode = opt;
                        break;

                default:
                        goto usage;
                }
        }


        if (do_conf_dump) {
                const char **arr;
                size_t cnt;
                int pass;

                for (pass = 0; pass < 2; pass++) {
                        if (pass == 0) {
                                arr = rd_kafka_conf_dump(conf, &cnt);
                                printf("# Global config\n");
                        } else {
                                rd_kafka_topic_conf_t *topic_conf =
                                    rd_kafka_conf_get_default_topic_conf(conf);
                                if (topic_conf) {
                                        printf("# Topic config\n");
                                        arr = rd_kafka_topic_conf_dump(
                                            topic_conf, &cnt);
                                } else {
                                        arr = NULL;
                                }
                        }

                        if (!arr)
                                continue;

                        for (i = 0; i < (int)cnt; i += 2)
                                printf("%s = %s\n", arr[i], arr[i + 1]);

                        printf("\n");
                        rd_kafka_conf_dump_free(arr, cnt);
                }

                exit(0);
        }


        if (strchr("OC", mode) && optind == argc) {
        usage:
                fprintf(stderr,
                        "Usage: %s [options] <topic[:part]> <topic[:part]>..\n"
                        "\n"
                        "librdkafka version %s (0x%08x)\n"
                        "\n"
                        " Options:\n"
                        "  -g <group>      Consumer group (%s)\n"
                        "  -b <brokers>    Broker address (%s)\n"
                        "  -e              Exit consumer when last message\n"
                        "                  in partition has been received.\n"
                        "  -D              Describe group.\n"
                        "  -O              Get commmitted offset(s)\n"
                        "  -d [facs..]     Enable debugging contexts:\n"
                        "                  %s\n"
                        "  -q              Be quiet\n"
                        "  -A              Raw payload output (consumer)\n"
                        "  -X <prop=name> Set arbitrary librdkafka "
                        "configuration property\n"
                        "               Use '-X list' to see the full list\n"
                        "               of supported properties.\n"
                        "\n"
                        "For balanced consumer groups use the 'topic1 topic2..'"
                        " format\n"
                        "and for static assignment use "
                        "'topic1:part1 topic1:part2 topic2:part1..'\n"
                        "\n",
                        argv[0], rd_kafka_version_str(), rd_kafka_version(),
                        group, brokers, RD_KAFKA_DEBUG_CONTEXTS);
                exit(1);
        }


        signal(SIGINT, stop);
        signal(SIGUSR1, sig_usr1);

        if (debug && rd_kafka_conf_set(conf, "debug", debug, errstr,
                                       sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%% Debug configuration failed: %s: %s\n",
                        errstr, debug);
                exit(1);
        }

        /*
         * Client/Consumer group
         */

        if (strchr("CO", mode)) {
                /* Consumer groups require a group id */
                if (!group)
                        group = "rdkafka_consumer_example";
                if (rd_kafka_conf_set(conf, "group.id", group, errstr,
                                      sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                        fprintf(stderr, "%% %s\n", errstr);
                        exit(1);
                }

                /* Callback called on partition assignment changes */
                rd_kafka_conf_set_rebalance_cb(conf, rebalance_cb);

                rd_kafka_conf_set(conf, "enable.partition.eof", "true", NULL,
                                  0);
        }

        /* Set bootstrap servers */
        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%% %s\n", errstr);
                exit(1);
        }

        /* Create Kafka handle */
        if (!(rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr,
                                sizeof(errstr)))) {
                fprintf(stderr, "%% Failed to create new consumer: %s\n",
                        errstr);
                exit(1);
        }

        if (mode == 'D') {
                int r;
                /* Describe groups */
                r = describe_groups(rk, group);

                rd_kafka_destroy(rk);
                exit(r == -1 ? 1 : 0);
        }

        /* Redirect rd_kafka_poll() to consumer_poll() */
        rd_kafka_poll_set_consumer(rk);

        topics          = rd_kafka_topic_partition_list_new(argc - optind);
        is_subscription = 1;
        for (i = optind; i < argc; i++) {
                /* Parse "topic[:part] */
                char *topic = argv[i];
                char *t;
                int32_t partition = -1;

                if ((t = strstr(topic, ":"))) {
                        *t              = '\0';
                        partition       = atoi(t + 1);
                        is_subscription = 0; /* is assignment */
                        wait_eof++;
                }

                rd_kafka_topic_partition_list_add(topics, topic, partition);
        }

        if (mode == 'O') {
                /* Offset query */

                err = rd_kafka_committed(rk, topics, 5000);
                if (err) {
                        fprintf(stderr, "%% Failed to fetch offsets: %s\n",
                                rd_kafka_err2str(err));
                        exit(1);
                }

                for (i = 0; i < topics->cnt; i++) {
                        rd_kafka_topic_partition_t *p = &topics->elems[i];
                        printf("Topic \"%s\" partition %" PRId32, p->topic,
                               p->partition);
                        if (p->err)
                                printf(" error %s", rd_kafka_err2str(p->err));
                        else {
                                printf(" offset %" PRId64 "", p->offset);

                                if (p->metadata_size)
                                        printf(" (%d bytes of metadata)",
                                               (int)p->metadata_size);
                        }
                        printf("\n");
                }

                goto done;
        }


        if (is_subscription) {
                fprintf(stderr, "%% Subscribing to %d topics\n", topics->cnt);

                if ((err = rd_kafka_subscribe(rk, topics))) {
                        fprintf(stderr,
                                "%% Failed to start consuming topics: %s\n",
                                rd_kafka_err2str(err));
                        exit(1);
                }
        } else {
                fprintf(stderr, "%% Assigning %d partitions\n", topics->cnt);

                if ((err = rd_kafka_assign(rk, topics))) {
                        fprintf(stderr, "%% Failed to assign partitions: %s\n",
                                rd_kafka_err2str(err));
                }
        }

        while (run) {
                rd_kafka_message_t *rkmessage;

                rkmessage = rd_kafka_consumer_poll(rk, 1000);
                if (rkmessage) {
                        msg_consume(rkmessage);
                        rd_kafka_message_destroy(rkmessage);
                }
        }

done:
        err = rd_kafka_consumer_close(rk);
        if (err)
                fprintf(stderr, "%% Failed to close consumer: %s\n",
                        rd_kafka_err2str(err));
        else
                fprintf(stderr, "%% Consumer closed\n");

        rd_kafka_topic_partition_list_destroy(topics);

        /* Destroy handle */
        rd_kafka_destroy(rk);

        /* Let background threads clean up and terminate cleanly. */
        run = 5;
        while (run-- > 0 && rd_kafka_wait_destroyed(1000) == -1)
                printf("Waiting for librdkafka to decommission\n");
        if (run <= 0)
                rd_kafka_dump(stdout, rk);

        return 0;
}
