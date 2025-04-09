/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2023, Confluent Inc.
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
 * ARE DISCLAIMED. IN NO EVENT SH THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Example utility that shows how to use SCRAM APIs (AdminAPI)
 * DescribeUserScramCredentials -> Describe user SCRAM credentials
 * AlterUserScramCredentials -> Upsert or delete user SCRAM credentials
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef _WIN32
#include "../win32/wingetopt.h"
#else
#include <getopt.h>
#endif

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is builtin from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"

const char *argv0;

static rd_kafka_queue_t *queue; /** Admin result queue.
                                 *  This is a global so we can
                                 *  yield in stop() */
static volatile sig_atomic_t run = 1;

/**
 * @brief Signal termination of program
 */
static void stop(int sig) {
        if (!run) {
                fprintf(stderr, "%% Forced termination\n");
                exit(2);
        }
        run = 0;
        rd_kafka_queue_yield(queue);
}


static void usage(const char *reason, ...) {
        fprintf(stderr,
                "Describe/Alter user SCRAM credentials\n"
                "\n"
                "Usage: %s <options>\n"
                "       DESCRIBE <user1> ... \n"
                "       UPSERT <user1> <mechanism1> <iterations1> "
                "<password1> <salt1> ... \n"
                "       DELETE <user1> <mechanism1> ... \n"
                "\n"
                "Options:\n"
                "   -b <brokers>    Bootstrap server list to connect to.\n"
                "   -X <prop=val>   Set librdkafka configuration property.\n"
                "                   See CONFIGURATION.md for full list.\n"
                "   -d <dbg,..>     Enable librdkafka debugging (%s).\n"
                "\n",
                argv0, rd_kafka_get_debug_contexts());

        if (reason) {
                va_list ap;
                char reasonbuf[512];

                va_start(ap, reason);
                vsnprintf(reasonbuf, sizeof(reasonbuf), reason, ap);
                va_end(ap);

                fprintf(stderr, "ERROR: %s\n", reasonbuf);
        }

        exit(reason ? 1 : 0);
}

#define fatal(...)                                                             \
        do {                                                                   \
                fprintf(stderr, "ERROR: ");                                    \
                fprintf(stderr, __VA_ARGS__);                                  \
                fprintf(stderr, "\n");                                         \
                exit(2);                                                       \
        } while (0)


/**
 * @brief Set config property. Exit on failure.
 */
static void conf_set(rd_kafka_conf_t *conf, const char *name, const char *val) {
        char errstr[512];

        if (rd_kafka_conf_set(conf, name, val, errstr, sizeof(errstr)) !=
            RD_KAFKA_CONF_OK)
                fatal("Failed to set %s=%s: %s", name, val, errstr);
}


/**
 * @brief Parse an integer or fail.
 */
int64_t parse_int(const char *what, const char *str) {
        char *end;
        unsigned long n = strtoull(str, &end, 0);

        if (end != str + strlen(str)) {
                fprintf(stderr, "%% Invalid input for %s: %s: not an integer\n",
                        what, str);
                exit(1);
        }

        return (int64_t)n;
}

rd_kafka_ScramMechanism_t parse_mechanism(const char *arg) {
        return !strcmp(arg, "SCRAM-SHA-256")
                   ? RD_KAFKA_SCRAM_MECHANISM_SHA_256
                   : !strcmp(arg, "SCRAM-SHA-512")
                         ? RD_KAFKA_SCRAM_MECHANISM_SHA_512
                         : RD_KAFKA_SCRAM_MECHANISM_UNKNOWN;
}

static void print_descriptions(
    const rd_kafka_UserScramCredentialsDescription_t **descriptions,
    size_t description_cnt) {
        size_t i;
        printf("DescribeUserScramCredentials descriptions[%zu]\n",
               description_cnt);
        for (i = 0; i < description_cnt; i++) {
                const rd_kafka_UserScramCredentialsDescription_t *description;
                description = descriptions[i];
                const char *username;
                const rd_kafka_error_t *error;
                username =
                    rd_kafka_UserScramCredentialsDescription_user(description);
                error =
                    rd_kafka_UserScramCredentialsDescription_error(description);
                rd_kafka_resp_err_t err = rd_kafka_error_code(error);
                printf("    Username: \"%s\" Error: \"%s\"\n", username,
                       rd_kafka_err2str(err));
                if (err) {
                        const char *errstr = rd_kafka_error_string(error);
                        printf("        ErrorMessage: \"%s\"\n", errstr);
                }
                size_t num_credentials =
                    rd_kafka_UserScramCredentialsDescription_scramcredentialinfo_count(
                        description);
                size_t itr;
                for (itr = 0; itr < num_credentials; itr++) {
                        const rd_kafka_ScramCredentialInfo_t *scram_credential =
                            rd_kafka_UserScramCredentialsDescription_scramcredentialinfo(
                                description, itr);
                        rd_kafka_ScramMechanism_t mechanism;
                        int32_t iterations;
                        mechanism = rd_kafka_ScramCredentialInfo_mechanism(
                            scram_credential);
                        iterations = rd_kafka_ScramCredentialInfo_iterations(
                            scram_credential);
                        switch (mechanism) {
                        case RD_KAFKA_SCRAM_MECHANISM_UNKNOWN:
                                printf(
                                    "        Mechanism is "
                                    "UNKNOWN\n");
                                break;
                        case RD_KAFKA_SCRAM_MECHANISM_SHA_256:
                                printf(
                                    "        Mechanism is "
                                    "SCRAM-SHA-256\n");
                                break;
                        case RD_KAFKA_SCRAM_MECHANISM_SHA_512:
                                printf(
                                    "        Mechanism is "
                                    "SCRAM-SHA-512\n");
                                break;
                        default:
                                printf(
                                    "        Mechanism does "
                                    "not match enums\n");
                        }
                        printf("        Iterations are %d\n", iterations);
                }
        }
}

static void print_alteration_responses(
    const rd_kafka_AlterUserScramCredentials_result_response_t **responses,
    size_t responses_cnt) {
        size_t i;
        printf("AlterUserScramCredentials responses [%zu]:\n", responses_cnt);
        for (i = 0; i < responses_cnt; i++) {
                const rd_kafka_AlterUserScramCredentials_result_response_t
                    *response = responses[i];
                const char *username;
                const rd_kafka_error_t *error;
                username =
                    rd_kafka_AlterUserScramCredentials_result_response_user(
                        response);
                error =
                    rd_kafka_AlterUserScramCredentials_result_response_error(
                        response);
                rd_kafka_resp_err_t err = rd_kafka_error_code(error);
                if (err) {
                        const char *errstr = rd_kafka_error_string(error);
                        printf("    Username: \"%s\", Error: \"%s\"\n",
                               username, rd_kafka_err2str(err));
                        printf("        ErrorMessage: \"%s\"\n", errstr);
                } else {
                        printf("    Username: \"%s\" Success\n", username);
                }
        }
}

static void Describe(rd_kafka_t *rk, const char **users, size_t user_cnt) {
        rd_kafka_event_t *event;
        char errstr[512]; /* librdkafka API error reporting buffer */

        rd_kafka_AdminOptions_t *options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_DESCRIBEUSERSCRAMCREDENTIALS);

        if (rd_kafka_AdminOptions_set_request_timeout(
                options, 30 * 1000 /* 30s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set timeout: %s\n", errstr);
                return;
        }

        /* NULL argument gives us all the users*/
        rd_kafka_DescribeUserScramCredentials(rk, users, user_cnt, options,
                                              queue);
        rd_kafka_AdminOptions_destroy(options);

        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /*indefinitely*/);
        if (!event) {
                /* User hit Ctrl-C */
                fprintf(stderr, "%% Cancelled by user\n");

        } else if (rd_kafka_event_error(event)) {
                /* Request failed */
                fprintf(stderr, "%% DescribeUserScramCredentials failed: %s\n",
                        rd_kafka_event_error_string(event));

        } else {
                /* Request succeeded */
                const rd_kafka_DescribeUserScramCredentials_result_t *result;
                const rd_kafka_UserScramCredentialsDescription_t **descriptions;
                size_t description_cnt;
                result =
                    rd_kafka_event_DescribeUserScramCredentials_result(event);
                descriptions =
                    rd_kafka_DescribeUserScramCredentials_result_descriptions(
                        result, &description_cnt);
                print_descriptions(descriptions, description_cnt);
        }
        rd_kafka_event_destroy(event);
}

static void Alter(rd_kafka_t *rk,
                  rd_kafka_UserScramCredentialAlteration_t **alterations,
                  size_t alteration_cnt) {
        rd_kafka_event_t *event;
        char errstr[512]; /* librdkafka API error reporting buffer */

        /* Set timeout (optional) */
        rd_kafka_AdminOptions_t *options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_ALTERUSERSCRAMCREDENTIALS);

        if (rd_kafka_AdminOptions_set_request_timeout(
                options, 30 * 1000 /* 30s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set timeout: %s\n", errstr);
                return;
        }

        /* Call the AlterUserScramCredentials function*/
        rd_kafka_AlterUserScramCredentials(rk, alterations, alteration_cnt,
                                           options, queue);
        rd_kafka_AdminOptions_destroy(options);

        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /*indefinitely*/);
        if (!event) {
                /* User hit Ctrl-C */
                fprintf(stderr, "%% Cancelled by user\n");

        } else if (rd_kafka_event_error(event)) {
                /* Request failed */
                fprintf(stderr, "%% AlterUserScramCredentials failed: %s\n",
                        rd_kafka_event_error_string(event));

        } else {
                /* Request succeeded */
                const rd_kafka_AlterUserScramCredentials_result_t *result =
                    rd_kafka_event_AlterUserScramCredentials_result(event);
                const rd_kafka_AlterUserScramCredentials_result_response_t *
                    *responses;
                size_t responses_cnt;
                responses = rd_kafka_AlterUserScramCredentials_result_responses(
                    result, &responses_cnt);

                print_alteration_responses(responses, responses_cnt);
        }
        rd_kafka_event_destroy(event);
}

static void cmd_user_scram(rd_kafka_conf_t *conf, int argc, const char **argv) {
        char errstr[512]; /* librdkafka API error reporting buffer */
        rd_kafka_t *rk;   /* Admin client instance */
        size_t i;
        const int min_argc  = 1;
        const int args_rest = argc - min_argc;

        int is_describe = 0;
        int is_upsert   = 0;
        int is_delete   = 0;

        /*
         * Argument validation
         */
        int correct_argument_cnt = argc >= min_argc;

        if (!correct_argument_cnt)
                usage("Wrong number of arguments");

        is_describe = !strcmp(argv[0], "DESCRIBE");
        is_upsert   = !strcmp(argv[0], "UPSERT");
        is_delete   = !strcmp(argv[0], "DELETE");

        correct_argument_cnt = is_describe ||
                               (is_upsert && (args_rest % 5) == 0) ||
                               (is_delete && (args_rest % 2) == 0) || 0;

        if (!correct_argument_cnt)
                usage("Wrong number of arguments");


        /*
         * Create an admin client, it can be created using any client type,
         * so we choose producer since it requires no extra configuration
         * and is more light-weight than the consumer.
         *
         * NOTE: rd_kafka_new() takes ownership of the conf object
         *       and the application must not reference it again after
         *       this call.
         */
        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        if (!rk) {
                fprintf(stderr, "%% Failed to create new producer: %s\n",
                        errstr);
                exit(1);
        }

        /* The Admin API is completely asynchronous, results are emitted
         * on the result queue that is passed to DeleteRecords() */
        queue = rd_kafka_queue_new(rk);

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        if (is_describe) {

                /* Describe  the users */
                Describe(rk, &argv[min_argc], argc - min_argc);

        } else if (is_upsert) {
                size_t upsert_cnt        = args_rest / 5;
                const char **upsert_args = &argv[min_argc];
                rd_kafka_UserScramCredentialAlteration_t **upserts =
                    calloc(upsert_cnt, sizeof(*upserts));
                for (i = 0; i < upsert_cnt; i++) {
                        const char **upsert_args_curr = &upsert_args[i * 5];
                        size_t salt_size              = 0;
                        const char *username          = upsert_args_curr[0];
                        rd_kafka_ScramMechanism_t mechanism =
                            parse_mechanism(upsert_args_curr[1]);
                        int iterations =
                            parse_int("iterations", upsert_args_curr[2]);
                        const char *password = upsert_args_curr[3];
                        const char *salt     = upsert_args_curr[4];

                        if (strlen(salt) == 0)
                                salt = NULL;
                        else
                                salt_size = strlen(salt);

                        upserts[i] = rd_kafka_UserScramCredentialUpsertion_new(
                            username, mechanism, iterations,
                            (const unsigned char *)password, strlen(password),
                            (const unsigned char *)salt, salt_size);
                }
                Alter(rk, upserts, upsert_cnt);
                rd_kafka_UserScramCredentialAlteration_destroy_array(
                    upserts, upsert_cnt);
                free(upserts);
        } else {
                size_t deletion_cnt      = args_rest / 2;
                const char **delete_args = &argv[min_argc];
                rd_kafka_UserScramCredentialAlteration_t **deletions =
                    calloc(deletion_cnt, sizeof(*deletions));
                for (i = 0; i < deletion_cnt; i++) {
                        const char **delete_args_curr = &delete_args[i * 2];
                        rd_kafka_ScramMechanism_t mechanism =
                            parse_mechanism(delete_args_curr[1]);
                        const char *username = delete_args_curr[0];

                        deletions[i] = rd_kafka_UserScramCredentialDeletion_new(
                            username, mechanism);
                }
                Alter(rk, deletions, deletion_cnt);
                rd_kafka_UserScramCredentialAlteration_destroy_array(
                    deletions, deletion_cnt);
                free(deletions);
        }

        signal(SIGINT, SIG_DFL);

        /* Destroy queue */
        rd_kafka_queue_destroy(queue);


        /* Destroy the producer instance */
        rd_kafka_destroy(rk);
}

int main(int argc, char **argv) {
        rd_kafka_conf_t *conf; /**< Client configuration object */
        int opt;
        argv0 = argv[0];

        /*
         * Create Kafka client configuration place-holder
         */
        conf = rd_kafka_conf_new();


        /*
         * Parse common options
         */
        while ((opt = getopt(argc, argv, "b:X:d:")) != -1) {
                switch (opt) {
                case 'b':
                        conf_set(conf, "bootstrap.servers", optarg);
                        break;

                case 'X': {
                        char *name = optarg, *val;

                        if (!(val = strchr(name, '=')))
                                fatal("-X expects a name=value argument");

                        *val = '\0';
                        val++;

                        conf_set(conf, name, val);
                        break;
                }

                case 'd':
                        conf_set(conf, "debug", optarg);
                        break;

                default:
                        usage("Unknown option %c", (char)opt);
                }
        }

        cmd_user_scram(conf, argc - optind, (const char **)&argv[optind]);
        return 0;
}
