/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_parser.h>
#include <semaphore.h>
#include "flb_tests_runtime.h"

extern struct flb_output_plugin out_stdout_plugin;

void init_test(void) __attribute__ ((constructor));

static sem_t sem_last_tag;
static char last_tag[256] = { 0 };
static void (*old_cb_stdout_flush)(const void *data, size_t bytes, const char *tag, int tag_len, struct flb_input_instance *i_ins, void *out_context, struct flb_config *config);
static void cb_stdout_flush(const void *data, size_t bytes, const char *tag, int tag_len, struct flb_input_instance *i_ins, void *out_context, struct flb_config *config);

/* Test data */
const char SYSLOG_DATA[] = "<162>1 2019-08-15T15:50:46.866915+03:00 localhost MyApp 5001 Type1 - No chain 'foo' found in org.springframework...\n";
const char SYSLOG_LONG_DATA[] = "<162>1 2019-08-15T15:50:46.866915+03:00 localhost 123456789012345678901234567890123456789X 5001 ABCDEFGHIJKLMNOPQRSTUVWXYZ9876543210 - No chain 'foo' found in org.springframework...\n";

/* Test functions */
void flb_test_syslog(const char* log_data, const char *tag_def, const char *result_tag);
void flb_test_syslog_tagging_static(void);
void flb_test_syslog_tagging_with_ident(void);
void flb_test_syslog_tagging_with_ident_n_msgid(void);
void flb_test_syslog_tagging_minimal(void);
void flb_test_syslog_tagging_oversized(void);
void flb_test_syslog_tagging_long_fields(void);

/* Test list */
TEST_LIST = {
    {"tagging_static",             flb_test_syslog_tagging_static },
    {"tagging_with_ident",         flb_test_syslog_tagging_with_ident },
    {"tagging_with_ident_n_msgid", flb_test_syslog_tagging_with_ident_n_msgid},
    {"tagging_minimal",            flb_test_syslog_tagging_minimal},
    {"tagging_oversized",          flb_test_syslog_tagging_oversized},
    {"tagging_long_fields",        flb_test_syslog_tagging_long_fields},
    {NULL, NULL}
};


void init_test(void)
{
    sem_init(&sem_last_tag, 0, 0);
    old_cb_stdout_flush = out_stdout_plugin.cb_flush;
    out_stdout_plugin.cb_flush = cb_stdout_flush;
}

static void cb_stdout_flush(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    strncpy(last_tag, tag, tag_len);
    last_tag[tag_len] = '\0';
    sem_post(&sem_last_tag);
    old_cb_stdout_flush(data, bytes, tag, tag_len, i_ins, out_context, config);
}

void flb_test_syslog_tagging_static(void)
{
    flb_test_syslog(SYSLOG_DATA, "Syslog", "Syslog");
}

void flb_test_syslog_tagging_with_ident(void)
{
    flb_test_syslog(SYSLOG_DATA, "Syslog_*X", "Syslog_MyAppX");
}

void flb_test_syslog_tagging_with_ident_n_msgid(void)
{
    flb_test_syslog(SYSLOG_DATA, "Syslog_*_*X", "Syslog_MyApp_Type1X");
}

void flb_test_syslog_tagging_minimal(void)
{
    flb_test_syslog(SYSLOG_DATA, "**", "MyAppType1");
}

void flb_test_syslog_tagging_oversized(void)
{
    char input_tag[128];
    char output_tag[128];
    int i;
    for (i = 0; i < 120; i++) {
        input_tag[i] = output_tag[i] = '_';
    }
    input_tag[120] = output_tag[120] = '\0';
    strcat(input_tag, "*_*");
    strcat(output_tag, "MyApp_T");
    flb_test_syslog(SYSLOG_DATA, input_tag, output_tag);
}

// for msgpack string between 32-255 bytes
void flb_test_syslog_tagging_long_fields(void)
{
    flb_test_syslog(SYSLOG_LONG_DATA, "*-*", "123456789012345678901234567890123456789X-ABCDEFGHIJKLMNOPQRSTUVWXYZ9876543210");
}

void flb_test_syslog(const char *log_data, const char *tag_def, const char *result_tag)
{
    flb_ctx_t *ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    struct flb_parser *parser = flb_parser_create(
        "syslog-rfc5424", "regex", "^\\<(?<pri>[0-9]{1,5})\\>1 (?<time>[^ ]+) (?<host>[^ ]+) (?<ident>[^ ]+) (?<pid>[-0-9]+) (?<msgid>[^ ]+) (?<extradata>(\\[(.*)\\]|-)) (?<message>.+)$",
        "%Y-%m-%dT%H:%M:%S.%L", "time", NULL, MK_TRUE, NULL, 0,
        NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    int in_ffd = flb_input(ctx, (char *) "syslog", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "mode", "tcp", NULL);
    flb_input_set(ctx, in_ffd, "tag", tag_def, NULL);

    int out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    int flb_ret = flb_start(ctx);
    TEST_CHECK(flb_ret == 0);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_CHECK(sockfd >= 0);

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(5140),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_zero = { 0 }
    };
    TEST_CHECK(connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) >= 0);

    int data_len = strlen(log_data);
    TEST_CHECK(write(sockfd, log_data, data_len) == data_len);
    close(sockfd);

    sem_wait(&sem_last_tag);

    flb_info("[test_in_syslog] received tag: [%s]", last_tag);
    TEST_CHECK(strcmp(last_tag, result_tag) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

