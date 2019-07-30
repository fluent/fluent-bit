/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#define _GNU_SOURCE /* for accept4 */
#include <fluent-bit.h>
#include <fluent-bit/flb_info.h>
#include "flb_tests_runtime.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

struct kube_test {
    flb_ctx_t *flb;
};

struct kube_test_result {
    const char *target;
    const char *suffix;
    int   type;
    int   nMatched;
};

/* Test target mode */
#define KUBE_TAIL     0
#define KUBE_SYSTEMD  1

#ifdef FLB_HAVE_SYSTEMD
int flb_test_systemd_send(void);
char kube_test_id[64];
#endif

/* Constants */
#define KUBE_IP          "127.0.0.1"
#define KUBE_PORT        "8002"
#define KUBE_URL         "http://" KUBE_IP ":" KUBE_PORT
#define DPATH            FLB_TESTS_DATA_PATH "/data/kubernetes"

/*
 * Data files
 * ==========
 */
#define T_APACHE_LOGS           "default_apache-logs_apache-logs"
#define T_APACHE_LOGS_ANN       "default_apache-logs-annotated_apache-logs-annotated"
#define T_APACHE_LOGS_ANN_INV   "default_apache-logs-annotated-invalid_apache-logs-annotated-invalid"
#define T_APACHE_LOGS_ANN_MERGE "default_apache-logs-annotated-merge_apache-logs-annotated-merge"
#define T_APACHE_LOGS_ANN_EXCL  "default_apache-logs-annotated-exclude_apache-logs-annotated-exclude"
#define T_JSON_LOGS             "default_json-logs_json-logs"
#define T_JSON_LOGS_NO_KEEP     "default_json-logs-no-keep_json-logs-no-keep"
#define T_JSON_LOGS_INV         "default_json-logs-invalid_json-logs-invalid"
#define T_JSON_LOGS_INV_NO_KEEP "default_json-logs-invalid_json-logs-invalid"
#define T_SYSTEMD_SIMPLE        "kairosdb-914055854-b63vq"

#define T_MULTI_INIT            "socks_session-db-fdd649d68-cq5sp_istio-init"
#define T_MULTI_PROXY           "socks_session-db-fdd649d68-cq5sp_istio-proxy"
#define T_MULTI_REDIS           "socks_session-db-fdd649d68-cq5sp_session-db"

static int file_to_buf(const char *path, char **out_buf, size_t *out_size)
{
    int ret;
    long bytes;
    char *buf;
    FILE *fp;
    struct stat st;

    ret = stat(path, &st);
    if (ret == -1) {
        return -1;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    buf = flb_malloc(st.st_size);
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes != 1) {
        flb_errno();
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}

/* Given a target, lookup the .out file and return it content in a new buffer */
static char *get_out_file_content(const char *target, const char *suffix)
{
    int ret;
    char file[PATH_MAX];
    char *p;
    char *out_buf;
    size_t out_size;

    if (suffix) {
        snprintf(file, sizeof(file) - 1, DPATH "/out/%s_%s.out", target, suffix);
    }
    else {
        snprintf(file, sizeof(file) - 1, DPATH "/out/%s.out", target);
    }

    ret = file_to_buf(file, &out_buf, &out_size);
    TEST_CHECK_(ret == 0, "getting output file content: %s", file);
    if (ret != 0) {
        return NULL;
    }

    /* Sanitize content, get rid of ending \n */
    p = out_buf + (out_size - 1);
    while (*p == '\n' || *p == '\r') p--;
    *++p = '\0';

    return out_buf;
}

static int cb_check_result(void *record, size_t size, void *data)
{
    struct kube_test_result *result;
    char *out;

    result = (struct kube_test_result *) data;
    out = get_out_file_content(result->target, result->suffix);
    if (!out) {
        return -1;
    }
    if (result->type == KUBE_SYSTEMD) {
        char *skip_record, *skip_out;
        int check;

        /* Skip the other records since some are created by systemd,
           only check the kubernetes annotations
         */
        skip_out = strstr(out, "\"kubernetes\":");
        skip_record = strstr(record, "\"kubernetes\":");
        if (skip_out && skip_record) {
            check = strcmp(skip_record, skip_out);
            TEST_CHECK(check == 0);
            if (check != 0) {
                printf("skip_record: %s\nskip_out: %s\n",
                         skip_record, skip_out);
            }
            result->nMatched++;
        }
    } else {
        char *check;
        char streamfilter[64] = {'\0'};

        if (result->suffix && *result->suffix) {
            sprintf(streamfilter, "\"stream\":\"%s\"", result->suffix);
        }
        if (!*streamfilter ||
            strstr(record, streamfilter)) {

            /*
             * Our validation is: check that the content of out file is found
             * in the output record.
             */
            check = strstr(record, out);
            TEST_CHECK_(check != NULL,
                       "comparing expected record with actual record");
            if (check == NULL) {
                if (result->suffix) {
                    printf("Target: %s, suffix: %s\n",
                           result->target, result->suffix);
                }
                else
                {
                    printf("Target: %s\n",
                           result->target);
                }
                printf("Expected record:\n%s\n"
                       "Actual record:\n%s\n",
                       out, (char *)record);
            }
            result->nMatched++;
        }
    }
    if (size > 0) {
        flb_free(record);
    }
    flb_free(out);
    return 0;
}

static void kube_test(const char *target, int type, const char *suffix, int nExpected, ...)
{
    int ret;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *key;
    char *value;
    char path[PATH_MAX];
    va_list va;
    struct kube_test ctx;
    struct flb_lib_out_cb cb_data;
    struct kube_test_result result = {0};

    result.nMatched = 0;
    result.target = target;
    result.suffix = suffix;
    result.type = type;

    ctx.flb = flb_create();
    TEST_CHECK_(ctx.flb != NULL, "initialising service");
    if (!ctx.flb) {
        goto exit;
    }

    ret = flb_service_set(ctx.flb,
                          "Flush", "1",
                          "Grace", "1",
                          "Log_Level", "error",
                          "Parsers_File", DPATH "/parsers.conf",
                          NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    if (type == KUBE_TAIL) {
        /* Compose path based on target */
        snprintf(path, sizeof(path) - 1, DPATH "/log/%s.log", target);
        TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);
        in_ffd = flb_input(ctx.flb, "tail", NULL);
        TEST_CHECK_(in_ffd >= 0, "initialising input");
        ret = flb_input_set(ctx.flb, in_ffd,
                            "Tag", "kube.<namespace>.<pod>.<container>",
                            "Tag_Regex", "^" DPATH "/log/(?<namespace>.+)_(?<pod>.+)_(?<container>.+)\\.log$",
                            "Path", path,
                            "Parser", "docker",
                            "Docker_Mode", "On",
                            NULL);
        TEST_CHECK_(ret == 0, "setting input options");
    }
#ifdef FLB_HAVE_SYSTEMD
    else if (type == KUBE_SYSTEMD) {
        sprintf(kube_test_id, "KUBE_TEST=%u%lu", getpid(), random());
        in_ffd = flb_input(ctx.flb, "systemd", NULL);
        TEST_CHECK_(in_ffd >= 0, "initialising input");
        ret = flb_input_set(ctx.flb, in_ffd,
                            "Tag", "kube.*",
                            "Systemd_Filter", kube_test_id,
                            NULL);
        TEST_CHECK_(ret == 0, "setting input options");
    }
#endif

    filter_ffd = flb_filter(ctx.flb, "kubernetes", NULL);
    TEST_CHECK_(filter_ffd >= 0, "initialising filter");
    ret = flb_filter_set(ctx.flb, filter_ffd,
                         "Match", "kube.*",
                         "Kube_Url", KUBE_URL,
                         "Kube_Meta_Preload_Cache_Dir", DPATH "/meta",
                         NULL);
    TEST_CHECK_(ret == 0, "setting filter options");

    /* Iterate number of arguments for filter_kubernetes additional options */
    va_start(va, nExpected);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            break;
        }
        ret = flb_filter_set(ctx.flb, filter_ffd, key, value, NULL);
        TEST_CHECK_(ret == 0, "setting filter additional options");
    }
    va_end(va);

    if (type == KUBE_TAIL) {
        ret = flb_filter_set(ctx.flb, filter_ffd,
                             "Regex_Parser", "kubernetes-tag",
                             "Kube_Tag_Prefix", "kube.",
                             NULL);
        TEST_CHECK_(ret == 0, "setting filter specific options");
    }
#ifdef FLB_HAVE_SYSTEMD
    else if (type == KUBE_SYSTEMD) {
        ret = flb_filter_set(ctx.flb, filter_ffd,
                             "Use_Journal", "On",
                             NULL);
        TEST_CHECK_(ret == 0, "setting filter specific options");
    }
#endif

    /* Prepare output callback context*/
    cb_data.cb = cb_check_result;
    cb_data.data = &result;

    /* Output */
    out_ffd = flb_output(ctx.flb, "lib", (void *) &cb_data);
    TEST_CHECK_(out_ffd >= 0, "initialising output");
    flb_output_set(ctx.flb, out_ffd,
                   "Match", "kube.*",
                   "format", "json",
                   NULL);
    TEST_CHECK_(ret == 0, "setting output options");

#ifdef FLB_HAVE_SYSTEMD
    /*
     * If the source of data is Systemd, just let the output lib plugin
     * to process one record only, otherwise when the test case stop after
     * the first callback it destroy the contexts, but out_lib still have
     * pending data to flush. This option solves the problem.
     */
    if (type == KUBE_SYSTEMD) {
        flb_output_set(ctx.flb, out_ffd,
                       "Max_Records", "1",
                       NULL);
        TEST_CHECK_(ret == 0, "setting output specific options");
    }
#endif

    /* Start the engine */
    ret = flb_start(ctx.flb);
    TEST_CHECK_(ret == 0, "starting engine");
    if (ret == -1) {
        goto exit;
    }
#ifdef FLB_HAVE_SYSTEMD
    if (type == KUBE_SYSTEMD) {
        TEST_CHECK_(flb_test_systemd_send() >= 0,
                    "sending sample message to journal");
    }
#endif

    /* Poll for up to 2 seconds or until we got a match */
    for (ret = 0; ret < 2000 && result.nMatched == 0; ret++) {
        usleep(1000);
    }
    TEST_CHECK(result.nMatched == nExpected);
    TEST_MSG("result.nMatched: %i\nnExpected: %i", result.nMatched, nExpected);

    ret = flb_stop(ctx.flb);
    TEST_CHECK_(ret == 0, "stopping engine");

exit:
    if (ctx.flb) {
        flb_destroy(ctx.flb);
    }
}

static void flb_test_apache_logs()
{
    kube_test(T_APACHE_LOGS, KUBE_TAIL, NULL, 1, NULL);
}

static void flb_test_apache_logs_merge()
{
    kube_test(T_APACHE_LOGS, KUBE_TAIL, NULL, 1,
              "Merge_Log", "On",
              "Merge_Log_Key", "merge",
              NULL);
}

static void flb_test_apache_logs_annotated()
{
    kube_test(T_APACHE_LOGS_ANN, KUBE_TAIL, NULL, 1,
              "k8s-logging.parser", "On",
              "Merge_Log", "On",
              NULL);
}

static void flb_test_apache_logs_annotated_invalid()
{
    kube_test(T_APACHE_LOGS_ANN_INV, KUBE_TAIL, NULL, 1,
              "k8s-logging.parser", "On",
              NULL);
}

static void flb_test_apache_logs_annotated_exclude()
{
    kube_test(T_APACHE_LOGS_ANN_EXCL, KUBE_TAIL, NULL, 0,
              "k8s-logging.exclude", "On",
              NULL);
}

static void flb_test_apache_logs_annotated_merge()
{
    kube_test(T_APACHE_LOGS_ANN_MERGE, KUBE_TAIL, NULL, 1,
              "k8s-logging.parser", "On",
              "Merge_Log", "On",
              "Merge_Log_Key", "merge",
              NULL);
}

static void flb_test_json_logs()
{
    kube_test(T_JSON_LOGS, KUBE_TAIL, NULL, 1,
              "Merge_Log", "On",
              NULL);
}

static void flb_test_json_logs_no_keep()
{
    kube_test(T_JSON_LOGS_NO_KEEP, KUBE_TAIL, NULL, 1,
              "Merge_Log", "On",
              "Keep_Log", "Off",
              NULL);
}

static void flb_test_json_logs_invalid()
{
    kube_test(T_JSON_LOGS_INV, KUBE_TAIL, NULL, 1, NULL);
}

static void flb_test_json_logs_invalid_no_keep()
{
    kube_test(T_JSON_LOGS_INV_NO_KEEP, KUBE_TAIL, NULL, 1,
              "Merge_Log", "On",
              "Keep_Log", "Off",
              NULL);
}

#ifdef FLB_HAVE_SYSTEMD
#define CONTAINER_NAME "CONTAINER_NAME=k8s_kairosdb_kairosdb-914055854-b63vq_default_d6c53deb-05a4-11e8-a8c4-080027435fb7_23"
#include <systemd/sd-journal.h>

int flb_test_systemd_send()
{
    return sd_journal_send(
            "@timestamp=2018-02-23T08:58:45.0Z",
            "PRIORITY=6",
            CONTAINER_NAME,
            "CONTAINER_TAG=",
            "CONTAINER_ID=56e257661383",
            "CONTAINER_ID_FULL=56e257661383836fac4cd90a23ee8a7a02ee1538c8f35657d1a90f3de1065a22",
            "MESSAGE=08:58:45.839 [qtp151442075-47] DEBUG [HttpParser.java:281] - filled 157/157",
            kube_test_id,
            NULL);
}

static void flb_test_systemd_logs()
{
    struct stat statb;
    /* We want to avoid possibly getting a log from a previous run,
       so create a unique-id for each 'send' */
    sprintf(kube_test_id, "KUBE_TEST=%u%lu", getpid(), random());

    if (stat("/run/systemd/journal/socket", &statb) == 0 &&
        statb.st_mode & S_IFSOCK) {

        int r;
        sd_journal *journal;
        r = sd_journal_open(&journal, 0);
        if (r < 0) {
            flb_error("Skip test: journal error: ", strerror(-r));
            return;
        }

        r = sd_journal_get_fd(journal);
        if (r < 0) {
            flb_error("Skip test: journal fd error: ", strerror(-r));
            sd_journal_close(journal);
            return;
        }
        sd_journal_add_match(journal, CONTAINER_NAME, 0);
        sd_journal_seek_tail(journal);

        /*
         * Send test message to Journal. If this fails (e.g. journal is
         * not running then skip the test.
         */
        if (flb_test_systemd_send() < 0) {

            flb_error("Skip test: journal send error: ", strerror(-r));
            sd_journal_close(journal);
            return;
        }

        r = sd_journal_previous(journal);
        if (r < 0) {
            flb_error("Skip test: journal previous error: ", strerror(-r));
            sd_journal_close(journal);
            return;
        }

        r = sd_journal_next(journal);
        if (r < 0) {
            flb_error("Skip test: journal next error: ", strerror(-r));
            sd_journal_close(journal);
            return;
        }

        r = sd_journal_wait(journal, 2000);
        if (r < 0) {
            flb_error("Skip test: journal wait error: ", strerror(-r));
            sd_journal_close(journal);
            return;
        }
        sd_journal_close(journal);

        kube_test(T_SYSTEMD_SIMPLE, KUBE_SYSTEMD, NULL, 1,
                  "Merge_Log", "On",
                  NULL);
    }
}
#endif

static void flb_test_multi_logs(char *log, char *suffix)
{
    kube_test(log, KUBE_TAIL, suffix, 1,
              "k8s-logging.parser", "On",
              "Merge_Log", "On",
              NULL);
}
static void flb_test_multi_init_stdout() { flb_test_multi_logs(T_MULTI_INIT, "stdout"); }
static void flb_test_multi_init_stderr() { flb_test_multi_logs(T_MULTI_INIT, "stderr"); }
static void flb_test_multi_proxy() { flb_test_multi_logs(T_MULTI_PROXY, NULL); }
static void flb_test_multi_redis() { flb_test_multi_logs(T_MULTI_REDIS, NULL); }

TEST_LIST = {
    {"kube_apache_logs", flb_test_apache_logs},
    {"kube_apache_logs_merge", flb_test_apache_logs_merge},
    {"kube_apache_logs_annotated", flb_test_apache_logs_annotated},
    {"kube_apache_logs_annotated_invalid", flb_test_apache_logs_annotated_invalid},
    {"kube_apache_logs_annotated_exclude", flb_test_apache_logs_annotated_exclude},
    {"kube_apache_logs_annotated_merge_log", flb_test_apache_logs_annotated_merge},
    {"kube_json_logs", flb_test_json_logs},
    {"kube_json_logs_no_keep", flb_test_json_logs_no_keep},
    {"kube_json_logs_invalid", flb_test_json_logs_invalid},
    {"kube_json_logs_invalid_no_keep", flb_test_json_logs_invalid_no_keep},
#ifdef FLB_HAVE_SYSTEMD
    {"kube_systemd_logs", flb_test_systemd_logs},
#endif
    {"kube_multi_init_stdout", flb_test_multi_init_stdout},
    {"kube_multi_init_stderr", flb_test_multi_init_stderr},
    {"kube_multi_proxy", flb_test_multi_proxy},
    {"kube_multi_redis", flb_test_multi_redis},
    {NULL, NULL}
};
