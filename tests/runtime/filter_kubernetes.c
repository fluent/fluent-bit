/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#define _GNU_SOURCE /* for accept4 */
#include <fluent-bit.h>
#include <monkey/mk_lib.h>
#include "flb_tests_runtime.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

struct kube_test {
    flb_ctx_t *flb;
    mk_ctx_t *http;
};

struct kube_test_result {
    char *target;
    char *suffix;
    int   nmatched;
};

/* Test target mode */
#define KUBE_TAIL     0
#define KUBE_SYSTEMD  1

/* Constants */
#define KUBE_IP       "127.0.0.1"
#define KUBE_PORT     "8002"
#define KUBE_URL      "http://" KUBE_IP ":" KUBE_PORT
#define DPATH         FLB_TESTS_DATA_PATH "/data/kubernetes/"
#define STD_PARSER    "../conf/parsers.conf"

/*
 * Data files
 * ==========
 */
#define T_APACHE_LOGS           DPATH "apache-logs_default"
#define T_APACHE_LOGS_ANN       DPATH "apache-logs-annotated_default"
#define T_APACHE_LOGS_ANN_INV   DPATH "apache-logs-annotated-invalid"
#define T_APACHE_LOGS_ANN_MERGE DPATH "apache-logs-annotated-merge"
#define T_JSON_LOGS             DPATH "json-logs_default"
#define T_JSON_LOGS_INV         DPATH "json-logs-invalid"
#define T_SYSTEMD_SIMPLE        DPATH "kairosdb-914055854-b63vq"

#define T_MULTI_INIT            DPATH "session-db-fdd649d68-cq5sp_socks_istio-init-"
#define T_MULTI_PROXY           DPATH "session-db-fdd649d68-cq5sp_socks_istio-proxy-"
#define T_MULTI_REDIS           DPATH "session-db-fdd649d68-cq5sp_socks_istio-session-db-"

static int file_to_buf(char *path, char **out_buf, size_t *out_size)
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

static void cb_api_server_root(mk_request_t *request, void *data)
{
    int ret;
    char *pod;
    char meta[PATH_MAX];
    char *uri = NULL;
    char *meta_buf;
    size_t meta_size;

    uri = strndup(request->uri.data, request->uri.len);
    pod = strrchr(uri, '/');
    if (!pod) {
        goto not_found;
    }

    snprintf(meta, sizeof(meta) - 1, "%s%s.meta", DPATH, pod);
    flb_free(uri);

    ret = file_to_buf(meta, &meta_buf, &meta_size);
    if (ret == -1) {
        goto not_found;
    }

    mk_http_status(request, 200);
    mk_http_send(request, meta_buf, meta_size, NULL);
    flb_free(meta_buf);
    mk_http_done(request);
    return;

 not_found:
    mk_http_status(request, 404);
    mk_http_send(request, "Resource not found\n", 19, NULL);
    mk_http_done(request);

}

/* A simple fake Kubernetes API Server */
static mk_ctx_t *api_server_create(char *listen, char *tcp)
{
    int vid;
    int ret;
    char tmp[32];
    mk_ctx_t *ctx;

    /* Monkey HTTP Server context */
    ctx = mk_create();
    if (!ctx) {
        flb_error("[rt-filter_kube] error creating API Server");
        return NULL;
    }

    /* Bind */
    snprintf(tmp, sizeof(tmp) -1, "%s:%s", listen, tcp);
    mk_config_set(ctx, "Listen", tmp, NULL);

    /* Default Virtual Host */
    vid = mk_vhost_create(ctx, NULL);
    mk_vhost_set(ctx, vid, "Name", "rt-filter_kube", NULL);
    mk_vhost_handler(ctx, vid, "/", cb_api_server_root, NULL);

    ret = mk_start(ctx);
    if (ret != 0) {
        TEST_CHECK(ret != 0);
        flb_error("Fake API Server ERROR");
        mk_destroy(ctx);
        return NULL;
    }

    return ctx;
}

static void api_server_stop(mk_ctx_t *ctx)
{
    mk_stop(ctx);
    mk_destroy(ctx);
}

/* Given a target, lookup the .out file and return it content in a new buffer */
static char *get_out_file_content(char *target, char *suffix)
{
    int ret;
    char file[PATH_MAX];
    char *p;
    char *out_buf;
    size_t out_size;

    snprintf(file, sizeof(file) - 1, "%s%s.out", target,suffix);

    ret = file_to_buf(file, &out_buf, &out_size);
    if (ret != 0) {
        flb_error("no output file found '%s'", file);
        exit(EXIT_FAILURE);
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
    char *check;
    char streamfilter[64];

    result = (struct kube_test_result *) data;
    out = get_out_file_content(result->target, result->suffix);
    if (!out) {
        exit(EXIT_FAILURE);
    }
    sprintf(streamfilter, "\"stream\":\"%s\"", result->suffix);
    if (!result->suffix || !*result->suffix || strstr(record, streamfilter)) {

        /*
         * Our validation is: check that the content of out file is found
         * in the output record.
         */
        check = strstr(record, out);
        if (!check) {
            fprintf(stderr, "Validator mismatch::\nTarget: <<%s>>, Suffix: <<%s>\n"
                            "Filtered record: <<%s>>\nExpected record: <<%s>>\n",
                            result->target, result->suffix, (char *)record, out);
        }
        TEST_CHECK(check != NULL);
        result->nmatched++;
    }
    if (size > 0) {
        flb_free(record);
    }
    flb_free(out);
    return 0;
}

static struct kube_test *kube_test_create(char *target, int type, char *suffix, char *parserconf, ...)
{
    int ret;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *key;
    char *value;
    char path[PATH_MAX];
    va_list va;
    struct kube_test *ctx;
    struct flb_lib_out_cb cb_data;
    struct kube_test_result result;

    result.nmatched = 0;
    result.target = target;
    result.suffix = suffix;

    /* Compose path pattern based on target */
    snprintf(path, sizeof(path) - 1, "%s*.log", target);

    ctx = flb_malloc(sizeof(struct kube_test));
    if (!ctx) {
        flb_errno();
        TEST_CHECK(ctx != NULL);
        exit(EXIT_FAILURE);
    }

    ctx->http = api_server_create(KUBE_IP, KUBE_PORT);
    TEST_CHECK(ctx->http != NULL);
    if (!ctx->http) {
        exit(EXIT_FAILURE);
    }

    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "1",
                    "Grace", "1",
                    "Parsers_File", parserconf,
                    NULL);

    if (type == KUBE_TAIL) {
        in_ffd = flb_input(ctx->flb, "tail", NULL);
        ret = flb_input_set(ctx->flb, in_ffd,
                            "Tag", "kube.*",
                            "Path", path,
                            "Parser", "docker",
                            "Decode_Field", "json log",
                            NULL);
        TEST_CHECK(ret == 0);
    }
    else if (type == KUBE_SYSTEMD) {
        in_ffd = flb_input(ctx->flb, "systemd", NULL);
        ret = flb_input_set(ctx->flb, in_ffd,
                            "Tag", "kube.*",
                            "Systemd_Filter", "KUBE_TEST=2018",
                            NULL);
        TEST_CHECK(ret == 0);
    }

    filter_ffd = flb_filter(ctx->flb, "kubernetes", NULL);
    ret = flb_filter_set(ctx->flb, filter_ffd,
                         "Match", "kube.*",
                         "Kube_URL", KUBE_URL,
                         "k8s-logging.parser", "On",
                         NULL);

    /* Iterate number of arguments for filter_kubernetes additional options */
    va_start(va, parserconf);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            break;
        }
        flb_filter_set(ctx->flb, filter_ffd, key, value, NULL);
    }
    va_end(va);

    if (type == KUBE_TAIL) {
        ret = flb_filter_set(ctx->flb, filter_ffd,
                             "Regex_Parser", "filter-kube-test",
                             NULL);
    }
    else if (type == KUBE_SYSTEMD) {
        flb_filter_set(ctx->flb, filter_ffd,
                       "Use_Journal", "On",
                       NULL);
    }

    /* Prepare output callback context*/
    cb_data.cb = cb_check_result;
    cb_data.data = &result;

    /* Output */
    out_ffd = flb_output(ctx->flb, "lib", (void *) &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx->flb, out_ffd,
                   "Match", "kube.*",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Poll for up to 2 seconds or until we got a match */
    for (ret = 0; ret < 2000 && result.nmatched == 0; ret++) {
        usleep(1000);
    }
    TEST_CHECK(result.nmatched);

    return ctx;
}

static void kube_test_destroy(struct kube_test *ctx)
{
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    api_server_stop(ctx->http);
    flb_free(ctx);
}

void flb_test_apache_logs()
{
    struct kube_test *ctx;

    ctx = kube_test_create(T_APACHE_LOGS, KUBE_TAIL, "", STD_PARSER, NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    kube_test_destroy(ctx);
}

void flb_test_apache_logs_merge()
{
    struct kube_test *ctx;

    ctx = kube_test_create(T_APACHE_LOGS, KUBE_TAIL, "", STD_PARSER,
                           "Merge_Log", "On",
                           "Merge_Log_Key", "merge",
                           NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    kube_test_destroy(ctx);
}

void flb_test_apache_logs_annotated()
{
    struct kube_test *ctx;

    ctx = kube_test_create(T_APACHE_LOGS_ANN, KUBE_TAIL, "", STD_PARSER,
                           "Merge_Log", "On",
                           NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    kube_test_destroy(ctx);
}

void flb_test_apache_logs_annotated_invalid()
{
    struct kube_test *ctx;

    ctx = kube_test_create(T_APACHE_LOGS_ANN_INV, KUBE_TAIL, "", STD_PARSER,
                           NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    kube_test_destroy(ctx);
}

void flb_test_apache_logs_annotated_merge()
{
    struct kube_test *ctx;

    ctx = kube_test_create(T_APACHE_LOGS_ANN_MERGE, KUBE_TAIL, "", STD_PARSER,
                           "Merge_Log", "On",
                           "Merge_Log_Key", "merge", NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    kube_test_destroy(ctx);
}

void flb_test_json_logs()
{
    struct kube_test *ctx;

    ctx = kube_test_create(T_JSON_LOGS, KUBE_TAIL, "", STD_PARSER,
                           "Merge_Log", "On",
                           NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    kube_test_destroy(ctx);
}

void flb_test_json_logs_invalid()
{
    struct kube_test *ctx;

    ctx = kube_test_create(T_JSON_LOGS_INV, KUBE_TAIL, "", STD_PARSER, NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    kube_test_destroy(ctx);
}

#ifdef FLB_HAVE_SYSTEMD
#include <systemd/sd-journal.h>
void flb_test_systemd_logs()
{
    struct stat statb;
    struct kube_test *ctx;

    if (stat("/run/systemd/journal/socket", &statb) == 0 && statb.st_mode & S_IFSOCK) {

        /* Send test message to Journal. If this fails (e.g. journal is not running
         * then skip the test
         */
        if (sd_journal_send(
                        "@timestamp=2018-02-23T08:58:45.0Z",
                        "PRIORITY=6",
                        "CONTAINER_NAME=k8s_kairosdb_kairosdb-914055854-b63vq_default_d6c53deb-05a4-11e8-a8c4-080027435fb7_23",
                        "CONTAINER_TAG=",
                        "CONTAINER_ID=56e257661383",
                        "CONTAINER_ID_FULL=56e257661383836fac4cd90a23ee8a7a02ee1538c8f35657d1a90f3de1065a22",
                        "MESSAGE=08:58:45.839 [qtp151442075-47] DEBUG [HttpParser.java:281] - filled 157/157",
                        "KUBE_TEST=2018",
                        NULL) == 0) {

            ctx = kube_test_create(T_SYSTEMD_SIMPLE, KUBE_SYSTEMD, "", STD_PARSER,
                                   "Merge_Log", "On",
                                   NULL);
            if (!ctx) {
                exit(EXIT_FAILURE);
            }
            kube_test_destroy(ctx);
        }
    }
}
#endif

void flb_test_multi_logs(char *log, char *suffix)
{
    struct kube_test *ctx;

    flb_info("\n");
    flb_info("Multi test: log <%s>", log);
    ctx = kube_test_create(log, KUBE_TAIL, suffix, "../tests/runtime/data/kubernetes/multi-parsers.conf", "Merge_Log", "On", NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    kube_test_destroy(ctx);
}
void flb_test_multi_init_stdout() { flb_test_multi_logs(T_MULTI_INIT, "stdout"); }
void flb_test_multi_init_stderr() { flb_test_multi_logs(T_MULTI_INIT, "stderr"); }
void flb_test_multi_proxy() { flb_test_multi_logs(T_MULTI_PROXY, ""); }
void flb_test_multi_redis() { flb_test_multi_logs(T_MULTI_REDIS, ""); }

TEST_LIST = {
    {"kube_apache_logs", flb_test_apache_logs},
    {"kube_apache_logs_merge", flb_test_apache_logs_merge},
    {"kube_apache_logs_annotated", flb_test_apache_logs_annotated},
    {"kube_apache_logs_annotated_invalid", flb_test_apache_logs_annotated_invalid},
    {"kube_apache_logs_annotated_merge_log", flb_test_apache_logs_annotated_merge},
    {"kube_json_logs", flb_test_json_logs},
    {"kube_json_logs_invalid", flb_test_json_logs_invalid},
#ifdef FLB_HAVE_SYSTEMD
    {"kube_systemd_logs", flb_test_systemd_logs},
#endif
    {"kube_multi_init_stdout", flb_test_multi_init_stdout},
    {"kube_multi_init_stderr", flb_test_multi_init_stderr},
    {"kube_multi_proxy", flb_test_multi_proxy},
    {"kube_multi_redis", flb_test_multi_redis},
    {NULL, NULL}
};
