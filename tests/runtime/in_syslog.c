/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_parser.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef FLB_HAVE_UNIX_SOCKET
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <fcntl.h>
#include "flb_tests_runtime.h"

#define DPATH            FLB_TESTS_DATA_PATH "/data/common"

/* Examples from RFCs */
#define RFC5424_EXAMPLE_1 "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8\n"
#define RFC3164_EXAMPLE_1 "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"

char *RFC5424_EXPECTED_STRS_1[] = {"\"pri\":\"34\"", "\"message\":\"'su root' failed for lonvick on /dev/pts/8\"",
                                   "\"host\":\"mymachine.example.com\"", "\"msgid\":\"ID47\"","\"time\":\"2003-10-11T22:14:15.003Z\"",
                                   "\"ident\":\"su\""
};

char *RFC5424_EXPECTED_STRS_TCP[] = {"\"pri\":\"34\"", "\"message\":\"'su root' failed for lonvick on /dev/pts/8\"",
                                     "\"host\":\"mymachine.example.com\"", "\"msgid\":\"ID47\"","\"time\":\"2003-10-11T22:14:15.003Z\"",
                                     "\"ident\":\"su\"",
                                     "\"source_host\":\"tcp://"
};

char *RFC5424_EXPECTED_STRS_UDP[] = {"\"pri\":\"34\"", "\"message\":\"'su root' failed for lonvick on /dev/pts/8\"",
                                     "\"host\":\"mymachine.example.com\"", "\"msgid\":\"ID47\"","\"time\":\"2003-10-11T22:14:15.003Z\"",
                                     "\"ident\":\"su\"",
                                     "\"source_host\":\"udp://"
};

char *RFC3164_EXPECTED_STRS_1[] = {"\"pri\":\"34\"", "\"message\":\"'su root' failed for lonvick on /dev/pts/8\"",
                                   "\"host\":\"mymachine\"", "\"time\":\"Oct 11 22:14:15\"", "\"ident\":\"su\""
};


struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */
};


pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    set_output_num(0);
}

struct str_list {
    size_t size;
    char **lists;
};

/* Callback to check expected results */
static int cb_check_json_str_list(void *record, size_t size, void *data)
{
    char *p;
    char *result;
    int num = get_output_num();
    size_t i;
    struct str_list *l = (struct str_list*)data;

    if (!TEST_CHECK(l != NULL)) {
        flb_error("Data is NULL");
        flb_free(record);
        return 0;
    }
    set_output_num(num+1);

    result = (char *) record;

    for (i=0; i<l->size; i++) {
        p = strstr(result, l->lists[i]);
        if(!TEST_CHECK(p != NULL)) {
            flb_error("Expected to find: '%s' in result '%s'",
                      l->lists[i], result);
        }
    }
    flb_free(record);
    return 0;
}

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    int ret;
    struct test_ctx *ctx = NULL;

    ctx = flb_malloc(sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("malloc failed");
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    "Parsers_File", DPATH "/parsers.conf",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "syslog", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    return ctx;
}

#define PARSER_NAME_RFC5424 "syslog-rfc5424"
#define PARSER_NAME_RFC3164 "syslog-rfc3164"

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 5140
static flb_sockfd_t connect_tcp(char *in_host, int in_port)
{
    int port = in_port;
    char *host = in_host;
    flb_sockfd_t fd;
    int ret;
    struct sockaddr_in addr;

    if (host == NULL) {
        host = DEFAULT_HOST;
    }
    if (port < 0) {
        port = DEFAULT_PORT;
    }

    memset(&addr, 0, sizeof(addr));
    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("failed to socket. host=%s port=%d errno=%d", host, port, errno);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    ret = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("failed to connect. host=%s port=%d errno=%d", host, port, errno);
        flb_socket_close(fd);
        return -1;
    }
    return fd;
}

#ifdef FLB_HAVE_UNIX_SOCKET
static flb_sockfd_t connect_tcp_unix(char *path)
{
    flb_sockfd_t fd;
    struct sockaddr_un sun;
    int ret;

    if (!TEST_CHECK(path != NULL)) {
        TEST_MSG("path is NULL");
        return -1;
    }

    memset(&sun, 0, sizeof(sun));
    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("failed to socket. path=%s errno=%d", path, errno);
        return -1;
    }

    sun.sun_family = AF_LOCAL;
    strcpy(sun.sun_path, path);
    ret = connect(fd, (const struct sockaddr *)&sun, sizeof(sun));
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("failed to connect. path=%s errno=%d", path, errno);
        flb_socket_close(fd);
        return -1;
    }
    return fd;
}

static flb_sockfd_t init_udp_unix(char *path, struct sockaddr_un *sun)
{
    flb_sockfd_t fd;
    int ret;

    if (!TEST_CHECK(path != NULL)) {
        TEST_MSG("path is NULL");
        return -1;
    }
    if (!TEST_CHECK(sun != NULL)) {
        TEST_MSG("sun is NULL");
        return -1;
    }

    memset(sun, 0, sizeof(struct sockaddr_un));
    fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("failed to socket. path=%s errno=%d", path, errno);
        return -1;
    }

    sun->sun_family = AF_LOCAL;
    strcpy(sun->sun_path, path);
    ret = connect(fd, (const struct sockaddr *)sun, sizeof(struct sockaddr_un));
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("failed to connect. path=%s errno=%d", path, errno);
        flb_socket_close(fd);
        return -1;
    }
    return fd;
}
#endif

static int init_udp(char *in_host, int in_port, struct sockaddr_in *addr)
{
    int port = in_port;
    char *host = in_host;
    flb_sockfd_t fd;

    if (host == NULL) {
        host = DEFAULT_HOST;
    }
    if (port < 0) {
        port = DEFAULT_PORT;
    }

    memset(addr, 0, sizeof(struct sockaddr_in));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("failed to socket. host=%s port=%d errno=%d", host, port, errno);
        return -1;
    }

    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(host);
    addr->sin_port = htons(port);

    return fd;
}

/* Copy src into dst, stripping a single trailing '\n' if present; return len */
static size_t rstrip_nl_copy(char *dst, size_t dstsz, const char *src)
{
    size_t n = strlen(src);
    if (n > 0 && src[n - 1] == '\n') {
        n -= 1;
    }
    if (n + 1 > dstsz) {
        n = dstsz - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
    return n;
}

/* Build one octet-counted frame into 'out' as: "<len> " + msg [+ '\n' if add_lf] */
/* Returns total bytes written (excluding terminal '\0' in 'out') */
static size_t build_octet_frame(char *out, size_t outsz,
                                const char *msg, int add_lf)
{
    char tmp[2048];
    size_t mlen = 0;
    char hdr[64];
    int  hlen = 0;
    size_t need = 0;

    mlen = rstrip_nl_copy(tmp, sizeof(tmp), msg);
    hlen = snprintf(hdr, sizeof(hdr), "%zu ", mlen);
    need = (size_t)hlen + mlen + (add_lf ? 1 : 0);

    if (need + 1 > outsz) {
        /* truncate conservatively if buffer too small (shouldn't happen in tests) */
        need = outsz - 1;
        add_lf = 0;
        if ((size_t)hlen > need) {
            hlen = (int)need;
        }
    }

    memcpy(out, hdr, hlen);
    memcpy(out + hlen, tmp, mlen);
    if (add_lf) {
        out[hlen + mlen] = '\n';
    }
    out[need] = '\0';
    return need;
}

/* Build two consecutive octet-counted frames into one buffer */
static size_t build_two_frames(char *out, size_t outsz,
                               const char *msg1, const char *msg2,
                               int add_lf_for_each)
{
    size_t off = 0;
    off += build_octet_frame(out + off, outsz - off, msg1, add_lf_for_each);
    off += build_octet_frame(out + off, outsz - off, msg2, add_lf_for_each);
    return off;
}

void flb_test_syslog_tcp()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char *buf = RFC5424_EXAMPLE_1;
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "tcp",
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = send(fd, buf, size, 0);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_syslog_tcp_port()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    char *port = "15140";

    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char *buf = RFC5424_EXAMPLE_1;
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "tcp",
                        "Port", port,
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = connect_tcp(NULL, atoi(port));
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = send(fd, buf, size, 0);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_syslog_tcp_source_address()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_TCP)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_TCP[0],
    };

    char *buf = RFC5424_EXAMPLE_1;
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "tcp",
                        "source_address_key", "source_host",
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = send(fd, buf, size, 0);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_syslog_unknown_mode()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;

    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_1[0],
    };


    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "UNKNOWN",
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    if(!TEST_CHECK(ret != 0)) {
        TEST_MSG("flb_start should be failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* free ctx directly to avoid calling flb_stop */
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_syslog_unix_perm()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    char *unix_path = "in_syslog_unix";
    struct stat sb;
    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_1[0],
    };


    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "path", unix_path,
                        "unix_perm", "0600",
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = stat(unix_path, &sb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("stat failed. errno=%d", errno);
                test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK((sb.st_mode & S_IRWXO) == 0)) {
        TEST_MSG("Permssion(others) error. val=0x%x",sb.st_mode & S_IRWXO);
    }
    if (!TEST_CHECK((sb.st_mode & S_IRWXG) == 0)) {
        TEST_MSG("Permssion(group) error. val=0x%x",sb.st_mode & S_IRWXG);
    }
    if (!TEST_CHECK((sb.st_mode & S_IRWXU) == (S_IRUSR | S_IWUSR))) {
        TEST_MSG("Permssion(user) error. val=0x%x",sb.st_mode & S_IRWXU);
    }

    test_ctx_destroy(ctx);
}

void flb_test_syslog_udp()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct sockaddr_in addr;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char *buf = RFC5424_EXAMPLE_1;
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "udp",
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = init_udp(NULL, -1, &addr);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = sendto(fd, buf, size, 0, (const struct sockaddr *)&addr, sizeof(addr));
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_syslog_udp_port()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct sockaddr_in addr;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    char *port = "15140";

    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char *buf = RFC5424_EXAMPLE_1;
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "udp",
                        "Port", port,
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = init_udp(NULL, atoi(port), &addr);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = sendto(fd, buf, size, 0, (const struct sockaddr *)&addr, sizeof(addr));
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_syslog_udp_source_address()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct sockaddr_in addr;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_UDP)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_UDP[0],
    };

    char *buf = RFC5424_EXAMPLE_1;
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "udp",
                        "source_address_key", "source_host",
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = init_udp(NULL, -1, &addr);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = sendto(fd, buf, size, 0, (const struct sockaddr *)&addr, sizeof(addr));
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

#ifdef FLB_HAVE_UNIX_SOCKET
void flb_test_syslog_tcp_unix()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    char *unix_path = "in_syslog_unix";

    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char *buf = RFC5424_EXAMPLE_1;
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "unix_tcp",
                        "path", unix_path,
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = connect_tcp_unix(unix_path);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = send(fd, buf, size, 0);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_syslog_udp_unix()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct sockaddr_un sun;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    char *unix_path = "in_syslog_unix";

    struct str_list expected = {
                                .size = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
                                .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char *buf = RFC5424_EXAMPLE_1;
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "unix_udp",
                        "path", unix_path,
                        "parser", PARSER_NAME_RFC5424,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    fd = init_udp_unix(unix_path, &sun);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = sendto(fd, buf, size, 0, (const struct sockaddr *)&sun, sizeof(sun));
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}
#endif

void flb_test_syslog_rfc3164()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    struct str_list expected = {
                                .size = sizeof(RFC3164_EXPECTED_STRS_1)/sizeof(char*),
                                .lists = &RFC3164_EXPECTED_STRS_1[0],
    };

    char *buf = RFC3164_EXAMPLE_1;
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "tcp",
                        "parser", PARSER_NAME_RFC3164,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = send(fd, buf, size, 0);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_syslog_tcp_octet_counting()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    struct str_list expected = {
        .size  = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
        .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char frame[4096];
    size_t fsize = 0;

    fsize = build_octet_frame(frame, sizeof(frame), RFC5424_EXAMPLE_1, /*add_lf=*/0);
    clear_output_num();
    cb_data.cb   = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "tcp",
                        "frame", "octet_counting",
                        "parser", PARSER_NAME_RFC5424,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = send(fd, frame, fsize, 0);
    if (!TEST_CHECK(w_size == (ssize_t)fsize)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    flb_time_msleep(500);
    num = get_output_num();
    if (!TEST_CHECK(num > 0)) {
        TEST_MSG("no outputs (octet_counting single)");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

/* -------- TCP + RFC6587 octet-counting: frame with trailing LF -------- */
void flb_test_syslog_tcp_octet_counting_lf()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    struct str_list expected = {
        .size  = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
        .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char frame[4096];
    size_t fsize = 0;

    fsize = build_octet_frame(frame, sizeof(frame), RFC5424_EXAMPLE_1, /*add_lf=*/1);
    clear_output_num();
    cb_data.cb   = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "tcp",
                        "frame", "octet_counting",
                        "parser", PARSER_NAME_RFC5424,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = send(fd, frame, fsize, 0);
    if (!TEST_CHECK(w_size == (ssize_t)fsize)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    flb_time_msleep(500);
    num = get_output_num();
    if (!TEST_CHECK(num > 0)) {
        TEST_MSG("no outputs (octet_counting + LF)");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

/* -------- TCP + RFC6587 octet-counting: fragmented send (header then body) -------- */
void flb_test_syslog_tcp_octet_counting_fragmented()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    struct str_list expected = {
        .size  = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
        .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char msg[2048];
    size_t mlen = 0;
    char hdr[64];
    int  hlen = 0;

    mlen = rstrip_nl_copy(msg, sizeof(msg), RFC5424_EXAMPLE_1);
    hlen = snprintf(hdr, sizeof(hdr), "%zu ", mlen);

    clear_output_num();
    cb_data.cb   = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "tcp",
                        "frame", "octet_counting",
                        "parser", PARSER_NAME_RFC5424,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Send header only first */
    w_size = send(fd, hdr, (size_t)hlen, 0);
    if (!TEST_CHECK(w_size == hlen)) {
        TEST_MSG("failed to send header, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }
    /* Give the input a moment to hit 'need more bytes' path */
    flb_time_msleep(50);

    /* Now send body */
    w_size = send(fd, msg, mlen, 0);
    if (!TEST_CHECK(w_size == (ssize_t)mlen)) {
        TEST_MSG("failed to send body, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    flb_time_msleep(500);
    num = get_output_num();
    if (!TEST_CHECK(num > 0)) {
        TEST_MSG("no outputs (octet_counting fragmented)");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

/* -------- TCP + RFC6587 octet-counting: two frames back-to-back -------- */
void flb_test_syslog_tcp_octet_counting_multi()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    struct str_list expected = {
        .size  = sizeof(RFC5424_EXPECTED_STRS_1)/sizeof(char*),
        .lists = &RFC5424_EXPECTED_STRS_1[0],
    };

    char frames[8192];
    size_t fsize = 0;

    fsize = build_two_frames(frames, sizeof(frames),
                             RFC5424_EXAMPLE_1, RFC5424_EXAMPLE_1,
                             /*add_lf_for_each=*/0);

    clear_output_num();
    cb_data.cb   = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "mode", "tcp",
                        "frame", "octet_counting",
                        "parser", PARSER_NAME_RFC5424,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    w_size = send(fd, frames, fsize, 0);
    if (!TEST_CHECK(w_size == (ssize_t)fsize)) {
        TEST_MSG("failed to send frames, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    flb_time_msleep(500);
    num = get_output_num();
    if (!TEST_CHECK(num >= 2)) {
        TEST_MSG("expected at least 2 outputs (octet_counting multi), got %d", num);
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

TEST_LIST = {
    {"syslog_tcp", flb_test_syslog_tcp},
    {"syslog_udp", flb_test_syslog_udp},
    {"syslog_tcp_port", flb_test_syslog_tcp_port},
    {"syslog_tcp_source_address", flb_test_syslog_tcp_source_address},
    {"syslog_udp_port", flb_test_syslog_udp_port},
    {"syslog_udp_source_address", flb_test_syslog_udp_source_address},
    {"syslog_unknown_mode", flb_test_syslog_unknown_mode},
#ifdef FLB_HAVE_UNIX_SOCKET
    {"syslog_unix_perm", flb_test_syslog_unix_perm},
#endif
    {"syslog_rfc3164", flb_test_syslog_rfc3164},
#ifdef FLB_HAVE_UNIX_SOCKET
    {"syslog_tcp_unix", flb_test_syslog_tcp_unix},
#ifndef FLB_SYSTEM_MACOS
    {"syslog_udp_unix", flb_test_syslog_udp_unix},
#endif
#endif
    {"syslog_tcp_octet_counting", flb_test_syslog_tcp_octet_counting},
    {"syslog_tcp_octet_counting_lf", flb_test_syslog_tcp_octet_counting_lf},
    {"syslog_tcp_octet_counting_fragmented", flb_test_syslog_tcp_octet_counting_fragmented},
    {"syslog_tcp_octet_counting_multi", flb_test_syslog_tcp_octet_counting_multi},
    {NULL, NULL}
};
