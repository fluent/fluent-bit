/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

/*
 * AWS Signv4 documentation
 * ========================
 *
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 *
 * AWS Signv4 Test Suite
 * =====================
 *
 * AWS provides a test suite that can be used to validate certain requests type and
 * expected signatures. The following unit test file, uses the suite provided and
 * provides certain wrappers to validate expected results.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <monkey/mk_core.h>

#include "flb_tests_internal.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>

/* Test suite entry point */
#define AWS_SUITE   FLB_TESTS_DATA_PATH "data/signv4/aws-sig-v4-test-suite/"

/* Credentials Environment Variables */
#define AWS_ACCESS_KEY_ID              "AWS_ACCESS_KEY_ID"
#define AWS_SECRET_ACCESS_KEY          "AWS_SECRET_ACCESS_KEY"
#define AWS_SESSION_TOKEN              "AWS_SESSION_TOKEN"

struct request {
    int method_i;
    flb_sds_t method;
    flb_sds_t uri;
    flb_sds_t uri_full;
    flb_sds_t query_string;
    flb_sds_t payload;
    struct mk_list headers;
};

struct aws_test {
    flb_sds_t name;       /* test name */
    flb_sds_t authz;
    flb_sds_t creq;
    flb_sds_t req;
    flb_sds_t sreq;
    flb_sds_t sts;
    struct request *r;
    struct flb_http_client *c;
    struct mk_list _head;
};

static struct request *http_request_create(char *request)
{
    int len;
    char *sep;
    char *start;
    char *end;
    char *p;
    char *br = NULL;
    flb_sds_t tmp;
    flb_sds_t key;
    flb_sds_t val;
    flb_sds_t payload = NULL;
    struct flb_kv *kv = NULL;
    struct request *req;

    req = flb_calloc(1, sizeof(struct request));
    if (!req) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&req->headers);

    /* method */
    p = strchr(request, ' ');
    req->method = flb_sds_create_size(10);
    if (!req->method) {
        flb_free(req);
        return NULL;
    }

    tmp = flb_sds_copy(req->method, request, p - request);
    if (!tmp) {
        flb_sds_destroy(req->method);
        flb_free(req);
        return NULL;
    }
    req->method = tmp;

    if (strcmp(req->method, "GET") == 0) {
        req->method_i = FLB_HTTP_GET;
    }
    else if (strcmp(req->method, "POST") == 0) {
        req->method_i = FLB_HTTP_POST;
    }

    /* URI */
    start = p + 1;
    p = strchr(start, '\n');
    if (!p) {
        flb_sds_destroy(req->method);
        flb_free(req);
        return NULL;
    }
    p--;
    if ((p - 8) <= start) {
        return NULL;
    }
    end = (p - 8);

    len = end - start;
    req->uri = flb_sds_create_size(len);
    tmp = flb_sds_copy(req->uri, start, len);
    if (!tmp) {
        flb_sds_destroy(req->method);
        flb_sds_destroy(req->uri);
        flb_free(req);
        return NULL;
    }

    req->uri = tmp;
    req->uri_full = flb_sds_create(req->uri);

    /* Query string: it might be inside the URI */
    start = req->uri;
    p = strchr(start, '?');
    if (p) {
        flb_sds_len_set(req->uri, (p - req->uri));
        len = flb_sds_len(req->uri) - (p - req->uri);
        *p = '\0'; /* terminate the string */
        start = p + 1;
        req->query_string = flb_sds_create_len(start, len);
    }

    /* Headers, everything after the first LF (\n) */
    p = strchr(request, '\n');
    p++;

    len = strlen(request) - (p - request);
    start = p;
    do {
        /* HTTP line folding (multi line header) */
        if ((*start == ' ' || *start == '\t') && kv) {
            key = flb_sds_create(kv->key);
            sep = start + 1;
        }
        else {
            /* key */
            sep = strchr(start, ':');
            if (!sep) {
                break;
            }
            key = flb_sds_create_len(start, sep - start);
        }

        /* value */
        start = sep + 1;
        br = strchr(start, '\n');
        if (!br) {
            break;
        }

        val = flb_sds_create_len(start, br - start);
        kv = flb_kv_item_create_len(&req->headers,
                                    key, flb_sds_len(key), val, flb_sds_len(val));
        flb_sds_destroy(key);
        flb_sds_destroy(val);

        /* next header */
        start = br + 1;
        p = strchr(start, '\n');
    } while (p && *p == '\n');

    /* Is this a POST request with a payload ? */
    if (p && *p == '\n') {
        p++;
        if (p) {
            len = strlen(request) - (p - request);
            payload = flb_sds_create_len(p, len);
        }
    }
    else {
        /* Append any remaining headers, aws tests do not end files with a \n */
        br++;
        if ((br - request) - len) {
            start = br;
            sep = strchr(start, ':');

            key = flb_sds_create_len(start, sep - start);
            val = flb_sds_create(sep + 1);
            flb_kv_item_create_len(&req->headers,
                                   key, flb_sds_len(key), val, flb_sds_len(val));
            flb_sds_destroy(key);
            flb_sds_destroy(val);
        }
    }

    if (payload) {
        req->payload = payload;
    }

    return req;
}

static void http_request_destroy(struct request *req)
{
    if (!req) {
        return;
    }

    if (req->method) {
        flb_sds_destroy(req->method);
    }
    if (req->uri) {
        flb_sds_destroy(req->uri);
    }
    if (req->uri_full) {
        flb_sds_destroy(req->uri_full);
    }
    if (req->query_string) {
        flb_sds_destroy(req->query_string);
    }
    if (req->payload) {
        flb_sds_destroy(req->payload);
    }

    flb_kv_release(&req->headers);
    flb_free(req);
}

/* Convert a TXT HTTP request to a Fluent Bit http_client context */
static struct flb_http_client *convert_request_file(char *request,
                                                    struct request **r,
                                                    struct flb_config *config)
{
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct mk_list *head;
    struct flb_kv *kv;
    struct request *req;

    /* Fake Upstream context, required by http client */
    u = flb_upstream_create(config, "127.0.0.1", 80, 0, NULL);
    if (!u) {
        fprintf(stderr, "error creating upstream context");
        flb_free(config);
        return NULL;
    }

    /* Fake upstream connection */
    u_conn = flb_calloc(1, sizeof(struct flb_connection));
    if (!u_conn) {
        flb_errno();
        flb_upstream_destroy(u);
        flb_free(config);
    }
    u_conn->upstream = u;

    /* Convert TXT HTTP request to our local 'request' structure */
    req = http_request_create(request);
    if (!req) {
        fprintf(stderr, "error parsing txt http request");
        exit(1);
    }

    /* HTTP Client context */
    c = flb_http_client(u_conn, req->method_i, req->uri_full,
                        req->payload, req->payload ? flb_sds_len(req->payload): -1,
                        NULL, -1, NULL, 0);

    /*
     * flb_http_client automatically adds host and content-length
     * for the tests we remove these since all headers come from
     * the the test file
     */
     mk_list_foreach(head, &c->headers) {
         kv = mk_list_entry(head, struct flb_kv, _head);
         if (strncasecmp(kv->key, "Host", 4) == 0) {
             flb_kv_item_destroy(kv);
             break;
         }
     }
     mk_list_foreach(head, &c->headers) {
         kv = mk_list_entry(head, struct flb_kv, _head);
         if (strncasecmp(kv->key, "Content-Length", 14) == 0) {
             flb_kv_item_destroy(kv);
             break;
         }
     }

    /* Append registered headers */
    mk_list_foreach(head, &req->headers) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        flb_http_add_header(c,
                            kv->key, flb_sds_len(kv->key),
                            kv->val, flb_sds_len(kv->val));
    }

    *r = req;
    return c;
}

static flb_sds_t file_to_buffer(char *path, char *context, char *ext)
{
    char abs_path[2048];
    char *buf;
    flb_sds_t data;

    snprintf(abs_path, sizeof(abs_path) - 1, "%s/%s.%s", path, context, ext);
    buf = mk_file_to_buffer(abs_path);
    if (!buf) {
        return NULL;
    }

    data = flb_sds_create(buf);
    if (!data) {
        fprintf(stderr, "error allocating sds buffer to test %s file\n", abs_path);
        flb_free(buf);
        return NULL;
    }
    flb_free(buf);

    return data;
}

static void aws_test_destroy(struct aws_test *awt)
{
    if (awt->name) {
        flb_sds_destroy(awt->name);
    }
    if (awt->authz) {
        flb_sds_destroy(awt->authz);
    }
    if (awt->creq) {
        flb_sds_destroy(awt->creq);
    }
    if (awt->req) {
        flb_sds_destroy(awt->req);
    }
    if (awt->sreq) {
        flb_sds_destroy(awt->sreq);
    }
    if (awt->sts) {
        flb_sds_destroy(awt->sts);
    }

    if (awt->c) {
        flb_upstream_destroy(awt->c->u_conn->upstream);
        flb_free(awt->c->u_conn);
        flb_http_client_destroy(awt->c);
    }

    http_request_destroy(awt->r);
    flb_free(awt);
}

static struct aws_test *aws_test_create(char *path, char *context,
                                        struct flb_config *config)
{
    struct aws_test *awt;

    awt = flb_calloc(1, sizeof(struct aws_test));
    if (!awt) {
        flb_errno();
        return NULL;
    }

    awt->name = flb_sds_create(context);
    if (!awt->name) {
        fprintf(stderr, "cannot allocate awt name\n");
        goto error;
    }

    /* If no 'authz' file is found, return right away */
    awt->authz = file_to_buffer(path, context, "authz");
    if (!awt->authz) {
        aws_test_destroy(awt);
        return NULL;
    }

    awt->creq = file_to_buffer(path, context, "creq");
    if (!awt->creq) {
        fprintf(stderr, "error reading creq file");
        goto error;
    }

    awt->req = file_to_buffer(path, context, "req");
    if (!awt->req) {
        fprintf(stderr, "error reading req file");
        goto error;
    }

    awt->sreq = file_to_buffer(path, context, "sreq");
    if (!awt->sreq) {
        fprintf(stderr, "error reading req file");
        goto error;
    }

    awt->sts = file_to_buffer(path, context, "sts");
    if (!awt->sts) {
        fprintf(stderr, "error reading req file");
        goto error;
    }

    /* Convert TXT HTTP request to http_client context */
    awt->c = convert_request_file(awt->req, &awt->r, config);
    if (!awt->c) {
        fprintf(stderr, "error converting TXT request to a context: %s", awt->name);
        goto error;
    }

    return awt;

 error:
    //aws_test_destroy(awt);
    return NULL;
}

static int load_aws_test_directory(struct mk_list *list, char *ut_path,
                                   struct flb_config *config)
{
    int ret;
    struct dirent *e;
    DIR *dir;
    char path[2048];
    char ut[4096];
    struct stat st;
    struct aws_test *awt;

    dir = opendir(ut_path);
    if (!dir) {
        flb_errno();
        flb_error("signv4: cannot open test suite located at '%s'", AWS_SUITE);
        return -1;
    }

    /* Read directory entries */
    while ((e = readdir(dir)) != NULL) {
        if (*e->d_name == '.') {
            continue;
        }

        snprintf(path, sizeof(path) - 1, "%s%s", ut_path, e->d_name);
        ret = stat(path, &st);
        if (ret == -1) {
            continue;
        }

        /* only process directories */
        if (!S_ISDIR(st.st_mode)) {
            continue;
        }

        /* check for unit test file */
        snprintf(ut, sizeof(ut) - 1, "%s%s/%s.req", path, e->d_name, e->d_name);
        ret = stat(path, &st);
        if (ret == -1) {
            continue;
        }

        awt = aws_test_create(path, e->d_name, config);
        if (!awt) {
            continue;
        }
        mk_list_add(&awt->_head, list);
    }

    closedir(dir);
    return 0;
}

static void aws_tests_destroy(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct aws_test *awt;

    mk_list_foreach_safe(head, tmp, list) {
        awt = mk_list_entry(head, struct aws_test, _head);
        mk_list_del(&awt->_head);
        aws_test_destroy(awt);
    }

    flb_free(list);
}

static struct mk_list *aws_tests_create(struct flb_config *config)
{
    struct mk_list *list;
    char path[2048];

    printf("\n");

    list = flb_malloc(sizeof(struct mk_list));
    if (!list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(list);

    /* Load base path for AWS test suite, some sub-directories will be skipped */
    load_aws_test_directory(list, AWS_SUITE, config);

    /* Load pending sub-directories */
    snprintf(path, sizeof(path) - 1, "%s/normalize-path/", AWS_SUITE);
    load_aws_test_directory(list, path, config);

    snprintf(path, sizeof(path) - 1, "%s/post-sts-token/", AWS_SUITE);
    load_aws_test_directory(list, path, config);

    return list;
}

static void aws_test_suite()
{
    int ret;
    time_t t;
    char *region = NULL;
    char *access_key = NULL;
    char *service = NULL;
    char *secret_key = NULL;
    flb_sds_t signature;
    struct mk_list *head;
    struct mk_list *tests;
    struct flb_config *config;
    struct aws_test *awt;
    struct flb_aws_provider *provider;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }
    mk_list_init(&config->upstreams);

    /* Get a list of tests */
    tests = aws_tests_create(config);
    TEST_CHECK(tests != NULL);
    if (!tests) {
        flb_free(config);
        return;
    }

    /* Convert static '20150830T123600Z' to unix timestamp */
    t = 1440938160;
    region = "us-east-1";
    access_key = "AKIDEXAMPLE";
    service = "service";
    secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    /* credentials */
    ret = setenv(AWS_ACCESS_KEY_ID, access_key, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    ret = setenv(AWS_SECRET_ACCESS_KEY, secret_key, 1);
    if (ret < 0) {
        flb_errno();
        return;
    }
    provider = flb_aws_env_provider_create();
    if (!provider) {
        flb_errno();
        return;
    }

    /* Iterate tests and sign the requests */
    mk_list_foreach(head, tests) {
        awt = mk_list_entry(head, struct aws_test, _head);
        fprintf(stderr, "[AWS Signv4 Unit Test] %-50s", awt->name);
        signature = flb_signv4_do(awt->c,
                                  FLB_TRUE,  /* normalize URI ? */
                                  FLB_FALSE, /* add x-amz-date header ? */
                                  t, region, service,
                                  0, NULL,
                                  provider);
        TEST_CHECK(signature != NULL);
        if (signature) {
            ret = strncmp(awt->authz, signature, flb_sds_len(awt->authz));
            TEST_CHECK(ret == 0);
            if (ret != 0) {
                fprintf(stderr, "\t\tFAIL");
                fprintf(stderr,
                        ">\n> signature check failed...\n  received: %s\n  expected: %s\n",
                        signature, awt->authz);
            }
            else {
                fprintf(stderr, "PASS");
            }
            flb_sds_destroy(signature);
        }
        fprintf(stderr, "\n");
    }

    aws_tests_destroy(tests);
    flb_aws_provider_destroy(provider);
    flb_free(config);
}

static void check_normalize(char *s, size_t len, char *out)
{
    flb_sds_t o;

    o = flb_signv4_uri_normalize_path(s, len);
    TEST_CHECK(strcmp(o, out) == 0);
    flb_sds_destroy(o);
}

void normalize()
{
    /* get-relative */
    check_normalize("/example/..", 11, "/");

    /* get-relative-relative */
    check_normalize("/example1/example2/../..", 24, "/");

    /* get-slash */
    check_normalize("//", 2, "/");

    /* get-slash-dot-slash */
    check_normalize("/./", 3, "/");

    /* get-slashes */
    check_normalize("//example//", 11, "/example/");

    /* get-slash-pointless-dot */
    check_normalize("/./example", 10, "/example");
}

TEST_LIST = {
    { "aws_test_suite", aws_test_suite},
    { "normalize", normalize},
    { 0 }
};
