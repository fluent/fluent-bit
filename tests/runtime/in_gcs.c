/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
 * Runtime tests for in_gcs.
 *
 * Model (use cases / edge cases / defensive cases):
 *  - use cases: rehydrate objects (plain and gzip) page by page, split them
 *    in lines, build records (JSON object, or {"log": line}), timestamps from
 *    the 'date' key, tags from the object name, resume state from a db.
 *  - edge cases: empty bucket, zero-byte objects, blank lines, CRLF, no
 *    trailing newline, batches smaller than the object, oversize objects.
 *  - defensive cases: 401 (token refresh, once), 403, 404, 5xx with retries,
 *    token failures, corrupt gzip, invalid configuration.
 *
 * The GCS API and the metadata server are faked with monkey in this file.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <monkey/mk_core.h>
#include <monkey/mk_lib.h>
#include <monkey/mk_http.h>

#include "flb_tests_runtime.h"
#include "../include/flb_tests_tmpdir.h"

#define FAKE_HOST        "127.0.0.1"
#define FAKE_PORT        18931
#define FAKE_BUCKET      "test-bucket"
#define FAKE_URL         "http://127.0.0.1:18931"
#define META_TOKEN_PATH  "/computeMetadata/v1/instance/service-accounts/default/token"

#define MAX_OBJS         16
#define MAX_QUERIES      32
#define SINK_MAX         512
#define LIST_JSON_MAX    262144

#define REJECT_LIST      1
#define REJECT_DOWNLOAD  2

/* ------------------------------------------------------------------ */
/* fake GCS + metadata server                                          */
/* ------------------------------------------------------------------ */

struct fake_obj {
    char name[1100];
    char generation[24];
    char *body;
    size_t body_len;
    long listed_size;           /* -1: use body_len */
    int fail_status;
    int fail_times;             /* -1: forever */
    int hits;
    char last_generation[24];
};

struct fake {
    pthread_mutex_t lock;
    int lock_ready;
    mk_ctx_t *mk;
    int vid;

    struct fake_obj objs[MAX_OBJS];
    int count;
    int page_size;

    /* listing */
    int list_hits;
    int list_fail_status;
    int list_fail_times;
    char queries[MAX_QUERIES][512];
    char q_prefix[256];
    char q_start[256];
    char q_end[256];
    char q_max[32];

    /* auth */
    int meta_hits;
    int meta_fail;
    int reject_token1;          /* mask of REJECT_* for 'Bearer token-1' */
    int reject_all;             /* mask of REJECT_* for any token */
    int saw_token2;
    int bad_auth;
    int accept_encoding_seen;
    int missing_alt;
};

static struct fake fk;

static void url_decode(const char *in, size_t len, char *out, size_t out_size)
{
    size_t i;
    size_t o = 0;
    char hex[3] = {0, 0, 0};

    for (i = 0; i < len && o + 1 < out_size; i++) {
        if (in[i] == '%' && i + 2 < len) {
            hex[0] = in[i + 1];
            hex[1] = in[i + 2];
            out[o++] = (char) strtol(hex, NULL, 16);
            i += 2;
        }
        else {
            out[o++] = in[i];
        }
    }
    out[o] = '\0';
}

static int query_get(const char *query, const char *key, char *out, size_t out_size)
{
    const char *p = query;
    size_t klen = strlen(key);
    const char *end;

    out[0] = '\0';
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            p += klen + 1;
            end = strchr(p, '&');
            if (!end) {
                end = p + strlen(p);
            }
            url_decode(p, end - p, out, out_size);
            return 1;
        }
        p = strchr(p, '&');
        if (p) {
            p++;
        }
    }
    return 0;
}

static void reply(mk_request_t *request, int status, const char *ctype,
                  const char *body, size_t len)
{
    mk_http_status(request, status);
    mk_http_header(request, "Content-Type", 12, (char *) ctype, strlen(ctype));
    if (len > 0) {
        mk_http_send(request, (char *) body, len, NULL);
    }
    mk_http_done(request);
}

static int should_reject(int kind, const char *auth)
{
    if (fk.reject_all & kind) {
        return FLB_TRUE;
    }
    if ((fk.reject_token1 & kind) && strcmp(auth, "Bearer token-1") == 0) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/* JSON string escaping, control characters as \u00XX */
static void json_escape(const char *in, char *out, size_t out_size)
{
    size_t o = 0;

    for (; *in && o + 8 < out_size; in++) {
        if ((unsigned char) *in < 0x20) {
            o += snprintf(out + o, out_size - o, "\\u%04x", (unsigned char) *in);
        }
        else if (*in == '"' || *in == '\\') {
            out[o++] = '\\';
            out[o++] = *in;
        }
        else {
            out[o++] = *in;
        }
    }
    out[o] = '\0';
}

static void handle_list(mk_request_t *request, const char *query, const char *auth)
{
    int i;
    int start = 0;
    int sent = 0;
    int max = 1000;
    int next = -1;
    int idx = 0;
    char prefix[256];
    char start_off[256];
    char end_off[256];
    char token[32];
    char maxr[32];
    char *json;
    char escaped[8192];
    size_t off = 0;
    struct fake_obj *o;

    pthread_mutex_lock(&fk.lock);
    if (fk.list_hits < MAX_QUERIES) {
        snprintf(fk.queries[fk.list_hits], sizeof(fk.queries[0]), "%s", query);
    }
    if (fk.list_hits == 0) {
        query_get(query, "prefix", fk.q_prefix, sizeof(fk.q_prefix));
        query_get(query, "startOffset", fk.q_start, sizeof(fk.q_start));
        query_get(query, "endOffset", fk.q_end, sizeof(fk.q_end));
        query_get(query, "maxResults", fk.q_max, sizeof(fk.q_max));
    }
    fk.list_hits++;

    if (should_reject(REJECT_LIST, auth)) {
        pthread_mutex_unlock(&fk.lock);
        reply(request, 401, "application/json", "{\"error\":\"unauthorized\"}", 24);
        return;
    }
    if (fk.list_fail_status != 0 && fk.list_fail_times != 0) {
        if (fk.list_fail_times > 0) {
            fk.list_fail_times--;
        }
        pthread_mutex_unlock(&fk.lock);
        reply(request, fk.list_fail_status, "application/json",
              "{\"error\":\"forced\"}", 18);
        return;
    }

    query_get(query, "prefix", prefix, sizeof(prefix));
    query_get(query, "startOffset", start_off, sizeof(start_off));
    query_get(query, "endOffset", end_off, sizeof(end_off));
    if (query_get(query, "pageToken", token, sizeof(token))) {
        start = atoi(token);
    }
    if (query_get(query, "maxResults", maxr, sizeof(maxr))) {
        max = atoi(maxr);
    }
    if (fk.page_size > 0 && fk.page_size < max) {
        max = fk.page_size;
    }

    json = flb_calloc(1, LIST_JSON_MAX);
    off += snprintf(json + off, LIST_JSON_MAX - off, "{\"kind\":\"storage#objects\"");
    for (i = 0; i < fk.count; i++) {
        o = &fk.objs[i];
        if (prefix[0] && strncmp(o->name, prefix, strlen(prefix)) != 0) {
            continue;
        }
        if (start_off[0] && strcmp(o->name, start_off) < 0) {
            continue;
        }
        if (end_off[0] && strcmp(o->name, end_off) >= 0) {
            continue;
        }
        if (idx++ < start) {
            continue;
        }
        if (sent == max) {
            next = idx - 1;
            break;
        }
        json_escape(o->name, escaped, sizeof(escaped));
        off += snprintf(json + off, LIST_JSON_MAX - off, "%s{\"name\":\"%s\","
                        "\"generation\":\"%s\",\"size\":\"%ld\"}",
                        sent == 0 ? ",\"items\":[" : ",", escaped, o->generation,
                        o->listed_size >= 0 ? o->listed_size : (long) o->body_len);
        sent++;
    }
    if (sent > 0) {
        off += snprintf(json + off, LIST_JSON_MAX - off, "]");
    }
    if (next >= 0) {
        off += snprintf(json + off, LIST_JSON_MAX - off, ",\"nextPageToken\":\"%d\"", next);
    }
    off += snprintf(json + off, LIST_JSON_MAX - off, "}");
    pthread_mutex_unlock(&fk.lock);

    reply(request, 200, "application/json", json, off);
    flb_free(json);
}

static void handle_download(mk_request_t *request, const char *name,
                            const char *query, const char *auth)
{
    int i;
    int status = 200;
    char gen[24];
    char alt[32];
    struct fake_obj *o = NULL;
    char *body = NULL;
    size_t len = 0;

    pthread_mutex_lock(&fk.lock);
    for (i = 0; i < fk.count; i++) {
        if (strcmp(fk.objs[i].name, name) == 0) {
            o = &fk.objs[i];
            break;
        }
    }
    if (!o) {
        pthread_mutex_unlock(&fk.lock);
        reply(request, 404, "application/json", "{\"error\":\"nf\"}", 14);
        return;
    }

    o->hits++;
    query_get(query, "generation", gen, sizeof(gen));
    snprintf(o->last_generation, sizeof(o->last_generation), "%s", gen);
    if (!query_get(query, "alt", alt, sizeof(alt)) || strcmp(alt, "media") != 0) {
        fk.missing_alt++;
    }

    if (should_reject(REJECT_DOWNLOAD, auth)) {
        status = 401;
    }
    else if (o->fail_status != 0 && o->fail_times != 0) {
        status = o->fail_status;
        if (o->fail_times > 0) {
            o->fail_times--;
        }
    }
    else if (strcmp(gen, o->generation) != 0) {
        status = 404;
    }
    else {
        body = o->body;
        len = o->body_len;
    }
    pthread_mutex_unlock(&fk.lock);

    if (status != 200) {
        reply(request, status, "application/json", "{\"error\":\"forced\"}", 18);
        return;
    }
    reply(request, 200, "application/octet-stream", body, len);
}

static void cb_root(mk_request_t *request, void *data)
{
    char path[1024];
    char query[1024];
    char auth[256];
    char tmp[256];
    const char *p;
    size_t n;
    struct mk_http_header *h;
    char token_json[256];
    int hits;
    int fail;
    (void) data;

    n = request->uri_processed.len;
    if (n >= sizeof(path)) {
        n = sizeof(path) - 1;
    }
    memcpy(path, request->uri_processed.data, n);
    path[n] = '\0';
    p = strchr(path, '?');
    if (p) {
        path[p - path] = '\0';
    }

    n = request->query_string.len;
    if (n >= sizeof(query)) {
        n = sizeof(query) - 1;
    }
    if (request->query_string.data) {
        memcpy(query, request->query_string.data, n);
    }
    else {
        n = 0;
    }
    query[n] = '\0';

    auth[0] = '\0';
    h = mk_http_header_get(MK_HEADER_AUTHORIZATION, request, NULL, 0);
    if (h && h->val.data && h->val.len > 0 && h->val.len < sizeof(auth)) {
        memcpy(auth, h->val.data, h->val.len);
        auth[h->val.len] = '\0';
    }

    if (strcmp(path, META_TOKEN_PATH) == 0) {
        pthread_mutex_lock(&fk.lock);
        hits = ++fk.meta_hits;
        fail = fk.meta_fail;
        pthread_mutex_unlock(&fk.lock);
        if (fail) {
            reply(request, 500, "application/json", "{}", 2);
            return;
        }
        n = snprintf(token_json, sizeof(token_json),
                     "{\"access_token\":\"token-%d\",\"expires_in\":3600,"
                     "\"token_type\":\"Bearer\"}", hits);
        reply(request, 200, "application/json", token_json, n);
        return;
    }

    pthread_mutex_lock(&fk.lock);
    if (strncmp(auth, "Bearer token-", 13) != 0) {
        fk.bad_auth++;
    }
    if (strcmp(auth, "Bearer token-2") == 0) {
        fk.saw_token2++;
    }
    h = mk_http_header_get(MK_HEADER_ACCEPT_ENCODING, request, NULL, 0);
    if (h && h->val.data && h->val.len > 0) {
        fk.accept_encoding_seen++;
    }
    pthread_mutex_unlock(&fk.lock);

    snprintf(tmp, sizeof(tmp), "/storage/v1/b/%s/o", FAKE_BUCKET);
    if (strcmp(path, tmp) == 0) {
        handle_list(request, query, auth);
        return;
    }

    strcat(tmp, "/");
    if (strncmp(path, tmp, strlen(tmp)) == 0) {
        handle_download(request, path + strlen(tmp), query, auth);
        return;
    }

    reply(request, 404, "application/json", "{}", 2);
}

static void fake_begin(void)
{
    char addr[64];

    memset(&fk, 0, sizeof(fk));
    pthread_mutex_init(&fk.lock, NULL);
    fk.lock_ready = 1;

    fk.mk = mk_create();
    TEST_CHECK(fk.mk != NULL);
    snprintf(addr, sizeof(addr), "%s:%d", FAKE_HOST, FAKE_PORT);
    mk_config_set(fk.mk, "Listen", addr, NULL);
    fk.vid = mk_vhost_create(fk.mk, NULL);
    mk_vhost_set(fk.mk, fk.vid, "Name", "fake-gcs", NULL);
    mk_vhost_handler(fk.mk, fk.vid, "/", cb_root, NULL);
    mk_start(fk.mk);

    unsetenv("GOOGLE_APPLICATION_CREDENTIALS");
    unsetenv("GOOGLE_SERVICE_CREDENTIALS");
}

static void fake_end(void)
{
    int i;

    mk_stop(fk.mk);
    mk_destroy(fk.mk);
    for (i = 0; i < fk.count; i++) {
        flb_free(fk.objs[i].body);
    }
    pthread_mutex_destroy(&fk.lock);
}

static struct fake_obj *fake_add_bin(const char *name, const char *gen,
                                     const void *body, size_t len)
{
    struct fake_obj *o = &fk.objs[fk.count++];

    snprintf(o->name, sizeof(o->name), "%s", name);
    snprintf(o->generation, sizeof(o->generation), "%s", gen);
    o->body = flb_malloc(len + 1);
    if (len > 0) {
        memcpy(o->body, body, len);
    }
    o->body_len = len;
    o->listed_size = -1;
    return o;
}

static struct fake_obj *fake_add(const char *name, const char *gen, const char *body)
{
    return fake_add_bin(name, gen, body, strlen(body));
}

static struct fake_obj *fake_add_gzip(const char *name, const char *gen, const char *body)
{
    void *out = NULL;
    size_t out_len = 0;
    struct fake_obj *o;

    flb_gzip_compress((void *) body, strlen(body), &out, &out_len);
    o = fake_add_bin(name, gen, out, out_len);
    flb_free(out);
    return o;
}

/* ------------------------------------------------------------------ */
/* record sink + context                                               */
/* ------------------------------------------------------------------ */

struct sink_rec {
    char *json;
    struct flb_time ts;
};

struct sink {
    pthread_mutex_t lock;
    int count;
    struct sink_rec recs[SINK_MAX];
};

struct tctx {
    flb_ctx_t *flb;
    int in;
    int out1;
    int out2;
    struct sink s1;
    struct sink s2;
    struct flb_lib_out_cb cb1;
    struct flb_lib_out_cb cb2;
    int exit_status;            /* exit status requested by the plugin */
};

static int cb_sink(void *record, size_t size, void *data)
{
    int ret;
    struct sink *s = data;
    struct flb_log_event_decoder dec;
    struct flb_log_event ev;

    ret = flb_log_event_decoder_init(&dec, record, size);
    if (ret == FLB_EVENT_DECODER_SUCCESS) {
        while (flb_log_event_decoder_next(&dec, &ev) == FLB_EVENT_DECODER_SUCCESS) {
            pthread_mutex_lock(&s->lock);
            if (s->count < SINK_MAX) {
                s->recs[s->count].json = flb_msgpack_to_json_str(256, ev.body, FLB_FALSE);
                flb_time_copy(&s->recs[s->count].ts, &ev.timestamp);
                s->count++;
            }
            pthread_mutex_unlock(&s->lock);
        }
        flb_log_event_decoder_destroy(&dec);
    }
    flb_free(record);
    return 0;
}

static int sink_count(struct sink *s)
{
    int n;

    pthread_mutex_lock(&s->lock);
    n = s->count;
    pthread_mutex_unlock(&s->lock);
    return n;
}

static const char *rec(struct sink *s, int i)
{
    if (i >= s->count || !s->recs[i].json) {
        return "";
    }
    return s->recs[i].json;
}

static int has_key(const char **props, const char *key)
{
    int i;

    for (i = 0; props && props[i]; i += 2) {
        if (strcmp(props[i], key) == 0) {
            return FLB_TRUE;
        }
    }
    return FLB_FALSE;
}

static struct tctx *tctx_create(const char **props, const char *match1,
                                const char *match2)
{
    int i;
    struct tctx *t;

    t = flb_calloc(1, sizeof(struct tctx));
    TEST_CHECK(t != NULL);
    pthread_mutex_init(&t->s1.lock, NULL);
    pthread_mutex_init(&t->s2.lock, NULL);
    t->cb1.cb = cb_sink;
    t->cb1.data = &t->s1;
    t->cb2.cb = cb_sink;
    t->cb2.data = &t->s2;

    t->flb = flb_create();
    flb_service_set(t->flb, "Flush", "0.200000000", "Grace", "2",
                    "Log_Level", "info", NULL);

    t->in = flb_input(t->flb, (char *) "gcs", NULL);
    TEST_CHECK(t->in >= 0);
    flb_input_set(t->flb, t->in, "tag", "gcs.in", "metadata_server", FAKE_URL, NULL);
    if (!has_key(props, "endpoint")) {
        flb_input_set(t->flb, t->in, "endpoint", FAKE_URL, NULL);
    }
    if (!has_key(props, "bucket") && !has_key(props, "!bucket")) {
        flb_input_set(t->flb, t->in, "bucket", FAKE_BUCKET, NULL);
    }
    for (i = 0; props && props[i]; i += 2) {
        if (props[i][0] == '!') {
            continue;
        }
        flb_input_set(t->flb, t->in, props[i], props[i + 1], NULL);
    }

    t->out1 = flb_output(t->flb, (char *) "lib", &t->cb1);
    flb_output_set(t->flb, t->out1, "match", match1 ? match1 : "*", NULL);
    if (match2) {
        t->out2 = flb_output(t->flb, (char *) "lib", &t->cb2);
        flb_output_set(t->flb, t->out2, "match", match2, NULL);
    }
    return t;
}

static void sink_free(struct sink *s)
{
    int i;

    for (i = 0; i < s->count; i++) {
        flb_free(s->recs[i].json);
    }
    pthread_mutex_destroy(&s->lock);
}

static void tctx_destroy(struct tctx *t)
{
    flb_destroy(t->flb);
    sink_free(&t->s1);
    sink_free(&t->s2);
    flb_free(t);
}

static int wait_until_done(struct tctx *t, int timeout_ms)
{
    int waited = 0;

    while (t->flb->status != FLB_LIB_NONE && waited < timeout_ms) {
        flb_time_msleep(25);
        waited += 25;
    }
    return t->flb->status == FLB_LIB_NONE ? 0 : -1;
}

static int wait_records(struct sink *s, int n, int timeout_ms)
{
    int waited = 0;

    while (sink_count(s) < n && waited < timeout_ms) {
        flb_time_msleep(25);
        waited += 25;
    }
    return sink_count(s) >= n ? 0 : -1;
}

/* start, wait for the run to complete (exit_on_complete) and stop */
static void run_to_completion(struct tctx *t)
{
    int ret;

    ret = flb_start(t->flb);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }
    ret = wait_until_done(t, 30000);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        TEST_MSG("the run did not complete");
    }
    t->exit_status = t->flb->config->exit_status_code;
    flb_stop(t->flb);
}

#define EXIT_ON_COMPLETE "exit_on_complete", "on"

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

static void test_happy_path(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add("fluent-bit-logs/app/a.log", "11", "{\"n\":1}\n{\"n\":2}\n");
    fake_add("fluent-bit-logs/app/b.log", "12", "{\"n\":3}\n{\"n\":4}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 4);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"n\":2}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"n\":3}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 3), "{\"n\":4}") == 0);
    TEST_CHECK(fk.meta_hits == 1);
    TEST_CHECK(fk.bad_auth == 0);
    TEST_CHECK(fk.accept_encoding_seen == 0);
    TEST_CHECK(fk.missing_alt == 0);
    TEST_CHECK(strcmp(fk.objs[0].last_generation, "11") == 0);
    TEST_CHECK(fk.objs[0].hits == 1 && fk.objs[1].hits == 1);
    TEST_CHECK(fk.list_hits == 1);
    TEST_CHECK(t->exit_status == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_no_exit_keeps_running(void)
{
    int ret;
    struct tctx *t;
    const char *props[] = {NULL};

    fake_begin();
    fake_add("a", "1", "{\"n\":1}\n{\"n\":2}\n");

    t = tctx_create(props, NULL, NULL);
    ret = flb_start(t->flb);
    TEST_CHECK(ret == 0);
    TEST_CHECK(wait_records(&t->s1, 2, 15000) == 0);
    flb_time_msleep(800);
    TEST_CHECK(t->flb->status == FLB_LIB_OK);
    TEST_CHECK(sink_count(&t->s1) == 2);
    TEST_CHECK(fk.list_hits == 1);
    flb_stop(t->flb);

    tctx_destroy(t);
    fake_end();
}

static void test_pagination(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fk.page_size = 1;
    fake_add("o1", "1", "{\"n\":1}\n");
    fake_add("o2", "1", "{\"n\":2}\n");
    fake_add("o3", "1", "{\"n\":3}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 3);
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"n\":3}") == 0);
    TEST_CHECK(fk.list_hits == 3);
    TEST_CHECK(strstr(fk.queries[0], "pageToken") == NULL);
    TEST_CHECK(strstr(fk.queries[1], "pageToken=") != NULL);
    TEST_CHECK(strstr(fk.queries[2], "pageToken=") != NULL);

    tctx_destroy(t);
    fake_end();
}

static void test_prefix_and_offsets(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "prefix", "logs/", "start_offset", "logs/b",
                           "end_offset", "logs/d", "page_size", "7", NULL};

    fake_begin();
    fake_add("logs/a", "1", "{\"n\":1}\n");
    fake_add("logs/b", "1", "{\"n\":2}\n");
    fake_add("logs/c", "1", "{\"n\":3}\n");
    fake_add("logs/d", "1", "{\"n\":4}\n");
    fake_add("other/z", "1", "{\"n\":5}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(strcmp(fk.q_prefix, "logs/") == 0);
    TEST_CHECK(strcmp(fk.q_start, "logs/b") == 0);
    TEST_CHECK(strcmp(fk.q_end, "logs/d") == 0);
    TEST_CHECK(strcmp(fk.q_max, "7") == 0);
    TEST_CHECK(sink_count(&t->s1) == 2);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":2}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"n\":3}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_unset_params_are_omitted(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(strstr(fk.queries[0], "prefix") == NULL);
    TEST_CHECK(strstr(fk.queries[0], "startOffset") == NULL);
    TEST_CHECK(strstr(fk.queries[0], "endOffset") == NULL);
    TEST_CHECK(strstr(fk.queries[0], "pageToken") == NULL);
    TEST_CHECK(strcmp(fk.q_max, "1000") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_empty_bucket(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 0);
    TEST_CHECK(fk.list_hits == 1);

    tctx_destroy(t);
    fake_end();
}

static void test_folder_placeholder_skipped(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add("dir/", "1", "");
    fake_add("dir/a", "1", "{\"n\":1}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(fk.objs[0].hits == 0);

    tctx_destroy(t);
    fake_end();
}

/* only an empty object whose name ends with '/' is a folder placeholder */
static void test_slash_object_with_content(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add("logs/archive/", "1", "{\"n\":1}\n");
    fake_add("logs/empty/", "1", "");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);
    TEST_CHECK(fk.objs[0].hits == 1);
    TEST_CHECK(fk.objs[1].hits == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_edge_content(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add("a-zero", "1", "");
    fake_add("b-blank", "1", "\n\n\r\n\n");
    fake_add("c-nonl", "1", "{\"n\":1}\n{\"n\":2}");
    fake_add("d-crlf", "1", "{\"n\":3}\r\n{\"n\":4}\r\n");
    fake_add("e-text-crlf", "1", "plain text\r\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 5);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"n\":2}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"n\":3}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 3), "{\"n\":4}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 4), "{\"log\":\"plain text\"}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_gzip_auto(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add_gzip("a.gz", "1", "{\"n\":1}\n{\"n\":2}\n");
    fake_add("b", "1", "{\"n\":3}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 3);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"n\":2}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"n\":3}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_gzip_explicit(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "compression", "gzip", NULL};

    fake_begin();
    fake_add_gzip("a.gz", "1", "{\"n\":1}\n");
    fake_add("b-plain", "1", "{\"n\":2}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    /* the plain object is not valid gzip: skipped */
    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_compression_none_on_gzip_body(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "compression", "none", NULL};

    fake_begin();
    fake_add_gzip("a.gz", "1", "{\"n\":1}\n");
    fake_add("b", "1", "{\"n\":2}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    /* no crash; the plain object is always there, in order after the binary one */
    TEST_CHECK(sink_count(&t->s1) >= 1);
    TEST_CHECK(strcmp(rec(&t->s1, sink_count(&t->s1) - 1), "{\"n\":2}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_corrupt_gzip(void)
{
    void *out = NULL;
    size_t out_len = 0;
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};
    const char *text = "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n{\"n\":4}\n{\"n\":5}\n";

    fake_begin();
    flb_gzip_compress((void *) text, strlen(text), &out, &out_len);
    fake_add_bin("a-truncated", "1", out, out_len - 8);
    flb_free(out);
    fake_add("b-good", "1", "{\"n\":9}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":9}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_non_json_lines(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add("a", "1", "not json\n[1,2,3]\n42\n{\"a\":1} trailing\n{\"ok\":true}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 5);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"log\":\"not json\"}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"log\":\"[1,2,3]\"}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"log\":\"42\"}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 3), "{\"log\":\"{\\\"a\\\":1} trailing\"}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 4), "{\"ok\":true}") == 0);

    tctx_destroy(t);
    fake_end();
}

static int is_ts(struct sink *s, int i, long sec, long nsec)
{
    if (i >= s->count) {
        return FLB_FALSE;
    }
    return s->recs[i].ts.tm.tv_sec == sec && s->recs[i].ts.tm.tv_nsec == nsec;
}

static int is_recent(struct sink *s, int i)
{
    long diff;

    if (i >= s->count) {
        return FLB_FALSE;
    }
    diff = (long) time(NULL) - (long) s->recs[i].ts.tm.tv_sec;
    return diff >= -5 && diff < 300;
}

static void test_timestamps_auto(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add("a", "1",
             "{\"date\":\"2023-11-14T22:13:20.500000Z\",\"m\":\"iso\"}\n"
             "{\"date\":\"2023-11-14T23:13:20+01:00\",\"m\":\"off\"}\n"
             "{\"date\":\"2023-11-14 22:13:20.500000\",\"m\":\"sql\"}\n"
             "{\"date\":1700000000.5,\"m\":\"dbl\"}\n"
             "{\"date\":1700000000,\"m\":\"ep\"}\n"
             "{\"date\":1700000000500,\"m\":\"ms\"}\n"
             "{\"m\":\"none\"}\n"
             "{\"date\":\"yesterday\",\"m\":\"bad\"}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 8);
    TEST_CHECK(is_ts(&t->s1, 0, 1700000000, 500000000));
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"m\":\"iso\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 1, 1700000000, 0));
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"m\":\"off\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 2, 1700000000, 500000000));
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"m\":\"sql\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 3, 1700000000, 500000000));
    TEST_CHECK(strcmp(rec(&t->s1, 3), "{\"m\":\"dbl\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 4, 1700000000, 0));
    TEST_CHECK(strcmp(rec(&t->s1, 4), "{\"m\":\"ep\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 5, 1700000000, 500000000));
    TEST_CHECK(strcmp(rec(&t->s1, 5), "{\"m\":\"ms\"}") == 0);
    TEST_CHECK(is_recent(&t->s1, 6));
    TEST_CHECK(strcmp(rec(&t->s1, 6), "{\"m\":\"none\"}") == 0);
    TEST_CHECK(is_recent(&t->s1, 7));
    TEST_CHECK(strcmp(rec(&t->s1, 7), "{\"date\":\"yesterday\",\"m\":\"bad\"}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_time_keep(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "time_keep", "true", NULL};

    fake_begin();
    fake_add("a", "1", "{\"date\":\"2023-11-14T22:13:20.500000Z\",\"m\":1}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(is_ts(&t->s1, 0, 1700000000, 500000000));
    TEST_CHECK(strcmp(rec(&t->s1, 0),
                      "{\"date\":\"2023-11-14T22:13:20.500000Z\",\"m\":1}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_custom_time_key(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "time_key", "ts", NULL};

    fake_begin();
    fake_add("a", "1", "{\"ts\":\"2023-11-14T22:13:20Z\",\"date\":\"keep\",\"m\":1}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(is_ts(&t->s1, 0, 1700000000, 0));
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"date\":\"keep\",\"m\":1}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_time_key_disabled(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "time_key", "false", NULL};

    fake_begin();
    fake_add("a", "1", "{\"date\":\"2023-11-14T22:13:20Z\",\"m\":1}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(is_recent(&t->s1, 0));
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"date\":\"2023-11-14T22:13:20Z\",\"m\":1}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_time_format_explicit(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "time_format", "java_sql_timestamp", NULL};

    fake_begin();
    fake_add("a", "1",
             "{\"date\":\"2023-11-14 22:13:20.500000\",\"m\":1}\n"
             "{\"date\":\"2023-11-14T22:13:20Z\",\"m\":2}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 2);
    TEST_CHECK(is_ts(&t->s1, 0, 1700000000, 500000000));
    TEST_CHECK(is_recent(&t->s1, 1));
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"date\":\"2023-11-14T22:13:20Z\",\"m\":2}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_tag_regex(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "tag_regex", "^fluent-bit-logs/([^/]+)/", NULL};

    fake_begin();
    fake_add("fluent-bit-logs/app.web/2023/a", "1", "{\"n\":1}\n");
    fake_add("other/zzz", "1", "{\"n\":2}\n");

    t = tctx_create(props, "app.web", "gcs.in");
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);
    TEST_CHECK(sink_count(&t->s2) == 1);
    TEST_CHECK(strcmp(rec(&t->s2, 0), "{\"n\":2}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_object_key(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "object_key", "src", NULL};

    fake_begin();
    fake_add("dir/a b.log", "1", "{\"n\":1}\nplain\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 2);
    TEST_CHECK(strstr(rec(&t->s1, 0), "\"src\":\"dir/a b.log\"") != NULL);
    TEST_CHECK(strstr(rec(&t->s1, 0), "\"n\":1") != NULL);
    TEST_CHECK(strstr(rec(&t->s1, 1), "\"src\":\"dir/a b.log\"") != NULL);
    TEST_CHECK(strstr(rec(&t->s1, 1), "\"log\":\"plain\"") != NULL);

    tctx_destroy(t);
    fake_end();
}

static void test_batch_size(void)
{
    int i;
    char expected[32];
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "batch_size", "2", NULL};

    fake_begin();
    fake_add("a", "1", "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n{\"n\":4}\n{\"n\":5}\n");
    fake_add("b", "1", "{\"n\":6}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 6);
    for (i = 0; i < 6; i++) {
        snprintf(expected, sizeof(expected), "{\"n\":%d}", i + 1);
        TEST_CHECK(strcmp(rec(&t->s1, i), expected) == 0);
    }

    tctx_destroy(t);
    fake_end();
}

static void test_max_object_size(void)
{
    struct tctx *t;
    struct fake_obj *liar;
    const char *props[] = {EXIT_ON_COMPLETE, "max_object_size", "64", NULL};
    const char *big = "{\"n\":1,\"pad\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n";

    fake_begin();
    fake_add("a-big", "1", big);
    liar = fake_add("b-liar", "1", big);
    liar->listed_size = 10;
    fake_add("c-small", "1", "{\"n\":2}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":2}") == 0);
    TEST_CHECK(fk.objs[0].hits == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_download_404(void)
{
    struct tctx *t;
    struct fake_obj *o;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    o = fake_add("a", "1", "{\"n\":1}\n");
    o->fail_status = 404;
    o->fail_times = -1;
    fake_add("b", "1", "{\"n\":2}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":2}") == 0);
    TEST_CHECK(fk.objs[0].hits == 1);
    /* a missing object is skipped, it does not fail the run */
    TEST_CHECK(t->exit_status == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_download_retry_then_ok(void)
{
    struct tctx *t;
    struct fake_obj *o;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    o = fake_add("a", "1", "{\"n\":1}\n{\"n\":2}\n");
    o->fail_status = 500;
    o->fail_times = 2;
    fake_add("b", "1", "{\"n\":3}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 3);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"n\":2}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"n\":3}") == 0);
    TEST_CHECK(fk.objs[0].hits == 3);

    tctx_destroy(t);
    fake_end();
}

static void test_download_503_retry(void)
{
    struct tctx *t;
    struct fake_obj *o;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    o = fake_add("a", "1", "{\"n\":1}\n");
    /* monkey cannot send a 429; any 5xx follows the same transient path */
    o->fail_status = 503;
    o->fail_times = 1;

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(fk.objs[0].hits == 2);

    tctx_destroy(t);
    fake_end();
}

static void test_download_retry_exhausted(void)
{
    struct tctx *t;
    struct fake_obj *o;
    const char *props[] = {EXIT_ON_COMPLETE, "retry_limit", "1", NULL};

    fake_begin();
    o = fake_add("a", "1", "{\"n\":1}\n");
    o->fail_status = 500;
    o->fail_times = -1;
    fake_add("b", "1", "{\"n\":2}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    /* first attempt + retry_limit retries, then the object is skipped */
    TEST_CHECK(fk.objs[0].hits == 2);
    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":2}") == 0);
    /* an object skipped because of errors makes the exit status non-zero */
    TEST_CHECK(t->exit_status == 1);

    tctx_destroy(t);
    fake_end();
}

static void test_download_403_fails_run(void)
{
    struct tctx *t;
    struct fake_obj *o;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    o = fake_add("a", "1", "{\"n\":1}\n");
    o->fail_status = 403;
    o->fail_times = -1;
    fake_add("b", "1", "{\"n\":2}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 0);
    TEST_CHECK(fk.objs[0].hits == 1);
    TEST_CHECK(fk.objs[1].hits == 0);
    TEST_CHECK(t->exit_status == 1);

    tctx_destroy(t);
    fake_end();
}

static void test_list_403(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fk.list_fail_status = 403;
    fk.list_fail_times = -1;
    fake_add("a", "1", "{\"n\":1}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 0);
    TEST_CHECK(fk.list_hits == 1);
    TEST_CHECK(t->exit_status == 1);

    tctx_destroy(t);
    fake_end();
}

static void test_list_retry_exhausted(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "retry_limit", "1", NULL};

    fake_begin();
    fk.list_fail_status = 503;
    fk.list_fail_times = -1;
    fake_add("a", "1", "{\"n\":1}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 0);
    TEST_CHECK(fk.list_hits == 2);

    tctx_destroy(t);
    fake_end();
}

static void test_list_retry_then_ok(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fk.list_fail_status = 500;
    fk.list_fail_times = 2;
    fake_add("a", "1", "{\"n\":1}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(fk.list_hits == 3);

    tctx_destroy(t);
    fake_end();
}

static void test_token_failure(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "retry_limit", "1", NULL};

    fake_begin();
    fk.meta_fail = 1;
    fake_add("a", "1", "{\"n\":1}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 0);
    TEST_CHECK(fk.meta_hits >= 2);
    TEST_CHECK(fk.list_hits == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_list_401_refreshes_token(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fk.reject_token1 = REJECT_LIST;
    fake_add("a", "1", "{\"n\":1}\n{\"n\":2}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(fk.meta_hits == 2);
    TEST_CHECK(fk.list_hits == 2);
    TEST_CHECK(fk.saw_token2 >= 2);
    TEST_CHECK(sink_count(&t->s1) == 2);

    tctx_destroy(t);
    fake_end();
}

static void test_download_401_refreshes_token(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "retry_limit", "0", NULL};

    fake_begin();
    fk.reject_token1 = REJECT_DOWNLOAD;
    fake_add("a", "1", "{\"n\":1}\n{\"n\":2}\n");
    fake_add("b", "1", "{\"n\":3}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    /* the 401 retry does not consume retry_limit (0 here) */
    TEST_CHECK(fk.meta_hits == 2);
    TEST_CHECK(fk.objs[0].hits == 2);
    TEST_CHECK(fk.objs[1].hits == 1);
    TEST_CHECK(sink_count(&t->s1) == 3);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"n\":3}") == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_list_401_always(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fk.reject_all = REJECT_LIST;
    fake_add("a", "1", "{\"n\":1}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(fk.list_hits == 2);
    TEST_CHECK(fk.meta_hits == 2);
    TEST_CHECK(sink_count(&t->s1) == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_download_401_always(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fk.reject_all = REJECT_DOWNLOAD;
    fake_add("a", "1", "{\"n\":1}\n");
    fake_add("b", "1", "{\"n\":2}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(fk.list_hits == 1);
    TEST_CHECK(fk.objs[0].hits == 2);
    TEST_CHECK(fk.objs[1].hits == 0);
    TEST_CHECK(sink_count(&t->s1) == 0);

    tctx_destroy(t);
    fake_end();
}

static void test_many_records_no_loss(void)
{
    int i;
    char expected[64];
    char *body;
    size_t off = 0;
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "batch_size", "10", "mem_buf_limit", "2K",
                           NULL};

    fake_begin();
    body = flb_calloc(1, 64 * 1024);
    for (i = 0; i < 300; i++) {
        off += snprintf(body + off, 64 * 1024 - off,
                        "{\"n\":%d,\"pad\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}\n", i);
    }
    fake_add("a", "1", body);
    flb_free(body);

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 300);
    for (i = 0; i < 300 && i < sink_count(&t->s1); i++) {
        snprintf(expected, sizeof(expected),
                 "{\"n\":%d,\"pad\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}", i);
        if (!TEST_CHECK(strcmp(rec(&t->s1, i), expected) == 0)) {
            TEST_MSG("record %d mismatch: %s", i, rec(&t->s1, i));
            break;
        }
    }

    tctx_destroy(t);
    fake_end();
}

/* backpressure: a small memory limit and a slow flush pause the input; nothing is lost */
static void test_backpressure_no_loss(void)
{
    int i;
    char expected[64];
    char *body;
    size_t off = 0;
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "batch_size", "5", "mem_buf_limit", "1K",
                           NULL};

    fake_begin();
    body = flb_calloc(1, 32 * 1024);
    for (i = 0; i < 100; i++) {
        off += snprintf(body + off, 32 * 1024 - off,
                        "{\"n\":%d,\"pad\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}\n", i);
    }
    fake_add("a", "1", body);
    flb_free(body);

    t = tctx_create(props, NULL, NULL);
    flb_service_set(t->flb, "Flush", "1", NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 100);
    for (i = 0; i < 100 && i < sink_count(&t->s1); i++) {
        snprintf(expected, sizeof(expected),
                 "{\"n\":%d,\"pad\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}", i);
        if (!TEST_CHECK(strcmp(rec(&t->s1, i), expected) == 0)) {
            TEST_MSG("record %d mismatch: %s", i, rec(&t->s1, i));
            break;
        }
    }

    tctx_destroy(t);
    fake_end();
}

#ifdef FLB_HAVE_SQLDB
static void db_cleanup(const char *path)
{
    char tmp[512];

    remove(path);
    snprintf(tmp, sizeof(tmp), "%s-wal", path);
    remove(tmp);
    snprintf(tmp, sizeof(tmp), "%s-shm", path);
    remove(tmp);
    snprintf(tmp, sizeof(tmp), "%s-journal", path);
    remove(tmp);
}

static void test_db_skips_processed(void)
{
    char *db;
    struct tctx *t;
    const char *props[6] = {EXIT_ON_COMPLETE, "db", NULL, NULL, NULL};

    db = flb_test_tmpdir_cat("/flb_in_gcs_test.db");
    db_cleanup(db);
    props[3] = db;

    fake_begin();
    fake_add("a", "1", "{\"n\":1}\n{\"n\":2}\n");
    fake_add("b", "1", "{\"n\":3}\n");

    /* first run: everything is emitted */
    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);
    TEST_CHECK(sink_count(&t->s1) == 3);
    tctx_destroy(t);

    /* second run: nothing new */
    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);
    TEST_CHECK(sink_count(&t->s1) == 0);
    TEST_CHECK(fk.objs[0].hits == 1);
    tctx_destroy(t);

    /* a new generation of 'a' is processed again, 'b' is not */
    strcpy(fk.objs[0].generation, "2");
    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);
    TEST_CHECK(sink_count(&t->s1) == 2);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);
    TEST_CHECK(fk.objs[1].hits == 1);
    tctx_destroy(t);

    fake_end();
    db_cleanup(db);
    flb_free(db);
}

static void test_db_failed_object_not_recorded(void)
{
    char *db;
    struct tctx *t;
    struct fake_obj *o;
    const char *props[6] = {EXIT_ON_COMPLETE, "db", NULL, NULL, NULL};

    db = flb_test_tmpdir_cat("/flb_in_gcs_test2.db");
    db_cleanup(db);
    props[3] = db;

    fake_begin();
    o = fake_add("a", "1", "{\"n\":1}\n");
    o->fail_status = 500;
    o->fail_times = -1;

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);
    TEST_CHECK(sink_count(&t->s1) == 0);
    tctx_destroy(t);

    /* the object failed, so a later run must try it again */
    o->fail_status = 0;
    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);
    TEST_CHECK(sink_count(&t->s1) == 1);
    tctx_destroy(t);

    fake_end();
    db_cleanup(db);
    flb_free(db);
}
#endif

/* ------------------------------------------------------------------ */
/* record building and timestamps                                      */
/* ------------------------------------------------------------------ */

/* object_key equal to the time key: the map size must match the packed pairs */
static void test_object_key_equals_time_key(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "object_key", "date", NULL};

    fake_begin();
    fake_add("obj", "1",
             "{\"date\":\"2023-11-14T22:13:20.500000Z\",\"message\":\"x\"}\n"
             "{\"message\":\"y\"}\n"
             "{\"date\":\"2023-11-14T22:13:21Z\",\"message\":\"z\"}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 3);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"message\":\"x\",\"date\":\"obj\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 0, 1700000000, 500000000));
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"message\":\"y\",\"date\":\"obj\"}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"message\":\"z\",\"date\":\"obj\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 2, 1700000001, 0));

    tctx_destroy(t);
    fake_end();
}

/* 'auto' applies the milliseconds threshold to floats too */
static void test_timestamps_auto_float_ms(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add("a", "1",
             "{\"date\":1700000000500.0,\"m\":\"ms\"}\n"
             "{\"date\":1700000000.5,\"m\":\"sec\"}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 2);
    TEST_CHECK(is_ts(&t->s1, 0, 1700000000, 500000000));
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"m\":\"ms\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 1, 1700000000, 500000000));
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"m\":\"sec\"}") == 0);

    tctx_destroy(t);
    fake_end();
}

/* timestamps that the event encoder cannot represent fall back to the ingestion time */
static void test_timestamps_out_of_range(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "time_format", "epoch", NULL};

    fake_begin();
    fake_add("a", "1",
             "{\"date\":4294967296,\"msg\":\"a\"}\n"
             "{\"date\":1700000000,\"msg\":\"b\"}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 2);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"date\":4294967296,\"msg\":\"a\"}") == 0);
    TEST_CHECK(is_recent(&t->s1, 0));
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"msg\":\"b\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 1, 1700000000, 0));

    tctx_destroy(t);
    fake_end();
}

/* explicit 'double' does not use the milliseconds heuristic: out of range */
static void test_timestamps_double_not_ms(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "time_format", "double", NULL};

    fake_begin();
    fake_add("a", "1", "{\"date\":1700000000500.0,\"msg\":\"c\"}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(strstr(rec(&t->s1, 0), "\"msg\":\"c\"") != NULL);
    TEST_CHECK(strstr(rec(&t->s1, 0), "\"date\"") != NULL);
    TEST_CHECK(is_recent(&t->s1, 0));

    tctx_destroy(t);
    fake_end();
}

static void test_timestamps_out_of_range_iso(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add("a", "1",
             "{\"date\":\"2200-01-01T00:00:00Z\",\"msg\":\"a\"}\n"
             "{\"date\":\"2023-11-14T22:13:20Z\",\"msg\":\"b\"}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 2);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"date\":\"2200-01-01T00:00:00Z\",\"msg\":\"a\"}") == 0);
    TEST_CHECK(is_recent(&t->s1, 0));
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"msg\":\"b\"}") == 0);
    TEST_CHECK(is_ts(&t->s1, 1, 1700000000, 0));

    tctx_destroy(t);
    fake_end();
}

/* a parser that provides a timestamp the encoder cannot represent */
static void test_parser_timestamp_out_of_range(void)
{
    int ret;
    char *path;
    FILE *fp;
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "parser", "gcs_epoch", NULL};

    path = flb_test_tmpdir_cat("/flb_in_gcs_parsers.conf");
    TEST_CHECK(path != NULL);
    fp = fopen(path, "wb");
    TEST_CHECK(fp != NULL);
    if (!fp) {
        flb_free(path);
        return;
    }
    fputs("[PARSER]\n    Name        gcs_epoch\n    Format      json\n"
          "    Time_Key    date\n    Time_Format %s\n", fp);
    fclose(fp);

    fake_begin();
    fake_add("a", "1",
             "{\"date\":\"99999999999\",\"msg\":\"a\"}\n"
             "{\"date\":\"1700000000\",\"msg\":\"b\"}\n");

    t = tctx_create(props, NULL, NULL);
    ret = flb_service_set(t->flb, "Parsers_File", path, NULL);
    TEST_CHECK(ret == 0);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 2);
    TEST_CHECK(is_recent(&t->s1, 0));
    TEST_CHECK(strstr(rec(&t->s1, 0), "\"msg\":\"a\"") != NULL);
    TEST_CHECK(is_ts(&t->s1, 1, 1700000000, 0));

    tctx_destroy(t);
    fake_end();
    remove(path);
    flb_free(path);
}

/* ------------------------------------------------------------------ */
/* encode failures (test seam: FLB_IN_GCS_PLUGIN_UNDER_TEST)           */
/* ------------------------------------------------------------------ */

#define ENCODE_FAIL_ALWAYS "__flb_in_gcs_test_encode_failure__"
#define ENCODE_FAIL_TWICE  "__flb_in_gcs_test_encode_failure__:2"

/* a batch that cannot be encoded is retried, then the object is given up */
static void test_encode_failure_gives_up(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "batch_size", "2", "retry_limit", "2",
                           NULL};

    setenv("FLB_IN_GCS_PLUGIN_UNDER_TEST", "true", 1);
    fake_begin();
    fake_add("a", "1", "{\"n\":1}\n{\"n\":2}\n" ENCODE_FAIL_ALWAYS "\n{\"n\":4}\n");
    fake_add("b", "1", "{\"n\":5}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    /* the first batch of 'a' was already ingested (at-least-once), the failing one
     * is dropped and 'b' is still processed */
    TEST_CHECK(sink_count(&t->s1) == 3);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":1}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"n\":2}") == 0);
    TEST_CHECK(strcmp(rec(&t->s1, 2), "{\"n\":5}") == 0);
    TEST_CHECK(fk.objs[1].hits == 1);
    TEST_CHECK(t->exit_status == 1);

    tctx_destroy(t);
    fake_end();
    unsetenv("FLB_IN_GCS_PLUGIN_UNDER_TEST");
}

/* the records of a failed batch that were already encoded are not ingested */
static void test_encode_failure_drops_partial_batch(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "batch_size", "3", "retry_limit", "1",
                           NULL};

    setenv("FLB_IN_GCS_PLUGIN_UNDER_TEST", "true", 1);
    fake_begin();
    fake_add("a", "1", "{\"n\":1}\n{\"n\":2}\n" ENCODE_FAIL_ALWAYS "\n");
    fake_add("b", "1", "{\"n\":3}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(strcmp(rec(&t->s1, 0), "{\"n\":3}") == 0);
    TEST_CHECK(t->exit_status == 1);

    tctx_destroy(t);
    fake_end();
    unsetenv("FLB_IN_GCS_PLUGIN_UNDER_TEST");
}

/* encode failures within 'retry_limit' are recovered, and the counter is per batch */
static void test_encode_failure_recovers(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, "batch_size", "1", "retry_limit", "2",
                           NULL};

    setenv("FLB_IN_GCS_PLUGIN_UNDER_TEST", "true", 1);
    fake_begin();
    fake_add("a", "1", ENCODE_FAIL_TWICE "\n{\"n\":2}\n" ENCODE_FAIL_TWICE "\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 3);
    TEST_CHECK(strstr(rec(&t->s1, 0), ENCODE_FAIL_ALWAYS) != NULL);
    TEST_CHECK(strcmp(rec(&t->s1, 1), "{\"n\":2}") == 0);
    TEST_CHECK(strstr(rec(&t->s1, 2), ENCODE_FAIL_ALWAYS) != NULL);
    TEST_CHECK(t->exit_status == 0);

    tctx_destroy(t);
    fake_end();
    unsetenv("FLB_IN_GCS_PLUGIN_UNDER_TEST");
}

#ifdef FLB_HAVE_SQLDB
/* an object given up because of encode failures is not recorded in the db */
static void test_encode_failure_not_recorded(void)
{
    char *db;
    struct tctx *t;
    const char *props[7] = {EXIT_ON_COMPLETE, "retry_limit", "0", "db", NULL, NULL};

    db = flb_test_tmpdir_cat("/flb_in_gcs_test3.db");
    db_cleanup(db);
    props[5] = db;

    setenv("FLB_IN_GCS_PLUGIN_UNDER_TEST", "true", 1);
    fake_begin();
    fake_add("a", "1", ENCODE_FAIL_ALWAYS "\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);
    TEST_CHECK(sink_count(&t->s1) == 0);
    TEST_CHECK(t->exit_status == 1);
    tctx_destroy(t);
    unsetenv("FLB_IN_GCS_PLUGIN_UNDER_TEST");

    /* not recorded: a later run (without the seam) reads the object again */
    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);
    TEST_CHECK(sink_count(&t->s1) == 1);
    TEST_CHECK(fk.objs[0].hits == 2);
    TEST_CHECK(t->exit_status == 0);
    tctx_destroy(t);

    fake_end();
    db_cleanup(db);
    flb_free(db);
}
#endif

/* names that need JSON escaping: the listing limit must cover the worst case */
static void test_listing_escaped_names(void)
{
    int i;
    char name[1100];
    struct tctx *t;
    struct fake_obj *o;
    const char *props[] = {EXIT_ON_COMPLETE, "page_size", "16", "max_object_size", "1",
                           NULL};

    fake_begin();
    for (i = 0; i < MAX_OBJS; i++) {
        memset(name, 1, 1000);
        snprintf(name + 1000, sizeof(name) - 1000, "-%02d", i);
        o = fake_add(name, "1", "{\"n\":1}\n");
        o->listed_size = 100;
    }

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    /* the objects were listed (and skipped for their size): the run did not fail */
    TEST_CHECK(fk.list_hits == 1);
    TEST_CHECK(t->exit_status == 0);
    TEST_CHECK(sink_count(&t->s1) == 0);

    tctx_destroy(t);
    fake_end();
}

/* calendar validation and time zone forms of ISO8601 timestamps */
static void test_timestamps_iso_forms(void)
{
    struct tctx *t;
    const char *props[] = {EXIT_ON_COMPLETE, NULL};

    fake_begin();
    fake_add("a", "1",
             "{\"date\":\"2023-11-14T23:13:20+0100\",\"m\":\"0\"}\n"
             "{\"date\":\"2023-11-14T23:13:20+01:00\",\"m\":\"1\"}\n"
             "{\"date\":\"2023-11-14T23:13:20+01\",\"m\":\"2\"}\n"
             "{\"date\":\"2023-11-14T22:13:20Z\",\"m\":\"3\"}\n"
             "{\"date\":\"2023-11-14T23:13:20+01:\",\"m\":\"4\"}\n"
             "{\"date\":\"2023-11-14T22:13:20Zx\",\"m\":\"5\"}\n"
             "{\"date\":\"2023-02-29T00:00:00Z\",\"m\":\"6\"}\n"
             "{\"date\":\"2024-02-29T00:00:00Z\",\"m\":\"7\"}\n"
             "{\"date\":\"2023-04-31T00:00:00Z\",\"m\":\"8\"}\n");

    t = tctx_create(props, NULL, NULL);
    run_to_completion(t);

    TEST_CHECK(sink_count(&t->s1) == 9);
    TEST_CHECK(is_ts(&t->s1, 0, 1700000000, 0));
    TEST_CHECK(is_ts(&t->s1, 1, 1700000000, 0));
    TEST_CHECK(is_ts(&t->s1, 2, 1700000000, 0));
    TEST_CHECK(is_ts(&t->s1, 3, 1700000000, 0));
    TEST_CHECK(is_recent(&t->s1, 4));
    TEST_CHECK(strstr(rec(&t->s1, 4), "\"date\":\"2023-11-14T23:13:20+01:\"") != NULL);
    TEST_CHECK(is_recent(&t->s1, 5));
    TEST_CHECK(strstr(rec(&t->s1, 5), "\"date\"") != NULL);
    TEST_CHECK(is_recent(&t->s1, 6));
    TEST_CHECK(strstr(rec(&t->s1, 6), "\"date\":\"2023-02-29T00:00:00Z\"") != NULL);
    TEST_CHECK(is_ts(&t->s1, 7, 1709164800, 0));
    TEST_CHECK(strcmp(rec(&t->s1, 7), "{\"m\":\"7\"}") == 0);
    TEST_CHECK(is_recent(&t->s1, 8));
    TEST_CHECK(strstr(rec(&t->s1, 8), "\"date\":\"2023-04-31T00:00:00Z\"") != NULL);

    tctx_destroy(t);
    fake_end();
}

/* invalid configuration: the engine must refuse to start, without crashing */
static void check_invalid(const char **props)
{
    int ret;
    struct tctx *t;

    t = tctx_create(props, NULL, NULL);
    ret = flb_start(t->flb);
    TEST_CHECK(ret != 0);
    if (ret == 0) {
        flb_stop(t->flb);
    }
    tctx_destroy(t);
}

static void test_invalid_configs(void)
{
    const char *missing_bucket[] = {"!bucket", "x", NULL};
    const char *bad_compression[] = {"compression", "foo", NULL};
    const char *bad_time_format[] = {"time_format", "foo", NULL};
    const char *bad_regex[] = {"tag_regex", "(", NULL};
    const char *bad_batch[] = {"batch_size", "0", NULL};
    const char *bad_object_size[] = {"max_object_size", "0", NULL};
    const char *bad_retry[] = {"retry_limit", "-1", NULL};
    const char *bad_parser[] = {"parser", "no_such_parser", NULL};
    const char *bad_endpoint[] = {"endpoint", "ftp://example.com", NULL};

    unsetenv("GOOGLE_APPLICATION_CREDENTIALS");
    unsetenv("GOOGLE_SERVICE_CREDENTIALS");

    check_invalid(missing_bucket);
    check_invalid(bad_compression);
    check_invalid(bad_time_format);
    check_invalid(bad_regex);
    check_invalid(bad_batch);
    check_invalid(bad_object_size);
    check_invalid(bad_retry);
    check_invalid(bad_parser);
    check_invalid(bad_endpoint);
}

TEST_LIST = {
    {"happy_path", test_happy_path},
    {"no_exit_keeps_running", test_no_exit_keeps_running},
    {"pagination", test_pagination},
    {"prefix_and_offsets", test_prefix_and_offsets},
    {"unset_params_are_omitted", test_unset_params_are_omitted},
    {"empty_bucket", test_empty_bucket},
    {"folder_placeholder_skipped", test_folder_placeholder_skipped},
    {"slash_object_with_content", test_slash_object_with_content},
    {"edge_content", test_edge_content},
    {"gzip_auto", test_gzip_auto},
    {"gzip_explicit", test_gzip_explicit},
    {"compression_none_on_gzip_body", test_compression_none_on_gzip_body},
    {"corrupt_gzip", test_corrupt_gzip},
    {"non_json_lines", test_non_json_lines},
    {"timestamps_auto", test_timestamps_auto},
    {"time_keep", test_time_keep},
    {"custom_time_key", test_custom_time_key},
    {"time_key_disabled", test_time_key_disabled},
    {"time_format_explicit", test_time_format_explicit},
    {"tag_regex", test_tag_regex},
    {"object_key", test_object_key},
    {"batch_size", test_batch_size},
    {"max_object_size", test_max_object_size},
    {"download_404", test_download_404},
    {"download_retry_then_ok", test_download_retry_then_ok},
    {"download_503_retry", test_download_503_retry},
    {"download_retry_exhausted", test_download_retry_exhausted},
    {"download_403_fails_run", test_download_403_fails_run},
    {"list_403", test_list_403},
    {"list_retry_exhausted", test_list_retry_exhausted},
    {"list_retry_then_ok", test_list_retry_then_ok},
    {"token_failure", test_token_failure},
    {"list_401_refreshes_token", test_list_401_refreshes_token},
    {"download_401_refreshes_token", test_download_401_refreshes_token},
    {"list_401_always", test_list_401_always},
    {"download_401_always", test_download_401_always},
    {"many_records_no_loss", test_many_records_no_loss},
    {"backpressure_no_loss", test_backpressure_no_loss},
#ifdef FLB_HAVE_SQLDB
    {"db_skips_processed", test_db_skips_processed},
    {"db_failed_object_not_recorded", test_db_failed_object_not_recorded},
#endif
    {"object_key_equals_time_key", test_object_key_equals_time_key},
    {"timestamps_auto_float_ms", test_timestamps_auto_float_ms},
    {"timestamps_out_of_range", test_timestamps_out_of_range},
    {"timestamps_double_not_ms", test_timestamps_double_not_ms},
    {"timestamps_out_of_range_iso", test_timestamps_out_of_range_iso},
    {"parser_timestamp_out_of_range", test_parser_timestamp_out_of_range},
    {"encode_failure_gives_up", test_encode_failure_gives_up},
    {"encode_failure_drops_partial_batch", test_encode_failure_drops_partial_batch},
    {"encode_failure_recovers", test_encode_failure_recovers},
#ifdef FLB_HAVE_SQLDB
    {"encode_failure_not_recorded", test_encode_failure_not_recorded},
#endif
    {"listing_escaped_names", test_listing_escaped_names},
    {"timestamps_iso_forms", test_timestamps_iso_forms},
    {"invalid_configs", test_invalid_configs},
    {NULL, NULL}
};
