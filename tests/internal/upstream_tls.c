/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_conn.h>
#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_output.h>

#include "flb_tests_internal.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef FLB_HAVE_TLS

#ifdef FLB_SYSTEM_WINDOWS
#include <fluent-bit/flb_compat.h>
#else
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#define FLB_TEST_HAVE_PROXY_STUB
#endif

struct test_backend_ctx {
    int invalidate_calls;
    int destroy_calls;
};

static int copy_file(const char *src, const char *dst)
{
    FILE *in;
    FILE *out;
    char buf[4096];
    size_t bytes;

    in = fopen(src, "rb");
    if (in == NULL) {
        return -1;
    }

    out = fopen(dst, "wb");
    if (out == NULL) {
        fclose(in);
        return -1;
    }

    while ((bytes = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, bytes, out) != bytes) {
            fclose(out);
            fclose(in);
            return -1;
        }
    }

    if (ferror(in)) {
        fclose(out);
        fclose(in);
        return -1;
    }

    fclose(out);
    fclose(in);

    return 0;
}

static int append_file(const char *path, const char *data)
{
    FILE *out;

    out = fopen(path, "ab");
    if (out == NULL) {
        return -1;
    }

    if (fwrite(data, 1, strlen(data), out) != strlen(data)) {
        fclose(out);
        return -1;
    }

    fclose(out);

    return 0;
}

static int reload_mutation_count;

static int test_reload_and_mutate_key(struct flb_tls *tls)
{
    reload_mutation_count++;

    return append_file(tls->key_file, "\n");
}

static void test_session_invalidate(void *session)
{
    struct test_backend_ctx *ctx = session;

    if (ctx != NULL) {
        ctx->invalidate_calls++;
    }
}

static int test_session_destroy(void *session)
{
    struct test_backend_ctx *ctx = session;

    if (ctx != NULL) {
        ctx->destroy_calls++;
    }

    return 0;
}

static int setup_conn(struct flb_connection *conn,
                      struct flb_upstream *upstream,
                      struct flb_config *config,
                      flb_pipefd_t *socket_pair)
{
    if (flb_pipe_create(socket_pair) != 0) {
        return -1;
    }

    config->is_shutting_down    = FLB_FALSE;
    upstream->base.config       = config;
    upstream->base.net.keepalive = FLB_FALSE;
    upstream->tcp_host          = "example";
    upstream->tcp_port          = 443;
    flb_upstream_queue_init(&upstream->queue);

    conn->fd          = socket_pair[0];
    conn->event.fd    = conn->fd;
    conn->event.status = 0;
    conn->stream      = (struct flb_stream *) upstream;
    conn->net         = &upstream->base.net;
    conn->net_error   = 0;

    mk_list_init(&conn->_head);
    mk_list_add(&conn->_head, &upstream->queue.busy_queue);

    return 0;
}

void test_prepare_destroy_conn_marks_tls_session_stale(void)
{
    struct test_backend_ctx backend_session = {0};
    struct flb_tls_backend backend_api = {0};
    struct flb_tls tls_context = {0};
    struct flb_tls_session tls_session = {0};
    struct flb_connection conn = {0};
    struct flb_upstream upstream = {0};
    struct flb_config config = {0};
    flb_pipefd_t socket_pair[2];

#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    TEST_CHECK(setup_conn(&conn, &upstream, &config, socket_pair) == 0);

    backend_api.session_invalidate = test_session_invalidate;
    tls_context.api = &backend_api;
    tls_session.ptr = &backend_session;
    tls_session.tls = &tls_context;
    tls_session.connection = &conn;
    conn.tls_session = &tls_session;

    TEST_CHECK(flb_upstream_conn_release(&conn) == 0);

    TEST_CHECK(backend_session.invalidate_calls == 1);
    TEST_CHECK(conn.fd == -1);
    TEST_CHECK(conn.event.fd == -1);
    TEST_CHECK(mk_list_size(&upstream.queue.destroy_queue) == 1);
    TEST_CHECK(conn.shutdown_flag == FLB_TRUE);

    flb_pipe_close(socket_pair[1]);

#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

void test_tls_session_destroy_no_double_free(void)
{
    struct test_backend_ctx backend_session = {0};
    struct flb_tls_backend backend_api = {0};
    struct flb_tls tls_context = {0};
    struct flb_tls_session *tls_session;
    struct flb_connection *conn;
    struct flb_upstream upstream = {0};
    struct flb_config config = {0};
    flb_pipefd_t socket_pair[2];

#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    /* heap-allocate conn to match production; pending_destroy calls flb_free on it */
    conn = flb_calloc(1, sizeof(struct flb_connection));
    TEST_CHECK(conn != NULL);
    conn->dynamically_allocated = FLB_TRUE;
    TEST_CHECK(setup_conn(conn, &upstream, &config, socket_pair) == 0);

    backend_api.session_invalidate = test_session_invalidate;
    backend_api.session_destroy    = test_session_destroy;
    tls_context.api = &backend_api;

    /* heap-allocated to match production; flb_tls_session_destroy calls flb_free */
    tls_session = flb_calloc(1, sizeof(struct flb_tls_session));
    TEST_CHECK(tls_session != NULL);
    tls_session->ptr        = &backend_session;
    tls_session->tls        = &tls_context;
    tls_session->connection = conn;
    conn->tls_session       = tls_session;

    /* explicit destroy before release — the fix */
    TEST_CHECK(flb_tls_session_destroy(tls_session) == 0);
    TEST_CHECK(conn->tls_session == NULL);

    TEST_CHECK(flb_upstream_conn_release(conn) == 0);

    /* pending_destroy must not double-free the already-destroyed session */
    TEST_CHECK(flb_upstream_conn_pending_destroy(&upstream) == 0);
    TEST_CHECK(backend_session.destroy_calls == 1);

    flb_pipe_close(socket_pair[1]);

#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

/*
 * Verify that flb_upstream_create creates a proxy_tls_context with
 * verify_hostname enabled when an https:// proxy is configured.
 */
void test_upstream_create_https_proxy_sets_tls_context(void)
{
    struct flb_config *config;
    struct flb_upstream *u;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        return;
    }

    config->http_proxy = "https://proxy.example.com:8080";

    u = flb_upstream_create(config, "dest.example.com", 443,
                            FLB_IO_TLS, NULL);
    TEST_CHECK(u != NULL);
    if (u == NULL) {
        config->http_proxy = NULL;
        flb_config_exit(config);
        return;
    }

    TEST_CHECK(u->proxy_tls_context != NULL);
    TEST_MSG("proxy_tls_context should be non-NULL for https:// proxy");

    if (u->proxy_tls_context != NULL) {
        TEST_CHECK(u->proxy_tls_context->verify_hostname == FLB_TRUE);
        TEST_MSG("proxy_tls_context should have verify_hostname enabled");
    }

    config->http_proxy = NULL;
    flb_upstream_destroy(u);
    flb_config_exit(config);
}

/*
 * Verify that flb_upstream_create does NOT create a proxy_tls_context
 * when a plain http:// proxy is configured.
 */
void test_upstream_create_http_proxy_no_tls_context(void)
{
    struct flb_config *config;
    struct flb_upstream *u;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        return;
    }

    config->http_proxy = "http://proxy.example.com:3128";

    u = flb_upstream_create(config, "dest.example.com", 80,
                            FLB_IO_TCP, NULL);
    TEST_CHECK(u != NULL);
    if (u == NULL) {
        config->http_proxy = NULL;
        flb_config_exit(config);
        return;
    }

    TEST_CHECK(u->proxy_tls_context == NULL);
    TEST_MSG("proxy_tls_context should be NULL for plain http:// proxy");

    config->http_proxy = NULL;
    flb_upstream_destroy(u);
    flb_config_exit(config);
}

void test_tls_reload_when_certificate_file_changes(void)
{
    int ret;
    char src_crt[4096];
    char src_key[4096];
    char *dst_crt;
    char *dst_key;
    struct flb_tls *tls;

    snprintf(src_crt, sizeof(src_crt), "%sdata/tls/certificate.pem",
             FLB_TESTS_DATA_PATH);
    snprintf(src_key, sizeof(src_key), "%sdata/tls/private_key.pem",
             FLB_TESTS_DATA_PATH);

    dst_crt = flb_test_tmpdir_cat("/flb_tls_reload_certificate.pem");
    dst_key = flb_test_tmpdir_cat("/flb_tls_reload_private_key.pem");
    TEST_CHECK(dst_crt != NULL);
    TEST_CHECK(dst_key != NULL);

    TEST_CHECK(copy_file(src_crt, dst_crt) == 0);
    TEST_CHECK(copy_file(src_key, dst_key) == 0);

    tls = flb_tls_create(FLB_TLS_SERVER_MODE,
                         FLB_TRUE,
                         0,
                         NULL,
                         NULL,
                         NULL,
                         dst_crt,
                         dst_key,
                         NULL);
    TEST_CHECK(tls != NULL);

    TEST_CHECK(flb_tls_reload_if_needed(tls) == 0);

    TEST_CHECK(append_file(dst_key, "\n") == 0);
    ret = flb_tls_reload_if_needed(tls);
    TEST_CHECK(ret == 1);

    flb_tls_destroy(tls);
    remove(dst_crt);
    remove(dst_key);
    flb_free(dst_crt);
    flb_free(dst_key);
}

#ifdef FLB_SYSTEM_LINUX
void test_tls_reload_when_certificate_file_is_replaced(void)
{
    char src_crt[4096];
    char src_key[4096];
    char *dst_crt;
    char *dst_key;
    char *replacement_key;
    struct stat st;
    struct flb_tls *tls;

    snprintf(src_crt, sizeof(src_crt), "%sdata/tls/certificate.pem",
             FLB_TESTS_DATA_PATH);
    snprintf(src_key, sizeof(src_key), "%sdata/tls/private_key.pem",
             FLB_TESTS_DATA_PATH);

    dst_crt = flb_test_tmpdir_cat("/flb_tls_replace_certificate.pem");
    dst_key = flb_test_tmpdir_cat("/flb_tls_replace_private_key.pem");
    replacement_key = flb_test_tmpdir_cat("/flb_tls_replacement_private_key.pem");
    TEST_CHECK(dst_crt != NULL);
    TEST_CHECK(dst_key != NULL);
    TEST_CHECK(replacement_key != NULL);

    TEST_CHECK(copy_file(src_crt, dst_crt) == 0);
    TEST_CHECK(copy_file(src_key, dst_key) == 0);
    TEST_CHECK(copy_file(src_key, replacement_key) == 0);

    tls = flb_tls_create(FLB_TLS_SERVER_MODE,
                         FLB_TRUE,
                         0,
                         NULL,
                         NULL,
                         NULL,
                         dst_crt,
                         dst_key,
                         NULL);
    TEST_CHECK(tls != NULL);

    TEST_CHECK(rename(replacement_key, dst_key) == 0);
    TEST_CHECK(stat(dst_key, &st) == 0);

    /* Make the inode the only observable difference from the cached status. */
    tls->key_file_status.size = (uint64_t) st.st_size;
    tls->key_file_status.device = (uint64_t) st.st_dev;
    tls->key_file_status.mtime = (uint64_t) st.st_mtime;
    tls->key_file_status.ctime = (uint64_t) st.st_ctime;
    tls->key_file_status.mtime_nsec = (uint64_t) st.st_mtim.tv_nsec;
    tls->key_file_status.ctime_nsec = (uint64_t) st.st_ctim.tv_nsec;

    TEST_CHECK(tls->key_file_status.inode != (uint64_t) st.st_ino);
    TEST_CHECK(flb_tls_reload_if_needed(tls) == 1);

    flb_tls_destroy(tls);
    remove(dst_crt);
    remove(dst_key);
    remove(replacement_key);
    flb_free(dst_crt);
    flb_free(dst_key);
    flb_free(replacement_key);
}
#endif

void test_tls_reload_does_not_hide_concurrent_file_change(void)
{
    char src_crt[4096];
    char src_key[4096];
    char *dst_crt;
    char *dst_key;
    struct flb_tls_backend test_backend = {0};
    struct flb_tls_backend *openssl_backend;
    struct flb_tls *tls;

    snprintf(src_crt, sizeof(src_crt), "%sdata/tls/certificate.pem",
             FLB_TESTS_DATA_PATH);
    snprintf(src_key, sizeof(src_key), "%sdata/tls/private_key.pem",
             FLB_TESTS_DATA_PATH);

    dst_crt = flb_test_tmpdir_cat("/flb_tls_concurrent_certificate.pem");
    dst_key = flb_test_tmpdir_cat("/flb_tls_concurrent_private_key.pem");
    TEST_CHECK(dst_crt != NULL);
    TEST_CHECK(dst_key != NULL);

    TEST_CHECK(copy_file(src_crt, dst_crt) == 0);
    TEST_CHECK(copy_file(src_key, dst_key) == 0);

    tls = flb_tls_create(FLB_TLS_SERVER_MODE,
                         FLB_TRUE,
                         0,
                         NULL,
                         NULL,
                         NULL,
                         dst_crt,
                         dst_key,
                         NULL);
    TEST_CHECK(tls != NULL);

    openssl_backend = tls->api;
    test_backend.context_reload = test_reload_and_mutate_key;
    tls->api = &test_backend;
    reload_mutation_count = 0;

    TEST_CHECK(append_file(dst_key, "\n") == 0);
    TEST_CHECK(flb_tls_reload_if_needed(tls) == 1);
    TEST_CHECK(flb_tls_reload_if_needed(tls) == 1);
    TEST_CHECK(reload_mutation_count == 2);

    tls->api = openssl_backend;
    flb_tls_destroy(tls);
    remove(dst_crt);
    remove(dst_key);
    flb_free(dst_crt);
    flb_free(dst_key);
}

/*
 * Verify that flb_upstream_proxy_tls_setup() is a safe no-op when the
 * upstream has no HTTPS proxy in effect (proxy_tls_context == NULL).
 */
void test_upstream_proxy_tls_setup_noop_without_proxy(void)
{
    struct flb_config *config;
    struct flb_upstream *u;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        return;
    }

    u = flb_upstream_create(config, "dest.example.com", 80, FLB_IO_TCP, NULL);
    TEST_CHECK(u != NULL);
    if (u == NULL) {
        flb_config_exit(config);
        return;
    }

    TEST_CHECK(u->proxy_tls_context == NULL);
    TEST_CHECK(flb_upstream_proxy_tls_setup(u, FLB_TRUE, FLB_TRUE, NULL, NULL) == 0);
    TEST_CHECK(u->proxy_tls_context == NULL);

    flb_upstream_destroy(u);
    flb_config_exit(config);
}

/*
 * Verify that flb_upstream_proxy_tls_setup() rebuilds the proxy TLS context
 * using the caller-supplied ca_file/verify/verify_hostname instead of the
 * hardcoded defaults set by flb_upstream_create(), and that these settings
 * are independent from the destination TLS context.
 */
void test_upstream_proxy_tls_setup_configures_ca(void)
{
    struct flb_config *config;
    struct flb_upstream *u;
    char ca_file[4096];

    snprintf(ca_file, sizeof(ca_file), "%sdata/tls/certificate.pem",
             FLB_TESTS_DATA_PATH);

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        return;
    }

    config->http_proxy = "https://proxy.example.com:8080";
    u = flb_upstream_create(config, "dest.example.com", 443, FLB_IO_TLS, NULL);
    config->http_proxy = NULL;

    TEST_CHECK(u != NULL);
    if (u == NULL) {
        flb_config_exit(config);
        return;
    }

    TEST_CHECK(u->proxy_tls_context != NULL);
    if (u->proxy_tls_context == NULL) {
        flb_upstream_destroy(u);
        flb_config_exit(config);
        return;
    }

    /* Hardcoded defaults from flb_upstream_create(): no CA, verify_hostname on. */
    TEST_CHECK(u->proxy_tls_context->ca_file == NULL);
    TEST_CHECK(u->proxy_tls_context->verify_hostname == FLB_TRUE);

    TEST_CHECK(flb_upstream_proxy_tls_setup(u, FLB_TRUE, FLB_FALSE,
                                            NULL, ca_file) == 0);

    TEST_CHECK(u->proxy_tls_context != NULL);
    if (u->proxy_tls_context != NULL) {
        TEST_CHECK(u->proxy_tls_context->ca_file != NULL);
        TEST_MSG("proxy_tls_context->ca_file should reflect tls.proxy.ca_file");
        if (u->proxy_tls_context->ca_file != NULL) {
            TEST_CHECK(strcmp(u->proxy_tls_context->ca_file, ca_file) == 0);
        }
        TEST_CHECK(u->proxy_tls_context->verify_hostname == FLB_FALSE);
        TEST_MSG("proxy_tls_context->verify_hostname should reflect tls.proxy.verify_hostname");

        /* The vhost is reused from the proxy hostname, independent of any
         * destination tls.vhost setting. */
        TEST_CHECK(u->proxy_tls_context->vhost != NULL);
        if (u->proxy_tls_context->vhost != NULL) {
            TEST_CHECK(strcmp(u->proxy_tls_context->vhost, "proxy.example.com") == 0);
        }
    }

    flb_upstream_destroy(u);
    flb_config_exit(config);
}

/* Invalid tls.proxy.ca_file/ca_path must fail output init. */
void test_output_proxy_tls_ca_check(void)
{
    struct flb_output_instance ins = {0};
    char valid_ca_file[4096];

    snprintf(valid_ca_file, sizeof(valid_ca_file), "%sdata/tls/proxy_stub_certificate.pem",
             FLB_TESTS_DATA_PATH);

    snprintf(ins.name, sizeof(ins.name), "test");
    ins.tls_proxy_verify = FLB_TRUE;

    /* No proxy CA configured: nothing to validate. */
    ins.tls_proxy_ca_file = NULL;
    ins.tls_proxy_ca_path = NULL;
    TEST_CHECK(flb_output_proxy_tls_ca_check(&ins) == 0);

    /* Invalid ca_file: must fail so the caller aborts output init. */
    ins.tls_proxy_ca_file = "/this/path/does/not/exist.pem";
    TEST_CHECK(flb_output_proxy_tls_ca_check(&ins) == -1);

    /* Valid ca_file: must succeed. */
    ins.tls_proxy_ca_file = valid_ca_file;
    TEST_CHECK(flb_output_proxy_tls_ca_check(&ins) == 0);
}

/*
 * Verify that the connection-scoped FLB_IO_PROXY_TLS flag (set by the fixed
 * flb_io.c proxy-connect path) never leaks into the shared stream's flags.
 * This directly protects flb_http_client.c's Host-header logic, which reads
 * the stream's FLB_IO_TLS flag to decide whether to omit the port.
 */
void test_io_proxy_tls_flag_does_not_leak_to_stream(void)
{
    struct flb_connection conn = {0};
    struct flb_upstream upstream = {0};
    struct flb_config config = {0};
    flb_pipefd_t socket_pair[2];

#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    TEST_CHECK(setup_conn(&conn, &upstream, &config, socket_pair) == 0);

    /* Simulate what flb_io_net_connect() now does for an HTTPS proxy leg. */
    flb_connection_enable_flags(&conn, FLB_IO_PROXY_TLS);

    TEST_CHECK(flb_stream_get_flag_status(&upstream.base, FLB_IO_TLS) == FLB_FALSE);
    TEST_MSG("the shared stream must never observe FLB_IO_PROXY_TLS as FLB_IO_TLS");

    TEST_CHECK((flb_connection_get_flags(&conn) & FLB_IO_PROXY_TLS) != 0);
    TEST_CHECK((flb_connection_get_flags(&conn) & FLB_IO_TLS) == 0);

    flb_pipe_close(socket_pair[1]);
    flb_pipe_close(conn.fd);

#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

/*
 * Regression test for the exact scenario edsiper flagged: a plain HTTP
 * destination on port 443 reached through an HTTPS proxy must keep ":443"
 * in its Host header. Before the fix, flb_io_net_connect() enabled
 * FLB_IO_TLS on the shared destination stream merely because the proxy leg
 * was TLS, which made flb_http_client.c's is_https_default_port check treat
 * the destination as HTTPS-on-default-port and drop the port.
 *
 * This test never performs any I/O: add_host_and_content_length() queues
 * the computed Host header onto flb_http_client's headers list at
 * flb_http_client() call time, before any network access is attempted.
 */
void test_http_client_host_header_not_polluted_by_proxy_tls(void)
{
    struct flb_connection conn = {0};
    struct flb_upstream upstream = {0};
    struct flb_config config = {0};
    struct flb_http_client *c;
    struct flb_kv *kv;
    struct mk_list *head;
    int found_with_port = FLB_FALSE;
    int found_without_port = FLB_FALSE;

    config.is_shutting_down  = FLB_FALSE;
    upstream.base.config     = &config;
    upstream.base.type       = FLB_UPSTREAM;
    upstream.base.transport  = FLB_TRANSPORT_TCP;
    /* Intentionally no FLB_IO_TLS here: this reproduces the fixed state
     * where only the proxy leg is TLS and the destination stream flags
     * are left untouched. */

    conn.type   = FLB_UPSTREAM_CONNECTION;
    conn.fd     = -1;
    conn.stream = (struct flb_stream *) &upstream;
    conn.net    = &upstream.base.net;

    c = flb_http_client(&conn, FLB_HTTP_GET, "/", NULL, 0,
                        "dest.example.com", 443, NULL, 0);
    TEST_CHECK(c != NULL);
    if (c == NULL) {
        return;
    }

    mk_list_foreach(head, &c->headers) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (flb_sds_casecmp(kv->key, "Host", 4) == 0) {
            if (strcmp(kv->val, "dest.example.com:443") == 0) {
                found_with_port = FLB_TRUE;
            }
            else if (strcmp(kv->val, "dest.example.com") == 0) {
                found_without_port = FLB_TRUE;
            }
        }
    }

    TEST_CHECK(found_with_port == FLB_TRUE);
    TEST_MSG("Host header should retain :443 for a plain HTTP destination reached through an HTTPS proxy");
    TEST_CHECK(found_without_port == FLB_FALSE);
    TEST_MSG("Host header must not drop :443 due to proxy-only TLS being mistaken for destination TLS");

    flb_http_client_destroy(c);
}

#ifdef FLB_TEST_HAVE_PROXY_STUB
/*
 * Minimal loopback "HTTPS CONNECT proxy" used to exercise the real
 * flb_io_net_connect() path end-to-end: TCP connect, proxy TLS handshake,
 * HTTP CONNECT tunneling, and (optionally) a second, nested TLS handshake
 * for the destination leg, mirroring what a real HTTPS destination behind
 * an HTTPS proxy looks like on the wire.
 */
struct https_proxy_stub {
    int listen_fd;
    int port;
    pthread_t thread;
    SSL_CTX *ssl_ctx;
    int nested_tls;   /* also perform an inner TLS handshake after CONNECT */
    int outer_ok;     /* outer handshake + CONNECT ack completed */
    int inner_ok;     /* nested_tls only: inner handshake + echo round-trip ok */
};

static void *https_proxy_stub_thread(void *arg)
{
    struct https_proxy_stub *stub = (struct https_proxy_stub *) arg;
    int fd;
    SSL *ssl;
    char buf[1024];
    int n;

    fd = accept(stub->listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }

    ssl = SSL_new(stub->ssl_ctx);
    if (!ssl) {
        close(fd);
        return NULL;
    }
    SSL_set_fd(ssl, fd);

    if (SSL_accept(ssl) <= 0) {
        SSL_free(ssl);
        close(fd);
        return NULL;
    }

    /* Read (and discard) the CONNECT request. */
    n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n <= 0) {
        SSL_free(ssl);
        close(fd);
        return NULL;
    }

    /* Acknowledge the tunnel. */
    n = SSL_write(ssl, "HTTP/1.1 200 Connection Established\r\n\r\n", 40);
    if (n <= 0) {
        SSL_free(ssl);
        close(fd);
        return NULL;
    }

    stub->outer_ok = FLB_TRUE;

    if (stub->nested_tls) {
        BIO *bio;
        SSL *inner_ssl;

        /*
         * Layer a second, inner TLS server handshake on top of the
         * already-established outer TLS stream, mirroring what
         * tls_session_set_outer()/BIO_f_ssl() do on the client side in
         * src/tls/openssl.c for the destination leg of TLS-in-TLS.
         */
        bio = BIO_new(BIO_f_ssl());
        if (bio != NULL) {
            BIO_set_ssl(bio, ssl, BIO_NOCLOSE);

            inner_ssl = SSL_new(stub->ssl_ctx);
            if (inner_ssl != NULL) {
                SSL_set_bio(inner_ssl, bio, bio);

                if (SSL_accept(inner_ssl) > 0) {
                    n = SSL_read(inner_ssl, buf, sizeof(buf) - 1);
                    if (n > 0) {
                        buf[n] = '\0';
                        if (strcmp(buf, "ping") == 0 &&
                            SSL_write(inner_ssl, "pong", 4) > 0) {
                            stub->inner_ok = FLB_TRUE;
                        }
                    }
                    SSL_shutdown(inner_ssl);
                }

                /* Frees 'bio' too; BIO_NOCLOSE above keeps 'ssl' alive. */
                SSL_free(inner_ssl);
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);

    return NULL;
}

static int start_https_proxy_stub(struct https_proxy_stub *stub,
                                  const char *crt_file, const char *key_file,
                                  int nested_tls)
{
    struct sockaddr_in addr;
    socklen_t addr_len;
    int fd;
    int one = 1;

    memset(stub, 0, sizeof(*stub));
    stub->listen_fd = -1;
    stub->nested_tls = nested_tls;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
        listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }

    addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *) &addr, &addr_len) != 0) {
        close(fd);
        return -1;
    }

    stub->listen_fd = fd;
    stub->port = ntohs(addr.sin_port);

    /*
     * TLS_server_method() requires OpenSSL >= 1.1.0; older builds (e.g. the
     * system OpenSSL on CentOS 7) only have the versioned SSLv23_*_method()
     * API, which src/tls/openssl.c already falls back to for the same
     * reason.
     */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    stub->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
#else
    stub->ssl_ctx = SSL_CTX_new(TLS_server_method());
#endif
    if (!stub->ssl_ctx) {
        close(fd);
        stub->listen_fd = -1;
        return -1;
    }

    if (SSL_CTX_use_certificate_file(stub->ssl_ctx, crt_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(stub->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(stub->ssl_ctx);
        stub->ssl_ctx = NULL;
        close(fd);
        stub->listen_fd = -1;
        return -1;
    }

    if (pthread_create(&stub->thread, NULL, https_proxy_stub_thread, stub) != 0) {
        SSL_CTX_free(stub->ssl_ctx);
        stub->ssl_ctx = NULL;
        close(fd);
        stub->listen_fd = -1;
        return -1;
    }

    return 0;
}

static void stop_https_proxy_stub(struct https_proxy_stub *stub)
{
    if (stub->listen_fd >= 0) {
        pthread_join(stub->thread, NULL);
        close(stub->listen_fd);
        stub->listen_fd = -1;
    }
    if (stub->ssl_ctx != NULL) {
        SSL_CTX_free(stub->ssl_ctx);
        stub->ssl_ctx = NULL;
    }
}

static struct flb_connection *build_proxy_test_connection(struct flb_upstream *u)
{
    struct flb_connection *conn;

    conn = flb_calloc(1, sizeof(struct flb_connection));
    if (conn == NULL) {
        return NULL;
    }

    conn->type                 = FLB_UPSTREAM_CONNECTION;
    conn->fd                   = -1;
    conn->event.fd              = -1;
    conn->dynamically_allocated = FLB_TRUE;
    conn->stream                = (struct flb_stream *) u;
    conn->net                   = &u->base.net;

    mk_list_init(&conn->_head);
    flb_upstream_queue_init(&u->queue);
    mk_list_add(&conn->_head, &u->queue.busy_queue);

    return conn;
}

static void destroy_proxy_test_connection(struct flb_connection *conn)
{
    if (conn == NULL) {
        return;
    }

    if (conn->fd > 0) {
        flb_socket_close(conn->fd);
        conn->fd = -1;
        conn->event.fd = -1;
    }

    /*
     * Do not free 'conn' here: build_proxy_test_connection() registered it
     * in u->queue.busy_queue with dynamically_allocated = TRUE, so
     * flb_upstream_destroy(u) will walk the queue and destroy/free it
     * (including any live tls_session) via destroy_conn(). Freeing it here
     * too would double-free the connection once flb_upstream_destroy() is
     * called.
     */
}

/*
 * A plain HTTP destination (no destination TLS context) reached through a
 * trusted HTTPS proxy: the proxy CONNECT tunnel must succeed once
 * tls.proxy.ca_file names a CA that trusts the proxy certificate, and the
 * connection must come back with FLB_IO_PROXY_TLS set while the shared
 * stream's FLB_IO_TLS flag stays untouched. Uses port 443 to also cover
 * edsiper's literal "plain HTTP destination on port 443" scenario.
 */
void test_proxy_connect_trusted_ca_succeeds(void)
{
    struct https_proxy_stub stub;
    struct flb_config *config;
    struct flb_upstream *u;
    struct flb_connection *conn;
    char crt_file[4096];
    char key_file[4096];
    char proxy_url[64];
    int ret;

    snprintf(crt_file, sizeof(crt_file), "%sdata/tls/proxy_stub_certificate.pem",
             FLB_TESTS_DATA_PATH);
    snprintf(key_file, sizeof(key_file), "%sdata/tls/proxy_stub_private_key.pem",
             FLB_TESTS_DATA_PATH);

    TEST_CHECK(start_https_proxy_stub(&stub, crt_file, key_file, FLB_FALSE) == 0);
    if (stub.listen_fd < 0) {
        return;
    }

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        stop_https_proxy_stub(&stub);
        return;
    }

    snprintf(proxy_url, sizeof(proxy_url), "https://127.0.0.1:%d", stub.port);
    config->http_proxy = proxy_url;
    u = flb_upstream_create(config, "dest.example.com", 443, FLB_IO_TCP, NULL);
    config->http_proxy = NULL;

    TEST_CHECK(u != NULL);
    if (u == NULL) {
        flb_config_exit(config);
        stop_https_proxy_stub(&stub);
        return;
    }

    /* Trust the stub's self-signed certificate; hostname verification is
     * left off since the cert's CN does not match 127.0.0.1. */
    TEST_CHECK(flb_upstream_proxy_tls_setup(u, FLB_TRUE, FLB_FALSE,
                                            NULL, crt_file) == 0);

    conn = build_proxy_test_connection(u);
    TEST_CHECK(conn != NULL);
    if (conn != NULL) {
        ret = flb_io_net_connect(conn, NULL);
        TEST_CHECK(ret == 0);
        TEST_MSG("expected proxy CONNECT with a trusted CA to succeed");

        if (ret == 0) {
            TEST_CHECK((flb_connection_get_flags(conn) & FLB_IO_PROXY_TLS) != 0);
            TEST_CHECK(flb_stream_get_flag_status(&u->base, FLB_IO_TLS) == FLB_FALSE);
            TEST_MSG("destination stream must not be marked TLS by the proxy-only handshake");
        }

        destroy_proxy_test_connection(conn);
    }

    stop_https_proxy_stub(&stub);
    TEST_CHECK(stub.outer_ok == FLB_TRUE);

    flb_upstream_destroy(u);
    flb_config_exit(config);
}

/*
 * An HTTPS proxy whose certificate is not trusted (no tls.proxy.ca_file
 * configured, so verification falls back to the system trust store, which
 * does not know this self-signed test certificate) must cause the connect
 * to fail before any CONNECT request is sent.
 */
void test_proxy_connect_untrusted_ca_rejected(void)
{
    struct https_proxy_stub stub;
    struct flb_config *config;
    struct flb_upstream *u;
    struct flb_connection *conn;
    char crt_file[4096];
    char key_file[4096];
    char proxy_url[64];
    int ret;

    snprintf(crt_file, sizeof(crt_file), "%sdata/tls/proxy_stub_certificate.pem",
             FLB_TESTS_DATA_PATH);
    snprintf(key_file, sizeof(key_file), "%sdata/tls/proxy_stub_private_key.pem",
             FLB_TESTS_DATA_PATH);

    TEST_CHECK(start_https_proxy_stub(&stub, crt_file, key_file, FLB_FALSE) == 0);
    if (stub.listen_fd < 0) {
        return;
    }

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        stop_https_proxy_stub(&stub);
        return;
    }

    snprintf(proxy_url, sizeof(proxy_url), "https://127.0.0.1:%d", stub.port);
    config->http_proxy = proxy_url;
    u = flb_upstream_create(config, "dest.example.com", 443, FLB_IO_TCP, NULL);
    config->http_proxy = NULL;

    TEST_CHECK(u != NULL);
    if (u == NULL) {
        flb_config_exit(config);
        stop_https_proxy_stub(&stub);
        return;
    }

    /* No CA configured: verification falls back to the system trust store,
     * which must not trust this self-signed test certificate. */
    TEST_CHECK(flb_upstream_proxy_tls_setup(u, FLB_TRUE, FLB_FALSE,
                                            NULL, NULL) == 0);

    conn = build_proxy_test_connection(u);
    TEST_CHECK(conn != NULL);
    if (conn != NULL) {
        ret = flb_io_net_connect(conn, NULL);
        TEST_CHECK(ret == -1);
        TEST_MSG("expected proxy CONNECT with an untrusted CA to be rejected");

        destroy_proxy_test_connection(conn);
    }

    stop_https_proxy_stub(&stub);
    TEST_CHECK(stub.outer_ok == FLB_FALSE);

    flb_upstream_destroy(u);
    flb_config_exit(config);
}

/*
 * End-to-end nested TLS-in-TLS coverage for an HTTPS destination reached
 * through an HTTPS proxy: after the outer proxy handshake and CONNECT ack,
 * flb_tls_session_create() must automatically chain a second, inner
 * destination TLS handshake through the outer session (session_set_outer),
 * and application data must round-trip correctly through both layers.
 */
void test_proxy_connect_https_destination_nested_tls(void)
{
    struct https_proxy_stub stub;
    struct flb_config *config;
    struct flb_tls *dest_tls;
    struct flb_upstream *u;
    struct flb_connection *conn;
    char crt_file[4096];
    char key_file[4096];
    char proxy_url[64];
    size_t out_len;
    char buf[16];
    int ret;

    snprintf(crt_file, sizeof(crt_file), "%sdata/tls/proxy_stub_certificate.pem",
             FLB_TESTS_DATA_PATH);
    snprintf(key_file, sizeof(key_file), "%sdata/tls/proxy_stub_private_key.pem",
             FLB_TESTS_DATA_PATH);

    TEST_CHECK(start_https_proxy_stub(&stub, crt_file, key_file, FLB_TRUE) == 0);
    if (stub.listen_fd < 0) {
        return;
    }

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        stop_https_proxy_stub(&stub);
        return;
    }

    /* Destination TLS context: the same self-signed cert acts as its own
     * CA. Hostname verification is left off since the cert's CN does not
     * match 127.0.0.1. */
    dest_tls = flb_tls_create(FLB_TLS_CLIENT_MODE, FLB_TRUE, 0, NULL,
                              NULL, crt_file, NULL, NULL, NULL);
    TEST_CHECK(dest_tls != NULL);
    if (dest_tls == NULL) {
        flb_config_exit(config);
        stop_https_proxy_stub(&stub);
        return;
    }

    snprintf(proxy_url, sizeof(proxy_url), "https://127.0.0.1:%d", stub.port);
    config->http_proxy = proxy_url;
    u = flb_upstream_create(config, "dest.example.com", 443, FLB_IO_TLS, dest_tls);
    config->http_proxy = NULL;

    TEST_CHECK(u != NULL);
    if (u == NULL) {
        flb_tls_destroy(dest_tls);
        flb_config_exit(config);
        stop_https_proxy_stub(&stub);
        return;
    }

    TEST_CHECK(flb_upstream_proxy_tls_setup(u, FLB_TRUE, FLB_FALSE,
                                            NULL, crt_file) == 0);

    conn = build_proxy_test_connection(u);
    TEST_CHECK(conn != NULL);
    if (conn != NULL) {
        ret = flb_io_net_connect(conn, NULL);
        TEST_CHECK(ret == 0);
        TEST_MSG("expected proxy CONNECT + nested destination TLS handshake to succeed");

        if (ret == 0) {
            TEST_CHECK((flb_connection_get_flags(conn) & FLB_IO_PROXY_TLS) != 0);

            ret = flb_io_net_write(conn, "ping", 4, &out_len);
            TEST_CHECK(ret >= 0 && out_len == 4);

            if (ret >= 0 && out_len == 4) {
                memset(buf, 0, sizeof(buf));
                ret = flb_io_net_read(conn, buf, 4);
                TEST_CHECK(ret == 4);
                TEST_CHECK(strncmp(buf, "pong", 4) == 0);
                TEST_MSG("application data should round-trip through both TLS layers");
            }
        }

        destroy_proxy_test_connection(conn);
    }

    stop_https_proxy_stub(&stub);
    TEST_CHECK(stub.outer_ok == FLB_TRUE);
    TEST_CHECK(stub.inner_ok == FLB_TRUE);
    TEST_MSG("nested destination TLS handshake and encrypted echo should both succeed");

    /*
     * flb_upstream_destroy() only owns/frees proxy_tls_context; the
     * destination TLS context passed into flb_upstream_create() (dest_tls)
     * is owned by the caller, matching production where it belongs to the
     * output instance (ins->tls) and is freed independently.
     */
    flb_upstream_destroy(u);
    flb_tls_destroy(dest_tls);
    flb_config_exit(config);
}
#endif /* FLB_TEST_HAVE_PROXY_STUB */

#endif

TEST_LIST = {
#ifdef FLB_HAVE_TLS
    {"prepare_destroy_conn_marks_tls_session_stale", test_prepare_destroy_conn_marks_tls_session_stale},
    {"tls_session_destroy_no_double_free", test_tls_session_destroy_no_double_free},
    {"upstream_create_https_proxy_sets_tls_context", test_upstream_create_https_proxy_sets_tls_context},
    {"upstream_create_http_proxy_no_tls_context", test_upstream_create_http_proxy_no_tls_context},
    {"tls_reload_when_certificate_file_changes", test_tls_reload_when_certificate_file_changes},
#ifdef FLB_SYSTEM_LINUX
    {"tls_reload_when_certificate_file_is_replaced", test_tls_reload_when_certificate_file_is_replaced},
#endif
    {"tls_reload_does_not_hide_concurrent_file_change",
     test_tls_reload_does_not_hide_concurrent_file_change},
    {"upstream_proxy_tls_setup_noop_without_proxy", test_upstream_proxy_tls_setup_noop_without_proxy},
    {"upstream_proxy_tls_setup_configures_ca", test_upstream_proxy_tls_setup_configures_ca},
    {"output_proxy_tls_ca_check", test_output_proxy_tls_ca_check},
    {"io_proxy_tls_flag_does_not_leak_to_stream", test_io_proxy_tls_flag_does_not_leak_to_stream},
    {"http_client_host_header_not_polluted_by_proxy_tls",
     test_http_client_host_header_not_polluted_by_proxy_tls},
#ifdef FLB_TEST_HAVE_PROXY_STUB
    {"proxy_connect_trusted_ca_succeeds", test_proxy_connect_trusted_ca_succeeds},
    {"proxy_connect_untrusted_ca_rejected", test_proxy_connect_untrusted_ca_rejected},
    {"proxy_connect_https_destination_nested_tls", test_proxy_connect_https_destination_nested_tls},
#endif
#endif
    {0}
};
