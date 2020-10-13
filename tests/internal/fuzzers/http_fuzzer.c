#include <stdlib.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_http_client.h>

#include "flb_fuzz_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn = NULL;
    struct flb_http_client *c;
    struct flb_config *config;
    char *uri = NULL;

    if (size < 120) {
        return 0;
    }

    config = flb_config_init();
    if (config == NULL) {
        return 0;
    }

    u = flb_upstream_create(config, "127.0.0.1", 8001, 0, NULL);
    u_conn = flb_malloc(sizeof(struct flb_upstream_conn));
    if (u_conn == NULL)
        return 0;
    u_conn->u = u;

    char *proxy = NULL;
    if (GET_MOD_EQ(2,1)) {
        proxy = get_null_terminated(50, &data, &size);
    }

    uri = get_null_terminated(20, &data, &size);

    int method = (int)data[0];
    c = flb_http_client(u_conn, method, uri, NULL, 0,
                    "127.0.0.1", 8001, proxy, 0);

    if (c != NULL) {
        char *null_terminated = get_null_terminated(size-20, &data, &size);

        /* Perform a set of operations on the http_client */
        flb_http_basic_auth(c, null_terminated, null_terminated);
        flb_http_set_content_encoding_gzip(c);
        flb_http_set_keepalive(c);
        flb_http_strip_port_from_host(c);
        flb_http_allow_duplicated_headers(c, 0);

        flb_http_buffer_size(c, (*(size_t *)data) & 0xfff);
        MOVE_INPUT(4)
        flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
        flb_http_add_header(c, (char*)data, size, "Fluent-Bit", 10);
        flb_http_buffer_size(c, (int)data[0]);
        MOVE_INPUT(1)
        flb_http_buffer_available(c);
        size_t out_size = 0;
        flb_http_buffer_increase(c, (*(size_t *)data) & 0xfff, &out_size);
        MOVE_INPUT(4)

        size_t b_sent;
        flb_http_do(c, &b_sent);
        flb_http_client_destroy(c);

        flb_free(null_terminated);
    }

    flb_free(u_conn);
    flb_upstream_destroy(u);
    flb_config_exit(config);
    if (uri != NULL) {
        flb_free(uri);
    }
    if (proxy != NULL) {
        flb_free(proxy);
    }

    return 0;
}
