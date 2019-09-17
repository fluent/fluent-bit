Fluent Bit SSL Interface
========================

`flb_ssl` is a simple interface for creating TLS connections, both for
servers and clients.

The interface is loosely based on libtls (https://www.libressl.org/),
and intended to make it easier to use TLS/SSL.

HOW TO CREATE A TLS SERVER
--------------------------

First, create a new config object.

 * Call `flb_ssl_config()` to create a config object.
 * Call `flb_ssl_set_key_file()` and `flb_ssl_set_cert_file()`.

Then create a server context.

 * Call `flb_ssl_server()` to create a new server context.
 * Call `flb_ssl_configure()` to configure the context
 * Call `flb_ssl_bind()` to bind to ip:port

Now you can accept a new connection.

 * Call `flb_ssl_accept()` to accept a new connection.
 * Call `flb_ssl_read()` or `flb_ssl_write()` on the connection context.
 * Call `flb_ssl_free()` to clean up the connection.

On exit:

 * Call `flb_ssl_free()` to clean up the listening socket.
 * Call `flb_ssl_config_free()` to cean up the config object.

EXAMPLE SERVER
--------------

```
#include <fluent-bit/ssl/flb_ssl.h>

int main(void) {
    struct flb_ssl *ctx = NULL;
    struct flb_ssl *cctx = NULL;
    struct flb_ssl_config *config = NULL;
    char buf = "Hello World!";
    int bytes;
    int ret;

    /* Configure */
    config = flb_ssl_config_new();
    if (config == NULL)
        goto exit;

    flb_ssl_set_cert_file(config, "/etc/fluent.crt");
    flb_ssl_set_key_file(config, "/etc/fluent.key", "password");

    /* Create server */
    ctx = flb_ssl_server();
    if (ctx == NULL)
        goto exit;

    if (flb_ssl_configure(ctx, config))
        goto exit;

    if (flb_ssl_bind(ctx, host, port))
        goto exit;

    /* Listening ... */
    while (1) {
        if (flb_ssl_accept(ctx, &cctx))
            goto exit;

        bytes = 0;
        while (bytes < strlen(buf)) {
            n = flb_ssl_write(cctx, buf + bytes, strlen(buf) - bytes);
            if (n < 0) {
                break;
            bytes += n;
        }
        flb_ssl_free(cctx);
    }
exit:
    flb_ssl_config_free(config);
    flb_ssl_free(ctx);
    return 0;
}
```
