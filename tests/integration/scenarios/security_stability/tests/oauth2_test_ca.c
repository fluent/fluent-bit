/* Add the local test CA to OAuth2's system trust store without disabling verification. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <openssl/ssl.h>

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *file, const char *path)
{
    int ret;
    const char *test_ca;
    int (*load_verify_locations)(SSL_CTX *, const char *, const char *);

    load_verify_locations = dlsym(RTLD_NEXT, "SSL_CTX_load_verify_locations");
    if (load_verify_locations == NULL) {
        return 0;
    }
    ret = load_verify_locations(ctx, file, path);
    test_ca = getenv("OAUTH2_TEST_CA");
    if (ret == 1 && test_ca != NULL) {
        ret = load_verify_locations(ctx, test_ca, NULL);
    }
    return ret;
}
