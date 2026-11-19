/* Process-local fault injection for JWKS timeout integration tests. */
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/ssl.h>

int setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
    int (*real_setsockopt)(int, int, int, const void *, socklen_t);
    const char *marker;
    const struct timeval *timeout;

    real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    marker = getenv("JWKS_RCV_FAILURE_MARKER");
    if (marker != NULL && level == SOL_SOCKET && option == SO_RCVTIMEO &&
        length == sizeof(struct timeval)) {
        timeout = value;
        if (timeout->tv_sec > 0 && unlink(marker) == 0) {
            errno = EPERM;
            return -1;
        }
    }
    return real_setsockopt(fd, level, option, value, length);
}

int SSL_read(SSL *session, void *buffer, int length)
{
    int (*real_read)(SSL *, void *, int);
    const char *marker;

    marker = getenv("JWKS_WANT_WRITE_MARKER");
    if (marker != NULL && access(marker, F_OK) == 0) {
        errno = EAGAIN;
        return -1;
    }
    real_read = dlsym(RTLD_NEXT, "SSL_read");
    return real_read(session, buffer, length);
}

int SSL_get_error(const SSL *session, int result)
{
    int (*real_error)(const SSL *, int);
    const char *marker;

    marker = getenv("JWKS_WANT_WRITE_MARKER");
    if (result == -1 && marker != NULL && access(marker, F_OK) == 0) {
        return SSL_ERROR_WANT_WRITE;
    }
    real_error = dlsym(RTLD_NEXT, "SSL_get_error");
    return real_error(session, result);
}

/* Preserve certificate and hostname verification while adding the test CA. */
int SSL_CTX_load_verify_locations(SSL_CTX *context, const char *ca_file, const char *ca_path)
{
    int (*real_load)(SSL_CTX *, const char *, const char *);
    const char *test_ca;

    real_load = dlsym(RTLD_NEXT, "SSL_CTX_load_verify_locations");
    test_ca = getenv("JWKS_TEST_CA");
    if (test_ca != NULL) {
        ca_file = test_ca;
    }
    return real_load(context, ca_file, ca_path);
}
