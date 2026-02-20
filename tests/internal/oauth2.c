/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_base64.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fluent-bit/flb_compat.h>
#endif

#include "flb_tests_internal.h"

#define MOCK_BODY_SIZE 16384
#define TEST_CERT_FILENAME "oauth2_private_key_jwt_test_cert.pem"
#define TEST_KEY_FILENAME  "oauth2_private_key_jwt_test_key.pem"

static const char *TEST_PRIVATE_KEY_PEM =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQ2q+ICzQ7U1dm\n"
"sEQVvbQjVlv3iZITTrXcX0Hkxu5qh/L41QIG3ZKEkih3S0rDtumiHUDrQVlG9Ioz\n"
"9s7zOY3sbwEC1c9UzqowI0urm9wJVkC8rDPhKTCD6pAAMwP27npxSmI6EfFRCefg\n"
"42z5o/KKZGBzrR9FK+Mbik821eLJG67bT4ElclnSeIUC8+/rUgAMygCLH+o2BsTn\n"
"BklBqDdnOTzMKOkH/rp8eC2EXimyokWb/jVUfMG6dw8Dg3WNNKIZ5Ye756qjdOsY\n"
"lV6ptQpbyKK2RBDxK5yJnqP30IMHOcDvf4Ohko4jZpKB9gdC58Lqi5w/J1pI3gO4\n"
"WUQxmcmVAgMBAAECggEADRIamSuGVc4l8qXGZQvtyaZedBP2geHTrNqDT7OJeT5P\n"
"3PXLvi1Ava49/RVHtQ7t+TjWdsKsuS2VtqHUGtG3yZu61vgVlSun6AJVeoRzFVyC\n"
"CazHRGilAiR8ZZ7LuTj8jbmHgzXbQeSaT+87wzXY+INGrAaiJdyUxoT15yskmcxW\n"
"L7qxnXimxvGjYLn67xOJwhN6/JP+L1DV1TE6l9aSDlYAXR6Mb3mXDDcvaVDsddGF\n"
"uoDyErJKANy37DlsC6GIkDoq/lR8GI0yy4pUzrwP2ANWNlG+hExhksrw9+e8sTgL\n"
"GFIOZLTvL1GU5k3kspDOQakHZz80YuQBgYfQvRptsQKBgQD635AKe2LbduqnG2vQ\n"
"8Y7BUTAaUuVftfL2XeuNZ4kuBq7cqBrNIrPZWIEmkuU4imNhQ3gCpmQ5XXbQqfqz\n"
"DbE6p8eBMtK1K3iyN7P5myP94PlzJ0VPbcKt24xILrAkw3ePObgPaVzGIcWAR38k\n"
"ZpNRlN1LDy3mjbj44AYNEQUKeQKBgQDVH00ock5kwtO4vniBxuUtt59zTsscmOry\n"
"NGbdHZ03sh1qZpijZlYc6ocLZ+rdkxpwIA7SfOOnV+5v6WnI1Hzuj4A5P66J3GT/\n"
"UNjiamuQHFzDSbdEtaFNWr7EV6QXbNBP1ZoYY5GiKpa6SoSuFyAuJVJfxov3PGpU\n"
"rlx/oPXw/QKBgQD6iFionx/SW6dqyo+ZUiJmHFYVc8NtGZ9ROeoKhOMR+8qUwaxC\n"
"P+2rmB8iDoCrPkiQ0Xf/7XsZbqVBLP8X4QykrvklpUOXeZpHICmzk6MV3p4+yXEG\n"
"KW7JgP9O9pEhpbK4bcPKYEYt93vs53mpOGbWifuVAcus+stGfzKLyftmwQKBgQCa\n"
"mohojPNdmQ/p9xKIYnaigZBEH6asaioV5fmw8ei5HJbGNwMHlhdmBqRMm+f/MNV+\n"
"/WKDQ2IKZXls6dB5hdvTW3pTDWVaUO1bYZTUOwsokcqhSHqQd4o6CVhWKpW5AJDl\n"
"OTj99E0TbP3GyoQRnmkT0LM/E1M52TPxlkM3utZvKQKBgFoEeP8L8gO9Tvc4TaBp\n"
"S6arcO3FIObR8Hb9FxHu+lK+M/y+y77PmrHr2l1BFkiX8dWPk9OZLsC6tno6PfCn\n"
"dooXSFG+U6C+kDQjwtXQCXMW6Vry7AuRY8dbaHH0f1o2fePM08ZdzcHlwWQmwGsL\n"
"mzHuWItixgGqYX2cs3yslCQ/\n"
"-----END PRIVATE KEY-----\n";

static const char *TEST_CERT_PEM =
"-----BEGIN CERTIFICATE-----\n"
"MIIDFTCCAf2gAwIBAgIUIg54y3h7UiGzRc50dFWpdMdzLqYwDQYJKoZIhvcNAQEL\n"
"BQAwGjEYMBYGA1UEAwwPZmxiLW9hdXRoMi10ZXN0MB4XDTI2MDIyMDIxNDIwMloX\n"
"DTI2MDIyMTIxNDIwMlowGjEYMBYGA1UEAwwPZmxiLW9hdXRoMi10ZXN0MIIBIjAN\n"
"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0NqviAs0O1NXZrBEFb20I1Zb94mS\n"
"E0613F9B5Mbuaofy+NUCBt2ShJIod0tKw7bpoh1A60FZRvSKM/bO8zmN7G8BAtXP\n"
"VM6qMCNLq5vcCVZAvKwz4Skwg+qQADMD9u56cUpiOhHxUQnn4ONs+aPyimRgc60f\n"
"RSvjG4pPNtXiyRuu20+BJXJZ0niFAvPv61IADMoAix/qNgbE5wZJQag3Zzk8zCjp\n"
"B/66fHgthF4psqJFm/41VHzBuncPA4N1jTSiGeWHu+eqo3TrGJVeqbUKW8iitkQQ\n"
"8SuciZ6j99CDBznA73+DoZKOI2aSgfYHQufC6oucPydaSN4DuFlEMZnJlQIDAQAB\n"
"o1MwUTAdBgNVHQ4EFgQUWcCHMz10eB1evM0LeU9OCOMIwXkwHwYDVR0jBBgwFoAU\n"
"WcCHMz10eB1evM0LeU9OCOMIwXkwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n"
"AQsFAAOCAQEAKoZHiuU2UzO1RRmQD5js3HEuTd1YrMtGzm/k2D6YDrTWDH0au7vj\n"
"DitXp41XqE0t4BOPoF+Ee9FJDRViKLCEIEnqX+KtJzoNuHgaOFAva6Ja5uxj+ws1\n"
"iJnhj1Dwg50mhLsIe4Mb8tVvZPsEKVo5szFlJLi4KNMtIwCVmSS68bdGcGYB6ia1\n"
"6i07IhmDRGJr5Mi2b+8maDLVKzrNp7caF19vnNI7juaQXbIutGKLXAmZlgvmd4EL\n"
"TnkYGS36JMp9WK7IoLpvdn28KyV4LRysFJITxpBuM3MvinVlhSioDxzunLuNvjNm\n"
"gDmvspwf6GKRi6hV6WhahalSGz8itHJ5VQ==\n"
"-----END CERTIFICATE-----\n";

struct oauth2_mock_server {
    flb_sockfd_t listen_fd;
    int port;
    int stop;
    int token_requests;
    int resource_requests;
    int resource_challenge;
    int expires_in;
    char latest_token[64];
    char latest_token_request[MOCK_BODY_SIZE];
    pthread_t thread;
#ifdef _WIN32
    int wsa_initialized;
#endif
};

static void compose_http_response(flb_sockfd_t fd, int status, const char *body)
{
    char buffer[MOCK_BODY_SIZE];
    int body_len = 0;
    ssize_t sent = 0;
    ssize_t total = 0;
    ssize_t len;

    if (body != NULL) {
        body_len = strlen(body);
    }

    snprintf(buffer, sizeof(buffer),
             "HTTP/1.1 %d\r\n"
             "Content-Length: %d\r\n"
             "Content-Type: application/json\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             status, body_len, body ? body : "");

    len = strlen(buffer);
    /* Ensure we send all data - loop until complete */
    while (total < len) {
        sent = send(fd, buffer + total, len - total, 0);
        if (sent <= 0) {
            break;
        }
        total += sent;
    }
}

static int request_content_length(const char *request)
{
    int len;
    const char *p;

    p = strstr(request, "Content-Length:");
    if (!p) {
        return 0;
    }

    p += sizeof("Content-Length:") - 1;
    while (*p == ' ') {
        p++;
    }

    len = atoi(p);
    if (len < 0) {
        len = 0;
    }

    return len;
}

static void handle_token_request(struct oauth2_mock_server *server, flb_sockfd_t fd,
                                 const char *request)
{
    char payload[MOCK_BODY_SIZE];
    char *body;
    size_t body_len;

    server->token_requests++;
    snprintf(server->latest_token, sizeof(server->latest_token),
             "mock-token-%d", server->token_requests);

    body = strstr(request, "\r\n\r\n");
    if (body) {
        body += 4;
        body_len = strlen(body);
        if (body_len >= sizeof(server->latest_token_request)) {
            body_len = sizeof(server->latest_token_request) - 1;
        }
        memcpy(server->latest_token_request, body, body_len);
        server->latest_token_request[body_len] = '\0';
    }
    else {
        server->latest_token_request[0] = '\0';
    }

    snprintf(payload, sizeof(payload),
             "{\"access_token\":\"%s\",\"token_type\":\"Bearer\","\
             "\"expires_in\":%d}",
             server->latest_token, server->expires_in);

    compose_http_response(fd, 200, payload);
}

static void handle_resource_request(struct oauth2_mock_server *server, flb_sockfd_t fd,
                                    const char *request)
{
    int authorized = 0;
    const char *auth;

    server->resource_requests++;

    if (server->resource_challenge > 0) {
        server->resource_challenge--;
        compose_http_response(fd, 401, "");
        return;
    }

    auth = strstr(request, "Authorization: ");
    if (auth && strstr(auth, server->latest_token)) {
        authorized = 1;
    }

    if (authorized) {
        compose_http_response(fd, 200, "{\"ok\":true}");
    }
    else {
        compose_http_response(fd, 401, "");
    }
}

static void *oauth2_mock_server_thread(void *data)
{
    int content_len;
    struct oauth2_mock_server *server = (struct oauth2_mock_server *) data;
    const char *headers_end;
    flb_sockfd_t client_fd;
    fd_set rfds;
    struct timeval tv;
    char buffer[MOCK_BODY_SIZE];
    ssize_t total;
    ssize_t n;

    while (!server->stop) {
        FD_ZERO(&rfds);
        FD_SET(server->listen_fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        if (select((int)(server->listen_fd + 1), &rfds, NULL, NULL, &tv) <= 0) {
            continue;
        }

        client_fd = accept(server->listen_fd, NULL, NULL);
        if (client_fd == FLB_INVALID_SOCKET) {
            continue;
        }

        /* Read the full HTTP request - loop until we get the complete request */
        memset(buffer, 0, sizeof(buffer));
        total = 0;

        /* Make socket blocking for both read and write to ensure reliable operation */
        flb_net_socket_blocking(client_fd);

        /* Read until we get headers first */
        while (total < sizeof(buffer) - 1) {
            n = recv(client_fd, buffer + total, (int)(sizeof(buffer) - 1 - total), 0);
            if (n <= 0) {
                /* Connection closed or error */
                break;
            }
            total += n;
            /* Check if we've received the complete HTTP request */
            if (strstr(buffer, "\r\n\r\n") != NULL) {
                break;
            }
        }

        headers_end = strstr(buffer, "\r\n\r\n");
        if (headers_end != NULL) {
            content_len = request_content_length(buffer);
            while (content_len > 0 && total < sizeof(buffer) - 1) {
                if (total >= ((headers_end - buffer) + 4 + content_len)) {
                    break;
                }
                n = recv(client_fd, buffer + total,
                         (int)(sizeof(buffer) - 1 - total), 0);
                if (n <= 0) {
                    break;
                }
                total += n;
            }
            buffer[total] = '\0';
        }

        if (strstr(buffer, "/token")) {
            handle_token_request(server, client_fd, buffer);
        }
        else if (strstr(buffer, "/resource")) {
            handle_resource_request(server, client_fd, buffer);
        }

        flb_socket_close(client_fd);
    }

    return NULL;
}

static int oauth2_mock_server_start(struct oauth2_mock_server *server, int expires_in,
                                    int resource_challenge)
{
    int on = 1;
    struct sockaddr_in addr;
    socklen_t len;
#ifdef _WIN32
    WSADATA wsa_data;
    int wsa_result;
#endif

    memset(server, 0, sizeof(struct oauth2_mock_server));
    server->expires_in = expires_in;
    server->resource_challenge = resource_challenge;

#ifdef _WIN32
    /* Initialize Winsock on Windows */
    wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_result != 0) {
        flb_errno();
        return -1;
    }
    server->wsa_initialized = 1;
#endif

    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd == FLB_INVALID_SOCKET) {
        flb_errno();
#ifdef _WIN32
        if (server->wsa_initialized) {
            WSACleanup();
            server->wsa_initialized = 0;
        }
#endif
        return -1;
    }

    setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(server->listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        flb_errno();
        flb_socket_close(server->listen_fd);
#ifdef _WIN32
        if (server->wsa_initialized) {
            WSACleanup();
            server->wsa_initialized = 0;
        }
#endif
        return -1;
    }

    if (listen(server->listen_fd, 4) < 0) {
        flb_errno();
        flb_socket_close(server->listen_fd);
#ifdef _WIN32
        if (server->wsa_initialized) {
            WSACleanup();
            server->wsa_initialized = 0;
        }
#endif
        return -1;
    }

    len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if (getsockname(server->listen_fd, (struct sockaddr *) &addr, &len) < 0) {
        flb_errno();
        flb_socket_close(server->listen_fd);
#ifdef _WIN32
        if (server->wsa_initialized) {
            WSACleanup();
            server->wsa_initialized = 0;
        }
#endif
        return -1;
    }

    server->port = ntohs(addr.sin_port);
    if (server->port == 0) {
        flb_errno();
        flb_socket_close(server->listen_fd);
#ifdef _WIN32
        if (server->wsa_initialized) {
            WSACleanup();
            server->wsa_initialized = 0;
        }
#endif
        return -1;
    }

    flb_net_socket_nonblocking(server->listen_fd);

    if (pthread_create(&server->thread, NULL, oauth2_mock_server_thread, server) != 0) {
        printf("pthread_create failed: %s\n", strerror(errno));
        flb_socket_close(server->listen_fd);
#ifdef _WIN32
        if (server->wsa_initialized) {
            WSACleanup();
            server->wsa_initialized = 0;
        }
#endif
        return -1;
    }
    printf("server started on port %d\n", server->port);
    return 0;
}

static int oauth2_mock_server_wait_ready(struct oauth2_mock_server *server)
{
    /* On macOS, we need to give the server thread time to start and enter
     * its select() loop. A simple delay is sufficient since pthread_create
     * returns when the thread is created, but the thread may not have
     * started executing yet. */
    int retries = 50;
    flb_sockfd_t test_fd;
    struct sockaddr_in addr;
    int ret;

    while (retries-- > 0) {
        /* Check if server is listening by attempting a non-blocking connect */
        test_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (test_fd != FLB_INVALID_SOCKET) {
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(server->port);

            flb_net_socket_nonblocking(test_fd);

            ret = connect(test_fd, (struct sockaddr *) &addr, sizeof(addr));

            /* If connect succeeds or is in progress, server is ready */
#ifdef _WIN32
            if (ret == 0 || (ret < 0 && WSAGetLastError() == WSAEWOULDBLOCK)) {
#else
            if (ret == 0 || (ret < 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK))) {
#endif
                flb_socket_close(test_fd);
                /* Give the server thread one more moment to be fully ready */
                flb_time_msleep(10);
                return 0;
            }

            flb_socket_close(test_fd);
        }

        flb_time_msleep(20);
    }

    return -1;
}

static void oauth2_mock_server_stop(struct oauth2_mock_server *server)
{
    if (server->listen_fd != FLB_INVALID_SOCKET) {
        server->stop = 1;
        shutdown(server->listen_fd, SHUT_RDWR);
        pthread_join(server->thread, NULL);
        flb_socket_close(server->listen_fd);
        server->listen_fd = FLB_INVALID_SOCKET;
    }
#ifdef _WIN32
    if (server->wsa_initialized) {
        WSACleanup();
        server->wsa_initialized = 0;
    }
#endif
}

static struct flb_oauth2 *create_oauth_ctx(struct flb_config *config,
                                           struct oauth2_mock_server *server,
                                           int refresh_skew)
{
    struct flb_oauth2_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.token_url = flb_sds_create_size(64);
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.refresh_skew = refresh_skew;
    cfg.client_id = flb_sds_create("id");
    cfg.client_secret = flb_sds_create("secret");

    flb_sds_printf(&cfg.token_url, "http://127.0.0.1:%d/token", server->port);

    struct flb_oauth2 *ctx = flb_oauth2_create_from_config(config, &cfg);

    flb_oauth2_config_destroy(&cfg);

    return ctx;
}

static int write_text_file(const char *path, const char *content)
{
    FILE *fp;
    size_t expected;
    size_t written;

    fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }

    expected = strlen(content);
    written = fwrite(content, 1, expected, fp);
    fclose(fp);

    if (written != expected) {
        return -1;
    }

    return 0;
}

static int test_setup_private_key_jwt_files(char *key_path, size_t key_path_size,
                                            char *cert_path, size_t cert_path_size)
{
    int ret;

    ret = snprintf(key_path, key_path_size, "/tmp/%s.%d",
                   TEST_KEY_FILENAME, (int) getpid());
    if (ret < 0 || (size_t) ret >= key_path_size) {
        return -1;
    }

    ret = snprintf(cert_path, cert_path_size, "/tmp/%s.%d",
                   TEST_CERT_FILENAME, (int) getpid());
    if (ret < 0 || (size_t) ret >= cert_path_size) {
        return -1;
    }

    ret = write_text_file(key_path, TEST_PRIVATE_KEY_PEM);
    if (ret != 0) {
        return -1;
    }

    ret = write_text_file(cert_path, TEST_CERT_PEM);
    if (ret != 0) {
        unlink(key_path);
        return -1;
    }

    return 0;
}

static void test_cleanup_private_key_jwt_files(const char *key_path,
                                               const char *cert_path)
{
    unlink(key_path);
    unlink(cert_path);
}

static int extract_form_value(const char *body, const char *key, char *out,
                              size_t out_size)
{
    int key_len;
    const char *end;
    const char *start;
    size_t val_len;
    char pattern[128];

    key_len = snprintf(pattern, sizeof(pattern), "%s=", key);
    if (key_len <= 0 || key_len >= (int) sizeof(pattern)) {
        return -1;
    }

    start = strstr(body, pattern);
    if (!start) {
        return -1;
    }
    start += key_len;

    end = strchr(start, '&');
    if (!end) {
        end = start + strlen(start);
    }

    val_len = end - start;
    if (val_len >= out_size) {
        return -1;
    }

    memcpy(out, start, val_len);
    out[val_len] = '\0';

    return 0;
}

static int base64_url_decode(const char *input, char *out, size_t out_size)
{
    int pad;
    int ret;
    int in_len;
    size_t decoded_size;
    size_t i;
    size_t normalized_len;
    unsigned char *decoded = NULL;
    unsigned char *normalized = NULL;

    if (!input || !out || out_size == 0) {
        return -1;
    }

    in_len = strlen(input);
    pad = (4 - (in_len % 4)) % 4;
    normalized_len = in_len + pad;

    normalized = flb_calloc(1, normalized_len + 1);
    if (!normalized) {
        flb_errno();
        return -1;
    }

    memcpy(normalized, input, in_len);
    for (i = 0; i < (size_t) in_len; i++) {
        if (normalized[i] == '-') {
            normalized[i] = '+';
        }
        else if (normalized[i] == '_') {
            normalized[i] = '/';
        }
    }

    for (i = 0; i < (size_t) pad; i++) {
        normalized[in_len + i] = '=';
    }

    decoded = flb_calloc(1, normalized_len + 1);
    if (!decoded) {
        flb_errno();
        flb_free(normalized);
        return -1;
    }

    ret = flb_base64_decode(decoded, normalized_len, &decoded_size,
                            normalized, normalized_len);
    flb_free(normalized);
    if (ret != 0) {
        flb_free(decoded);
        return -1;
    }

    if (decoded_size >= out_size) {
        flb_free(decoded);
        return -1;
    }

    memcpy(out, decoded, decoded_size);
    out[decoded_size] = '\0';
    flb_free(decoded);

    return 0;
}

static int base64_url_decode_bytes(const char *input, unsigned char *out,
                                   size_t out_size, size_t *decoded_size)
{
    int pad;
    int ret;
    int in_len;
    size_t i;
    size_t normalized_len;
    unsigned char *normalized = NULL;

    if (!input || !out || !decoded_size || out_size == 0) {
        return -1;
    }

    in_len = strlen(input);
    pad = (4 - (in_len % 4)) % 4;
    normalized_len = in_len + pad;

    normalized = flb_calloc(1, normalized_len + 1);
    if (!normalized) {
        flb_errno();
        return -1;
    }

    memcpy(normalized, input, in_len);
    for (i = 0; i < (size_t) in_len; i++) {
        if (normalized[i] == '-') {
            normalized[i] = '+';
        }
        else if (normalized[i] == '_') {
            normalized[i] = '/';
        }
    }

    for (i = 0; i < (size_t) pad; i++) {
        normalized[in_len + i] = '=';
    }

    ret = flb_base64_decode(out, out_size, decoded_size,
                            normalized, normalized_len);
    flb_free(normalized);

    if (ret != 0) {
        return -1;
    }

    return 0;
}

static int parse_jwt_header(const char *jwt, char *header_json,
                            size_t header_json_size)
{
    const char *dot;
    size_t header_len;
    char header_b64[4096];

    dot = strchr(jwt, '.');
    if (!dot) {
        return -1;
    }

    header_len = dot - jwt;
    if (header_len == 0 || header_len >= sizeof(header_b64)) {
        return -1;
    }

    memcpy(header_b64, jwt, header_len);
    header_b64[header_len] = '\0';

    return base64_url_decode(header_b64, header_json, header_json_size);
}

static struct flb_oauth2 *create_private_key_jwt_ctx(struct flb_config *config,
                                                     struct oauth2_mock_server *server,
                                                     const char *key_path,
                                                     const char *cert_path,
                                                     const char *header_name)
{
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;

    memset(&cfg, 0, sizeof(cfg));

    cfg.enabled = FLB_TRUE;
    cfg.token_url = flb_sds_create_size(64);
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_PRIVATE_KEY_JWT;
    cfg.client_id = flb_sds_create("id");
    cfg.resource = flb_sds_create("urn:resource:test");
    cfg.jwt_key_file = flb_sds_create(key_path);
    cfg.jwt_cert_file = flb_sds_create(cert_path);
    cfg.jwt_header = flb_sds_create(header_name);
    cfg.jwt_ttl = 300;

    flb_sds_printf(&cfg.token_url, "http://127.0.0.1:%d/token", server->port);
    cfg.jwt_aud = flb_sds_create(cfg.token_url);

    ctx = flb_oauth2_create_from_config(config, &cfg);
    flb_oauth2_config_destroy(&cfg);

    return ctx;
}

void test_parse_defaults(void)
{
    int ret;
    struct flb_oauth2 ctx;
    const char *payload = "{\"access_token\":\"abc\"}";

    memset(&ctx, 0, sizeof(ctx));
    ctx.refresh_skew = FLB_OAUTH2_DEFAULT_SKEW_SECS;

    ret = flb_oauth2_parse_json_response(payload, strlen(payload), &ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx.access_token != NULL);
    TEST_CHECK(strcmp(ctx.token_type, "Bearer") == 0);
    TEST_CHECK(ctx.expires_in == FLB_OAUTH2_DEFAULT_EXPIRES);

    flb_sds_destroy(ctx.access_token);
    flb_sds_destroy(ctx.token_type);
}

void test_caching_and_refresh(void)
{
    int ret;
    flb_sds_t token = NULL;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_mock_server server;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_mock_server_start(&server, 2, 0);
    TEST_CHECK(ret == 0);

    ctx = create_oauth_ctx(config, &server, 1);
    TEST_CHECK(ctx != NULL);

#ifdef FLB_SYSTEM_MACOS
    /* On macOS, wait for the server thread to be ready to accept connections.
     * This ensures the server has entered its select() loop before we make requests. */
    ret = oauth2_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    /* Give the server a moment to finish processing the test connection */
    flb_time_msleep(50);
#endif

    ret = flb_oauth2_get_access_token(ctx, &token, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(strcmp(token, "mock-token-1") == 0);
    TEST_CHECK(server.token_requests == 1);

    ret = flb_oauth2_get_access_token(ctx, &token, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(strcmp(token, "mock-token-1") == 0);
    TEST_CHECK(server.token_requests == 1);

    sleep(2);

    ret = flb_oauth2_get_access_token(ctx, &token, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(strcmp(token, "mock-token-2") == 0);
    TEST_CHECK(server.token_requests == 2);

    flb_oauth2_destroy(ctx);
    oauth2_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_private_key_jwt_body(void)
{
    int ret;
    flb_sds_t token = NULL;
    char cert_path[256];
    char key_path[256];
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_mock_server server;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = test_setup_private_key_jwt_files(key_path, sizeof(key_path),
                                           cert_path, sizeof(cert_path));
    TEST_CHECK(ret == 0);

    ret = oauth2_mock_server_start(&server, 30, 0);
    TEST_CHECK(ret == 0);

    ctx = create_private_key_jwt_ctx(config, &server, key_path, cert_path, "kid");
    TEST_CHECK(ctx != NULL);

    ret = flb_oauth2_get_access_token(ctx, &token, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(token != NULL);

    TEST_CHECK(strstr(server.latest_token_request,
                      "grant_type=client_credentials") != NULL);
    TEST_CHECK(strstr(server.latest_token_request,
                      "resource=urn%3Aresource%3Atest") != NULL);
    TEST_CHECK(strstr(server.latest_token_request,
                      "client_assertion_type="
                      "urn%3Aietf%3Aparams%3Aoauth%3A"
                      "client-assertion-type%3Ajwt-bearer") != NULL);
    TEST_CHECK(strstr(server.latest_token_request, "client_assertion=") != NULL);

    flb_oauth2_destroy(ctx);
    oauth2_mock_server_stop(&server);
    test_cleanup_private_key_jwt_files(key_path, cert_path);
    flb_config_exit(config);
}

void test_private_key_jwt_x5t_header(void)
{
    int ret;
    char *x5t_end;
    char *x5t_start;
    flb_sds_t token = NULL;
    char cert_path[256];
    char key_path[256];
    char x5t_b64[256];
    char assertion[8192];
    char header_json[4096];
    size_t decoded_len;
    unsigned char decoded_digest[64];
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_mock_server server;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = test_setup_private_key_jwt_files(key_path, sizeof(key_path),
                                           cert_path, sizeof(cert_path));
    TEST_CHECK(ret == 0);

    ret = oauth2_mock_server_start(&server, 30, 0);
    TEST_CHECK(ret == 0);

    ctx = create_private_key_jwt_ctx(config, &server, key_path, cert_path, "x5t");
    TEST_CHECK(ctx != NULL);

    ret = flb_oauth2_get_access_token(ctx, &token, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(token != NULL);

    ret = extract_form_value(server.latest_token_request, "client_assertion",
                             assertion, sizeof(assertion));
    TEST_CHECK(ret == 0);

    ret = parse_jwt_header(assertion, header_json, sizeof(header_json));
    TEST_CHECK(ret == 0);
    TEST_CHECK(strstr(header_json, "\"x5t\":\"") != NULL);

    x5t_start = strstr(header_json, "\"x5t\":\"");
    TEST_CHECK(x5t_start != NULL);
    if (x5t_start != NULL) {
        x5t_start += 7;
        x5t_end = strchr(x5t_start, '"');
        TEST_CHECK(x5t_end != NULL);
        if (x5t_end != NULL) {
            TEST_CHECK((size_t) (x5t_end - x5t_start) < sizeof(x5t_b64));
            if ((size_t) (x5t_end - x5t_start) < sizeof(x5t_b64)) {
                memcpy(x5t_b64, x5t_start, x5t_end - x5t_start);
                x5t_b64[x5t_end - x5t_start] = '\0';

                ret = base64_url_decode_bytes(x5t_b64, decoded_digest,
                                              sizeof(decoded_digest), &decoded_len);
                TEST_CHECK(ret == 0);
                TEST_CHECK(decoded_len == 20);
            }
        }
    }

    flb_oauth2_destroy(ctx);
    oauth2_mock_server_stop(&server);
    test_cleanup_private_key_jwt_files(key_path, cert_path);
    flb_config_exit(config);
}

TEST_LIST = {
    {"parse_defaults", test_parse_defaults},
    {"caching_and_refresh", test_caching_and_refresh},
    {"private_key_jwt_body", test_private_key_jwt_body},
    {"private_key_jwt_x5t_header", test_private_key_jwt_x5t_header},
    {0}
};
