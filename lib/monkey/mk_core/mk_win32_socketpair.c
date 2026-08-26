/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2026 Eduardo Silva <eduardo@monkey.io>
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

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef MK_HAVE_AFUNIX_H
#include <afunix.h>
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#include <string.h>

#include <mk_core/mk_core_info.h>
#include <mk_core/mk_win32_socketpair.h>

static LONG mk_win32_wsa_initialized = 0;

static int mk_win32_socketpair_init(void)
{
    int ret;
    WSADATA wsa_data;

    if (InterlockedCompareExchange(&mk_win32_wsa_initialized, 1, 0) != 0) {
        return 0;
    }

    ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (ret != 0) {
        InterlockedExchange(&mk_win32_wsa_initialized, 0);
        WSASetLastError(ret);
        return -1;
    }

    return 0;
}

#ifdef MK_HAVE_AFUNIX_H
static int mk_win32_afunix_supported = -1;

static int mk_win32_create_temp_path(char path[MAX_PATH])
{
    char short_path[MAX_PATH] = {0};
    char long_path[MAX_PATH] = {0};

    if (GetTempPathA(MAX_PATH, short_path) == 0) {
        return -1;
    }

    if (GetLongPathNameA(short_path, long_path, MAX_PATH) == 0) {
        strncpy(long_path, short_path, sizeof(long_path) - 1);
    }

    if (GetTempFileNameA(long_path, "mk", 0, path) == 0) {
        return -1;
    }

    DeleteFileA(path);
    return 0;
}

static int mk_win32_check_afunix(void)
{
    SOCKET fd;

    if (mk_win32_afunix_supported >= 0) {
        return mk_win32_afunix_supported;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) {
        mk_win32_afunix_supported = 0;
        return 0;
    }

    closesocket(fd);
    mk_win32_afunix_supported = 1;
    return 1;
}

static int mk_win32_socketpair_afunix(SOCKET pair[2])
{
    int ret;
    int path_len;
    int addr_len;
    SOCKET listener = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    SOCKET server = INVALID_SOCKET;
    struct sockaddr_un addr;
    char path[MAX_PATH] = {0};

    if (mk_win32_create_temp_path(path) != 0) {
        return -1;
    }

    path_len = (int) strlen(path);
    if (path_len >= (int) sizeof(addr.sun_path)) {
        DeleteFileA(path);
        WSASetLastError(WSAEINVAL);
        return -1;
    }

    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener == INVALID_SOCKET) {
        DeleteFileA(path);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, path_len + 1);

    ret = bind(listener, (struct sockaddr *) &addr, sizeof(addr));
    if (ret == SOCKET_ERROR) {
        goto error;
    }

    ret = listen(listener, 1);
    if (ret == SOCKET_ERROR) {
        goto error;
    }

    client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client == INVALID_SOCKET) {
        goto error;
    }

    addr_len = sizeof(addr);
    ret = getsockname(listener, (struct sockaddr *) &addr, &addr_len);
    if (ret == SOCKET_ERROR) {
        goto error;
    }

    ret = connect(client, (struct sockaddr *) &addr, addr_len);
    if (ret == SOCKET_ERROR) {
        goto error;
    }

    server = accept(listener, NULL, NULL);
    if (server == INVALID_SOCKET) {
        goto error;
    }

    closesocket(listener);
    DeleteFileA(path);

    pair[0] = server;
    pair[1] = client;
    return 0;

error:
    if (listener != INVALID_SOCKET) {
        closesocket(listener);
    }
    if (client != INVALID_SOCKET) {
        closesocket(client);
    }
    if (server != INVALID_SOCKET) {
        closesocket(server);
    }
    DeleteFileA(path);
    return -1;
}
#endif

static int mk_win32_socketpair_loopback(SOCKET pair[2])
{
    int ret;
    int one = 1;
    int addr_len;
    SOCKET listener = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    SOCKET server = INVALID_SOCKET;
    struct sockaddr_in addr;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        return -1;
    }

    ret = setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                     (const char *) &one, sizeof(one));
    if (ret == SOCKET_ERROR) {
        closesocket(listener);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    ret = bind(listener, (struct sockaddr *) &addr, sizeof(addr));
    if (ret == SOCKET_ERROR) {
        closesocket(listener);
        return -1;
    }

    ret = listen(listener, 1);
    if (ret == SOCKET_ERROR) {
        closesocket(listener);
        return -1;
    }

    addr_len = sizeof(addr);
    ret = getsockname(listener, (struct sockaddr *) &addr, &addr_len);
    if (ret == SOCKET_ERROR) {
        closesocket(listener);
        return -1;
    }

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        closesocket(listener);
        return -1;
    }

    ret = connect(client, (struct sockaddr *) &addr, sizeof(addr));
    if (ret == SOCKET_ERROR) {
        closesocket(client);
        closesocket(listener);
        return -1;
    }

    server = accept(listener, NULL, NULL);
    closesocket(listener);
    if (server == INVALID_SOCKET) {
        closesocket(client);
        return -1;
    }

    pair[0] = server;
    pair[1] = client;
    return 0;
}

int mk_win32_socketpair(SOCKET pair[2])
{
    if (pair == NULL) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }

    if (mk_win32_socketpair_init() != 0) {
        return -1;
    }

#ifdef MK_HAVE_AFUNIX_H
    if (mk_win32_check_afunix() && mk_win32_socketpair_afunix(pair) == 0) {
        return 0;
    }
#endif

    return mk_win32_socketpair_loopback(pair);
}

#endif
