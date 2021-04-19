/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#include <monkey/monkey.h>
#include <monkey/mk_core.h>
#include <monkey/mk_kernel.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_server.h>
#include <monkey/mk_scheduler.h>

#include <ctype.h>

#ifndef _WIN32
#include <sys/utsname.h>

int mk_kernel_version()
{
    int a, b, c;
    int len;
    int pos;
    char *p, *t;
    char *tmp;
    struct utsname uts;

    if (uname(&uts) == -1) {
        mk_libc_error("uname");
    }
    len = strlen(uts.release);

    /* Fixme: this don't support Linux Kernel 10.x.x :P */
    a = (*uts.release - '0');

    /* Second number */
    p = (uts.release) + 2;
    pos = mk_string_char_search(p, '.', len - 2);
    if (pos <= 0) {
        /* Some Debian systems uses a different notation, e.g: 3.14-2-amd64 */
        pos = mk_string_char_search(p, '-', len - 2);
        if (pos <= 0) {
            return -1;
        }
    }

    tmp = mk_string_copy_substr(p, 0, pos);
    if (!tmp) {
        return -1;
    }
    b = atoi(tmp);
    mk_mem_free(tmp);

    /* Last number (it needs filtering) */
    t = p = p + pos + 1;
    do {
        t++;
    } while (isdigit(*t));

    tmp = mk_string_copy_substr(p, 0, t - p);
    if (!tmp) {
        return -1;
    }
    c = atoi(tmp);
    mk_mem_free(tmp);

    MK_TRACE("Kernel detected: %i.%i.%i", a, b, c);
    return MK_KERNEL_VERSION(a, b, c);
}

/* Detect specific Linux Kernel features that we may use */
int mk_kernel_features(int version)
{
    int flags = 0;

    /*
     * TCP Auto Corking (disabled by #175)
     * -----------------------------------
     * I found that running some benchmarks on Linux 3.16 with
     * tcp_autocorking enabled, it lead to lower performance, looks like
     * a manual cork fits better for our needs.
     *
     * I think there is something wrong that we need to clarify, by now
     * I've logged the following issue:
     *
     *   https://github.com/monkey/monkey/issues/175
     *
    if (mk_kernel_runver >= MK_KERNEL_VERSION(3, 14, 0) &&
        mk_socket_tcp_autocorking() == MK_TRUE) {
        flags |= MK_KERNEL_TCP_AUTOCORKING;
    }
    */

    /* SO_REUSEPORT */
    if (version >= MK_KERNEL_VERSION(3, 9, 0)) {
        flags |= MK_KERNEL_SO_REUSEPORT;
    }

    /* TCP_FASTOPEN */
    if (version >= MK_KERNEL_VERSION(3, 7, 0)) {
        flags |= MK_KERNEL_TCP_FASTOPEN;
    }

    return flags;
}

int mk_kernel_features_print(char *buffer, size_t size,
                             struct mk_server *server)
{
    int offset = 0;
    int features = 0;

    if (server->kernel_features & MK_KERNEL_TCP_FASTOPEN) {
        offset += snprintf(buffer, size - offset, "%s", "TCP_FASTOPEN ");
        features++;
    }

    if (server->kernel_features & MK_KERNEL_SO_REUSEPORT) {
        if (server->scheduler_mode == MK_SCHEDULER_FAIR_BALANCING) {
            offset += snprintf(buffer + offset, size - offset,
                               "%s!%s", ANSI_BOLD ANSI_RED, ANSI_RESET);
        }
        offset += snprintf(buffer + offset, size - offset, "%s", "SO_REUSEPORT ");
        features++;
    }

    if (server->kernel_features & MK_KERNEL_TCP_AUTOCORKING) {
        snprintf(buffer + offset, size - offset, "%s", "TCP_AUTOCORKING ");
        features++;
    }

    return features;
}
#else
/* We still need to determine if this can be safely ignored or what do we need to do here */

int mk_kernel_version()
{
    return 1;
}

int mk_kernel_features(int version)
{
    return 0;
}

int mk_kernel_features_print(char* buffer, size_t size,
    struct mk_server* server)
{
    return 0;
}
#endif
