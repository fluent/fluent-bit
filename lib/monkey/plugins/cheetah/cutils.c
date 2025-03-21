/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#include <monkey/mk_api.h>

#include <pwd.h>
#include <stdarg.h>
#include <string.h>

#include "cheetah.h"
#include "cutils.h"

void mk_cheetah_print_worker_memory_usage(pid_t pid)
{
    int s = 1024;
    char *buf;
    pid_t ppid;
    FILE *f;

    ppid = getpid();
    buf = mk_api->mem_alloc(s);
    sprintf(buf, MK_CHEETAH_PROC_TASK, ppid, pid);

    f = fopen(buf, "r");
    if (!f) {
        CHEETAH_WRITE("Cannot get details\n");
        return;
    }

    buf = fgets(buf, s, f);
    fclose(f);
    if (!buf) {
        CHEETAH_WRITE("Cannot format details\n");
        return;
    }

    CHEETAH_WRITE("\n");
    return;

/*
    int n, c;
    int init = 0;
    int last = 0;
    char *value;

    while ((n = mk_api->str_search(buf + last, " ", MK_STR_SENSITIVE)) > 0) {
        if (c == 23) {
            value = mk_api->str_copy_substr(buf, init, last + n);
            printf("%s\n", value);
            mk_mem_free(buf);
            mk_mem_free(value);
            return;
        }
        init = last + n + 1;
        last += n + 1;
        c++;
    }*/
}

void mk_cheetah_print_running_user()
{
    struct passwd pwd;
    struct passwd *result;
    char *buf;
    long bufsize;
    uid_t uid;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {
        bufsize = 16384;
    }

    buf = mk_api->mem_alloc_z(bufsize);
    uid = getuid();
    getpwuid_r(uid, &pwd, buf, bufsize, &result);

    CHEETAH_WRITE("%s", pwd.pw_name);
    mk_api->mem_free(buf);
}

int mk_cheetah_write(const char *format, ...)
{
    int len = 0;
    char buf[1024];
    va_list ap;

    va_start(ap, format);
    len = vsprintf(buf, format, ap);

    if (listen_mode == LISTEN_STDIN) {
        len = fprintf(cheetah_output, buf, NULL);
    }
    else if (listen_mode == LISTEN_SERVER) {
        len = write(cheetah_socket, buf, len);
    }

    memset(buf, '\0', sizeof(buf));
    va_end(ap);

    return len;
}
