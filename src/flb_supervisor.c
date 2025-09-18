/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_supervisor.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>

#define FLB_SUPERVISOR_DEFAULT_FORCE_TIMEOUT 10
#define FLB_SUPERVISOR_CHILD_TITLE           "fluent-bit-child"
#define FLB_SUPERVISOR_NOTICE_VERSION        2

enum flb_supervisor_notice_command {
    FLB_SUPERVISOR_NOTICE_COMMAND_UPDATE_GRACE = 1,
    FLB_SUPERVISOR_NOTICE_COMMAND_SHUTTING_DOWN = 2
};

#ifndef FLB_SYSTEM_WINDOWS

struct flb_supervisor_notice {
    uint32_t version;
    uint32_t command;
    int32_t grace;
    int32_t grace_input;
};

static volatile sig_atomic_t sv_restart_requested = 0;
static volatile sig_atomic_t sv_stop_signal = 0;
static int sv_notify_fd = -1;
static size_t sv_notice_bytes = 0;
static struct flb_supervisor_notice sv_notice_buffer;
static int sv_grace_timeout = FLB_SUPERVISOR_DEFAULT_FORCE_TIMEOUT;
static time_t sv_shutdown_deadline = 0;
static int sv_shutdown_window = 0;
static int sv_child_grace = -1;
static int sv_child_grace_input = -1;
static int sv_child_notify_fd = -1;

static void supervisor_log(int level, const char *fmt, ...)
{
    int n;
    char buf[512];
    va_list args;

    va_start(args, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (n < 0) {
        return;
    }

    flb_log_print(level, NULL, 0, "[supervisor] %s", buf);
}

static void supervisor_reset_timeout(void)
{
    sv_grace_timeout = FLB_SUPERVISOR_DEFAULT_FORCE_TIMEOUT;
    sv_child_grace = -1;
    sv_child_grace_input = -1;
    sv_shutdown_deadline = 0;
    sv_shutdown_window = 0;
}

static void supervisor_close_notice_pipe(void)
{
    if (sv_notify_fd != -1) {
        close(sv_notify_fd);
        sv_notify_fd = -1;
    }

    sv_notice_bytes = 0;
    memset(&sv_notice_buffer, 0, sizeof(sv_notice_buffer));
}

static void supervisor_apply_grace(int grace, int grace_input)
{
    int total = 0;

    if (grace > 0) {
        total += grace;
    }

    if (grace_input > 0) {
        total += grace_input;
    }

    sv_child_grace = grace;
    sv_child_grace_input = grace_input;

    if (total <= 0) {
        sv_grace_timeout = FLB_SUPERVISOR_DEFAULT_FORCE_TIMEOUT;
        supervisor_log(FLB_LOG_INFO,
                       "child did not advertise grace settings, using default %d second timeout",
                       sv_grace_timeout);
    }
    else {
        sv_grace_timeout = total;
        supervisor_log(FLB_LOG_INFO,
                       "child grace windows observed: service=%d, inputs=%d -> supervising window=%d seconds",
                       sv_child_grace,
                       sv_child_grace_input,
                       sv_grace_timeout);
    }
}

static void supervisor_handle_notice(const struct flb_supervisor_notice *notice)
{
    time_t now;

    supervisor_apply_grace(notice->grace, notice->grace_input);

    switch (notice->command) {
    case FLB_SUPERVISOR_NOTICE_COMMAND_UPDATE_GRACE:
        sv_shutdown_deadline = 0;
        sv_shutdown_window = 0;
        break;
    case FLB_SUPERVISOR_NOTICE_COMMAND_SHUTTING_DOWN:
        now = time(NULL);
        sv_shutdown_window = sv_grace_timeout;
        sv_shutdown_deadline = now + sv_grace_timeout;
        supervisor_log(FLB_LOG_INFO,
                       "child reported shutdown in progress, enforcing deadline of %d seconds",
                       sv_shutdown_window);
        break;
    default:
        supervisor_log(FLB_LOG_WARN,
                       "received unknown notice command %u",
                       notice->command);
        break;
    }
}

static void supervisor_consume_notice()
{
    ssize_t bytes;
    char *buf;

    if (sv_notify_fd == -1) {
        return;
    }

    buf = (char *) &sv_notice_buffer;

    while ((bytes = read(sv_notify_fd,
                         buf + sv_notice_bytes,
                         sizeof(sv_notice_buffer) - sv_notice_bytes)) > 0) {
        sv_notice_bytes += (size_t) bytes;

        if (sv_notice_bytes == sizeof(sv_notice_buffer)) {
            if (sv_notice_buffer.version == FLB_SUPERVISOR_NOTICE_VERSION) {
                supervisor_handle_notice(&sv_notice_buffer);
            }
            else {
                supervisor_log(FLB_LOG_WARN,
                               "received incompatible notice version %u",
                               sv_notice_buffer.version);
            }

            sv_notice_bytes = 0;
            memset(&sv_notice_buffer, 0, sizeof(sv_notice_buffer));
        }
    }

    if (bytes == 0) {
        supervisor_close_notice_pipe();
    }
    else if (bytes == -1 && errno != EAGAIN && errno != EINTR) {
        supervisor_log(FLB_LOG_ERROR,
                       "failed reading child notices: %s",
                       strerror(errno));
        supervisor_close_notice_pipe();
    }
}

static int supervisor_child_notice_fd()
{
    const char *env;
    char *end;
    long value;

    if (sv_child_notify_fd != -1) {
        return sv_child_notify_fd;
    }

    env = getenv("FLB_SUPERVISOR_NOTIFY_FD");
    if (!env || env[0] == '\0') {
        return -1;
    }

    errno = 0;
    value = strtol(env, &end, 10);
    if (errno != 0 || end == env || value < 0 || value > INT_MAX) {
        return -1;
    }

    sv_child_notify_fd = (int) value;
    return sv_child_notify_fd;
}

static void supervisor_child_send_notice(uint32_t command,
                                         int grace,
                                         int grace_input)
{
    struct flb_supervisor_notice notice;
    ssize_t written;
    int fd;

    fd = supervisor_child_notice_fd();
    if (fd == -1) {
        return;
    }

    notice.version = FLB_SUPERVISOR_NOTICE_VERSION;
    notice.command = command;
    notice.grace = grace;
    notice.grace_input = grace_input;

    do {
        written = write(fd, &notice, sizeof(notice));
    }
    while (written == -1 && errno == EINTR);

    if (written != (ssize_t) sizeof(notice)) {
        if (errno == EPIPE || errno == EBADF) {
            sv_child_notify_fd = -1;
        }
    }
}

void flb_supervisor_child_update_grace(int grace, int grace_input)
{
    supervisor_child_send_notice(FLB_SUPERVISOR_NOTICE_COMMAND_UPDATE_GRACE,
                                 grace,
                                 grace_input);
}

void flb_supervisor_child_signal_shutdown(int grace, int grace_input)
{
    supervisor_child_send_notice(FLB_SUPERVISOR_NOTICE_COMMAND_SHUTTING_DOWN,
                                 grace,
                                 grace_input);
}

static void supervisor_parent_signal(int sig)
{
    if (sig == SIGHUP) {
        sv_restart_requested = 1;
    }
    else if (sig == SIGTERM || sig == SIGINT || sig == SIGQUIT) {
        sv_stop_signal = sig;
    }
}

static void supervisor_install_parent_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = supervisor_parent_signal;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

static int supervisor_wait_child(pid_t pid, int *status, int timeout)
{
    int ret;
    time_t start;

    start = time(NULL);

    while (1) {
        ret = waitpid(pid, status, WNOHANG);
        if (ret == pid) {
            return 0;
        }
        else if (ret == 0) {
            if (timeout >= 0 && (time(NULL) - start) >= timeout) {
                return -1;
            }
            usleep(200000);
            continue;
        }
        else {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
    }
}

static int supervisor_stop_child(pid_t pid, int signal, int *status, int timeout)
{
    int ret;

    if (kill(pid, signal) == -1) {
        if (errno == ESRCH) {
            return 0;
        }
        supervisor_log(FLB_LOG_ERROR,
                       "unable to deliver signal %d to child: %s",
                       signal,
                       strerror(errno));
    }

    ret = supervisor_wait_child(pid, status, timeout);
    if (ret == 0) {
        return 0;
    }

    if (timeout >= 0) {
        supervisor_log(FLB_LOG_WARN,
                       "child ignored signal %d for %d seconds, escalating with SIGKILL",
                       signal,
                       timeout);
    }
    else {
        supervisor_log(FLB_LOG_WARN,
                       "child ignored signal %d, escalating with SIGKILL",
                       signal);
    }

    if (kill(pid, SIGKILL) == -1) {
        if (errno == ESRCH) {
            return 0;
        }

        supervisor_log(FLB_LOG_ERROR,
                       "failed to deliver SIGKILL to child: %s",
                       strerror(errno));
    }

    while (waitpid(pid, status, 0) == -1) {
        if (errno != EINTR) {
            break;
        }
    }

    return -1;
}

static pid_t supervisor_spawn(int argc, char **argv, flb_supervisor_entry_fn entry)
{
    int ret;
    int pipefd[2];
    pid_t pid;
    char fd_env[32];

    if (pipe(pipefd) == -1) {
        supervisor_log(FLB_LOG_ERROR,
                       "failed to create notice pipe: %s",
                       strerror(errno));
        return -1;
    }

    if (fcntl(pipefd[0], F_SETFL, O_NONBLOCK) == -1) {
        supervisor_log(FLB_LOG_ERROR,
                       "failed to configure notice pipe: %s",
                       strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    snprintf(fd_env, sizeof(fd_env), "%d", pipefd[1]);
    setenv("FLB_SUPERVISOR_NOTIFY_FD", fd_env, 1);

    pid = fork();
    if (pid == -1) {
        supervisor_log(FLB_LOG_ERROR,
                       "unable to fork child: %s",
                       strerror(errno));
        unsetenv("FLB_SUPERVISOR_NOTIFY_FD");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        setenv("FLB_SUPERVISOR_ACTIVE", "1", 1);
#ifdef __linux__
        prctl(PR_SET_NAME, (unsigned long) "fluent-bit-child", 0, 0, 0);
#endif
        ret = entry(argc, argv);
        _exit(ret);
    }

    unsetenv("FLB_SUPERVISOR_NOTIFY_FD");
    close(pipefd[1]);

    if (sv_notify_fd != -1) {
        close(sv_notify_fd);
    }
    sv_notify_fd = pipefd[0];
    sv_notice_bytes = 0;
    memset(&sv_notice_buffer, 0, sizeof(sv_notice_buffer));

    supervisor_reset_timeout();
    supervisor_log(FLB_LOG_INFO,
                   "started child process %d",
                   (int) pid);
    return pid;
}

static int supervisor_translate_status(int status)
{
    int sig;

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        sig = WTERMSIG(status);
        supervisor_log(FLB_LOG_WARN,
                       "child terminated by signal %d",
                       sig);
        return 128 + sig;
    }

    return EXIT_FAILURE;
}

static int supervisor_supervise_loop(int argc, char **argv, flb_supervisor_entry_fn entry)
{
    int ret;
    int child_status = 0;
    int restart_pending = 0;
    int stop_signal = 0;
    int exit_rc;
    pid_t child_pid = -1;
    time_t now;

    supervisor_install_parent_handlers();
    while (1) {
        supervisor_consume_notice();

        if (sv_shutdown_deadline > 0 && child_pid != -1) {
            now = time(NULL);
            if (now >= sv_shutdown_deadline) {
                supervisor_log(FLB_LOG_WARN,
                                 "child failed to finish shutdown within %d seconds, forcing restart",
                                 sv_shutdown_window);
                supervisor_stop_child(child_pid,
                                      SIGTERM,
                                      &child_status,
                                      sv_grace_timeout);
                restart_pending = 1;
                child_pid = -1;
                supervisor_reset_timeout();
                continue;
            }
        }

        if (child_pid == -1) {
            child_pid = supervisor_spawn(argc, argv, entry);
            if (child_pid == -1) {
                return EXIT_FAILURE;
            }
        }

        if (sv_restart_requested) {
            restart_pending = 1;
            sv_restart_requested = 0;
            supervisor_log(FLB_LOG_INFO,
                             "restart requested, attempting graceful stop (timeout=%d)",
                             sv_grace_timeout);
            supervisor_stop_child(child_pid, SIGTERM, &child_status, sv_grace_timeout);
            child_pid = -1;
            supervisor_reset_timeout();
            continue;
        }

        if (sv_stop_signal) {
            stop_signal = sv_stop_signal;
            sv_stop_signal = 0;
            supervisor_log(FLB_LOG_INFO,
                           "stop requested, forwarding signal %d (timeout=%d)",
                           stop_signal,
                           sv_grace_timeout);
            supervisor_stop_child(child_pid, stop_signal, &child_status, sv_grace_timeout);
            return supervisor_translate_status(child_status);
        }

        ret = waitpid(child_pid, &child_status, WNOHANG);
        if (ret == child_pid) {
            exit_rc = supervisor_translate_status(child_status);
            if (restart_pending || exit_rc != 0) {
                if (!restart_pending) {
                    supervisor_log(FLB_LOG_WARN,
                                   "child exited with status %d, scheduling restart",
                                   exit_rc);
                }
                restart_pending = 0;
                child_pid = -1;
                supervisor_reset_timeout();
                sleep(1);
                continue;
            }

            supervisor_log(FLB_LOG_INFO,
                           "child exited cleanly, stopping supervision");
            return exit_rc;
        }
        else if (ret == -1 && errno != EINTR) {
            supervisor_log(FLB_LOG_ERROR,
                           "waitpid failure: %s",
                           strerror(errno));
            return EXIT_FAILURE;
        }

        sleep(1);
    }
}

static int supervisor_prepare_args(int argc, char **argv, char ***out_argv)
{
    char **copy;
    int i;
    int j;

    copy = flb_calloc(argc + 1, sizeof(char *));
    if (!copy) {
        flb_errno();
        supervisor_log(FLB_LOG_ERROR,
                       "failed to allocate sanitized arguments");
        return -1;
    }

    j = 0;
    for (i = 0; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "--supervisor") == 0) {
            continue;
        }
        copy[j++] = argv[i];
    }

    if (j > 0 && copy[0]) {
        copy[0] = (char *) FLB_SUPERVISOR_CHILD_TITLE;
    }

    copy[j] = NULL;
    *out_argv = copy;
    return j;
}

int flb_supervisor_requested(int argc, char **argv)
{
    int i;
    int help = FLB_FALSE;
    int requested = FLB_FALSE;

    for (i = 1; i < argc; i++) {
        if (!argv[i]) {
            continue;
        }

        if (strcmp(argv[i], "--supervisor") == 0) {
            requested = FLB_TRUE;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            help = FLB_TRUE;
        }
    }

    if (requested && help) {
        supervisor_log(FLB_LOG_DEBUG,
                       "help requested, skipping supervisor");
        return FLB_FALSE;
    }

    return requested;
}

int flb_supervisor_run(int argc, char **argv, flb_supervisor_entry_fn entry)
{
    char **clean_argv;
    int clean_argc;
    const char *env_child;
    int ret;

    if (!flb_supervisor_requested(argc, argv)) {
        return entry(argc, argv);
    }

    clean_argc = supervisor_prepare_args(argc, argv, &clean_argv);
    if (clean_argc < 0) {
        supervisor_log(FLB_LOG_ERROR,
                       "failed to prepare arguments");
        return EXIT_FAILURE;
    }

    env_child = getenv("FLB_SUPERVISOR_ACTIVE");
    if (env_child && strcmp(env_child, "1") == 0) {
        ret = entry(clean_argc, clean_argv);
        flb_free(clean_argv);
        return ret;
    }

    ret = supervisor_supervise_loop(clean_argc, clean_argv, entry);
    flb_free(clean_argv);
    return ret;
}

#else

int flb_supervisor_requested(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    return FLB_FALSE;
}

int flb_supervisor_run(int argc, char **argv, flb_supervisor_entry_fn entry)
{
    if (flb_supervisor_requested(argc, argv)) {
        fprintf(stderr, "supervisor mode is not supported on this platform\n");
    }

    return entry(argc, argv);
}

void flb_supervisor_child_update_grace(int grace, int grace_input)
{
    (void) grace;
    (void) grace_input;
}

void flb_supervisor_child_signal_shutdown(int grace, int grace_input)
{
    (void) grace;
    (void) grace_input;
}

#endif
