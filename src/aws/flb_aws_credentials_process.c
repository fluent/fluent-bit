/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2021      The Fluent Bit Authors
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

#include <fluent-bit/flb_aws_credentials.h>

#include "flb_aws_credentials_log.h"

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_time.h>

#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/wait.h>

#define DEV_NULL "/dev/null"

#define MS_PER_SEC 1000
#define MICROS_PER_MS 1000
#define NS_PER_MS 1000000

#define CREDENTIAL_PROCESS_TIMEOUT_MS 60000
#define CREDENTIAL_PROCESS_BUFFER_SIZE 8 * 1024

#define WAITPID_POLL_FREQUENCY_MS 20
#define WAITPID_TIMEOUT_MS 10 * WAITPID_POLL_FREQUENCY_MS

#define CREDENTIAL_PROCESS_RESPONSE_SESSION_TOKEN "SessionToken"

/* Declarations */
struct token_array;
static int new_token_array(struct token_array *arr, int cap);
static int append_token(struct token_array *arr, char* elem);

struct readbuf;
static int new_readbuf(struct readbuf* buf, int cap);

static int get_monotonic_time(struct flb_time* tm);

static char* ltrim(char* input);
static int scan_credential_process_token_quoted(char *input);
static int scan_credential_process_token_unquoted(char *input);
static int credential_process_token_count(char* process);
static int parse_credential_process_token(char **input, char** out_token);

static int read_until_block(char* name, flb_pipefd_t fd, struct readbuf* buf);
static int waitpid_timeout(char* name, pid_t pid, int* wstatus);

struct process;
static int new_process(struct process* p, char** args);
static void exec_process_child(struct process* p);
static int exec_process(struct process* p);
static int read_from_process(struct process* p, struct readbuf* buf);
static int wait_process(struct process* p);
static void destroy_process(struct process* p);
/* End Declarations */

struct token_array {
    char** tokens;
    int len;
    int cap;
};

/*
 * Initializes a new token array with the given capacity.
 * Returns 0 on success and < 0 on failure.
 * The caller is responsible for calling `flb_free(arr->tokens)`.
 */
static int new_token_array(struct token_array *arr, int cap)
{
    *arr = (struct token_array) { .len = 0, .cap = cap };
    arr->tokens = flb_malloc(cap * sizeof(char*));
    if (!arr->tokens) {
        flb_errno();
        return -1;
    }
    return 0;
}

/*
 * Appends the given token to the array, if there is capacity.
 * Returns 0 on success and < 0 on failure.
 */
static int append_token(struct token_array *arr, char* token)
{
    if (arr->len >= arr->cap) {
        /* This means there is a bug in credential_process_token_count. */
        AWS_CREDS_ERROR("append_token called on full token_array");
        return -1;
    }

    (arr->tokens)[arr->len] = token;
    arr->len++;
    return 0;
}

struct readbuf {
    char* buf;
    int len;
    int cap;
};

/*
 * Initializes a new buffer with the given capacity.
 * Returns 0 on success and < 0 on failure.
 * The caller is responsible for calling `flb_free(buf->buf)`.
 */
static int new_readbuf(struct readbuf* buf, int cap)
{
    *buf = (struct readbuf) { .len = 0, .cap = cap };
    buf->buf = flb_malloc(cap * sizeof(char));
    if (!buf->buf) {
        flb_errno();
        return -1;
    }
    return 0;
}

/*
 * Fetches the current time from the monotonic clock.
 * Returns 0 on success and < 0 on failure.
 * This is useful for calculating deadlines that are not sensitive to changes
 * in the system clock.
 */
static int get_monotonic_time(struct flb_time* tm)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        flb_errno();
        return -1;
    }
    flb_time_set(tm, ts.tv_sec, ts.tv_nsec);
    return 0;
}

/*
 * Skips over any leading spaces in the input string, returning the remainder.
 * If the entire string is consumed, returns the empty string (not NULL).
 */
static char* ltrim(char* input)
{
    while (*input == ' ') {
        input++;
    }
    return input;
}

/*
 * Scans the unquoted token string at the start of the input string.
 * The input must be the start of an unquoted token.
 * Returns the token length on success, and < 0 on failure.
 * This function does not add a null terminator to the token.
 * The token length is the index where the null terminator must be placed.
 * If the entire input is consumed, returns the length of the input string
 * (excluding the null terminator).
 */
static int scan_credential_process_token_unquoted(char *input)
{
    int i;

    for (i = 0; input[i] != ' '; i++) {
        if (input[i] == '\0') {
            break;
        }
        if (input[i] == '"') {
            AWS_CREDS_ERROR("unexpected quote in credential_process");
            return -1;
        }
    }

    return i;
}

/*
 * Scans the quoted token at the start of the input string.
 * The input must be the string after the opening quote.
 * Returns the token length on success, and < 0 on failure.
 * This function does not add a null terminator to the token.
 * The token length is the index where the null terminator must be placed.
 */
static int scan_credential_process_token_quoted(char *input)
{
    int i;

    for (i = 0; input[i] != '"'; i++) {
        if (input[i] == '\0') {
            AWS_CREDS_ERROR("unterminated quote in credential_process");
            return -1;
        }
    }

    if (input[i+1] != '\0' && input[i+1] != ' ') {
        AWS_CREDS_ERROR("unexpected character %c after closing quote in "
                        "credential_process", input[i+1]);
        return -1;
    }

    return i;
}

/*
 * Counts the number of tokens in the input string, which is assumed to be the
 * credential_process from the config file.
 * Returns < 0 on failure.
 */
static int credential_process_token_count(char* process)
{
    int count = 0;
    int i;

    while (1) {
        process = ltrim(process);
        if (*process == '\0') {
            break;
        }

        count++;

        if (*process == '"') {
            process++;
            i = scan_credential_process_token_quoted(process);
        }
        else {
            i = scan_credential_process_token_unquoted(process);
        }

        if (i < 0) {
            return -1;
        }

        process += i;
        if (*process != '\0') {
            process++;
        }
    }

    return count;
}

/*
 * Parses the input string, which is assumed to be the credential_process
 * from the config file. The next token will be put in *out_token, and the
 * remaining unprocessed input will be put in *input.
 * Returns 0 on success and < 0 on failure.
 * If there is an error, the value of *input and *out_token is not defined.
 * If it succeeds and *out_token is NULL, then there are no more tokens,
 * and this function should not be called again.
 * *out_token will be some substring of the original *input, so it should not
 * be freed.
 */
static int parse_credential_process_token(char** input, char** out_token)
{
    *out_token = NULL;
    int i;

    if (!*input) {
        AWS_CREDS_ERROR("parse_credential_process_token called after yielding last token");
        return -1;
    }

    *input = ltrim(*input);

    if (**input == '\0') {
        *input = NULL;
        *out_token = NULL;
        return 0;
    }

    if (**input == '"') {
        (*input)++;
        i = scan_credential_process_token_quoted(*input);
    }
    else {
        i = scan_credential_process_token_unquoted(*input);
    }

    if (i < 0) {
        return -1;
    }

    *out_token = *input;
    *input += i;

    if (**input != '\0') {
        **input = '\0';
        (*input)++;
    }

    return 0;
}

/* See <fluent-bit/flb_aws_credentials.h>. */
char** parse_credential_process(char* input)
{
    char* next_token = NULL;
    struct token_array arr = { 0 };
    int token_count = credential_process_token_count(input);

    if (token_count < 0) {
        goto error;
    }

    /* Add one extra capacity for the NULL terminator. */
    if (new_token_array(&arr, token_count + 1) < 0) {
        goto error;
    }

    while (1) {
        if (parse_credential_process_token(&input, &next_token) < 0) {
            goto error;
        }

        if (!next_token) {
            break;
        }

        if (append_token(&arr, next_token) < 0) {
            goto error;
        }
    }

    if (append_token(&arr, NULL) < 0) {
        goto error;
    }

    return arr.tokens;

error:
    flb_free(arr.tokens);
    return NULL;
}

/*
 * Reads from the pipe into the buffer until no more input is available.
 * If the input is exhausted (EOF), returns 0.
 * If reading would block (EWOULDBLOCK/EAGAIN), returns > 0.
 * If an error occurs or the buffer is full, returns < 0.
 */
static int read_until_block(char* name, flb_pipefd_t fd, struct readbuf* buf)
{
    int result = -1;

    while (1) {
        if (buf->len >= buf->cap) {
            AWS_CREDS_ERROR("credential_process %s exceeded max buffer size", name);
            return -1;
        }

        result = flb_pipe_r(fd, buf->buf + buf->len, buf->cap - buf->len);
        if (result < 0) {
            if (FLB_PIPE_WOULDBLOCK()) {
                return 1;
            }
            flb_pipe_error();
            return -1;
        }
        else if (result == 0) {   /* EOF */
            return 0;
        }
        else {
            buf->len += result;
        }
    }
}

/*
 * Polls waitpid until the given process exits, or the timeout is reached.
 * Returns 0 on success and < 0 on failure.
 */
static int waitpid_timeout(char* name, pid_t pid, int* wstatus)
{
    int result = -1;
    int retries = WAITPID_TIMEOUT_MS / WAITPID_POLL_FREQUENCY_MS;

    while (1) {
        result = waitpid(pid, wstatus, WNOHANG);
        if (result < 0) {
            flb_errno();
            return -1;
        }

        if (result > 0) {
            return 0;
        }

        if (retries <= 0) {
            AWS_CREDS_ERROR("timed out waiting for credential_process %s to exit", name);
            return -1;
        }
        retries--;

        usleep(WAITPID_POLL_FREQUENCY_MS * MICROS_PER_MS);
    }
}

struct process {
    int initialized;
    char** args;
    int stdin_stream;
    flb_pipefd_t stdout_stream[2];
    int stderr_stream;
    pid_t pid;
};

/*
 * Initializes a new process with the given args.
 * args is assumed to be a NULL terminated array, for use with execvp.
 * It must have a least one element, and the first element is assumed to be the
 * name/path of the executable.
 * Returns 0 on success and < 0 on failure.
 * The caller is responsible for calling `destroy_process(p)`.
 */
static int new_process(struct process* p, char** args)
{
    *p = (struct process) {
        .initialized = FLB_TRUE,
        .args = args,
        .stdin_stream = -1,
        .stdout_stream = {-1, -1},
        .stderr_stream = -1,
        .pid = -1,
    };

    while ((p->stdin_stream = open(DEV_NULL, O_RDONLY|O_CLOEXEC)) < 0) {
        if (errno != EINTR) {
            flb_errno();
            return -1;
        }
    }

    if (flb_pipe_create(p->stdout_stream) < 0) {;
        flb_errno();
        return -1;
    }

    if (fcntl(p->stdout_stream[0], F_SETFL, O_CLOEXEC) < 0) {
        flb_errno();
        return -1;
    }

    if (fcntl(p->stdout_stream[1], F_SETFL, O_CLOEXEC) < 0) {
        flb_errno();
        return -1;
    }

    while ((p->stderr_stream = open(DEV_NULL, O_WRONLY|O_CLOEXEC)) < 0) {
        if (errno != EINTR) {
            flb_errno();
            return -1;
        }
    }

    return 0;
}

/*
 * Sets up the credential_process's stdin, stdout, and stderr, and exec's
 * the actual process.
 * For this function to return at all is an error.
 * This function should not be called more than once.
 */
static void exec_process_child(struct process* p)
{
    while ((dup2(p->stdin_stream, STDIN_FILENO) < 0)) {
        if (errno != EINTR) {
            return;
        }
    }
    while ((dup2(p->stdout_stream[1], STDOUT_FILENO) < 0)) {
        if (errno != EINTR) {
            return;
        }
    }
    while ((dup2(p->stderr_stream, STDERR_FILENO) < 0)) {
        if (errno != EINTR) {
            return;
        }
    }

    close(p->stdin_stream);
    flb_pipe_close(p->stdout_stream[0]);
    flb_pipe_close(p->stdout_stream[1]);
    close(p->stderr_stream);

    execvp(p->args[0], p->args);
}

/*
 * Forks the credential_process, but does not wait for it to finish.
 * Returns 0 on success and < 0 on failure.
 * This function should not be called more than once.
 */
static int exec_process(struct process* p)
{
    AWS_CREDS_DEBUG("executing credential_process %s", p->args[0]);

    p->pid = fork();
    if (p->pid < 0) {
        flb_errno();
        return -1;
    }

    if (p->pid == 0) {
        exec_process_child(p);

        /* It should not be possible to reach this under normal circumstances. */
        exit(EXIT_FAILURE);
    }

    close(p->stdin_stream);
    p->stdin_stream = -1;

    flb_pipe_close(p->stdout_stream[1]);
    p->stdout_stream[1] = -1;

    close(p->stderr_stream);
    p->stderr_stream = -1;

    return 0;
}

/*
 * Reads from the credential_process's stdout into the given buffer.
 * Returns 0 on success, and < 0 on failure or timeout.
 * This function should not be called more than once.
 */
static int read_from_process(struct process* p, struct readbuf* buf)
{
    int result = -1;
    struct pollfd pfd;
    struct flb_time start, timeout, deadline, now, remaining;
    int remaining_ms;

    if (fcntl(p->stdout_stream[0], F_SETFL, O_NONBLOCK) < 0) {
        flb_errno();
        return -1;
    }

    if (get_monotonic_time(&start) < 0) {
        return -1;
    }

    flb_time_set(&timeout,
        (time_t) (CREDENTIAL_PROCESS_TIMEOUT_MS / MS_PER_SEC),
        ((long) (CREDENTIAL_PROCESS_TIMEOUT_MS % MS_PER_SEC)) * NS_PER_MS);

    /* deadline = start + timeout */
    flb_time_add(&start, &timeout, &deadline);

    while (1) {
        pfd = (struct pollfd) {
            .fd = p->stdout_stream[0],
            .events = POLLIN,
        };

        if (get_monotonic_time(&now) < 0) {
            return -1;
        }

        /* remaining = deadline - now */
        if (flb_time_diff(&deadline, &now, &remaining) < 0) {
            AWS_CREDS_ERROR("credential_process %s timed out", p->args[0]);
            return -1;
        }

        /*
         * poll uses millisecond resolution for the timeout.
         * If there is less than a millisecond left, then for simplicity we'll just
         * declare that it timed out.
         */
        remaining_ms = (int) (flb_time_to_nanosec(&remaining) / NS_PER_MS);
        if (remaining_ms <= 0) {
            AWS_CREDS_ERROR("credential_process %s timed out", p->args[0]);
            return -1;
        }

        result = poll(&pfd, 1, remaining_ms);
        if (result < 0) {
            if (errno != EINTR) {
                flb_errno();
                return -1;
            }
            continue;
        }

        if (result == 0) {
            AWS_CREDS_ERROR("credential_process %s timed out", p->args[0]);
            return -1;
        }

        if ((pfd.revents & POLLNVAL) == POLLNVAL) {
            AWS_CREDS_ERROR("credential_process %s POLLNVAL", p->args[0]);
            return -1;
        }

        if ((pfd.revents & POLLERR) == POLLERR) {
            AWS_CREDS_ERROR("credential_process %s POLLERR", p->args[0]);
            return -1;
        }

        if ((pfd.revents & POLLIN) == POLLIN || (pfd.revents & POLLHUP) == POLLHUP) {
            result = read_until_block(p->args[0], p->stdout_stream[0], buf);
            if (result <= 0) {
                return result;
            }
        }
    }
}

/*
 * Waits for the process to exit, up to a timeout.
 * Returns 0 on success and < 0 on failure.
 * This function should not be called more than once.
 */
static int wait_process(struct process* p)
{
    int wstatus;

    if (waitpid_timeout(p->args[0], p->pid, &wstatus) < 0) {
        return -1;
    }
    p->pid = -1;

    if (!WIFEXITED(wstatus)) {
        AWS_CREDS_ERROR("credential_process %s did not terminate normally", p->args[0]);
        return -1;
    }

    if (WEXITSTATUS(wstatus) != EXIT_SUCCESS) {
        AWS_CREDS_ERROR("credential_process %s exited with status %d", p->args[0],
                        WEXITSTATUS(wstatus));
        return -1;
    }

    AWS_CREDS_DEBUG("credential_process %s exited successfully", p->args[0]);
    return 0;
}

/*
 * Release all resources associated with this process.
 * Calling this function multiple times is a no-op.
 * Since the process does not own p->args, it does not free it.
 * Note that p->args will be set to NULL, so the caller must hold onto
 * it separately in order to free it.
 */
static void destroy_process(struct process* p)
{
    if (p->initialized) {
        if (p->stdin_stream >= 0) {
            close(p->stdin_stream);
            p->stdin_stream = -1;
        }
        if (p->stdout_stream[0] >= 0) {
            close(p->stdout_stream[0]);
            p->stdout_stream[0] = -1;
        }
        if (p->stdout_stream[1] >= 0) {
            close(p->stdout_stream[1]);
            p->stdout_stream[1] = -1;
        }
        if (p->stderr_stream >= 0) {
            close(p->stderr_stream);
            p->stderr_stream = -1;
        }

        if (p->pid > 0) {
            if (kill(p->pid, SIGKILL) < 0) {
                flb_errno();
                AWS_CREDS_ERROR("could not kill credential_process %s (pid=%d) "
                                "during cleanup", p->args[0], p->pid);
            }
            else {
                while (waitpid(p->pid, NULL, 0) < 0) {
                    if (errno != EINTR) {
                        flb_errno();
                        break;
                    }
                }
            }
            p->pid = -1;
        }

        p->args = NULL;

        p->initialized = FLB_FALSE;
    }
}

/* See <fluent-bit/flb_aws_credentials.h>. */
int exec_credential_process(char* process, struct flb_aws_credentials** creds,
                            time_t* expiration)
{
    char** args = NULL;
    int result = -1;
    struct process p = { 0 };
    struct readbuf buf = { 0 };
    *creds = NULL;
    *expiration = 0;

    args = parse_credential_process(process);
    if (!args) {
        result = -1;
        goto end;
    }

    if (!args[0]) {
        AWS_CREDS_ERROR("invalid credential_process");
        result = -1;
        goto end;
    }

    if (new_process(&p, args) < 0) {
        result = -1;
        goto end;
    }

    if (new_readbuf(&buf, CREDENTIAL_PROCESS_BUFFER_SIZE) < 0) {
        result = -1;
        goto end;
    }

    if (exec_process(&p) < 0) {
        result = -1;
        goto end;
    }

    if (read_from_process(&p, &buf) < 0) {
        result = -1;
        goto end;
    }

    if (wait_process(&p) < 0) {
        result = -1;
        goto end;
    }

    *creds = flb_parse_json_credentials(buf.buf, buf.len,
                                        CREDENTIAL_PROCESS_RESPONSE_SESSION_TOKEN,
                                        expiration);
    if (!*creds) {
        AWS_CREDS_ERROR("could not parse credentials from credential_process %s", args[0]);
        result = -1;
        goto end;
    }

    AWS_CREDS_DEBUG("successfully parsed credentials from credential_process %s", args[0]);

    result = 0;

end:
    destroy_process(&p);

    flb_free(buf.buf);
    buf.buf = NULL;

    flb_free(args);
    args = NULL;

    if (result < 0) {
        flb_aws_credentials_destroy(*creds);
        *creds = NULL;
    }

    return result;
}
