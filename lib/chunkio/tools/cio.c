/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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
#include <sys/types.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#ifndef _MSC_VER
#include <pwd.h>
#endif
#ifdef __MACH__
#  include <mach/clock.h>
#  include <mach/mach.h>
#endif

#include <monkey/mk_core/mk_getopt.h>
#include <chunkio/chunkio_compat.h>

#ifndef _MSC_VER
#define ANSI_RESET    "\033[0m"
#define ANSI_BOLD     "\033[1m"
#define ANSI_CYAN     "\033[96m"
#define ANSI_MAGENTA  "\033[95m"
#define ANSI_RED      "\033[91m"
#define ANSI_YELLOW   "\033[93m"
#define ANSI_BLUE     "\033[94m"
#define ANSI_GREEN    "\033[92m"
#define ANSI_WHITE    "\033[97m"
#else
#define ANSI_RESET    ""
#define ANSI_BOLD     ""
#define ANSI_CYAN     ""
#define ANSI_MAGENTA  ""
#define ANSI_RED      ""
#define ANSI_YELLOW   ""
#define ANSI_BLUE     ""
#define ANSI_GREEN    ""
#define ANSI_WHITE    ""
#endif

#define ANSI_BOLD_CYAN     ANSI_BOLD ANSI_CYAN
#define ANSI_BOLD_MAGENTA  ANSI_BOLD ANSI_MAGENTA
#define ANSI_BOLD_RED      ANSI_BOLD ANSI_RED
#define ANSI_BOLD_YELLOW   ANSI_BOLD ANSI_YELLOW
#define ANSI_BOLD_BLUE     ANSI_BOLD ANSI_BLUE
#define ANSI_BOLD_GREEN    ANSI_BOLD ANSI_GREEN
#define ANSI_BOLD_WHITE    ANSI_BOLD ANSI_WHITE

#ifdef _MSC_VER
#define STDIN_FILENO _fileno( stdin )
#define STDOUT_FILENO _fileno( stdout )
#define STDERR_FILENO _fileno( stderr )
#endif

#define CIO_ROOT_PATH  ".cio"
#define cio_print_signal(X) case X:                       \
    write (STDERR_FILENO, #X ")\n" , sizeof(#X ")\n")-1); \
    break;

#define CIO_PERF_PATH      "/tmp/cio-perf/"

#define ONESEC_IN_NSEC     1000000000

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_scan.h>
#include <chunkio/cio_utils.h>

static void cio_help(int rc)
{
    printf("Usage: cio [-r PATH] OPTIONS\n\n");
    printf("Available Options\n");
    printf("  -r, --root[=PATH]\tset root path\n");
    printf("  -i, --stdin\t\tdump stdin data to stream/file\n");
    printf("  -s, --stream=STREAM\tset stream name\n");
    printf("  -m, --metadata=INFO\tset metadata\n");
    printf("  -M, --memory\t\trun in-memory mode\n");
    printf("  -l, --list\t\tlist environment content\n");
    printf("  -E, --extension\tset chunk extension filter\n");
    printf("  -F, --full-sync\tforce data flush to disk\n");
    printf("  -k, --checksum\tenable CRC32 checksum\n");
    printf("  -f, --filename=FILE\tset name of file to create\n");
    printf("  -p, --perf=FILE\trun performance test\n");
    printf("  -w, --perf-writes=N\tset number of writes for performance mode "
           "(default: 5)\n");
    printf("  -e, --perf-files=N\tset number of files to create on "
           "performance mode (default: 1000)\n");
    printf("  -S, --silent\t\tmake chunkio quiet during the operation\n");
    printf("  -v, --verbose\t\tincrease logging verbosity\n");
    printf("  -h, --help\t\tprint this help\n");
    exit(rc);
}

static void cio_signal_handler(int signal)
{
    char s[] = "[cio] caught signal (";

    /* write signal number */
    write(STDERR_FILENO, s, sizeof(s) - 1);
    switch (signal) {
        cio_print_signal(SIGINT);
#ifndef _MSC_VER
        cio_print_signal(SIGQUIT);
        cio_print_signal(SIGHUP);
#endif
        cio_print_signal(SIGTERM);
        cio_print_signal(SIGSEGV);
    };

    /* Signal handlers */
    switch (signal) {
    case SIGINT:
#ifndef _MSC_VER
    case SIGQUIT:
    case SIGHUP:
#endif
    case SIGTERM:
        _exit(EXIT_SUCCESS);
    case SIGSEGV:
        abort();
    default:
        break;
    }
}

void cio_bytes_to_human_readable_size(size_t bytes,
                                      char *out_buf, size_t size)
{
    unsigned long i;
    uint64_t u = 1024;
    static const char *__units[] = {
        "b", "K", "M", "G",
        "T", "P", "E", "Z", "Y", NULL
    };

    for (i = 0; __units[i] != NULL; i++) {
        if ((bytes / u) == 0) {
            break;
        }
        u *= 1024;
    }
    if (!i) {
        snprintf(out_buf, size, "%lu%s", (long unsigned int) bytes, __units[0]);
    }
    else {
        float fsize = (float) ((double) bytes / (u / 1024));
        snprintf(out_buf, size, "%.1f%s", fsize, __units[i]);
    }
}

static void cio_signal_init()
{
    signal(SIGINT,  &cio_signal_handler);
#ifndef _MSC_VER
    signal(SIGQUIT, &cio_signal_handler);
    signal(SIGHUP,  &cio_signal_handler);
#endif
    signal(SIGTERM, &cio_signal_handler);
    signal(SIGSEGV, &cio_signal_handler);
}


static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    char *dtitle = "chunkio";
    char *dcolor = ANSI_BLUE;

    /* messages from this own client are in yellow */
    if (*file == 't') {
        dtitle = "  cli  ";
        dcolor = ANSI_YELLOW;
    }

    if (ctx->options.log_level > CIO_LOG_INFO) {
        printf("%s[%s]%s %-60s => %s%s:%i%s\n",
               dcolor, dtitle, ANSI_RESET, str,
               dcolor, file, line, ANSI_RESET);
    }
    else {
        printf("%s[%s]%s %s\n", dcolor, dtitle, ANSI_RESET, str);
    }

    return 0;
}

#ifndef _MSC_VER
static int cio_default_root_path(char *path, int size)
{
    int len;
    struct passwd *pw;

    pw = getpwuid(getuid());
    if (!pw) {
        perror("getpwuid");
        return -1;
    }

    /* ~/.cio */
    len = snprintf(path, size, "%s/%s",
                   pw->pw_dir, CIO_ROOT_PATH);
    if (len == -1) {
        perror("snprintf");
        return -1;
    }

    return 0;
}
#else
static int cio_default_root_path(char *path, int size)
{
    return -1;
}
#endif

static void cio_timespec_get(struct timespec *t)
{
#ifdef __MACH__ // macOS does not have timespec_get, use clock_get_time
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    t->tv_sec = mts.tv_sec;
    t->tv_nsec = mts.tv_nsec;
#else
    timespec_get(t, TIME_UTC);
#endif
}

/* command/list: iterate root path and list content */
static int cb_cmd_list(struct cio_ctx *ctx)
{
    cio_scan_dump(ctx);
    return 0;
}

/* command/stdin: read data from STDIN and dump it into stream/file */
static int cb_cmd_stdin(struct cio_ctx *ctx, const char *stream,
                        int opt_buffer,
                        const char *fname, const char *metadata)
{
    int fd;
    int ret;
    int err;
    int meta_len;
    size_t total = 0;
    ssize_t bytes;
    char buf[1024*8];
    struct cio_stream *st;
    struct cio_chunk *ch;

    /* Prepare stream and file contexts */
    st = cio_stream_create(ctx, stream, opt_buffer);
    if (!st) {
        cio_log_error(ctx, "cannot create stream\n");
        return -1;
    }

    /* Open a file with a hint of 32KB */
    ch = cio_chunk_open(ctx, st, fname, CIO_OPEN, 1024*32, &err);
    if (!ch) {
        cio_log_error(ctx, "cannot create file");
        return -1;
    }

    if (metadata) {
        meta_len = strlen(metadata);
        cio_meta_write(ch, (char *) metadata, meta_len);
    }

    /* Catch up stdin */
    fd = dup(STDIN_FILENO);
    if (fd == -1) {
        perror("dup");
        cio_log_error(ctx, "cannot open standard input");
        return -1;
    }

    do {
        bytes = read(fd, buf, sizeof(buf) - 1);
        if (bytes == 0) {
            break;
        }
        else if (bytes == -1) {
            perror("read");
        }
        else {
            ret = cio_chunk_write(ch, buf, bytes);
            if (ret == -1) {
                cio_log_error(ctx, "error writing to file");
                close(fd);
                return -1;
            }
            total += bytes;
        }
    } while (bytes > 0);

    /* close stdin dup(2) */
    close(fd);

    /* synchronize changes to disk and close */
    cio_chunk_sync(ch);
    cio_chunk_close(ch, CIO_FALSE);

    /* print some status */
    cio_bytes_to_human_readable_size(total, buf, sizeof(buf) - 1);
    cio_log_info(ctx, "stdin total bytes => %lu (%s)", total, buf);

    return 0;
}

static double time_to_double(struct timespec *t)
{
    return (double)(t->tv_sec) + ((double)t->tv_nsec/(double) ONESEC_IN_NSEC);
}

static int time_diff(struct timespec *tm0, struct timespec *tm1,
                     struct timespec *out)
{

    if (tm1->tv_sec >= tm0->tv_sec) {
        out->tv_sec = tm1->tv_sec - tm0->tv_sec;
        if (tm1->tv_nsec >= tm0->tv_nsec) {
            out->tv_nsec = tm1->tv_nsec - tm0->tv_nsec;
        }
        else if(tm0->tv_sec == 0){
            /* underflow */
            return -1;
        }
        else{
            out->tv_nsec = ONESEC_IN_NSEC \
                + tm1->tv_nsec - tm0->tv_nsec;
            out->tv_sec--;
        }
    }
    else {
        /* underflow */
        return -1;
    }

    return 0;
}

static void cb_cmd_perf(struct cio_ctx *ctx, int opt_buffer, char *pfile,
                        char *metadata, int writes, int files)
{
    int i;
    int j;
    int err;
    int meta_len = 0;
    int ret;
    uint64_t bytes = 0;
    double rate;
    char *in_data;
    size_t in_size;
    char tmp[255];
    struct cio_stream *stream;
    struct cio_chunk **carr;
    struct timespec t1;
    struct timespec t2;
    struct timespec t_final;

    /* Create pref stream */
    stream = cio_stream_create(ctx, "test-perf", opt_buffer);

    /*
     * Load sample data file and with the same content through multiple write
     * operations generating other files.
     */
    ret = cio_utils_read_file(pfile, &in_data, &in_size);
    if (ret == -1) {
        cio_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Allocate files array */
    carr = calloc(1, sizeof(struct cio_chunk) * files);
    if (!carr) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    if (metadata) {
        meta_len = strlen(metadata);
    }

    /* Perf-write test */
    cio_timespec_get(&t1);
    for (i = 0; i < files; i++) {
        snprintf(tmp, sizeof(tmp), "perf-test-%04i.txt", i);
        carr[i] = cio_chunk_open(ctx, stream, tmp, CIO_OPEN, in_size, &err);
        if (carr[i] == NULL) {
            continue;
        }

        if (meta_len > 0) {
            cio_meta_write(carr[i], metadata, meta_len);
            bytes += meta_len;
        }

        for (j = 0; j < writes; j++) {
            ret = cio_chunk_write(carr[i], in_data, in_size);
            if (ret == -1) {
                exit(1);
            }
            bytes += in_size;
        }
        cio_chunk_sync(carr[i]);
        cio_chunk_close(carr[i], CIO_FALSE);
    }
    cio_timespec_get(&t2);

    /* Check timing */
    time_diff(&t1, &t2, &t_final);

    /*
     * Write out the report
     * ====================
     */
    cio_bytes_to_human_readable_size(bytes, tmp, sizeof(tmp) - 1);
    printf("=== perf write === \n");
    printf("-  crc32 checksum : %s\n",
           ctx->options.flags & CIO_CHECKSUM ? "enabled" : "disabled");
    printf("-  fs sync mode   : %s\n",
           ctx->options.flags & CIO_FULL_SYNC ? "full" : "normal");

    cio_bytes_to_human_readable_size(in_size, tmp, sizeof(tmp) - 1);
    printf("-  file size      : %s (%lu bytes)\n", tmp, in_size);
    printf("-  total files    : %i\n", files);
    printf("-  file writes    : %i\n", writes);

    cio_bytes_to_human_readable_size(bytes, tmp, sizeof(tmp) - 1);
    printf("-  bytes written  : %s (%" PRIu64 " bytes)\n" , tmp, bytes);
    printf("-  elapsed time   : %.2f seconds\n", time_to_double(&t_final));

    rate = (double) (bytes / time_to_double(&t_final));
    cio_bytes_to_human_readable_size(rate, tmp, sizeof(tmp) - 1);
    printf("-  rate           : %s per second (%.2f bytes)\n", tmp, rate);

    /* Release file data and destroy context */
    free(carr);
    free(in_data);
}

int main(int argc, char **argv)
{
    int ret = 0;
    int opt;
    int opt_silent = CIO_FALSE;
    int opt_pwrites = 5;
    int opt_pfiles = 1000;
    int opt_buffer = CIO_STORE_FS;
    int cmd_stdin = CIO_FALSE;
    int cmd_list = CIO_FALSE;
    int cmd_perf = CIO_FALSE;
    int verbose = CIO_LOG_WARN;
    int flags = 0;
    char *chunk_ext = NULL;
    char *perf_file = NULL;
    char *fname = NULL;
    char *stream = NULL;
    char *metadata = NULL;
    char *root_path = NULL;
    char tmp[PATH_MAX];
    struct cio_ctx *ctx;
    struct cio_options cio_opts;

    static const struct option long_opts[] = {
        {"full-sync"  , no_argument      , NULL, 'F'},
        {"checksum"   , no_argument      , NULL, 'k'},
        {"extension"  , required_argument, NULL, 'E'},
        {"list"       , no_argument      , NULL, 'l'},
        {"root"       , required_argument, NULL, 'r'},
        {"silent"     , no_argument      , NULL, 'S'},
        {"stdin"      , no_argument      , NULL, 'i'},
        {"stream"     , required_argument, NULL, 's'},
        {"metadata"   , required_argument, NULL, 'm'},
        {"memory"     , no_argument      , NULL, 'M'},
        {"filename"   , required_argument, NULL, 'f'},
        {"perf"       , required_argument, NULL, 'p'},
        {"perf-writes", required_argument, NULL, 'w'},
        {"perf-files" , required_argument, NULL, 'e'},
        {"verbose"    , no_argument      , NULL, 'v'},
        {"version"    , no_argument      , NULL, 'V'},
        {"help"       , no_argument      , NULL, 'h'},
    };

    /* Initialize signals */
    cio_signal_init();

    while ((opt = getopt_long(argc, argv, "FkE:lr:p:w:e:Sis:m:Mf:vVh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'F':
            flags |= CIO_FULL_SYNC;
            break;
        case 'k':
            flags |= CIO_CHECKSUM;
            break;
        case 'E':
            chunk_ext = strdup(optarg);
            break;
        case 'l':
            cmd_list = CIO_TRUE;
            break;
        case 'i':
            cmd_stdin = CIO_TRUE;
            break;
        case 'r':
            root_path = strdup(optarg);
            break;
        case 'p':
            perf_file = strdup(optarg);
            cmd_perf = CIO_TRUE;
            break;
        case 'w':
            opt_pwrites = atoi(optarg);
            break;
        case 'e':
            opt_pfiles = atoi(optarg);
            break;
        case 'S':
            opt_silent = CIO_TRUE;
            break;
        case 's':
            stream = strdup(optarg);
            break;
        case 'm':
            metadata = strdup(optarg);
            break;
        case 'M':
            opt_buffer = CIO_STORE_MEM;
            break;
        case 'f':
            fname = strdup(optarg);
            break;
        case 'v':
            verbose++;
            break;
        case 'V':
            fprintf(stderr, "Chunk I/O v%s\n", cio_version());
            exit(0);
        case 'h':
            cio_help(EXIT_SUCCESS);
            break;
        default:
            cio_help(EXIT_FAILURE);
        }
    }

    if (opt_buffer == CIO_STORE_FS && cmd_perf) {
        root_path = strdup(CIO_PERF_PATH);
        cio_utils_recursive_delete(CIO_PERF_PATH);
    }

    /* Check root path, if not set, defaults to ~/.cio */
    if (opt_buffer == CIO_STORE_FS && !root_path) {
        ret = cio_default_root_path(tmp, sizeof(tmp) - 1);
        if (ret == -1) {
            fprintf(stderr,
                    "[chunkio cli] cannot set default root path\n");
            cio_help(EXIT_FAILURE);
        }
        root_path = strdup(tmp);
    }

    if (opt_silent == CIO_TRUE) {
        verbose = 0;
    }

    memset(&cio_opts, 0, sizeof(cio_opts));

    cio_opts.root_path = root_path;
    cio_opts.flags = flags;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = verbose;

    /* Create CIO instance */
    ctx = cio_create(&cio_opts);
    if (root_path) {
        free(root_path);
    }

    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Load */
    cio_load(ctx, chunk_ext);
    cio_log_info(ctx, "root_path => %s", ctx->options.root_path);

    /*
     * Process commands and options
     */
    if (cmd_list == CIO_TRUE) {
        ret = cb_cmd_list(ctx);
    }
    else if (cmd_stdin == CIO_TRUE) {
        /* we need the stream and file names */
        if (!stream) {
            fprintf(stderr, "[chunkio cli] missing stream name\n");
            cio_help(EXIT_FAILURE);
        }
        if (!fname) {
            fprintf(stderr, "[chunkio cli] missing file name\n");
            free(stream);
            cio_help(EXIT_FAILURE);
        }

        ret = cb_cmd_stdin(ctx, stream, opt_buffer, fname, metadata);
    }
    else if (cmd_perf == CIO_TRUE) {
        cb_cmd_perf(ctx, opt_buffer, perf_file, metadata, opt_pwrites,
                    opt_pfiles);
        free(perf_file);
    }
    else {
        cio_help(EXIT_FAILURE);
    }

    free(chunk_ext);
    free(stream);
    free(fname);
    free(metadata);
    cio_destroy(ctx);

    return ret;
}
