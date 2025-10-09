/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>

#include <chunkio/chunkio.h>

#include "flb_tests_internal.h"

#ifdef _WIN32
#  define FLB_UNLINK _unlink
#  define FLB_RMDIR  _rmdir
#else
#  define FLB_UNLINK unlink
#  define FLB_RMDIR  rmdir
#endif

static int mkpath(const char *p) {
#if FLB_SYSTEM_WINDOWS
    if (_mkdir(p) == 0) {
        return 0;
    }
#else
    if (mkdir(p, 0777) == 0) {
        return 0;
    }
#endif
    if (errno == EEXIST) {
        return 0;
    }
    return -1;
}

static void join_path(char *out, size_t cap, const char *a, const char *b)
{
#ifdef _WIN32
    _snprintf(out, cap, "%s\\%s", a, b);
#else
    snprintf(out, cap, "%s/%s", a, b);
#endif
    out[cap - 1] = '\0';
}

static void tmpdir_for(char *out, size_t n, const char *name)
{
#ifdef _WIN32
    DWORD pid = GetCurrentProcessId();
    _snprintf(out, n, "C:\\Windows\\Temp\\flb-dlq-%s-%lu", name, (unsigned long) pid);
#else
    snprintf(out, n, "/tmp/flb-dlq-%s-%ld", name, (long) getpid());
#endif
    out[n-1] = '\0';
    mkpath(out);
}

/* helper: open a DLQ chunk by basename and return its content copy */
static int read_dlq_chunk_content(struct flb_config *ctx,
                                  const char *rejected_stream_name,
                                  const char *chunk_basename,
                                  void **out_buf, size_t *out_size)
{
    int err = 0;
    struct cio_stream *st;
    struct cio_chunk  *ch;

    *out_buf = NULL;
    *out_size = 0;

    st = cio_stream_get(ctx->cio, rejected_stream_name);
    if (!st) {
        st = cio_stream_create(ctx->cio, rejected_stream_name, FLB_STORAGE_FS);
        if (!st) { return -1; }
    }

    /* Open existing DLQ file by name */
    ch = cio_chunk_open(ctx->cio, st, chunk_basename, CIO_OPEN, 0, &err);
    if (!ch) {
        return -1;
    }

    /* ensure it's readable */
    if (cio_chunk_is_up(ch) != CIO_TRUE) {
        if (cio_chunk_up_force(ch) != CIO_OK) {
            cio_chunk_close(ch, CIO_FALSE);
            return -1;
        }
    }

    if (cio_chunk_get_content_copy(ch, out_buf, out_size) != CIO_OK) {
        cio_chunk_close(ch, CIO_FALSE);
        return -1;
    }

    cio_chunk_close(ch, CIO_FALSE);
    return 0;
}

/* tiny binary “contains” (since memmem is non-portable) */
static int buf_contains(const void *hay, size_t hlen,
                        const void *needle, size_t nlen)
{
    size_t i;
    if (nlen == 0 || hlen < nlen) return 0;
    const unsigned char *h = (const unsigned char *) hay;
    const unsigned char *n = (const unsigned char *) needle;

    for (i = 0; i + nlen <= hlen; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

#if FLB_SYSTEM_WINDOWS
static int find_latest_flb_win32(const char *dir, char *out, size_t out_sz)
{
    WIN32_FIND_DATAA ffd;
    HANDLE h = INVALID_HANDLE_VALUE;
    char pattern[1024];
    ULONGLONG best_ts = 0ULL;
    char best_name[MAX_PATH] = {0};

    _snprintf(pattern, sizeof(pattern), "%s\\*.flb", dir);
    pattern[sizeof(pattern)-1] = '\0';

    h = FindFirstFileA(pattern, &ffd);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        ULONGLONG ts = (((ULONGLONG)ffd.ftLastWriteTime.dwHighDateTime) << 32) |
                        (ULONGLONG)ffd.ftLastWriteTime.dwLowDateTime;
        if (ts >= best_ts) {
            best_ts = ts;
            strncpy(best_name, ffd.cFileName, sizeof(best_name)-1);
            best_name[sizeof(best_name)-1] = '\0';
        }
    } while (FindNextFileA(h, &ffd));

    FindClose(h);

    if (best_name[0] == '\0') {
        return -1;
    }

    join_path(out, out_sz, dir, best_name);
    return 0;
}
#else
static int find_latest_flb_unix(const char *dir, char *out, size_t out_sz)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    time_t best_t = 0;
    char best_path[1024] = {0};
    struct stat st;
    char full[1024];

    if (!d) return -1;

    while ((e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len < 5) {
            continue;
        }
        if (strcmp(e->d_name + (len - 4), ".flb") != 0) {
            continue;
        }

        join_path(full, sizeof(full), dir, e->d_name);
        if (stat(full, &st) == 0) {
            if (st.st_mtime >= best_t) {
                best_t = st.st_mtime;
                strncpy(best_path, full, sizeof(best_path)-1);
            }
        }
    }
    closedir(d);

    if (best_path[0] == '\0') {
        return -1;
    }
    strncpy(out, best_path, out_sz - 1);
    out[out_sz-1] = '\0';
    return 0;
}
#endif

/* find the most recent *.flb file in dir; write full path into out */
static int find_latest_flb(const char *dir, char *out, size_t out_sz)
{
#if FLB_SYSTEM_WINDOWS
    return find_latest_flb_win32(dir, out, out_sz);
#else
    return find_latest_flb_unix(dir, out, out_sz);
#endif
}

static void free_ctx(struct flb_config *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->cio) {
        cio_destroy(ctx->cio);
        ctx->cio = NULL;
    }

    flb_config_exit(ctx);
}

static const char *get_dlq_stream_name(struct flb_config *ctx)
{
    if (ctx->storage_rejected_stream) {
        return ((struct cio_stream *)ctx->storage_rejected_stream)->name;
    }
    return ctx->storage_rejected_path ? ctx->storage_rejected_path : "rejected";
}

static void delete_all_chunks_in_stream(struct cio_ctx *cio, struct cio_stream *st)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct cio_chunk *ch;

    if (!cio || !st) {
        return;
    }

    mk_list_foreach_safe(head, tmp, &st->chunks) {
        ch = mk_list_entry(head, struct cio_chunk, _head);

        char *name_copy = flb_strdup(ch->name);
        if (!name_copy) {
            continue;
        }

        cio_chunk_close(ch, CIO_FALSE);

        (void) cio_chunk_delete(cio, st, name_copy);

        flb_free(name_copy);
    }
}

static void rmdir_stream_dir(const char *root, const char *stream_name)
{
    if (!root || !stream_name) {
        return;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", root, stream_name);
    path[sizeof(path)-1] = '\0';

    /* Best-effort: ignore errors */
    (void) rmdir(path);
}

/* Minimal POSIX rm -rf for the whole temp tree after CIO is gone */
#if FLB_SYSTEM_WINDOWS
static void rm_rf_best_effort_win32(const char *root)
{
    WIN32_FIND_DATAA ffd;
    HANDLE h = INVALID_HANDLE_VALUE;
    char pattern[1024], p[1024];

    _snprintf(pattern, sizeof(pattern), "%s\\*",
              root ? root : "");
    pattern[sizeof(pattern)-1] = '\0';

    h = FindFirstFileA(pattern, &ffd);
    if (h == INVALID_HANDLE_VALUE) {
        /* try removing root itself */
        (void) FLB_RMDIR(root);
        return;
    }

    do {
        const char *name = ffd.cFileName;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;

        join_path(p, sizeof(p), root, name);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            rm_rf_best_effort_win32(p);
        }
        else {
            /* clear read-only if needed */
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
                SetFileAttributesA(p,
                    ffd.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY);
            }
            (void) DeleteFileA(p);
        }
    } while (FindNextFileA(h, &ffd));

    FindClose(h);
    (void) FLB_RMDIR(root);
}
#else
static void rm_rf_best_effort_unix(const char *root)
{
    DIR *d = opendir(root);
    struct dirent *e;
    char p[1024];
    struct stat st;

    if (!d) {
        (void) FLB_RMDIR(root);
        return;
    }
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) { 
            continue;
        }
        join_path(p, sizeof(p), root, e->d_name);
        if (lstat(p, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            rm_rf_best_effort_unix(p);
        }
        else {
            (void) FLB_UNLINK(p);
        }
    }
    closedir(d);
    (void) FLB_RMDIR(root);
}
#endif

static void rm_rf_best_effort(const char *root)
{
#if FLB_SYSTEM_WINDOWS
    rm_rf_best_effort_win32(root);
#else
    rm_rf_best_effort_unix(root);
#endif
}

static void test_cleanup_with_cio(struct flb_config *ctx, const char *root)
{
    if (ctx && ctx->cio) {
        struct cio_stream *st_in  = cio_stream_get(ctx->cio, "in_tail");
        struct cio_stream *st_dlq = cio_stream_get(ctx->cio, get_dlq_stream_name(ctx));

        delete_all_chunks_in_stream(ctx->cio, st_in);
        delete_all_chunks_in_stream(ctx->cio, st_dlq);

        rmdir_stream_dir(root, "in_tail");
        rmdir_stream_dir(root, get_dlq_stream_name(ctx));
    }

    free_ctx(ctx);

    rm_rf_best_effort(root);
}

static struct flb_config *make_ctx_fs(const char *root, const char *rejected)
{
    struct cio_options opts;
    struct flb_config *ctx = flb_config_init();
    TEST_CHECK(ctx != NULL);

    ctx->storage_path           = flb_strdup(root);
    ctx->storage_keep_rejected  = FLB_TRUE;
    ctx->storage_rejected_path  = flb_strdup(rejected);

    cio_options_init(&opts);
    opts.root_path = ctx->storage_path;
    opts.flags     = CIO_OPEN | CIO_CHECKSUM;
    opts.log_cb    = NULL;

    ctx->cio = cio_create(&opts);
    TEST_CHECK(ctx->cio != NULL);

    /* mimic engine behavior: load + qsort */
    TEST_CHECK(cio_load(ctx->cio, NULL) == 0);
    cio_qsort(ctx->cio, NULL);

    return ctx;
}

static struct cio_chunk *make_src_chunk(struct flb_config *ctx,
                                        int storage_type,    /* FLB_STORAGE_FS */
                                        const char *stream_name,
                                        const char *file_name,
                                        const char *payload)
{
    int err = 0;
    int cio_type = storage_type;
    struct cio_stream *st = NULL;
    struct cio_chunk *ch = NULL;

    st = cio_stream_get(ctx->cio, stream_name);
    if (!st) {
        st = cio_stream_create(ctx->cio, stream_name, cio_type);
    }
    TEST_CHECK(st != NULL);

    ch = cio_chunk_open(ctx->cio, st, file_name, CIO_OPEN, 0, &err);
    TEST_CHECK(ch != NULL);

    TEST_CHECK(cio_chunk_write(ch, payload, strlen(payload)) == CIO_OK);
    TEST_CHECK(cio_chunk_sync(ch) == CIO_OK);

    return ch;
}

static void test_dlq_copy_from_fs_chunk(void)
{
    char root[256], rejdir[256], latest[1024];
    struct cio_chunk *src = NULL;
    struct flb_config *ctx = NULL;
    int rc;
    const char *payload =
        "{\"time\":\"2024-09-03 14:51:05.064735+00:00\",\"msg\":\"oops FS\"}\n";
    char latest_copy[1024];
    void  *content = NULL;
    size_t content_size = 0;
    char *base = NULL;

    tmpdir_for(root, sizeof(root), "fs");
    snprintf(rejdir, sizeof(rejdir), "%s/%s", root, "rejected");
    mkpath(rejdir);

    ctx = make_ctx_fs(root, "rejected");

    src = make_src_chunk(ctx, FLB_STORAGE_FS,
                         "in_tail",
                         "t0-0-0000000000.000000000.flb",
                         payload);

    rc = flb_storage_quarantine_chunk(ctx, src,
                                      "kube.var.log.containers.test",
                                      400, "http");
    TEST_CHECK(rc == 0);

    TEST_CHECK(find_latest_flb(rejdir, latest, sizeof(latest)) == 0);

    /* get just the filename (basename) */
    strncpy(latest_copy, latest, sizeof(latest_copy)-1);
    latest_copy[sizeof(latest_copy)-1] = '\0';
    base = basename(latest_copy);

    TEST_CHECK(read_dlq_chunk_content(ctx, "rejected", base, &content, &content_size) == 0);
    TEST_CHECK(content != NULL);
    TEST_CHECK(content_size > 0);
    TEST_CHECK(buf_contains(content, content_size, payload, strlen(payload)) == 1);

    flb_free(content);
    cio_chunk_close(src, CIO_FALSE);
    test_cleanup_with_cio(ctx, root);
}

static void test_dlq_disabled_no_copy(void)
{
    char root[256], rejdir[256], latest[1024];
    struct cio_chunk *src = NULL;
    struct flb_config *ctx = NULL;
    struct cio_options opts;
    int rc;
    const char *payload = "{\"msg\":\"should not be copied\"}\n";

    tmpdir_for(root, sizeof(root), "disabled");
    snprintf(rejdir, sizeof(rejdir), "%s/%s", root, "rejected");
    mkpath(rejdir);

    /* DLQ disabled */
    ctx = flb_config_init();
    TEST_CHECK(ctx != NULL);

    ctx->storage_path = flb_strdup(root);
    ctx->storage_keep_rejected = FLB_FALSE;
    ctx->storage_rejected_path = flb_strdup("rejected");

    cio_options_init(&opts);
    opts.root_path = ctx->storage_path;
    opts.flags     = CIO_OPEN;
    ctx->cio = cio_create(&opts);
    TEST_CHECK(ctx->cio != NULL);

    src = make_src_chunk(ctx, FLB_STORAGE_FS,
                         "in_tail",
                         "t1-0.flb",
                         payload);

    /* Attempt to copy: should fail because DLQ is disabled */
    rc = flb_storage_quarantine_chunk(ctx, src,
                                      "tag", 400, "out");
    TEST_CHECK(rc != 0);

    TEST_CHECK(find_latest_flb(rejdir, latest, sizeof(latest)) != 0);

    cio_chunk_close(src, CIO_FALSE);
    test_cleanup_with_cio(ctx, root);
}

TEST_LIST = {
    { "dlq_copy_from_fs_chunk",  test_dlq_copy_from_fs_chunk },
    { "dlq_disabled_no_copy",    test_dlq_disabled_no_copy },
    { NULL, NULL }
};
