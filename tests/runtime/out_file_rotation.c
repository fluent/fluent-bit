/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_compat.h>
#include "flb_tests_runtime.h"
#include <fluent-bit.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <cmetrics/cmt_counter.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#ifndef FLB_SYSTEM_WINDOWS
#include <dirent.h>
#include <unistd.h>
#define PATH_SEPARATOR "/"
#else
#include <direct.h>
#include <windows.h>
#define PATH_SEPARATOR "\\"
/* Windows S_ISDIR compatibility */
#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif

#endif

#define TEST_MKDIR(path) flb_test_mkdir(path)

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */
#include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/common/json_small.h"   /* JSON_SMALL   */

/* Test functions */
void flb_test_file_rotation_basic(void);
void flb_test_file_rotation_gzip_compression(void);
void flb_test_file_rotation_gzip_compression_exact_chunk(void);
void flb_test_file_rotation_max_files_cleanup(void);
void flb_test_file_rotation_max_files_validation(void);
void flb_test_file_rotation_format_csv(void);
void flb_test_file_rotation_format_ltsv(void);
void flb_test_file_rotation_format_plain(void);
void flb_test_file_rotation_format_msgpack(void);
void flb_test_file_rotation_format_template(void);
void flb_test_file_rotation_path(void);
void flb_test_file_rotation_mkdir(void);
void flb_test_file_rotation_delimiter(void);
void flb_test_file_rotation_label_delimiter(void);
void flb_test_file_rotation_csv_column_names(void);
void flb_test_file_rotation_multithreaded(void);
void flb_test_file_rotation_same_second_rotations(void);
void flb_test_file_rotation_filename_pattern(void);
void flb_test_file_rotation_cleanup_legacy_format(void);
void flb_test_file_rotation_gzip_round_trip(void);
void flb_test_file_rotation_dynamic_destination(void);
void flb_test_file_rotation_fallback_destination(void);
void flb_test_file_rotation_metrics(void);
void flb_test_file_rotation_repeated_flush_all_formats(void);
void flb_test_file_rotation_open_failure_releases_lock(void);

/* Test list */
TEST_LIST = {
    {"basic_rotation", flb_test_file_rotation_basic},
    {"gzip_compression", flb_test_file_rotation_gzip_compression},
    {"gzip_compression_exact_chunk",
     flb_test_file_rotation_gzip_compression_exact_chunk},
    {"max_files_cleanup", flb_test_file_rotation_max_files_cleanup},
    {"max_files_validation", flb_test_file_rotation_max_files_validation},
    {"format_csv", flb_test_file_rotation_format_csv},
    {"format_ltsv", flb_test_file_rotation_format_ltsv},
    {"format_plain", flb_test_file_rotation_format_plain},
    {"format_msgpack", flb_test_file_rotation_format_msgpack},
    {"format_template", flb_test_file_rotation_format_template},
    {"path", flb_test_file_rotation_path},
    {"mkdir", flb_test_file_rotation_mkdir},
    {"delimiter", flb_test_file_rotation_delimiter},
    {"label_delimiter", flb_test_file_rotation_label_delimiter},
    {"csv_column_names", flb_test_file_rotation_csv_column_names},
    {"multithreaded", flb_test_file_rotation_multithreaded},
    {"same_second_rotations", flb_test_file_rotation_same_second_rotations},
    {"filename_pattern", flb_test_file_rotation_filename_pattern},
    {"cleanup_legacy_format", flb_test_file_rotation_cleanup_legacy_format},
    {"gzip_round_trip", flb_test_file_rotation_gzip_round_trip},
    {"dynamic_destination", flb_test_file_rotation_dynamic_destination},
    {"fallback_destination", flb_test_file_rotation_fallback_destination},
    {"metrics_rotation", flb_test_file_rotation_metrics},
    {"repeated_flush_all_formats",
     flb_test_file_rotation_repeated_flush_all_formats},
    {"open_failure_releases_lock",
     flb_test_file_rotation_open_failure_releases_lock},
    {NULL, NULL}};

#define TEST_LOGFILE "flb_test_file_rotation.log"
#define TEST_LOGPATH "out_file_rotation"
#define TEST_FLUSH_INTERVAL "0.2"
#define TEST_POLL_INTERVAL_MS 50
#define TEST_TIMEOUT_MS 10000

#define JSON_DYNAMIC_A "[1448403340, {\"stream\":\"alpha\", \"message\":\"a\"}]"
#define JSON_DYNAMIC_B "[1448403340, {\"stream\":\"beta\", \"message\":\"b\"}]"

/* Helper function to recursively delete directory and all its contents */
static int recursive_delete_directory(const char *dir_path)
{
#ifdef FLB_SYSTEM_WINDOWS
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char search_path[PATH_MAX];
    char file_path[PATH_MAX];
    int ret = 0;

    if (dir_path == NULL) {
        return -1;
    }

    /* Create search path: dir_path\* */
    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);
    search_path[sizeof(search_path) - 1] = '\0';

    hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        /* Directory doesn't exist or can't be opened, consider it success */
        return 0;
    }

    do {
        /* Skip . and .. */
        if (strcmp(ffd.cFileName, ".") == 0 ||
            strcmp(ffd.cFileName, "..") == 0) {
            continue;
        }

        /* Build full path */
        snprintf(file_path, sizeof(file_path), "%s\\%s", dir_path,
                 ffd.cFileName);
        file_path[sizeof(file_path) - 1] = '\0';

        /* Recursively delete subdirectories */
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (recursive_delete_directory(file_path) != 0) {
                ret = -1;
            }
        }
        else {
            /* Delete file - clear read-only if needed */
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
                SetFileAttributesA(file_path, ffd.dwFileAttributes &
                                                  ~FILE_ATTRIBUTE_READONLY);
            }
            if (DeleteFileA(file_path) == 0) {
                ret = -1;
            }
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);

    /* Remove the directory itself */
    if (RemoveDirectoryA(dir_path) == 0) {
        ret = -1;
    }

    return ret;
#else
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char path[PATH_MAX];
    int ret = 0;

    if (dir_path == NULL) {
        return -1;
    }

    /* Check if directory exists */
    if (stat(dir_path, &statbuf) != 0) {
        /* Directory doesn't exist, consider it success */
        return 0;
    }

    /* Check if it's actually a directory */
    if (!S_ISDIR(statbuf.st_mode)) {
        /* Not a directory, try to remove as file */
        return remove(dir_path);
    }

    /* Open directory */
    dir = opendir(dir_path);
    if (dir == NULL) {
        return -1;
    }

    /* Iterate through directory entries */
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build full path */
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        /* Get file status */
        if (stat(path, &statbuf) != 0) {
            continue;
        }

        /* Recursively delete subdirectories */
        if (S_ISDIR(statbuf.st_mode)) {
            if (recursive_delete_directory(path) != 0) {
                ret = -1;
            }
        }
        else {
            /* Delete file */
            if (unlink(path) != 0) {
                ret = -1;
            }
        }
    }

    closedir(dir);

    /* Remove the directory itself */
    if (flb_test_rmdir(dir_path) != 0) {
        ret = -1;
    }

    return ret;
#endif
}

/* Helper function to count files in directory */
#ifdef FLB_SYSTEM_WINDOWS
static int count_files_in_directory(const char *dir_path, const char *prefix)
{
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char search_path[PATH_MAX];
    int count = 0;

    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);
    hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return -1;
    }

    do {
        if (strncmp(ffd.cFileName, prefix, strlen(prefix)) == 0) {
            count++;
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
    return count;
}
#else
static int count_files_in_directory(const char *dir_path, const char *prefix)
{
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    dir = opendir(dir_path);
    if (dir == NULL) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) {
            count++;
        }
    }

    closedir(dir);
    return count;
}
#endif

static int wait_for_output_counter(flb_ctx_t *ctx, struct cmt_counter *counter,
                                   double minimum_value)
{
    int ret;
    int elapsed_time;
    double value;
    char *labels[1];
    struct flb_output_instance *ins;

    if (ctx == NULL || counter == NULL) {
        return -1;
    }

    ins = mk_list_entry_first(&ctx->config->outputs,
                              struct flb_output_instance, _head);
    labels[0] = (char *) flb_output_name(ins);

    for (elapsed_time = 0; elapsed_time < TEST_TIMEOUT_MS;
         elapsed_time += TEST_POLL_INTERVAL_MS) {
        ret = cmt_counter_get_val(counter, 1, labels, &value);
        if (ret == 0 && value >= minimum_value) {
            return 0;
        }

        flb_time_msleep(TEST_POLL_INTERVAL_MS);
    }

    return -1;
}

static int wait_for_output_errors(flb_ctx_t *ctx, double minimum_errors)
{
    struct flb_output_instance *ins;

    if (ctx == NULL || mk_list_is_empty(&ctx->config->outputs) == 0) {
        return -1;
    }

    ins = mk_list_entry_first(&ctx->config->outputs,
                              struct flb_output_instance, _head);

    return wait_for_output_counter(ctx, ins->cmt_errors, minimum_errors);
}

static int wait_for_output_records(flb_ctx_t *ctx, double minimum_records)
{
    struct flb_output_instance *ins;

    if (ctx == NULL || mk_list_is_empty(&ctx->config->outputs) == 0) {
        return -1;
    }

    ins = mk_list_entry_first(&ctx->config->outputs,
                              struct flb_output_instance, _head);

    return wait_for_output_counter(ctx, ins->cmt_proc_records,
                                   minimum_records);
}

/*
 * Helper function: wait for a file matching "prefix*suffix" to appear in
 * dir_path. Returns 1 on match and 0 on timeout. An empty suffix matches any
 * suffix.
 */
#ifdef FLB_SYSTEM_WINDOWS
static int wait_for_file_pattern(const char *dir_path, const char *prefix,
                                 const char *suffix, int time_limit_ms)
{
    int elapsed_time;
    int found = 0;
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char search_path[PATH_MAX];
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    size_t name_len;

    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);

    for (elapsed_time = 0; elapsed_time < time_limit_ms && !found;
         elapsed_time += TEST_POLL_INTERVAL_MS) {
        hFind = FindFirstFileA(search_path, &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                name_len = strlen(ffd.cFileName);
                if (strncmp(ffd.cFileName, prefix, prefix_len) == 0 &&
                    name_len > prefix_len + suffix_len &&
                    (suffix_len == 0 ||
                     strcmp(ffd.cFileName + name_len - suffix_len,
                            suffix) == 0)) {
                    found = 1;
                    break;
                }
            } while (FindNextFileA(hFind, &ffd) != 0);
            FindClose(hFind);
        }
        if (!found) {
            flb_time_msleep(TEST_POLL_INTERVAL_MS);
        }
    }
    return found;
}
#else
static int wait_for_file_pattern(const char *dir_path, const char *prefix,
                                 const char *suffix, int time_limit_ms)
{
    int elapsed_time;
    int found = 0;
    DIR *dir;
    struct dirent *entry;
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    size_t name_len;

    for (elapsed_time = 0; elapsed_time < time_limit_ms && !found;
         elapsed_time += TEST_POLL_INTERVAL_MS) {
        dir = opendir(dir_path);
        if (dir) {
            while ((entry = readdir(dir)) != NULL) {
                name_len = strlen(entry->d_name);
                if (strncmp(entry->d_name, prefix, prefix_len) == 0 &&
                    name_len > prefix_len + suffix_len &&
                    (suffix_len == 0 ||
                     strcmp(entry->d_name + name_len - suffix_len,
                            suffix) == 0)) {
                    found = 1;
                    break;
                }
            }
            closedir(dir);
        }
        if (!found) {
            flb_time_msleep(TEST_POLL_INTERVAL_MS);
        }
    }
    return found;
}
#endif

/*
 * Helper function: find a file matching "prefix*suffix" and copy its full
 * path into 'out_path'. Returns 1 on success and 0 otherwise. An empty
 * suffix matches any suffix.
 */
#ifdef FLB_SYSTEM_WINDOWS
static int find_file_pattern(const char *dir_path, const char *prefix,
                             const char *suffix, char *out_path,
                             size_t out_path_size)
{
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char search_path[PATH_MAX];
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    size_t name_len;
    int found = 0;

    if (!dir_path || !prefix || !suffix || !out_path || out_path_size == 0) {
        return 0;
    }

    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);
    hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        name_len = strlen(ffd.cFileName);
        if (strncmp(ffd.cFileName, prefix, prefix_len) == 0 &&
            name_len > prefix_len + suffix_len &&
            (suffix_len == 0 ||
             strcmp(ffd.cFileName + name_len - suffix_len, suffix) == 0)) {
            snprintf(out_path, out_path_size, "%s\\%s", dir_path,
                     ffd.cFileName);
            out_path[out_path_size - 1] = '\0';
            found = 1;
            break;
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
    return found;
}
#else
static int find_file_pattern(const char *dir_path, const char *prefix,
                             const char *suffix, char *out_path,
                             size_t out_path_size)
{
    DIR *dir;
    struct dirent *entry;
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    size_t name_len;

    if (!dir_path || !prefix || !suffix || !out_path || out_path_size == 0) {
        return 0;
    }

    dir = opendir(dir_path);
    if (dir == NULL) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        name_len = strlen(entry->d_name);
        if (strncmp(entry->d_name, prefix, prefix_len) == 0 &&
            name_len > prefix_len + suffix_len &&
            (suffix_len == 0 ||
             strcmp(entry->d_name + name_len - suffix_len, suffix) == 0)) {
            snprintf(out_path, out_path_size, "%s/%s", dir_path,
                     entry->d_name);
            out_path[out_path_size - 1] = '\0';
            closedir(dir);
            return 1;
        }
    }

    closedir(dir);
    return 0;
}
#endif

/* Helper function: wait for a file to exist and have a minimum size */
static int wait_for_file_size(const char *path, size_t min_size,
                              int time_limit_ms)
{
    int elapsed_time;
    struct stat st;

    for (elapsed_time = 0; elapsed_time < time_limit_ms;
         elapsed_time += TEST_POLL_INTERVAL_MS) {
        if (stat(path, &st) == 0 && st.st_size >= min_size) {
            return 0;
        }
        flb_time_msleep(TEST_POLL_INTERVAL_MS);
    }
    return -1;
}

static int wait_for_file_size_and_output_records(flb_ctx_t *ctx,
                                                 const char *path,
                                                 size_t minimum_size,
                                                 double minimum_records)
{
    if (wait_for_file_size(path, minimum_size, TEST_TIMEOUT_MS) != 0) {
        return -1;
    }

    return wait_for_output_records(ctx, minimum_records);
}

static int wait_for_file_growth(const char *path, size_t previous_size,
                                int time_limit_ms)
{
    int elapsed_time;
    struct stat st;

    for (elapsed_time = 0; elapsed_time < time_limit_ms;
         elapsed_time += TEST_POLL_INTERVAL_MS) {
        if (stat(path, &st) == 0 && st.st_size > previous_size) {
            return 0;
        }
        flb_time_msleep(TEST_POLL_INTERVAL_MS);
    }

    return -1;
}

static int wait_for_file_count_at_least(const char *dir_path,
                                        const char *prefix,
                                        int minimum_count,
                                        int time_limit_ms)
{
    int count;
    int elapsed_time;

    for (elapsed_time = 0; elapsed_time < time_limit_ms;
         elapsed_time += TEST_POLL_INTERVAL_MS) {
        count = count_files_in_directory(dir_path, prefix);
        if (count >= minimum_count) {
            return 0;
        }
        flb_time_msleep(TEST_POLL_INTERVAL_MS);
    }

    return -1;
}

static int wait_for_file_count_at_most(const char *dir_path,
                                       const char *prefix,
                                       int maximum_count,
                                       int time_limit_ms)
{
    int count;
    int elapsed_time;

    for (elapsed_time = 0; elapsed_time < time_limit_ms;
         elapsed_time += TEST_POLL_INTERVAL_MS) {
        count = count_files_in_directory(dir_path, prefix);
        if (count >= 0 && count <= maximum_count) {
            return 0;
        }
        flb_time_msleep(TEST_POLL_INTERVAL_MS);
    }

    return -1;
}

/* Helper function to read file content into buffer */
static char *read_file_content(const char *filename, size_t *out_size)
{
    FILE *fp;
    char *buffer;
    struct stat st;
    size_t size;

    if (stat(filename, &st) != 0) {
        return NULL;
    }

    size = st.st_size;
    fp = fopen(filename, "rb");
    if (!fp) {
        return NULL;
    }

    buffer = flb_malloc(size + 1);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }

    if (fread(buffer, 1, size, fp) != size) {
        flb_free(buffer);
        fclose(fp);
        return NULL;
    }

    buffer[size] = '\0';
    fclose(fp);
    *out_size = size;
    return buffer;
}

static const char *test_basename(const char *path)
{
    const char *p;

    p = strrchr(path, '/');
#ifdef FLB_SYSTEM_WINDOWS
    {
        const char *p2 = strrchr(path, '\\');

        if (p2 != NULL && (p == NULL || p2 > p)) {
            p = p2;
        }
    }
#endif
    return (p != NULL) ? (p + 1) : path;
}

/* New rotation suffix: YYYYMMDD_HHMMSS + '_' + 8 lowercase hex digits */
static int new_rotation_suffix_valid(const char *suf)
{
    int i;

    if (strlen(suf) != 24) {
        return 0;
    }
    for (i = 0; i < 8; i++) {
        if (suf[i] < '0' || suf[i] > '9') {
            return 0;
        }
    }
    if (suf[8] != '_') {
        return 0;
    }
    for (i = 9; i < 15; i++) {
        if (suf[i] < '0' || suf[i] > '9') {
            return 0;
        }
    }
    if (suf[15] != '_') {
        return 0;
    }
    for (i = 16; i < 24; i++) {
        if (!((suf[i] >= '0' && suf[i] <= '9') ||
              (suf[i] >= 'a' && suf[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/*
 * Decompress a possibly multi-member gzip file into a newly allocated buffer.
 * Returns the buffer on success and NULL on failure; the caller frees it with
 * flb_free().
 */
static char *decompress_gzip_file(const char *path, size_t *out_size)
{
    char *raw;
    char *acc = NULL;
    char *tmp;
    void *member = NULL;
    size_t raw_size = 0;
    size_t member_size = 0;
    size_t remaining;
    size_t next_remaining;
    size_t acc_size = 0;
    unsigned char *cursor;

    raw = read_file_content(path, &raw_size);
    if (raw == NULL) {
        return NULL;
    }

    cursor = (unsigned char *) raw;
    remaining = raw_size;

    while (remaining > 0) {
        if (flb_gzip_uncompress_multi(cursor, remaining, &member,
                                      &member_size, &next_remaining) != 0) {
            flb_free(acc);
            flb_free(raw);
            return NULL;
        }

        tmp = flb_realloc(acc, acc_size + member_size + 1);
        if (tmp == NULL) {
            flb_free(member);
            flb_free(acc);
            flb_free(raw);
            return NULL;
        }
        acc = tmp;
        memcpy(acc + acc_size, member, member_size);
        acc_size += member_size;
        acc[acc_size] = '\0';
        flb_free(member);

        cursor += (remaining - next_remaining);
        remaining = next_remaining;
    }

    flb_free(raw);
    *out_size = acc_size;

    return acc;
}

void flb_test_file_rotation_basic(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char rotated[PATH_MAX];

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test",
                               "file", logfile,
                               "rotate", "true",
                               "rotate_max_size", "1",
                               "rotate_max_files", "3",
                               "rotate_gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Two flush cycles: the first creates the file, the second rotates it. */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", "",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(wait_for_output_records(ctx, 6) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* A rotated file is the base name plus '.' and the generated suffix. */
    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", "",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(find_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", "",
                                 rotated, sizeof(rotated)) == 1);

    recursive_delete_directory(TEST_LOGPATH);
}

/* Format Tests */
void flb_test_file_rotation_format_csv(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char *content;
    size_t content_size;

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_csv.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "csv", "rotate", "true",
                               "rotate_max_size", "100M", "rotate_gzip",
                               "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify CSV format - should contain commas as delimiters */
    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        /* CSV should contain commas */
        TEST_CHECK(strstr(content, ",") != NULL);
        /* CSV should contain timestamp */
        TEST_CHECK(strstr(content, "1448403340") != NULL);
        flb_free(content);
    }

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_format_ltsv(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char *content;
    size_t content_size;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_ltsv.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "ltsv", "rotate", "true",
                               "rotate_max_size", "100M", "rotate_gzip",
                               "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        TEST_CHECK(strstr(content, ":") != NULL);
        TEST_CHECK(strstr(content, "time") != NULL);
        flb_free(content);
    }

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_format_plain(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char *content;
    size_t content_size;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_plain.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "plain", "rotate", "true",
                               "rotate_max_size", "100M", "rotate_gzip",
                               "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        TEST_CHECK(strstr(content, "{") != NULL);
        TEST_CHECK(strstr(content, "test: [") == NULL);
        flb_free(content);
    }

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_format_msgpack(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    char logfile[512];
    struct stat st;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_msgpack.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "msgpack", "rotate", "true",
                               "rotate_max_size", "100M", "rotate_gzip",
                               "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    if (stat(logfile, &st) == 0) {
        TEST_CHECK(st.st_size > 0);
        fp = fopen(logfile, "rb");
        if (fp) {
            unsigned char first_bytes[10];
            size_t read_bytes = fread(first_bytes, 1, 10, fp);
            fclose(fp);
            if (read_bytes > 0) {
                TEST_CHECK(first_bytes[0] != '{' && first_bytes[0] != '[');
            }
        }
    }

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_format_template(void)
{
    int i;
    int ret;
    int bytes;
    const char *json_template = "[1448403340, {\"message\": \"test log "
                                "entry\", \"level\": \"info\"}]";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char *content;
    size_t content_size;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_template.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "template", "template",
                               "{time} {message}", "rotate", "true",
                               "rotate_max_size", "100M", "rotate_gzip",
                               "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, (char *)json_template,
                             strlen(json_template));
        TEST_CHECK(bytes == strlen(json_template));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        TEST_CHECK(strstr(content, "test log entry") != NULL);
        TEST_CHECK(strstr(content, "1448403340") != NULL ||
                   strstr(content, ".") != NULL);
        flb_free(content);
    }

    recursive_delete_directory(TEST_LOGPATH);
}

/* Configuration Option Tests */
void flb_test_file_rotation_path(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    char logfile[PATH_MAX];
    char test_path[PATH_MAX];

    snprintf(test_path, sizeof(test_path), "%s" PATH_SEPARATOR "path_test",
             TEST_LOGPATH);
    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "path_test.log",
             test_path);
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "path", test_path,
                               "file", "path_test.log", "mkdir", "true",
                               "rotate", "true", "rotate_max_size", "100M",
                               "rotate_gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(logfile, "r");
    TEST_CHECK(fp != NULL);
    if (fp) {
        fclose(fp);
    }

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_mkdir(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    char logfile[PATH_MAX];
    char nested_path[PATH_MAX];
    struct stat st;

    snprintf(nested_path, sizeof(nested_path),
             "%s" PATH_SEPARATOR "nested" PATH_SEPARATOR "deep" PATH_SEPARATOR
             "path",
             TEST_LOGPATH);
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "test_mkdir.log",
             nested_path);
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

    recursive_delete_directory(TEST_LOGPATH);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "mkdir", "true", "rotate", "true",
                               "rotate_max_size", "100M", "rotate_gzip",
                               "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(stat(nested_path, &st) == 0);
    TEST_CHECK(S_ISDIR(st.st_mode));

    fp = fopen(logfile, "r");
    TEST_CHECK(fp != NULL);
    if (fp) {
        fclose(fp);
    }

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_delimiter(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char *content;
    size_t content_size;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_delimiter.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "csv", "delimiter", "tab",
                               "rotate", "true", "rotate_max_size", "100M",
                               "rotate_gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        int has_tab = 0;
        int j;
        for (j = 0; j < content_size; j++) {
            if (content[j] == '\t') {
                has_tab = 1;
                break;
            }
        }
        TEST_CHECK(has_tab);
        flb_free(content);
    }

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_label_delimiter(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char *content;
    size_t content_size;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_label_delimiter.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "ltsv", "label_delimiter", "comma",
                               "rotate", "true", "rotate_max_size", "100M",
                               "rotate_gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        TEST_CHECK(strstr(content, ",") != NULL);
        TEST_CHECK(strstr(content, "\"time\",") != NULL);
        flb_free(content);
    }

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_csv_column_names(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char *content;
    size_t content_size;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_csv_columns.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "csv", "csv_column_names", "true",
                               "rotate", "true", "rotate_max_size", "100M",
                               "rotate_gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        TEST_CHECK(strstr(content, "timestamp") != NULL);
        TEST_CHECK(strstr(content, "key_0") != NULL);
        flb_free(content);
    }

    recursive_delete_directory(TEST_LOGPATH);
}

/* Multithreaded Test */
struct thread_data {
    flb_ctx_t *ctx;
    int in_ffd;
    int thread_id;
    int events_per_thread;
    char *json_data;
    size_t json_len;
    int *success;
    pthread_mutex_t *mutex;
};

static void *thread_worker(void *arg)
{
    struct thread_data *data = (struct thread_data *)arg;
    int i;
    int bytes;

    for (i = 0; i < data->events_per_thread; i++) {
        bytes = flb_lib_push(data->ctx, data->in_ffd, data->json_data,
                             data->json_len);
        if (bytes != (int)data->json_len) {
            pthread_mutex_lock(data->mutex);
            *data->success = 0;
            pthread_mutex_unlock(data->mutex);
            return NULL;
        }
        flb_time_msleep(10);
    }

    return NULL;
}

void flb_test_file_rotation_multithreaded(void)
{
    int ret;
    int i;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    pthread_t threads[8];
    struct thread_data thread_data[8];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    int success = 1;
    int num_threads = 4;
    int events_per_thread = 10;
    FILE *fp;
    char *content;
    size_t content_size;
    int line_count = 0;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_multithreaded.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "2", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "rotate", "true", "rotate_max_size", "1M",
                               "rotate_max_files", "5", "rotate_gzip", "false",
                               NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < num_threads; i++) {
        thread_data[i].ctx = ctx;
        thread_data[i].in_ffd = in_ffd;
        thread_data[i].thread_id = i;
        thread_data[i].events_per_thread = events_per_thread;
        thread_data[i].json_data = p;
        thread_data[i].json_len = strlen(p);
        thread_data[i].success = &success;
        thread_data[i].mutex = &mutex;
    }

    for (i = 0; i < num_threads; i++) {
        ret = pthread_create(&threads[i], NULL, thread_worker, &thread_data[i]);
        TEST_CHECK(ret == 0);
    }

    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    ret = wait_for_file_size(logfile, 100 * 1024, TEST_TIMEOUT_MS);
    TEST_CHECK(ret == 0);
    TEST_CHECK(wait_for_output_records(ctx,
                                       num_threads * events_per_thread) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(success == 1);

    fp = fopen(logfile, "r");
    TEST_CHECK(fp != NULL);
    if (fp) {
        char line[4096];
        while (fgets(line, sizeof(line), fp) != NULL) {
            line_count++;
        }
        fclose(fp);
    }

    TEST_CHECK(line_count >= num_threads * events_per_thread);

    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        TEST_CHECK(strstr(content, "test") != NULL);
        TEST_CHECK(strstr(content, "1448403340") != NULL);
        int key_count = 0;
        char *pos = content;
        while ((pos = strstr(pos, "key_0")) != NULL) {
            key_count++;
            pos++;
        }
        TEST_CHECK(key_count >= num_threads * events_per_thread);
        flb_free(content);
    }

    pthread_mutex_destroy(&mutex);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_same_second_rotations(void)
{
    int i;
    int ret;
    int bytes;
    int rotated_count;
    char *p = (char *)JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    static const char rotated_prefix[] = "flb_test_file_rotation.log.";

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "rotate", "true", "rotate_max_size", "5K",
                               "rotate_max_files", "10", "rotate_gzip", "false",
                               NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    ret = wait_for_file_size(logfile, 10 * 1024, TEST_TIMEOUT_MS);
    TEST_CHECK(ret == 0);
    TEST_CHECK(wait_for_output_records(ctx, 4) == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_count_at_least(TEST_LOGPATH, rotated_prefix, 1,
                                            TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(wait_for_output_records(ctx, 8) == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_count_at_least(TEST_LOGPATH, rotated_prefix, 2,
                                            TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(wait_for_output_records(ctx, 12) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    rotated_count = count_files_in_directory(TEST_LOGPATH, rotated_prefix);
    TEST_ASSERT(rotated_count >= 0);
    TEST_CHECK(rotated_count >= 2);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_filename_pattern(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char rotated_path[PATH_MAX];
    const char *base;
    const char *tail;
    char suf[32];

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "rotate", "true", "rotate_max_size", "5K",
                               "rotate_max_files", "5", "rotate_gzip", "false",
                               NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    ret = wait_for_file_size(logfile, 10 * 1024, TEST_TIMEOUT_MS);
    TEST_CHECK(ret == 0);
    TEST_CHECK(wait_for_output_records(ctx, 4) == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", "",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(wait_for_output_records(ctx, 8) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    ret = find_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", "",
                            rotated_path, sizeof(rotated_path));
    TEST_CHECK(ret == 1);

    base = test_basename(rotated_path);
    tail = strstr(base, TEST_LOGFILE ".");
    TEST_CHECK(tail != NULL);
    strncpy(suf, tail + strlen(TEST_LOGFILE) + 1, sizeof(suf) - 1);
    suf[sizeof(suf) - 1] = '\0';
    TEST_CHECK(new_rotation_suffix_valid(suf));

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_cleanup_legacy_format(void)
{
    int i;
    int ret;
    int bytes;
    int file_count;
    char *p = (char *)JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *lfp;
    char logfile[512];
    char legacy_path[PATH_MAX];
    static const char *legacy_sfx[] = {"20200101_000001", "20200101_000002",
                                         "20200101_000003"};

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);

    for (i = 0; i < 3; i++) {
        snprintf(legacy_path, sizeof(legacy_path), "%s" PATH_SEPARATOR "%s.%s",
                 TEST_LOGPATH, TEST_LOGFILE, legacy_sfx[i]);
        lfp = fopen(legacy_path, "wb");
        TEST_CHECK(lfp != NULL);
        if (lfp) {
            fclose(lfp);
        }
    }

    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "rotate", "true", "rotate_max_size", "5K",
                               "rotate_max_files", "2", "rotate_gzip", "false",
                               NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    ret = wait_for_file_size(logfile, 10 * 1024, TEST_TIMEOUT_MS);
    TEST_CHECK(ret == 0);
    TEST_CHECK(wait_for_output_records(ctx, 4) == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_count_at_most(TEST_LOGPATH, TEST_LOGFILE, 3,
                                           TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(wait_for_output_records(ctx, 8) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    file_count = count_files_in_directory(TEST_LOGPATH, TEST_LOGFILE);
    TEST_ASSERT(file_count >= 0);
    /* One active log plus two rotated artifacts retained */
    TEST_CHECK(file_count == 3);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_gzip_compression(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char gz_file[PATH_MAX];
    unsigned char header[10];
    FILE *fp;
    unsigned int mtime;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "rotate", "true", "rotate_max_size", "5K",
                               "rotate_max_files", "3", "rotate_gzip", "true",
                               NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    ret = wait_for_file_size(logfile, 10 * 1024, TEST_TIMEOUT_MS);
    TEST_CHECK(ret == 0);
    TEST_CHECK(wait_for_output_records(ctx, 4) == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", ".gz",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(wait_for_output_records(ctx, 8) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    ret = wait_for_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".",
                                ".gz", TEST_TIMEOUT_MS);
    TEST_CHECK(ret == 1);
    if (ret == 1) {
        ret = find_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".",
                                ".gz", gz_file, sizeof(gz_file));
        TEST_CHECK(ret == 1);

        if (ret == 1) {
            fp = fopen(gz_file, "rb");
            TEST_CHECK(fp != NULL);
            if (fp != NULL) {
                TEST_CHECK(fread(header, 1, sizeof(header), fp) == sizeof(header));
                fclose(fp);

                /*
                 * Validate gzip magic. flb_gzip_compress() emits an all-zero
                 * MTIME field, which is a valid "unknown" per RFC 1952; the
                 * gzip_round_trip test provides the content-level check.
                 */
                TEST_CHECK(header[0] == 0x1F);
                TEST_CHECK(header[1] == 0x8B);
                mtime = (unsigned int)header[4] |
                        ((unsigned int)header[5] << 8) |
                        ((unsigned int)header[6] << 16) |
                        ((unsigned int)header[7] << 24);
                (void) mtime;
            }
        }
    }

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_max_files_cleanup(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    int file_count;
    char logfile[512];
    char rotated_path[PATH_MAX];
    static const char *rotation_suffixes[] = {
        "20200101_000001_00000001", "20200101_000002_00000002",
        "20200101_000003_00000003", "20200101_000004_00000004"
    };

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    /* Start above the retention limit so one rotation must remove artifacts. */
    for (i = 0; i < 4; i++) {
        snprintf(rotated_path, sizeof(rotated_path),
                 "%s" PATH_SEPARATOR "%s.%s", TEST_LOGPATH, TEST_LOGFILE,
                 rotation_suffixes[i]);
        fp = fopen(rotated_path, "wb");
        TEST_ASSERT(fp != NULL);
        fclose(fp);
    }

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "rotate", "true", "rotate_max_size", "5K",
                               "rotate_max_files", "3", "rotate_gzip", "false",
                               NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile,
                                                     10 * 1024, 4) == 0);

    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_file_count_at_most(TEST_LOGPATH, TEST_LOGFILE, 4,
                                           TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(wait_for_output_records(ctx, 8) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    file_count = count_files_in_directory(TEST_LOGPATH, TEST_LOGFILE);
    TEST_ASSERT(file_count >= 0);
    TEST_CHECK(file_count <= 4);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_max_files_validation(void)
{
    flb_ctx_t *ctx;
    int out_ffd;
    char logfile[512];

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "off", NULL) == 0);

    /* Test with rotate_max_files = 0 */
    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "rotate", "true", "rotate_max_files", "0",
                               NULL) == 0);

    TEST_CHECK(flb_start(ctx) == -1);

    flb_destroy(ctx);

    /* Test with rotate_max_files = -1 */
    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "off", NULL) == 0);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "rotate", "true", "rotate_max_files", "-1",
                               NULL) == 0);

    TEST_CHECK(flb_start(ctx) == -1);

    flb_destroy(ctx);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_gzip_compression_exact_chunk(void)
{
    int ret;
    int bytes;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char *large_message;
    char *json_payload;
    char *small_payload;
    size_t msg_size = 64 * 1024; /* 64KB exact chunk size */
    size_t json_size;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "template", "template", "{message}",
                               "rotate", "true", "rotate_max_size", "64K",
                               "rotate_max_files", "3", "rotate_gzip", "true",
                               NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    large_message = flb_malloc(msg_size + 1);
    TEST_CHECK(large_message != NULL);
    memset(large_message, 'A', msg_size);
    large_message[msg_size] = '\0';

    json_size = msg_size + 100;
    json_payload = flb_malloc(json_size);
    TEST_CHECK(json_payload != NULL);

    snprintf(json_payload, json_size, "[%lld, {\"message\": \"%s\"}]",
             (long long) time(NULL), large_message);

    bytes = flb_lib_push(ctx, in_ffd, json_payload, strlen(json_payload));
    TEST_CHECK(bytes == strlen(json_payload));

    flb_free(large_message);
    flb_free(json_payload);

    TEST_CHECK(wait_for_file_size(logfile, msg_size, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(wait_for_output_records(ctx, 1) == 0);

    small_payload = "[1234567890, {\"message\": \"trigger\"}]";
    bytes = flb_lib_push(ctx, in_ffd, small_payload, strlen(small_payload));
    TEST_CHECK(bytes == strlen(small_payload));

    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", ".gz",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(wait_for_output_records(ctx, 2) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    ret = wait_for_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".",
                                ".gz", TEST_TIMEOUT_MS);
    TEST_CHECK(ret == 1);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_gzip_round_trip(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char archive[PATH_MAX];
    char *plain;
    size_t plain_size = 0;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test",
                               "file", logfile,
                               "format", "plain",
                               "rotate", "true",
                               "rotate_max_size", "1",
                               "rotate_max_files", "3",
                               "rotate_gzip", "true", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", ".gz",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(wait_for_output_records(ctx, 6) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", ".gz",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_ASSERT(find_file_pattern(TEST_LOGPATH, TEST_LOGFILE ".", ".gz",
                                  archive, sizeof(archive)) == 1);

    /* The archive must decompress back to the records that were rotated. */
    plain = decompress_gzip_file(archive, &plain_size);
    TEST_ASSERT(plain != NULL);
    TEST_CHECK(plain_size > 0);
    /* JSON_SMALL ends with "END_KEY": "JSON_END", which survives the round trip. */
    TEST_CHECK(strstr(plain, "JSON_END") != NULL);
    flb_free(plain);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_dynamic_destination(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_DYNAMIC_A;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char rotated[PATH_MAX];

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    /*
     * upstream cb_file_init() requires 'fallback_file' whenever the
     * destination is dynamic; supplying it does not affect what rotates.
     */
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test",
                               "path", TEST_LOGPATH,
                               "file", "$stream",
                               "fallback_file", "overflow.log",
                               "rotate", "true",
                               "rotate_max_size", "1",
                               "rotate_max_files", "3",
                               "rotate_gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_file_size(TEST_LOGPATH PATH_SEPARATOR "alpha", 1,
                                  TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(wait_for_output_records(ctx, 3) == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, "alpha.", "",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(wait_for_output_records(ctx, 6) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* The resolved destination 'alpha' must be the file that rotated. */
    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, "alpha.", "",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(find_file_pattern(TEST_LOGPATH, "alpha.", "",
                                 rotated, sizeof(rotated)) == 1);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_fallback_destination(void)
{
    int i;
    int ret;
    int bytes;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char rotated[PATH_MAX];

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test",
                               "path", TEST_LOGPATH,
                               "file", "$stream",
                               "max_dynamic_files", "1",
                               "on_limit_reached", "fallback",
                               "fallback_path", TEST_LOGPATH,
                               "fallback_file", "overflow.log",
                               "rotate", "true",
                               "rotate_max_size", "1",
                               "rotate_max_files", "3",
                               "rotate_gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Two distinct destinations exceed max_dynamic_files of one. */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, (char *) JSON_DYNAMIC_A,
                             strlen(JSON_DYNAMIC_A));
        TEST_CHECK(bytes == strlen(JSON_DYNAMIC_A));
        bytes = flb_lib_push(ctx, in_ffd, (char *) JSON_DYNAMIC_B,
                             strlen(JSON_DYNAMIC_B));
        TEST_CHECK(bytes == strlen(JSON_DYNAMIC_B));
    }
    TEST_CHECK(wait_for_file_size(TEST_LOGPATH PATH_SEPARATOR "overflow.log", 1,
                                  TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(wait_for_output_records(ctx, 6) == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, (char *) JSON_DYNAMIC_B,
                             strlen(JSON_DYNAMIC_B));
        TEST_CHECK(bytes == strlen(JSON_DYNAMIC_B));
    }
    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, "overflow.log.", "",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(wait_for_output_records(ctx, 9) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* The fallback destination is tracked and rotated like any other. */
    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, "overflow.log.", "",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(find_file_pattern(TEST_LOGPATH, "overflow.log.", "",
                                 rotated, sizeof(rotated)) == 1);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_metrics(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char rotated[PATH_MAX];

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "metrics.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_ASSERT(flb_input_set(ctx, in_ffd, "tag", "metrics",
                              "scrape_interval", "1", NULL) == 0);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "metrics",
                               "file", logfile,
                               "rotate", "true",
                               "rotate_max_size", "1",
                               "rotate_max_files", "3",
                               "rotate_gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    TEST_CHECK(wait_for_file_pattern(TEST_LOGPATH, "metrics.log.", "",
                                     TEST_TIMEOUT_MS) == 1);
    TEST_CHECK(wait_for_output_records(ctx, 2) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(find_file_pattern(TEST_LOGPATH, "metrics.log.", "",
                                 rotated, sizeof(rotated)) == 1);

    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_rotation_repeated_flush_all_formats(void)
{
    int i;
    int f;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    /*
     * upstream cb_file_init() accepts "out_file" (equivalent to json) but
     * rejects an explicit "json" string; use "out_file" for the JSON case.
     */
    const char *formats[] = {"out_file", "csv", "ltsv", "plain", "template",
                             "msgpack"};
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    struct stat first;
    struct stat second;
    struct stat last;

    for (f = 0; f < 6; f++) {
        recursive_delete_directory(TEST_LOGPATH);
        TEST_MKDIR(TEST_LOGPATH);
        snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s.log",
                 TEST_LOGPATH, formats[f]);

        ctx = flb_create();
        TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1",
                                    "Log_Level", "error", NULL) == 0);

        in_ffd = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(in_ffd >= 0);
        flb_input_set(ctx, in_ffd, "tag", "test", NULL);

        out_ffd = flb_output(ctx, (char *) "file", NULL);
        TEST_CHECK(out_ffd >= 0);
        /* A large limit means no rotation; this only exercises the locking. */
        TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test",
                                   "file", logfile,
                                   "format", formats[f],
                                   "rotate", "true",
                                   "rotate_max_size", "100M",
                                   "rotate_max_files", "3",
                                   "rotate_gzip", "false", NULL) == 0);

        ret = flb_start(ctx);
        TEST_CHECK(ret == 0);

        for (i = 0; i < 3; i++) {
            bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
            TEST_CHECK(bytes == strlen(p));
        }
        TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);
        TEST_ASSERT(stat(logfile, &first) == 0);

        for (i = 0; i < 3; i++) {
            bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
            TEST_CHECK(bytes == strlen(p));
        }
        TEST_CHECK(wait_for_file_growth(logfile, first.st_size,
                                        TEST_TIMEOUT_MS) == 0);
        TEST_CHECK(wait_for_output_records(ctx, 6) == 0);
        TEST_ASSERT(stat(logfile, &second) == 0);

        for (i = 0; i < 3; i++) {
            bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
            TEST_CHECK(bytes == strlen(p));
        }
        TEST_CHECK(wait_for_file_growth(logfile, second.st_size,
                                        TEST_TIMEOUT_MS) == 0);
        TEST_CHECK(wait_for_output_records(ctx, 9) == 0);

        flb_stop(ctx);
        flb_destroy(ctx);

        /* Later cycles must have appended, proving the lock was released. */
        TEST_ASSERT(stat(logfile, &last) == 0);
        TEST_CHECK(last.st_size > first.st_size);

        recursive_delete_directory(TEST_LOGPATH);
    }
}

/*
 * A directory placed at the configured file path makes fopen fail. Without a
 * release on that open-failure path, the next flush to the same destination
 * stalls on the held entry lock. Clear the blocker and assert a subsequent
 * flush can write.
 */
void flb_test_file_rotation_open_failure_releases_lock(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    struct stat st;

    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "open_fail.log",
             TEST_LOGPATH);

    /* Occupy the destination path so the first open fails. */
    TEST_MKDIR(logfile);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", TEST_FLUSH_INTERVAL, "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test",
                               "file", logfile,
                               "mkdir", "false",
                               "rotate", "true",
                               "rotate_max_size", "100M",
                               "rotate_max_files", "3",
                               "rotate_gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_output_errors(ctx, 1) == 0);

    /* Path is still a directory: open failed and must have released the lock. */
    TEST_ASSERT(stat(logfile, &st) == 0);
    TEST_CHECK(S_ISDIR(st.st_mode));

#ifdef FLB_SYSTEM_WINDOWS
    TEST_ASSERT(RemoveDirectoryA(logfile) != 0);
#else
    TEST_ASSERT(flb_test_rmdir(logfile) == 0);
#endif

    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    TEST_CHECK(wait_for_file_size_and_output_records(ctx, logfile, 1, 3) == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /*
     * A second flush after clearing the blocker must write a regular file.
     * If the first open left the entry lock held, this would time out /
     * fail instead of creating the log.
     */
    TEST_ASSERT(stat(logfile, &st) == 0);
    TEST_CHECK(S_ISREG(st.st_mode));
    TEST_CHECK(st.st_size > 0);

    recursive_delete_directory(TEST_LOGPATH);
}
