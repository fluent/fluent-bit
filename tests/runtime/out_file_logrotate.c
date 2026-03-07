/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "flb_tests_runtime.h"
#include <fluent-bit.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#ifndef FLB_SYSTEM_WINDOWS
#include <dirent.h>
#include <unistd.h>
#define TEST_MKDIR(path) mkdir(path, 0755)
#define PATH_SEPARATOR "/"
#else
#include <direct.h>
#include <windows.h>
#define TEST_MKDIR(path) _mkdir(path)
#define PATH_SEPARATOR "\\"
/* Windows S_ISDIR compatibility */
#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif
#endif

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */
#include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/common/json_small.h"   /* JSON_SMALL   */

/* Test functions */
void flb_test_file_logrotate_basic_rotation(void);
void flb_test_file_logrotate_gzip_compression(void);
void flb_test_file_logrotate_gzip_compression_exact_chunk(void);
void flb_test_file_logrotate_max_files_cleanup(void);
void flb_test_file_logrotate_max_files_validation(void);
void flb_test_file_logrotate_format_csv(void);
void flb_test_file_logrotate_format_ltsv(void);
void flb_test_file_logrotate_format_plain(void);
void flb_test_file_logrotate_format_msgpack(void);
void flb_test_file_logrotate_format_template(void);
void flb_test_file_logrotate_path(void);
void flb_test_file_logrotate_mkdir(void);
void flb_test_file_logrotate_delimiter(void);
void flb_test_file_logrotate_label_delimiter(void);
void flb_test_file_logrotate_csv_column_names(void);
void flb_test_file_logrotate_multithreaded(void);

/* Test list */
TEST_LIST = {
    {"basic_rotation", flb_test_file_logrotate_basic_rotation},
    {"gzip_compression", flb_test_file_logrotate_gzip_compression},
    {"gzip_compression_exact_chunk",
     flb_test_file_logrotate_gzip_compression_exact_chunk},
    {"max_files_cleanup", flb_test_file_logrotate_max_files_cleanup},
    {"max_files_validation", flb_test_file_logrotate_max_files_validation},
    {"logrotate_format_csv", flb_test_file_logrotate_format_csv},
    {"logrotate_format_ltsv", flb_test_file_logrotate_format_ltsv},
    {"logrotate_format_plain", flb_test_file_logrotate_format_plain},
    {"logrotate_format_msgpack", flb_test_file_logrotate_format_msgpack},
    {"logrotate_format_template", flb_test_file_logrotate_format_template},
    {"logrotate_path", flb_test_file_logrotate_path},
    {"logrotate_mkdir", flb_test_file_logrotate_mkdir},
    {"logrotate_delimiter", flb_test_file_logrotate_delimiter},
    {"logrotate_label_delimiter", flb_test_file_logrotate_label_delimiter},
    {"logrotate_csv_column_names", flb_test_file_logrotate_csv_column_names},
    {"logrotate_multithreaded", flb_test_file_logrotate_multithreaded},
    {NULL, NULL}};

#define TEST_LOGFILE "flb_test_file_logrotate.log"
#define TEST_LOGPATH "out_logrotate"
#define TEST_TIMEOUT 10

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
    if (rmdir(dir_path) != 0) {
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

/*
 * Helper function: Wait for a file matching the pattern "prefix*suffix" to
 * appear in dir_path
 */
#ifdef FLB_SYSTEM_WINDOWS
static int wait_for_file_pattern(const char *dir_path, const char *prefix,
                                 const char *suffix, int time_limit)
{
    int elapsed_time, found = 0;
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char search_path[PATH_MAX];
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);

    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);

    for (elapsed_time = 0; elapsed_time < time_limit && !found;
         elapsed_time++) {
        hFind = FindFirstFileA(search_path, &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strncmp(ffd.cFileName, prefix, prefix_len) == 0 &&
                    strlen(ffd.cFileName) > prefix_len + suffix_len &&
                    strcmp(ffd.cFileName + strlen(ffd.cFileName) - suffix_len,
                           suffix) == 0) {
                    found = 1;
                    break;
                }
            } while (FindNextFileA(hFind, &ffd) != 0);
            FindClose(hFind);
        }
        if (!found) {
            flb_time_msleep(1000);
        }
    }
    return found ? 0 : -1;
}
#else
static int wait_for_file_pattern(const char *dir_path, const char *prefix,
                                 const char *suffix, int time_limit)
{
    int elapsed_time, found = 0;
    DIR *dir;
    struct dirent *entry;
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);

    for (elapsed_time = 0; elapsed_time < time_limit && !found;
         elapsed_time++) {
        dir = opendir(dir_path);
        if (dir) {
            while ((entry = readdir(dir)) != NULL) {
                if (strncmp(entry->d_name, prefix, prefix_len) == 0 &&
                    strlen(entry->d_name) > prefix_len + suffix_len &&
                    strcmp(entry->d_name + strlen(entry->d_name) - suffix_len,
                           suffix) == 0) {
                    found = 1;
                    break;
                }
            }
            closedir(dir);
        }
        if (!found) {
            flb_time_msleep(1000);
        }
    }
    return found ? 0 : -1;
}
#endif

/* Helper function to find a file matching "prefix*suffix" and return its path */
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
    int found = 0;

    if (!dir_path || !prefix || !suffix || !out_path || out_path_size == 0) {
        return -1;
    }

    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);
    hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return -1;
    }

    do {
        if (strncmp(ffd.cFileName, prefix, prefix_len) == 0 &&
            strlen(ffd.cFileName) > prefix_len + suffix_len &&
            strcmp(ffd.cFileName + strlen(ffd.cFileName) - suffix_len,
                   suffix) == 0) {
            snprintf(out_path, out_path_size, "%s\\%s", dir_path, ffd.cFileName);
            out_path[out_path_size - 1] = '\0';
            found = 1;
            break;
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
    return found ? 0 : -1;
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

    if (!dir_path || !prefix || !suffix || !out_path || out_path_size == 0) {
        return -1;
    }

    dir = opendir(dir_path);
    if (dir == NULL) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, prefix_len) == 0 &&
            strlen(entry->d_name) > prefix_len + suffix_len &&
            strcmp(entry->d_name + strlen(entry->d_name) - suffix_len,
                   suffix) == 0) {
            snprintf(out_path, out_path_size, "%s/%s", dir_path, entry->d_name);
            out_path[out_path_size - 1] = '\0';
            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
    return -1;
}
#endif

/* Helper function: Wait for a file to exist and have a minimum size */
static int wait_for_file_size(const char *path, size_t min_size, int time_limit)
{
    int elapsed_time;
    struct stat st;

    for (elapsed_time = 0; elapsed_time < time_limit; elapsed_time++) {
        if (stat(path, &st) == 0 && st.st_size >= min_size) {
            return 0;
        }
        flb_time_msleep(1000);
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

/* Format Tests */
void flb_test_file_logrotate_format_csv(void)
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
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "csv", "files_rotation", "true",
                               "max_size", "100M", "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500);

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

void flb_test_file_logrotate_format_ltsv(void)
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
             "test_ltsv.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "ltsv", "files_rotation", "true",
                               "max_size", "100M", "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify LTSV format - should contain colons (label delimiter) and tabs */
    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        /* LTSV should contain colons for label:value pairs */
        TEST_CHECK(strstr(content, ":") != NULL);
        /* Should contain "time" label */
        TEST_CHECK(strstr(content, "time") != NULL);
        flb_free(content);
    }

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_logrotate_format_plain(void)
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
             "test_plain.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "plain", "files_rotation", "true",
                               "max_size", "100M", "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify plain format - should be JSON without tag/timestamp prefix */
    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        /* Plain format should contain JSON */
        TEST_CHECK(strstr(content, "{") != NULL);
        /* Should not contain tag prefix like "test: [" */
        TEST_CHECK(strstr(content, "test: [") == NULL);
        flb_free(content);
    }

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_logrotate_format_msgpack(void)
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

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_msgpack.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "msgpack", "files_rotation", "true",
                               "max_size", "100M", "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify msgpack format - should be binary data */
    if (stat(logfile, &st) == 0) {
        TEST_CHECK(st.st_size > 0);
        /* Msgpack files should not be readable as text (no newlines in first
         * bytes)
         */
        fp = fopen(logfile, "rb");
        if (fp) {
            unsigned char first_bytes[10];
            size_t read_bytes = fread(first_bytes, 1, 10, fp);
            fclose(fp);
            if (read_bytes > 0) {
                /*
                 * Msgpack typically starts with array markers (0x91, 0x92,
                 * etc.) or map markers. Just verify it's not plain text JSON.
                 */
                TEST_CHECK(first_bytes[0] != '{' && first_bytes[0] != '[');
            }
        }
    }

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_logrotate_format_template(void)
{
    int i;
    int ret;
    int bytes;
    /* Use JSON with specific fields for template testing */
    const char *json_template = "[1448403340, {\"message\": \"test log "
                                "entry\", \"level\": \"info\"}]";
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
             "test_template.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "template", "template",
                               "{time} {message}", "files_rotation", "true",
                               "max_size", "100M", "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, (char *)json_template,
                             strlen(json_template));
        TEST_CHECK(bytes == strlen(json_template));
    }

    flb_time_msleep(1500);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify template format - should contain substituted values */
    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        /* Template should contain the message value */
        TEST_CHECK(strstr(content, "test log entry") != NULL);
        /* Should contain timestamp (as float) */
        TEST_CHECK(strstr(content, "1448403340") != NULL ||
                   strstr(content, ".") != NULL);
        flb_free(content);
    }

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

/* Configuration Option Tests */
void flb_test_file_logrotate_path(void)
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
/* Construct logfile path - test_path is short so this is safe */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "path_test.log",
             test_path);
#pragma GCC diagnostic pop

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "path", test_path,
                               "file", "path_test.log", "mkdir", "true",
                               "files_rotation", "true", "max_size", "100M",
                               "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify file was created in the specified path */
    fp = fopen(logfile, "r");
    TEST_CHECK(fp != NULL);
    if (fp) {
        fclose(fp);
    }

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_logrotate_mkdir(void)
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
/* Construct logfile path - nested_path is short so this is safe */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "test_mkdir.log",
             nested_path);
#pragma GCC diagnostic pop

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "mkdir", "true", "files_rotation", "true",
                               "max_size", "100M", "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify nested directory was created */
    TEST_CHECK(stat(nested_path, &st) == 0);
    TEST_CHECK(S_ISDIR(st.st_mode));

    /* Verify file was created */
    fp = fopen(logfile, "r");
    TEST_CHECK(fp != NULL);
    if (fp) {
        fclose(fp);
    }

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_logrotate_delimiter(void)
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
             "test_delimiter.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "csv", "delimiter", "tab",
                               "files_rotation", "true", "max_size", "100M",
                               "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify tab delimiter is used (should contain tabs, not
     * commas) */
    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        /* Should contain tab characters */
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

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_logrotate_label_delimiter(void)
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
             "test_label_delimiter.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "ltsv", "label_delimiter", "comma",
                               "files_rotation", "true", "max_size", "100M",
                               "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify custom label delimiter is used */
    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        /* Should contain "," as label delimiter (comma) */
        TEST_CHECK(strstr(content, ",") != NULL);
        /* Should contain "time" label with comma delimiter */
        /* LTSV format prints "time" (with quotes) followed by
         * delimiter */
        TEST_CHECK(strstr(content, "\"time\",") != NULL);
        flb_free(content);
    }

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_logrotate_csv_column_names(void)
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
             "test_csv_columns.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "csv", "csv_column_names", "true",
                               "files_rotation", "true", "max_size", "100M",
                               "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write some data */
    for (i = 0; i < 3; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify CSV column names header exists */
    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        /* First line should contain "timestamp" */
        TEST_CHECK(strstr(content, "timestamp") != NULL);
        /* Should contain key names from JSON */
        TEST_CHECK(strstr(content, "key_0") != NULL);
        flb_free(content);
    }

    /* Clean up directory and all contents */
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
        /* Small delay to allow interleaving */
        flb_time_msleep(10);
    }

    return NULL;
}

void flb_test_file_logrotate_multithreaded(void)
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

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             "test_multithreaded.log");

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "0.5", "Grace", "2", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "files_rotation", "true", "max_size", "1M",
                               "max_files", "5", "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Prepare thread data */
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

    /* Create and start threads */
    for (i = 0; i < num_threads; i++) {
        ret = pthread_create(&threads[i], NULL, thread_worker, &thread_data[i]);
        TEST_CHECK(ret == 0);
    }

    /* Wait for all threads to complete */
    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Wait for flush to complete - allow multiple flush cycles */
    flb_time_msleep(3000);

    /* Wait for file to exist and have content before stopping */
    ret = wait_for_file_size(logfile, 100 * 1024, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Verify all data was written correctly */
    TEST_CHECK(success == 1);

    /* Verify file exists and has content */
    fp = fopen(logfile, "r");
    TEST_CHECK(fp != NULL);
    if (fp) {
        char line[4096];
        while (fgets(line, sizeof(line), fp) != NULL) {
            line_count++;
        }
        fclose(fp);
    }

    /* Should have at least num_threads * events_per_thread records
     */
    /* (may be more due to JSON format adding tag prefix) */
    TEST_CHECK(line_count >= num_threads * events_per_thread);

    /* Verify file content is valid - read and check for expected
     * data */
    content = read_file_content(logfile, &content_size);
    TEST_CHECK(content != NULL);
    if (content) {
        /* Should contain tag */
        TEST_CHECK(strstr(content, "test") != NULL);
        /* Should contain timestamp */
        TEST_CHECK(strstr(content, "1448403340") != NULL);
        /* Count occurrences of key_0 to verify records */
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

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
};

void flb_test_file_logrotate_basic_rotation(void)
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
    time_t now = time(NULL);
    struct tm tm_info;
    char timestamp[32];

    localtime_r(&now, &tm_info);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", &tm_info);

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "files_rotation", "true", "max_size", "5K",
                               "max_files", "3", "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write enough data to fill the file (JSON_SMALL is ~4KB, 4 events = ~16KB)
     */
    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    /* Wait for file to be created */
    ret = wait_for_file_size(logfile, 10 * 1024, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    /* Wait a bit more to ensure flush completes and file size is
     * updated */
    flb_time_msleep(1500);

    /* Write additional data to trigger rotation (4 more events =
     * ~16KB more) */
    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that the original file exists */
    fp = fopen(logfile, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
    }

    /* Check that at least one rotated file exists:
     * flb_test_file_logrotate.log.*"
     */
    TEST_CHECK(count_files_in_directory(TEST_LOGPATH,
                                        "flb_test_file_logrotate.log.") >= 1);

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
};

void flb_test_file_logrotate_gzip_compression(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char gz_file[PATH_MAX];
    unsigned char header[10];
    FILE *fp;
    unsigned int mtime;

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "files_rotation", "true", "max_size", "5K",
                               "max_files", "3", "gzip", "true", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write enough data for rotation to happen (JSON_SMALL is
     * ~4KB) */
    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    /* Wait for file to be created */
    ret = wait_for_file_size(logfile, 10 * 1024, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    /* Write enough data to trigger rotation (JSON_SMALL is ~4KB) */
    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(2000); /* waiting flush and rotation/compression */

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that a gzipped rotated file exists:
     * flb_test_file_logrotate.log.*.gz
     */
    ret = wait_for_file_pattern(TEST_LOGPATH, "flb_test_file_logrotate.log.",
                                ".gz", TEST_TIMEOUT);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        ret = find_file_pattern(TEST_LOGPATH, "flb_test_file_logrotate.log.",
                                ".gz", gz_file, sizeof(gz_file));
        TEST_CHECK(ret == 0);

        if (ret == 0) {
            fp = fopen(gz_file, "rb");
            TEST_CHECK(fp != NULL);
            if (fp != NULL) {
                TEST_CHECK(fread(header, 1, sizeof(header), fp) == sizeof(header));
                fclose(fp);

                /* Validate gzip magic and a non-zero MTIME field. */
                TEST_CHECK(header[0] == 0x1F);
                TEST_CHECK(header[1] == 0x8B);
                mtime = (unsigned int)header[4] |
                        ((unsigned int)header[5] << 8) |
                        ((unsigned int)header[6] << 16) |
                        ((unsigned int)header[7] << 24);
                TEST_CHECK(mtime != 0);
            }
        }
    }

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
};

void flb_test_file_logrotate_max_files_cleanup(void)
{
    int i, j;
    int ret;
    int bytes;
    char *p = (char *)JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int file_count;
    char logfile[512];

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "files_rotation", "true", "max_size", "5K",
                               "max_files", "3", "gzip", "false", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write enough data to trigger multiple rotations */
    for (i = 0; i < 5; i++) { /* Write enough data (5 * 4 * ~4KB = ~80KB) to
                                 trigger multiple rotations (max_size=5K) */
        /* Write enough data for rotation to happen (JSON_SMALL is ~4KB) */
        for (j = 0; j < 4; j++) {
            bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
            TEST_CHECK(bytes == strlen(p));
        }

        flb_time_msleep(1500); /* waiting flush */

        file_count = count_files_in_directory(TEST_LOGPATH, TEST_LOGFILE);
        TEST_ASSERT(file_count >= 0);
        TEST_CHECK(file_count <= 4);
    }

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that only Max_Files + 1 files exist (current + rotated)
     */
    file_count = count_files_in_directory(TEST_LOGPATH, TEST_LOGFILE);
    TEST_ASSERT(file_count >= 0);
    TEST_CHECK(file_count <=
               4); /* Current file + 3 rotated files (max_files=3) */

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_logrotate_max_files_validation(void)
{
    flb_ctx_t *ctx;
    int out_ffd;
    char logfile[512];

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "off", NULL) == 0);

    /* Test with max_files = 0 */
    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "files_rotation", "true", "max_files", "0",
                               NULL) == 0);

    /* Start should fail */
    TEST_CHECK(flb_start(ctx) == -1);

    flb_destroy(ctx);

    /* Test with max_files = -1 */
    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "off", NULL) == 0);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "files_rotation", "true", "max_files", "-1",
                               NULL) == 0);

    /* Start should fail */
    TEST_CHECK(flb_start(ctx) == -1);

    flb_destroy(ctx);

    /* Clean up directory */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_file_logrotate_gzip_compression_exact_chunk(void)
{
    int ret;
    int bytes;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    char *large_message;
    char *json_payload;
    size_t msg_size = 64 * 1024; /* 64KB exact chunk size */
    size_t json_size;

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    TEST_MKDIR(TEST_LOGPATH);
    snprintf(logfile, sizeof(logfile), "%s" PATH_SEPARATOR "%s", TEST_LOGPATH,
             TEST_LOGFILE);

    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level",
                                "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"file", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "test", "file", logfile,
                               "format", "template", "template", "{message}",
                               "files_rotation", "true", "max_size", "64K",
                               "max_files", "3", "gzip", "true", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Prepare 64KB message */
    large_message = flb_malloc(msg_size + 1);
    TEST_CHECK(large_message != NULL);
    memset(large_message, 'A', msg_size);
    large_message[msg_size] = '\0';

    /* Create JSON payload: [timestamp, {"message": "..."}] */
    /* Estimate size: msg_size + overhead */
    json_size = msg_size + 100;
    json_payload = flb_malloc(json_size);
    TEST_CHECK(json_payload != NULL);

    snprintf(json_payload, json_size, "[%lu, {\"message\": \"%s\"}]",
             time(NULL), large_message);

    /* Write exactly 64KB of data (the message content) */
    bytes = flb_lib_push(ctx, in_ffd, json_payload, strlen(json_payload));
    TEST_CHECK(bytes == strlen(json_payload));

    flb_free(large_message);
    flb_free(json_payload);

    /* Wait for flush and file creation */
    flb_time_msleep(1500);

    /* Trigger rotation by writing one more small record */
    char *small_payload = "[1234567890, {\"message\": \"trigger\"}]";
    bytes = flb_lib_push(ctx, in_ffd, small_payload, strlen(small_payload));
    TEST_CHECK(bytes == strlen(small_payload));

    flb_time_msleep(2000); /* waiting flush and rotation/compression */

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that a gzipped rotated file exists */
    ret = wait_for_file_pattern(TEST_LOGPATH, "flb_test_file_logrotate.log.",
                                ".gz", TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}
