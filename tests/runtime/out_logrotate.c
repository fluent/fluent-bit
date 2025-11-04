/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */
#include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/common/json_small.h"   /* JSON_SMALL   */

/* Test functions */
void flb_test_logrotate_basic_rotation(void);
void flb_test_logrotate_gzip_compression(void);
void flb_test_logrotate_max_files_cleanup(void);

/* Test list */
TEST_LIST = {
    {"basic_rotation",        flb_test_logrotate_basic_rotation},
    {"gzip_compression",      flb_test_logrotate_gzip_compression},
    {"max_files_cleanup",     flb_test_logrotate_max_files_cleanup},
    {NULL, NULL}
};

#define TEST_LOGFILE "flb_test_logrotate.log"
#define TEST_LOGPATH "out_logrotate"
#define TEST_TIMEOUT 10

/* Helper function to recursively delete directory and all its contents */
static int recursive_delete_directory(const char *dir_path)
{
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
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
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
        } else {
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
}

/* Helper function to count files in directory */
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

/* Helper function: Wait for a file matching the pattern "prefix*gz" to appear in dir_path */
static int wait_for_file_pattern(const char *dir_path, const char *prefix, const char *suffix, int time_limit)
{
    int elapsed_time, found = 0;
    DIR *dir;
    struct dirent *entry;
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);

    for (elapsed_time = 0; elapsed_time < time_limit && !found; elapsed_time++) {
        dir = opendir(dir_path);
        if (dir) {
            while ((entry = readdir(dir)) != NULL) {
                if (strncmp(entry->d_name, prefix, prefix_len) == 0 &&
                    strlen(entry->d_name) > prefix_len + suffix_len &&
                    strcmp(entry->d_name + strlen(entry->d_name) - suffix_len, suffix) == 0) {
                    found = 1;
                    break;
                }
            }
            closedir(dir);
        }
        if (!found) {
            sleep(1);
        }
    }
    return found ? 0 : -1;
}

void flb_test_logrotate_basic_rotation(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    char logfile[512];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    mkdir(TEST_LOGPATH, 0755);
    snprintf(logfile, sizeof(logfile), "%s/%s", TEST_LOGPATH, TEST_LOGFILE);
    
    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd,
        "match", "test",
        "file", logfile,
        "max_size", "5K",
        "max_files", "3",
        "gzip", "false",
        NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write enough data to for rotation to happen (JSON_SMALL is >4KB) */
    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    /* Wait for file to be created */
    ret = wait_for_file(logfile, 10*1024, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    /* Write additional data to trigger rotation */
    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }
    
    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that the original file exists */
    fp = fopen(logfile, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
    }

    /* Check that at least one rotated file exists: "flb_test_logrotate.log.*" */
    TEST_CHECK(count_files_in_directory(TEST_LOGPATH, "flb_test_logrotate.log.") >= 1);

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_logrotate_gzip_compression(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char logfile[512];
    
    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    mkdir(TEST_LOGPATH, 0755);
    snprintf(logfile, sizeof(logfile), "%s/%s", TEST_LOGPATH, TEST_LOGFILE);
    
    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd,
        "match", "test",
        "file", logfile,
        "max_size", "5K",
        "max_files", "3",
        "gzip", "true",
        NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write enough data to for rotation to happen (JSON_SMALL is ~4KB) */
    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    /* Wait for file to be created */
    ret = wait_for_file(logfile, 10*1024, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    /* Write enough data to trigger rotation (JSON_SMALL is ~4KB) */
    for (i = 0; i < 4; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that a gzipped rotated file exists: "flb_test_logrotate.log.*.gz" */
    ret = wait_for_file_pattern(TEST_LOGPATH, "flb_test_logrotate.log.", ".gz", TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}

void flb_test_logrotate_max_files_cleanup(void)
{
    int i, j;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int file_count;
    char logfile[512];

    /* Clean up any existing directory and contents */
    recursive_delete_directory(TEST_LOGPATH);
    mkdir(TEST_LOGPATH, 0755);
    snprintf(logfile, sizeof(logfile), "%s/%s", TEST_LOGPATH, TEST_LOGFILE);
    
    ctx = flb_create();
    TEST_ASSERT(flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd,
         "match", "test",
        "file", logfile,
        "max_size", "5K",
        "max_files", "3",
        "gzip", "false",
        NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write enough data to trigger multiple rotations */
    for (i = 0; i < 5; i++) {  /* Write ~5MB to trigger multiple rotations */
        /* Write enough data to for rotation to happen (JSON_SMALL is ~4KB) */
        for (j = 0; j < 4; j++) {
            bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
            TEST_CHECK(bytes == strlen(p));
        }
        sleep(1); /* Wait for flush */
        file_count = count_files_in_directory(TEST_LOGPATH, TEST_LOGFILE);
        TEST_CHECK(file_count <= 4);
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that only Max_Files + 1 files exist (current + rotated) */
    file_count = count_files_in_directory(TEST_LOGPATH, TEST_LOGFILE);
    TEST_CHECK(file_count <= 4);  /* Current file + 2 rotated files */

    /* Clean up directory and all contents */
    recursive_delete_directory(TEST_LOGPATH);
}
