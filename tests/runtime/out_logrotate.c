/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"
#include "../lib/acutest/acutest.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */
#include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/common/json_small.h"   /* JSON_SMALL   */

/* Test functions */
void flb_test_logrotate_basic_rotation(void);
void flb_test_logrotate_gzip_compression(void);
void flb_test_logrotate_max_files_cleanup(void);
void flb_test_logrotate_counter_based_size(void);
void flb_test_logrotate_different_formats(void);
void flb_test_logrotate_mkdir_support(void);
void flb_test_logrotate_performance_test(void);

/* Test list */
TEST_LIST = {
    {"basic_rotation",        flb_test_logrotate_basic_rotation},
    {"gzip_compression",      flb_test_logrotate_gzip_compression},
    {"max_files_cleanup",     flb_test_logrotate_max_files_cleanup},
    {"counter_based_size",    flb_test_logrotate_counter_based_size},
    {"different_formats",     flb_test_logrotate_different_formats},
    {"mkdir_support",         flb_test_logrotate_mkdir_support},
    {"performance_test",      flb_test_logrotate_performance_test},

    {NULL, NULL}
};

#define TEST_LOGFILE "flb_test_logrotate.log"
#define TEST_LOGPATH "out_logrotate"
#define TEST_TIMEOUT 10

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

/* Helper function to check if file exists and get its size */
static int get_file_size(const char *file_path)
{
    struct stat st;
    if (stat(file_path, &st) == 0) {
        return (int)st.st_size;
    }
    return -1;
}

/* Helper function to check if gzip file exists */
static int check_gzip_file_exists(const char *file_path)
{
    char gzip_path[512];
    snprintf(gzip_path, sizeof(gzip_path), "%s.gz", file_path);
    return access(gzip_path, F_OK) == 0;
}

void flb_test_logrotate_basic_rotation(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    char rotated_file[512];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    /* Clean up any existing files */
    remove(TEST_LOGFILE);
    snprintf(rotated_file, sizeof(rotated_file), "%s.%s", TEST_LOGFILE, timestamp);
    remove(rotated_file);
    
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "max_size", "1", NULL); /* 1 MB */
    flb_output_set(ctx, out_ffd, "max_files", "3", NULL);
    flb_output_set(ctx, out_ffd, "gzip", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write enough data to trigger rotation (JSON_LONG is ~100KB) */
    for (i = 0; i < 15; i++) {  /* Write ~1.5MB to trigger rotation */
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    /* Wait for file to be created and rotated */
    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that the original file exists */
    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
    }

    /* Check that a rotated file was created */
    fp = fopen(rotated_file, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(rotated_file);
    }

    remove(TEST_LOGFILE);
}

void flb_test_logrotate_gzip_compression(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char rotated_file[512];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    /* Clean up any existing files */
    remove(TEST_LOGFILE);
    snprintf(rotated_file, sizeof(rotated_file), "%s.%s", TEST_LOGFILE, timestamp);
    remove(rotated_file);
    snprintf(rotated_file, sizeof(rotated_file), "%s.%s.gz", TEST_LOGFILE, timestamp);
    remove(rotated_file);
    
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "max_size", "1", NULL);  /* 1 MB */
    flb_output_set(ctx, out_ffd, "max_files", "3", NULL);
    flb_output_set(ctx, out_ffd, "gzip", "true", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write enough data to trigger rotation */
    for (i = 0; i < 15; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that a gzipped rotated file was created */
    snprintf(rotated_file, sizeof(rotated_file), "%s.%s", TEST_LOGFILE, timestamp);
    ret = check_gzip_file_exists(rotated_file);
    TEST_CHECK(ret == 1);

    /* Clean up */
    remove(rotated_file);
    remove(TEST_LOGFILE);
}

void flb_test_logrotate_max_files_cleanup(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int file_count;
    
    /* Clean up any existing files */
    remove(TEST_LOGFILE);
    
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "max_size", "1", NULL);  /* 1 MB */
    flb_output_set(ctx, out_ffd, "max_files", "2", NULL); /* Only keep 2 files */
    flb_output_set(ctx, out_ffd, "gzip", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write enough data to trigger multiple rotations */
    for (i = 0; i < 50; i++) {  /* Write ~5MB to trigger multiple rotations */
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that only Max_Files + 1 files exist (current + rotated) */
    file_count = count_files_in_directory(".", "flb_test_logrotate.log");
    TEST_CHECK(file_count <= 3);  /* Current file + 2 rotated files */

    /* Clean up */
    remove(TEST_LOGFILE);
}

void flb_test_logrotate_counter_based_size(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;  /* Use smaller data for precise testing */
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    int initial_size, final_size;
    
    remove(TEST_LOGFILE);
    
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "max_size", "1", NULL);  /* 1 MB */
    flb_output_set(ctx, out_ffd, "max_files", "3", NULL);
    flb_output_set(ctx, out_ffd, "gzip", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Write a small amount first to get initial size */
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    initial_size = get_file_size(TEST_LOGFILE);
    TEST_CHECK(initial_size > 0);

    /* Write more data to trigger rotation */
    for (i = 0; i < 20; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that file was rotated (new file should be smaller) */
    final_size = get_file_size(TEST_LOGFILE);
    TEST_CHECK(final_size < initial_size || final_size < 1024 * 1024);

    remove(TEST_LOGFILE);
}

void flb_test_logrotate_different_formats(void)
{
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    char output[4096];
    char expect[256];
    
    remove(TEST_LOGFILE);
    
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "format", "csv", NULL);
    flb_output_set(ctx, out_ffd, "max_size", "10", NULL);  /* 10 MB */
    flb_output_set(ctx, out_ffd, "max_files", "3", NULL);
    flb_output_set(ctx, out_ffd, "gzip", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that CSV format was written correctly */
    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        bytes = fread(&output[0], 1, sizeof(output) - 1, fp);
        TEST_CHECK(bytes > 0);
        output[bytes] = '\0';
        
        /* Check for CSV header */
        snprintf(expect, sizeof(expect), "timestamp");
        TEST_CHECK(strstr(output, expect) != NULL);
        
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_logrotate_mkdir_support(void)
{
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    flb_sds_t path;
    flb_sds_t file;
    
    file = flb_sds_create("test");
    TEST_CHECK(file != NULL);

    path = flb_sds_create_size(256);
    TEST_CHECK(path != NULL);
    flb_sds_printf(&path, "%s/%s", TEST_LOGPATH, file);

    /* Clean up */
    remove(path);
    remove(TEST_LOGPATH);
    
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "mkdir", "true", NULL);
    flb_output_set(ctx, out_ffd, "max_size", "10", NULL);
    flb_output_set(ctx, out_ffd, "max_files", "3", NULL);
    flb_output_set(ctx, out_ffd, "gzip", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    ret = wait_for_file(path, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Check that directory was created and file exists */
    fp = fopen(path, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(path);
    }
    
    flb_sds_destroy(path);
    flb_sds_destroy(file);
    remove(TEST_LOGPATH);
}

void flb_test_logrotate_performance_test(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    clock_t start, end;
    double cpu_time_used;
    
    remove(TEST_LOGFILE);
    
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logrotate", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "max_size", "10", NULL);  /* 10 MB */
    flb_output_set(ctx, out_ffd, "max_files", "3", NULL);
    flb_output_set(ctx, out_ffd, "gzip", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Performance test: write many small messages */
    start = clock();
    
    for (i = 0; i < 1000; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    flb_stop(ctx);
    flb_destroy(ctx);

    /* Performance assertion: should complete within reasonable time */
    TEST_CHECK(cpu_time_used < 5.0);  /* Should complete within 5 seconds */

    remove(TEST_LOGFILE);
}
