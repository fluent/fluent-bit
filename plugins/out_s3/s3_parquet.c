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

#include <fluent-bit/flb_output_plugin.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <msgpack.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <Shlobj.h>
#endif

#include "s3.h"
#include "s3_store.h"
#include "s3_parquet.h"

static int build_columnify_command(struct flb_s3 *ctx,
                                   char *infile,
                                   char *outfile,
                                   flb_sds_t *cmd_buf)
{
    int ret = -1;
    int result;
    flb_sds_t tmp = NULL;
    flb_sds_t amount_page = NULL;
    flb_sds_t amount_row_group = NULL;

    amount_page = flb_sds_create_size(16);
    if (amount_page == NULL) {
        goto error;
    }

    amount_row_group = flb_sds_create_size(16);
    if (amount_row_group == NULL) {
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              DEFAULT_PARQUET_COMMAND, strlen(DEFAULT_PARQUET_COMMAND));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              " -parquetCompressionCodec ", 26);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              ctx->parquet_compression,
                              flb_sds_len(ctx->parquet_compression));
    if (result < 0) {
        ret = -1;
        goto error;
    }


    result = flb_sds_cat_safe(cmd_buf,
                              " -parquetPageSize ", 18);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    tmp = flb_sds_printf(&amount_page, "%zu", ctx->parquet_page_size);
    if (!tmp) {
        flb_errno();
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              amount_page, strlen(amount_page));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              " -parquetRowGroupSize ", 22);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    tmp = flb_sds_printf(&amount_row_group, "%zu", ctx->parquet_row_group_size);
    if (!tmp) {
        flb_errno();
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              amount_row_group, strlen(amount_row_group));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              " -recordType ", 13);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              ctx->parquet_record_type,
                              flb_sds_len(ctx->parquet_record_type));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              " -schemaType ", 13);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              ctx->parquet_schema_type,
                              flb_sds_len(ctx->parquet_schema_type));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              " -schemaFile ", 13);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              ctx->parquet_schema_file,
                              flb_sds_len(ctx->parquet_schema_file));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              " -output ", 9);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf,
                              outfile, strlen(outfile));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf, " ", 1);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(cmd_buf, infile, strlen(infile));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    flb_sds_destroy(amount_page);
    flb_sds_destroy(amount_row_group);

    return 0;

error:
    if (amount_page != NULL) {
        flb_sds_destroy(amount_page);
    }
    if (amount_row_group != NULL) {
        flb_sds_destroy(amount_row_group);
    }

    return ret;
}

static int s3_is_dir(const char *dir)
{
    int ret;
    struct stat st;

    if (!dir) {
        errno = EINVAL;
        return -1;
    }

    if (strlen(dir) == 0) {
        errno = EINVAL;
        return -1;
    }

    ret = stat(dir, &st);
    if (ret == -1) {
        return -1;
    }

    if (st.st_mode & S_IFDIR) {
        return 0;
    }

    errno = EINVAL;

    return -1;
}

static int s3_mkdir(struct flb_s3 *ctx, const char *dir, mode_t mode)
{
    struct stat st;
    char *dup_dir = NULL;
#ifdef FLB_SYSTEM_WINDOWS
    char path[PATH_MAX];
#endif
#ifdef FLB_SYSTEM_MACOS
    char *parent_dir = NULL;
#endif

    int ret;

    if (!stat(dir, &st)) {
        return 0;
    }

#ifdef FLB_SYSTEM_WINDOWS
    (void) mode;

    if (_fullpath(path, dir, MAX_PATH) == NULL) {
        return -1;
    }

    if (SHCreateDirectoryExA(NULL, path, NULL) != ERROR_SUCCESS) {
        return -1;
    }

    return 0;
#elif FLB_SYSTEM_MACOS
    dup_dir = strdup(dir);
    if (!dup_dir) {
        return -1;
    }

    /* macOS's dirname(3) should return current directory when slash
     * charachter is not included in passed string.
     * And note that macOS's dirname(3) does not modify passed string.
     */
    parent_dir = dirname(dup_dir);
    if (stat(parent_dir, &st) == 0 && strncmp(parent_dir, ".", 1)) {
        if (S_ISDIR (st.st_mode)) {
            flb_plg_debug(ctx->ins, "creating directory %s", dup_dir);
            ret = mkdir(dup_dir, mode);
            free(dup_dir);
            return ret;
        }
    }

    ret = s3_mkdir(ctx, dirname(dup_dir), mode);
    if (ret != 0) {
        free(dup_dir);
        return ret;
    }
    flb_plg_debug(ctx->ins, "creating directory %s", dup_dir);
    ret = mkdir(dup_dir, mode);
    free(dup_dir);
    return ret;
#else
    dup_dir = strdup(dir);
    if (!dup_dir) {
        return -1;
    }
    ret = s3_mkdir(ctx, dirname(dup_dir), mode);
    free(dup_dir);
    if (ret != 0) {
        return ret;
    }
    flb_plg_debug(ctx->ins, "creating directory %s", dir);
    return mkdir(dir, mode);
#endif
}


#if defined(FLB_SYSTEM_WINDOWS)
static flb_sds_t create_parquest_processing_dir(struct flb_s3 *ctx)
{
    int ret = 0;
    DWORD bytes;
    BOOL result = FALSE;
    flb_sds_t path_buf = NULL;
    TCHAR work_dir[MAX_PATH];
    TCHAR tmp_path[MAX_PATH];

    path_buf = flb_sds_create_size(PATH_MAX);
    if (path_buf == NULL) {
        goto error;
    }

    bytes = GetTempPathA(MAX_PATH,
                         tmp_path);
    if (bytes > MAX_PATH || bytes == 0) {
        flb_plg_error(ctx->ins, "GetTempPath failed");
        ret = GetLastError();
        goto error;
    }

    result = flb_sds_cat_safe(&path_buf, tmp_path, strlen(tmp_path));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(&path_buf, ctx->parquet_process_dir,
                              flb_sds_len(ctx->parquet_process_dir));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    ret = s3_is_dir(path_buf);
    if (ret == -1) {
        flb_plg_debug(ctx->ins, "creating process dir %s.", ctx->parquet_process_dir);
        if (s3_mkdir(ctx, ctx->parquet_process_dir, 0755) == -1) {
            flb_plg_error(ctx->ins, "ensuring existence of process dir %s is failed.",
                          ctx->parquet_process_dir);
            goto error;
        }
    }

    return path_buf;

error:
    if (path_buf != NULL) {
        flb_sds_destroy(path_buf);
    }

    return NULL;
}

int flb_s3_parquet_compress(struct flb_s3 *ctx,
                            char *body, size_t body_size,
                            void **payload_buf, size_t *payload_size)
{
    int ret = 0;
    char *template_in_prefix = "body";
    char *template_out_prefix = "parquet";
    HANDLE wh = NULL;
    HANDLE rh = NULL;
    BOOL result = FALSE;
    flb_sds_t parquet_cmd = NULL;
    DWORD bytes;
    FILE *cmdp = NULL;
    size_t parquet_size = 0;
    struct stat stbuf;
    int fdout = -1;
    flb_sds_t parquet_buf;
    TCHAR tmp_path[MAX_PATH];
    flb_sds_t path_buf = NULL;
    TCHAR in_temp_file[MAX_PATH];
    TCHAR out_temp_file[MAX_PATH];

    parquet_cmd = flb_sds_create_size(256);
    if (parquet_cmd == NULL) {
        goto error;
    }

    path_buf = create_parquest_processing_dir(ctx);
    if (path_buf == NULL) {
        flb_plg_error(ctx->ins, "create processing parquet directory failed");
        ret = GetLastError();
        goto error;
    }

    bytes = GetTempFileNameA(path_buf,
                             TEXT(template_in_prefix),
                             0, /* create unique name only */
                             in_temp_file);
    if (bytes == 0) {
        flb_plg_error(ctx->ins, "GetFileName failed");
        ret = GetLastError();
        goto error;
    }

    bytes = GetTempFileNameA(path_buf,
                             TEXT(template_out_prefix),
                             0, /* create unique name only */
                             out_temp_file);
    if (bytes == 0) {
        flb_plg_error(ctx->ins, "GetFileName failed");
        ret = GetLastError();
        goto error;
    }

    wh = CreateFileA((LPTSTR)in_temp_file,
                     GENERIC_WRITE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL,
                     CREATE_ALWAYS,
                     0,
                     NULL);
    if (wh == INVALID_HANDLE_VALUE) {
        ret = -3;
        goto error;
    }

    rh = CreateFileA((LPTSTR)out_temp_file,
                     GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL,
                     CREATE_ALWAYS,
                     0,
                     NULL);
    if (rh == INVALID_HANDLE_VALUE) {
        ret = -4;
        goto error;
    }

    fdout = _open_osfhandle((intptr_t) rh, _O_RDONLY);
    if (fdout == -1) {
        ret = -3;
        goto error;
    }

    result = WriteFile(wh, body, body_size, &bytes, NULL);
    if (!result) {
        ret = -5;
        goto error;
    }
    CloseHandle(wh);

    ret = build_columnify_command(ctx, in_temp_file, out_temp_file, &parquet_cmd);
    if (ret != 0) {
        ret = -1;
        goto error;
    }

    cmdp = _popen(parquet_cmd, "r");
    if (cmdp == NULL) {
        flb_plg_error(ctx->ins, "command %s failed", DEFAULT_PARQUET_COMMAND_CHECK);
        return -1;
    }
    _pclose(cmdp);

    if (fstat(fdout, &stbuf) == -1) {
        ret = -6;
        goto error;
    }
    parquet_size = stbuf.st_size;
    parquet_buf = flb_sds_create_size(parquet_size);

    result = ReadFile(rh, parquet_buf, parquet_size, &bytes, NULL);
    if (!result) {
        ret = -5;
        goto error;
    }

    CloseHandle(rh);

    if (!DeleteFileA((LPTSTR)in_temp_file)) {
        ret = -6;
        flb_plg_error(ctx->ins, "DeleteFileA for %s failed", (LPTSTR)in_temp_file);
    }
    if (!DeleteFileA((LPTSTR)out_temp_file)) {
        ret = -6;
        flb_plg_error(ctx->ins, "DeleteFileA for %s failed", (LPTSTR)out_temp_file);
    }

    *payload_buf = parquet_buf;
    *payload_size = parquet_size;

    flb_sds_destroy(parquet_cmd);
    flb_sds_destroy(path_buf);

    return 0;

error:
    if (wh != NULL) {
        CloseHandle(wh);
        DeleteFileA((LPTSTR)in_temp_file);
    }
    if (rh != NULL) {
        CloseHandle(rh);
        DeleteFileA((LPTSTR)out_temp_file);
    }
    if (parquet_cmd != NULL) {
        flb_sds_destroy(parquet_cmd);
    }
    if (parquet_buf != NULL) {
        flb_sds_destroy(parquet_buf);
    }
    if (path_buf != NULL) {
        flb_sds_destroy(path_buf);
    }

    return ret;
}

#else
static int create_tmpfile(struct flb_s3 *ctx, char *file_path, char *template, size_t template_len)
{
    int ret;
    int result;
    flb_sds_t path_buf;
    const char *process_dir;
    size_t process_dir_len;

    path_buf = flb_sds_create_size(PATH_MAX);
    if (path_buf == NULL) {
        goto error;
    }

    ret = s3_is_dir(ctx->parquet_process_dir);
    if (ret == -1) {
        flb_plg_debug(ctx->ins, "creating process dir %s.", ctx->parquet_process_dir);
        if (s3_mkdir(ctx, ctx->parquet_process_dir, 0755) == -1) {
            flb_plg_error(ctx->ins, "ensuring existence of process dir %s is failed.",
                          ctx->parquet_process_dir);
            goto error;
        }
    }

    process_dir = ctx->parquet_process_dir;
    process_dir_len = flb_sds_len(ctx->parquet_process_dir);

    result = flb_sds_cat_safe(&path_buf, process_dir, process_dir_len);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(&path_buf, "/", 1);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = flb_sds_cat_safe(&path_buf, template, template_len);
    if (result < 0) {
        ret = -1;
        goto error;
    }

    strncpy(file_path, path_buf, flb_sds_len(path_buf));
    if (mkstemp(file_path) == -1) {
        flb_errno();
        ret = -2;
        goto error;
    }

    flb_sds_destroy(path_buf);

    return 0;

error:
    if (path_buf != NULL) {
        flb_sds_destroy(path_buf);
    }

    return ret;
}

int flb_s3_parquet_compress(struct flb_s3 *ctx,
                            char *body, size_t body_size,
                            void **payload_buf, size_t *payload_size)
{
    int ret = 0;
    int result;
    char *template_in_suffix = "out_s3-body-XXXXXX";
    char *template_out_suffix = "out_s3-parquet-XXXXXX";
    char infile[PATH_MAX] = {0};
    char outfile[PATH_MAX] = {0};
    FILE *write_ptr = NULL;
    FILE *read_ptr = NULL;
    flb_sds_t parquet_cmd = NULL;
    size_t bytes;
    FILE *cmdp = NULL;
    size_t parquet_size = 0;
    struct stat stbuf;
    int fdout = -1;
    flb_sds_t parquet_buf;

    parquet_cmd = flb_sds_create_size(256);
    if (parquet_cmd == NULL) {
        goto error;
    }

    result = create_tmpfile(ctx, infile, template_in_suffix, strlen(template_in_suffix));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    result = create_tmpfile(ctx, outfile, template_out_suffix, strlen(template_out_suffix));
    if (result < 0) {
        ret = -1;
        goto error;
    }

    write_ptr = fopen(infile, "wb");
    if (write_ptr == NULL) {
        ret = -3;
        goto error;
    }

    read_ptr = fopen(outfile, "rb");
    if (read_ptr == NULL) {
        ret = -4;
        goto error;
    }

    fdout = fileno(read_ptr);
    if (fdout == -1) {
        ret = -3;
        goto error;
    }

    bytes = fwrite(body, body_size, 1, write_ptr);
    if (bytes == -1) {
        ret = -5;
        goto error;
    }
    fclose(write_ptr);

    ret = build_columnify_command(ctx, infile, outfile, &parquet_cmd);
    if (ret != 0) {
        ret = -1;
        goto error;
    }

    cmdp = flb_popen(parquet_cmd, "r");
    if (cmdp == NULL) {
        flb_plg_error(ctx->ins, "command %s failed", DEFAULT_PARQUET_COMMAND_CHECK);
        return -1;
    }
    flb_pclose(cmdp);

    if (fstat(fdout, &stbuf) == -1) {
        ret = -6;
        goto error;
    }
    parquet_size = stbuf.st_size;
    parquet_buf = flb_sds_create_size(parquet_size);

    bytes = fread(parquet_buf, parquet_size, 1, read_ptr);
    if (bytes == -1) {
        ret = -5;
        goto error;
    }

    /* Teardown for temporary files */
    unlink(infile);
    unlink(outfile);
    fclose(read_ptr);

    *payload_buf = parquet_buf;
    *payload_size = parquet_size;

    flb_sds_destroy(parquet_cmd);

    return 0;

error:
    if (infile[0] != '\0') {
        unlink(infile);
    }
    if (write_ptr != NULL) {
        fclose(write_ptr);
    }
    if (read_ptr != NULL) {
        unlink(outfile);
        fclose(read_ptr);
    }
    if (parquet_cmd != NULL) {
        flb_sds_destroy(parquet_cmd);
    }
    if (parquet_buf != NULL) {
        flb_sds_destroy(parquet_buf);
    }

    return ret;
}
#endif
