/*
 * Copyright (C) 2023 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_extension.h"
#include "libc_errno.h"
#include "win_util.h"

#include "PathCch.h"

#pragma comment(lib, "Pathcch.lib")

#define CHECK_VALID_HANDLE_WITH_RETURN_VALUE(win_handle, ret)         \
    do {                                                              \
        if ((win_handle) == NULL                                      \
            || ((win_handle)->type == windows_handle_type_socket      \
                && (win_handle)->raw.socket == INVALID_SOCKET)        \
            || ((win_handle)->type == windows_handle_type_file        \
                && (win_handle)->raw.handle == INVALID_HANDLE_VALUE)) \
            return (ret);                                             \
                                                                      \
    } while (0)

#define CHECK_VALID_HANDLE(win_handle) \
    CHECK_VALID_HANDLE_WITH_RETURN_VALUE(win_handle, __WASI_EBADF)

#define CHECK_VALID_FILE_HANDLE(win_handle)                        \
    do {                                                           \
        if ((win_handle) == NULL)                                  \
            return __WASI_EBADF;                                   \
                                                                   \
        if ((win_handle)->type == windows_handle_type_socket)      \
            return __WASI_EINVAL;                                  \
                                                                   \
        if (((win_handle)->type == windows_handle_type_file        \
             && (win_handle)->raw.handle == INVALID_HANDLE_VALUE)) \
            return __WASI_EBADF;                                   \
                                                                   \
    } while (0)

#define CHECK_VALID_WIN_DIR_STREAM(win_dir_stream)         \
    do {                                                   \
        if ((win_dir_stream) == NULL)                      \
            return __WASI_EINVAL;                          \
        CHECK_VALID_FILE_HANDLE((win_dir_stream)->handle); \
    } while (0)

static __wasi_filetype_t
get_disk_filetype(DWORD attribute)
{
    if (attribute == INVALID_FILE_ATTRIBUTES)
        return __WASI_FILETYPE_UNKNOWN;
    if (attribute & FILE_ATTRIBUTE_REPARSE_POINT)
        return __WASI_FILETYPE_SYMBOLIC_LINK;
    if (attribute & FILE_ATTRIBUTE_DIRECTORY)
        return __WASI_FILETYPE_DIRECTORY;

    return __WASI_FILETYPE_REGULAR_FILE;
}

static __wasi_filetype_t
get_socket_filetype(SOCKET socket)
{
    char socket_type = 0;
    int size = sizeof(socket_type);

    if (getsockopt(socket, SOL_SOCKET, SO_TYPE, &socket_type, &size) == 0) {
        switch (socket_type) {
            case SOCK_STREAM:
                return __WASI_FILETYPE_SOCKET_STREAM;
            case SOCK_DGRAM:
                return __WASI_FILETYPE_SOCKET_DGRAM;
        }
    }
    return __WASI_FILETYPE_UNKNOWN;
}

static __wasi_errno_t
convert_windows_filetype(os_file_handle handle, DWORD filetype,
                         __wasi_filetype_t *out_filetype)
{
    __wasi_errno_t error = __WASI_ESUCCESS;

    switch (filetype) {
        case FILE_TYPE_DISK:
            FILE_ATTRIBUTE_TAG_INFO file_info;

            bool success = GetFileInformationByHandleEx(
                handle->raw.handle, FileAttributeTagInfo, &file_info,
                sizeof(file_info));

            if (!success
                || file_info.FileAttributes == INVALID_FILE_ATTRIBUTES) {
                error = convert_windows_error_code(GetLastError());
                break;
            }

            *out_filetype = get_disk_filetype(file_info.FileAttributes);
            break;
        case FILE_TYPE_CHAR:
            *out_filetype = __WASI_FILETYPE_CHARACTER_DEVICE;
            break;
        case FILE_TYPE_PIPE:
            if (handle->type == windows_handle_type_socket)
                *out_filetype = get_socket_filetype(handle->raw.socket);
            else
                *out_filetype = __WASI_FILETYPE_BLOCK_DEVICE;

            break;
        case FILE_TYPE_REMOTE:
        case FILE_TYPE_UNKNOWN:
        default:
            *out_filetype = __WASI_FILETYPE_UNKNOWN;
    }

    return error;
}

// Converts the input string to a wchar string.
static __wasi_errno_t
convert_to_wchar(const char *str, wchar_t *buf, size_t buf_size)
{
    int converted_chars =
        MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, (int)buf_size);

    if (converted_chars == 0)
        return convert_windows_error_code(GetLastError());

    return __WASI_ESUCCESS;
}

// Get the filepath for a handle. The size of the buffer should be specified in
// terms of wchar.
static __wasi_errno_t
get_handle_filepath(HANDLE handle, wchar_t *buf, DWORD buf_size)
{
    DWORD bufsize_in_chars = buf_size * (sizeof(wchar_t) / sizeof(char));
    DWORD size = GetFinalPathNameByHandleW(
        handle, buf, bufsize_in_chars, FILE_NAME_NORMALIZED | VOLUME_NAME_NONE);

    if (size > bufsize_in_chars)
        return __WASI_ENAMETOOLONG;

    if (size == 0)
        return convert_windows_error_code(GetLastError());

    return __WASI_ESUCCESS;
}

static __wasi_errno_t
convert_hresult_error_code(HRESULT error_code)
{
    switch (error_code) {
        case E_OUTOFMEMORY:
            return __WASI_ENOMEM;
        case E_INVALIDARG:
        default:
            return __WASI_EINVAL;
    }
}

// Returns the absolute filepath from the relative path to the directory
// associated with the provided handle.
static __wasi_errno_t
get_absolute_filepath(HANDLE handle, const char *relative_path,
                      wchar_t *absolute_path, size_t buf_len)
{
    wchar_t handle_path[PATH_MAX];

    __wasi_errno_t error = get_handle_filepath(handle, handle_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    wchar_t relative_wpath[PATH_MAX];
    error = convert_to_wchar(relative_path, relative_wpath, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    HRESULT ret =
        PathCchCombine(absolute_path, buf_len, handle_path, relative_wpath);
    if (ret != S_OK)
        error = convert_hresult_error_code(ret);

    return error;
}

static bool
has_directory_attribute(DWORD attributes)
{
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return false;

    return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static bool
is_directory(const wchar_t *path)
{
    DWORD attributes = GetFileAttributesW(path);

    return has_directory_attribute(attributes);
}

static bool
has_symlink_attribute(DWORD attributes)
{
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return false;

    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

static void
init_dir_stream(os_dir_stream dir_stream, os_file_handle handle)
{
    dir_stream->cursor = 0;
    dir_stream->handle = handle;
    dir_stream->cookie = 0;
}

static void
reset_dir_stream(os_dir_stream dir_stream)
{
    dir_stream->cursor = 0;
    dir_stream->cookie = 0;
}

// Advances to the next directory entry and optionally reads into to the
// provided buffer if not NULL.
static __wasi_errno_t
read_next_dir_entry(os_dir_stream dir_stream, FILE_ID_BOTH_DIR_INFO **out_entry)
{
    FILE_INFO_BY_HANDLE_CLASS file_info_class;

    if (dir_stream->cookie == 0)
        file_info_class = FileIdBothDirectoryRestartInfo;
    else
        file_info_class = FileIdBothDirectoryInfo;

    if (dir_stream->cursor == 0
        && !GetFileInformationByHandleEx(dir_stream->handle->raw.handle,
                                         file_info_class, dir_stream->info_buf,
                                         sizeof(dir_stream->info_buf))) {
        if (out_entry != NULL)
            *out_entry = NULL;
        DWORD win_error = GetLastError();
        // We've reached the end of the directory - return success
        if (win_error == ERROR_NO_MORE_FILES) {
            dir_stream->cookie = 0;
            dir_stream->cursor = 0;
            return __WASI_ESUCCESS;
        }

        return convert_windows_error_code(win_error);
    }

    FILE_ID_BOTH_DIR_INFO *current_info =
        (FILE_ID_BOTH_DIR_INFO *)(dir_stream->info_buf + dir_stream->cursor);

    if (current_info->NextEntryOffset == 0)
        dir_stream->cursor = 0;
    else
        dir_stream->cursor += current_info->NextEntryOffset;

    ++dir_stream->cookie;

    if (out_entry != NULL)
        *out_entry = current_info;
    else
        return __WASI_ESUCCESS;

    // Convert and copy over the wchar filename into the entry_name buf
    int ret = WideCharToMultiByte(
        CP_UTF8, 0, current_info->FileName,
        current_info->FileNameLength / (sizeof(wchar_t) / sizeof(char)),
        dir_stream->current_entry_name, sizeof(dir_stream->current_entry_name),
        NULL, NULL);

    if (ret == 0)
        return convert_windows_error_code(GetLastError());

    return __WASI_ESUCCESS;
}

static HANDLE
create_handle(wchar_t *path, bool is_dir, bool follow_symlink, bool readonly)
{
    CREATEFILE2_EXTENDED_PARAMETERS create_params;

    create_params.dwSize = sizeof(create_params);
    create_params.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    create_params.dwSecurityQosFlags = 0;
    create_params.dwFileFlags = 0;
    create_params.lpSecurityAttributes = NULL;
    create_params.hTemplateFile = NULL;

    if (is_dir) {
        create_params.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
        create_params.dwFileFlags |= FILE_FLAG_BACKUP_SEMANTICS;
    }

    if (!follow_symlink)
        create_params.dwFileFlags |= FILE_FLAG_OPEN_REPARSE_POINT;

    DWORD desired_access = GENERIC_READ;

    if (!readonly)
        desired_access |= GENERIC_WRITE;
    else
        create_params.dwFileAttributes |= FILE_ATTRIBUTE_READONLY;

    return CreateFile2(path, desired_access,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       OPEN_EXISTING, &create_params);
}

#if WINAPI_PARTITION_DESKTOP == 0
// Modifies the given path in place and replaces it with the filename component
// (including the extension) of the path.
static __wasi_errno_t
extract_filename_from_path(wchar_t *path, size_t buf_size)
{
    wchar_t extension[256];
    wchar_t filename[256];
    __wasi_errno_t error = __WASI_ESUCCESS;

    // Get the filename from the fullpath.
    errno_t ret =
        _wsplitpath_s(path, NULL, 0, NULL, 0, filename, 256, extension, 256);
    if (ret != 0) {
        error = convert_errno(ret);
        return error;
    }

    ret = wcscat_s(filename, 256, extension);

    if (ret != 0) {
        error = convert_errno(ret);
        return error;
    }

    ret = wcscpy_s(path, buf_size, filename);

    if (ret != 0)
        error = convert_errno(ret);

    return error;
}

static __wasi_errno_t
get_handle_to_parent_directory(HANDLE handle, HANDLE *out_dir_handle)
{
    wchar_t path[PATH_MAX];
    __wasi_errno_t error = get_handle_filepath(handle, path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    wchar_t parent_dir_path[PATH_MAX];
    errno_t ret = wcscpy_s(parent_dir_path, PATH_MAX, path);

    if (ret != 0) {
        error = convert_errno(ret);
        return error;
    }

    ret = wcscat_s(parent_dir_path, PATH_MAX, L"/..");

    if (ret != 0) {
        error = convert_errno(ret);
        return error;
    }

    HANDLE dir_handle = create_handle(parent_dir_path, true, true, true);

    if (dir_handle == INVALID_HANDLE_VALUE) {
        error = convert_windows_error_code(GetLastError());
        return error;
    }

    *out_dir_handle = dir_handle;
    return error;
}

// The easiest way to get all the necessary file information for files is to
// open a handle to the parent directory and iterate through the entries via
// FileIdBothDirectoryInfo. Other file information classes are only
// available on desktop.
static __wasi_errno_t
get_disk_file_information(HANDLE handle, __wasi_filestat_t *buf)
{
    __wasi_errno_t error = __WASI_ESUCCESS;
    HANDLE raw_dir_handle = INVALID_HANDLE_VALUE;

    wchar_t path[PATH_MAX] = L".";

    if (buf->st_filetype != __WASI_FILETYPE_DIRECTORY) {
        error = get_handle_filepath(handle, path, PATH_MAX);

        if (error != __WASI_ESUCCESS)
            goto fail;

        error = get_handle_to_parent_directory(handle, &raw_dir_handle);

        if (error != __WASI_ESUCCESS)
            goto fail;

        error = extract_filename_from_path(path, PATH_MAX);

        if (error != __WASI_ESUCCESS)
            goto fail;
    }
    else {
        raw_dir_handle = handle;
    }

    windows_handle dir_handle = { .access_mode = windows_access_mode_read,
                                  .raw = { .handle = raw_dir_handle },
                                  .fdflags = 0,
                                  .type = windows_handle_type_file };
    windows_dir_stream dir_stream;
    init_dir_stream(&dir_stream, &dir_handle);

    do {
        FILE_ID_BOTH_DIR_INFO *file_id_both_dir_info = NULL;
        __wasi_errno_t error =
            read_next_dir_entry(&dir_stream, &file_id_both_dir_info);

        if (error != __WASI_ESUCCESS || file_id_both_dir_info == NULL)
            goto fail;

        const DWORD filename_length = file_id_both_dir_info->FileNameLength
                                      / (sizeof(wchar_t) / sizeof(char));

        if (wcsncmp(file_id_both_dir_info->FileName, path, filename_length)
            == 0) {
            buf->st_ino =
                (__wasi_inode_t)(file_id_both_dir_info->FileId.QuadPart);
            buf->st_atim = convert_filetime_to_wasi_timestamp(
                (LPFILETIME)&file_id_both_dir_info->LastAccessTime.QuadPart);
            buf->st_mtim = convert_filetime_to_wasi_timestamp(
                (LPFILETIME)&file_id_both_dir_info->LastWriteTime.QuadPart);
            buf->st_ctim = convert_filetime_to_wasi_timestamp(
                (LPFILETIME)&file_id_both_dir_info->ChangeTime.QuadPart);
            buf->st_size =
                (__wasi_filesize_t)(file_id_both_dir_info->EndOfFile.QuadPart);

            break;
        }
    } while (dir_stream.cookie != 0);

    FILE_STANDARD_INFO file_standard_info;

    bool success = GetFileInformationByHandleEx(handle, FileStandardInfo,
                                                &file_standard_info,
                                                sizeof(file_standard_info));

    if (!success) {
        error = convert_windows_error_code(GetLastError());
        goto fail;
    }

    buf->st_nlink = (__wasi_linkcount_t)file_standard_info.NumberOfLinks;
fail:
    if (buf->st_filetype != __WASI_FILETYPE_DIRECTORY
        && raw_dir_handle != INVALID_HANDLE_VALUE)
        CloseHandle(raw_dir_handle);

    return error;
}

#else

static __wasi_errno_t
get_disk_file_information(HANDLE handle, __wasi_filestat_t *buf)
{
    __wasi_errno_t error = __WASI_ESUCCESS;
    FILE_BASIC_INFO file_basic_info;

    int ret = GetFileInformationByHandleEx(
        handle, FileBasicInfo, &file_basic_info, sizeof(file_basic_info));

    if (ret == 0) {
        error = convert_windows_error_code(GetLastError());
        return error;
    }

    buf->st_atim = convert_filetime_to_wasi_timestamp(
        (LPFILETIME)&file_basic_info.LastAccessTime.QuadPart);
    buf->st_mtim = convert_filetime_to_wasi_timestamp(
        (LPFILETIME)&file_basic_info.LastWriteTime.QuadPart);
    buf->st_ctim = convert_filetime_to_wasi_timestamp(
        (LPFILETIME)&file_basic_info.ChangeTime.QuadPart);

    BY_HANDLE_FILE_INFORMATION file_info;
    ret = GetFileInformationByHandle(handle, &file_info);

    if (ret == 0) {
        error = convert_windows_error_code(GetLastError());
        return error;
    }

    ULARGE_INTEGER file_size = { .LowPart = file_info.nFileSizeLow,
                                 .HighPart = file_info.nFileSizeHigh };
    buf->st_size = (__wasi_filesize_t)(file_size.QuadPart);

    ULARGE_INTEGER file_id = { .LowPart = file_info.nFileIndexLow,
                               .HighPart = file_info.nFileIndexHigh };
    buf->st_ino = (__wasi_inode_t)(file_id.QuadPart);

    buf->st_dev = (__wasi_device_t)file_info.dwVolumeSerialNumber;
    buf->st_nlink = (__wasi_linkcount_t)file_info.nNumberOfLinks;

    return error;
}

#endif /* end of WINAPI_PARTITION_DESKTOP == 0 */

static __wasi_errno_t
get_file_information(os_file_handle handle, __wasi_filestat_t *buf)
{
    __wasi_errno_t error = __WASI_ESUCCESS;

    DWORD windows_filetype = GetFileType(handle->raw.handle);
    error =
        convert_windows_filetype(handle, windows_filetype, &buf->st_filetype);

    if (error != __WASI_ESUCCESS)
        return error;

    buf->st_dev = 0;

    if (windows_filetype != FILE_TYPE_DISK) {
        buf->st_atim = 0;
        buf->st_ctim = 0;
        buf->st_mtim = 0;
        buf->st_nlink = 0;
        buf->st_size = 0;
        buf->st_ino = 0;

        return error;
    }

    return get_disk_file_information(handle->raw.handle, buf);
}

__wasi_errno_t
os_fstat(os_file_handle handle, struct __wasi_filestat_t *buf)
{
    CHECK_VALID_HANDLE(handle);

    return get_file_information(handle, buf);
}

__wasi_errno_t
os_fstatat(os_file_handle handle, const char *path,
           struct __wasi_filestat_t *buf, __wasi_lookupflags_t lookup_flags)
{
    CHECK_VALID_FILE_HANDLE(handle);

    wchar_t absolute_path[PATH_MAX];

    __wasi_errno_t error = get_absolute_filepath(handle->raw.handle, path,
                                                 absolute_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    windows_handle resolved_handle = {
        .type = windows_handle_type_file,
        .fdflags = 0,
        .raw = { .handle = create_handle(
                     absolute_path, is_directory(absolute_path),
                     ((lookup_flags & __WASI_LOOKUP_SYMLINK_FOLLOW) != 0),
                     true) },
        .access_mode = windows_access_mode_read
    };

    if (resolved_handle.raw.handle == INVALID_HANDLE_VALUE)
        return convert_windows_error_code(GetLastError());

    error = get_file_information(&resolved_handle, buf);

    CloseHandle(resolved_handle.raw.handle);

    return error;
}

__wasi_errno_t
os_file_get_fdflags(os_file_handle handle, __wasi_fdflags_t *flags)
{
    CHECK_VALID_HANDLE(handle);

    *flags = handle->fdflags;
    return __WASI_ESUCCESS;
}

__wasi_errno_t
os_file_set_fdflags(os_file_handle handle, __wasi_fdflags_t flags)
{
    CHECK_VALID_HANDLE(handle);

    if (handle->type == windows_handle_type_socket
        && (((handle->fdflags ^ flags) & __WASI_FDFLAG_NONBLOCK) != 0)) {
        u_long non_block = flags & __WASI_FDFLAG_NONBLOCK;

        int ret = ioctlsocket(handle->raw.socket, (long)FIONBIO, &non_block);

        if (ret != 0)
            return convert_winsock_error_code(WSAGetLastError());

        if (non_block)
            handle->fdflags |= __WASI_FDFLAG_NONBLOCK;
        else
            handle->fdflags &= ~__WASI_FDFLAG_NONBLOCK;
        return __WASI_ESUCCESS;
    }

    // It's not supported setting FILE_FLAG_WRITE_THROUGH or
    // FILE_FLAG_NO_BUFFERING via SetFileAttributes so __WASI_FDFLAG_APPEND is
    // the only flags we can do anything with.
    if (((handle->fdflags ^ flags) & __WASI_FDFLAG_APPEND) != 0) {
        if ((flags & __WASI_FDFLAG_APPEND) != 0)
            handle->fdflags |= __WASI_FDFLAG_APPEND;
        else
            handle->fdflags &= ~__WASI_FDFLAG_APPEND;
    }

    return __WASI_ESUCCESS;
}

__wasi_errno_t
os_file_get_access_mode(os_file_handle handle,
                        wasi_libc_file_access_mode *access_mode)
{
    CHECK_VALID_HANDLE(handle);

    if ((handle->access_mode & windows_access_mode_read) != 0
        && (handle->access_mode & windows_access_mode_write) != 0)
        *access_mode = WASI_LIBC_ACCESS_MODE_READ_WRITE;
    else if ((handle->access_mode & windows_access_mode_write) != 0)
        *access_mode = WASI_LIBC_ACCESS_MODE_WRITE_ONLY;
    else
        *access_mode = WASI_LIBC_ACCESS_MODE_READ_ONLY;

    return __WASI_ESUCCESS;
}

static __wasi_errno_t
flush_file_buffers_on_handle(HANDLE handle)
{
    bool success = FlushFileBuffers(handle);

    return success ? __WASI_ESUCCESS
                   : convert_windows_error_code(GetLastError());
}

__wasi_errno_t
os_fdatasync(os_file_handle handle)
{
    CHECK_VALID_FILE_HANDLE(handle);

    return flush_file_buffers_on_handle(handle->raw.handle);
}

__wasi_errno_t
os_fsync(os_file_handle handle)
{
    CHECK_VALID_FILE_HANDLE(handle);

    return flush_file_buffers_on_handle(handle->raw.handle);
}

__wasi_errno_t
os_open_preopendir(const char *path, os_file_handle *out)
{
    *out = NULL;

    wchar_t wpath[PATH_MAX];
    __wasi_errno_t error = convert_to_wchar(path, wpath, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    HANDLE dir_handle = create_handle(wpath, true, true, true);

    if (dir_handle == INVALID_HANDLE_VALUE)
        return convert_windows_error_code(GetLastError());

    *out = BH_MALLOC(sizeof(windows_handle));

    if (*out == NULL) {
        CloseHandle(dir_handle);
        return __WASI_ENOMEM;
    }

    (*out)->type = windows_handle_type_file;
    (*out)->raw.handle = dir_handle;
    (*out)->fdflags = 0;
    (*out)->access_mode = windows_access_mode_read;

    return error;
}

__wasi_errno_t
os_openat(os_file_handle handle, const char *path, __wasi_oflags_t oflags,
          __wasi_fdflags_t fs_flags, __wasi_lookupflags_t lookup_flags,
          wasi_libc_file_access_mode access_mode, os_file_handle *out)
{
    CHECK_VALID_FILE_HANDLE(handle);
    *out = BH_MALLOC(sizeof(windows_handle));

    if (*out == NULL)
        return __WASI_ENOMEM;

    (*out)->type = windows_handle_type_file;
    (*out)->fdflags = fs_flags;
    (*out)->raw.handle = INVALID_HANDLE_VALUE;

    DWORD attributes = FILE_FLAG_BACKUP_SEMANTICS;

    if ((fs_flags & (__WASI_FDFLAG_SYNC | __WASI_FDFLAG_RSYNC)) != 0)
        attributes |= (FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING);
    if ((fs_flags & __WASI_FDFLAG_DSYNC) != 0)
        attributes |= FILE_FLAG_WRITE_THROUGH;

    if ((oflags & __WASI_O_DIRECTORY) != 0) {
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
        oflags &= ~(__WASI_O_DIRECTORY);
    }
    // Use async operations on the handle if it's not a directory
    else {
        attributes |= FILE_FLAG_OVERLAPPED;
    }

    __wasi_errno_t error = __WASI_ESUCCESS;

    DWORD access_flags = 0;

    switch (access_mode) {
        case WASI_LIBC_ACCESS_MODE_READ_ONLY:
            access_flags |= GENERIC_READ;
            (*out)->access_mode = windows_access_mode_read;
            break;
        case WASI_LIBC_ACCESS_MODE_WRITE_ONLY:
            access_flags |= GENERIC_WRITE;
            (*out)->access_mode = windows_access_mode_write;
            break;
        case WASI_LIBC_ACCESS_MODE_READ_WRITE:
            access_flags |= GENERIC_WRITE | GENERIC_READ;
            (*out)->access_mode =
                windows_access_mode_read | windows_access_mode_write;
            break;
    }

    DWORD creation_disposition = 0;

    switch (oflags) {
        case __WASI_O_CREAT | __WASI_O_EXCL:
        case __WASI_O_CREAT | __WASI_O_EXCL | __WASI_O_TRUNC:
            creation_disposition = CREATE_NEW;
            break;
        case __WASI_O_CREAT | __WASI_O_TRUNC:
            creation_disposition = CREATE_ALWAYS;
            break;
        case __WASI_O_CREAT:
            creation_disposition = OPEN_ALWAYS;
            break;
        case 0:
        case __WASI_O_EXCL:
            creation_disposition = OPEN_EXISTING;
            break;
        case __WASI_O_TRUNC:
        case __WASI_O_EXCL | __WASI_O_TRUNC:
            creation_disposition = TRUNCATE_EXISTING;
            // CreateFile2 requires write access if we truncate the file upon
            // opening
            access_flags |= GENERIC_WRITE;
            break;
    }

    wchar_t absolute_path[PATH_MAX];
    error = get_absolute_filepath(handle->raw.handle, path, absolute_path,
                                  PATH_MAX);

    if (error != __WASI_ESUCCESS)
        goto fail;

    if ((lookup_flags & __WASI_LOOKUP_SYMLINK_FOLLOW) == 0)
        attributes |= FILE_FLAG_OPEN_REPARSE_POINT;

    // Windows doesn't seem to throw an error for the following cases where the
    // file/directory already exists so add explicit checks.
    if (creation_disposition == OPEN_EXISTING) {
        DWORD file_attributes = GetFileAttributesW(absolute_path);

        if (file_attributes != INVALID_FILE_ATTRIBUTES) {
            bool is_dir = file_attributes & FILE_ATTRIBUTE_DIRECTORY;
            bool is_symlink = file_attributes & FILE_ATTRIBUTE_REPARSE_POINT;
            // Check that we're not trying to open an existing file/symlink as a
            // directory.
            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                && (!is_dir || is_symlink)) {
                error = __WASI_ENOTDIR;
                goto fail;
            }

            // Check that we're not trying to open an existing symlink with
            // O_NOFOLLOW.
            if ((file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                && (lookup_flags & __WASI_LOOKUP_SYMLINK_FOLLOW) == 0) {
                error = __WASI_ELOOP;
                goto fail;
            }
        }
    }

    CREATEFILE2_EXTENDED_PARAMETERS create_params;
    create_params.dwSize = sizeof(create_params);
    create_params.dwFileAttributes = attributes & 0xFFF;
    create_params.dwFileFlags = attributes & 0xFFF00000;
    create_params.dwSecurityQosFlags = 0;
    create_params.lpSecurityAttributes = NULL;
    create_params.hTemplateFile = NULL;

    (*out)->raw.handle =
        CreateFile2(absolute_path, access_flags,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    creation_disposition, &create_params);

    if ((*out)->raw.handle == INVALID_HANDLE_VALUE) {
        error = convert_windows_error_code(GetLastError());
        goto fail;
    }

    return error;
fail:
    if (*out != NULL) {
        if ((*out)->raw.handle != INVALID_HANDLE_VALUE)
            CloseHandle((*out)->raw.handle);

        BH_FREE(*out);
    }

    return error;
}

__wasi_errno_t
os_close(os_file_handle handle, bool is_stdio)
{
    CHECK_VALID_HANDLE(handle);

    // We don't own the underlying raw handle so just free the handle and return
    // success.
    if (is_stdio) {
        BH_FREE(handle);
        return __WASI_ESUCCESS;
    }

    switch (handle->type) {
        case windows_handle_type_file:
            bool success = CloseHandle(handle->raw.handle);

            if (!success)
                return convert_windows_error_code(GetLastError());

            break;
        case windows_handle_type_socket:
            int ret = closesocket(handle->raw.socket);

            if (ret != 0)
                return convert_winsock_error_code(WSAGetLastError());

            break;
        default:
            assert(false && "unreachable");
    }

    BH_FREE(handle);

    return __WASI_ESUCCESS;
}

static __wasi_errno_t
read_data_at_offset(HANDLE handle, const struct __wasi_iovec_t *iov, int iovcnt,
                    __wasi_filesize_t offset, size_t *nwritten)
{
    OVERLAPPED *read_operations =
        BH_MALLOC((uint32_t)(sizeof(OVERLAPPED) * (uint32_t)iovcnt));

    if (read_operations == NULL)
        return __WASI_ENOMEM;

    ULARGE_INTEGER query_offset = { .QuadPart = offset };
    __wasi_errno_t error = __WASI_ESUCCESS;
    size_t total_bytes_read = 0;

    const __wasi_iovec_t *current = iov;
    int successful_read_count = 0;

    for (int i = 0; i < iovcnt; ++i, ++current) {
        read_operations[i].Internal = 0;
        read_operations[i].InternalHigh = 0;
        read_operations[i].Offset = query_offset.LowPart;
        read_operations[i].OffsetHigh = query_offset.HighPart;
        read_operations[i].hEvent = NULL;

        if (!ReadFileEx(handle, current->buf, (DWORD)current->buf_len,
                        &read_operations[i], NULL)) {
            DWORD win_error = GetLastError();
            if (win_error != ERROR_IO_PENDING) {
                error = convert_windows_error_code(win_error);
                break;
            }
        }
        ++successful_read_count;
        query_offset.QuadPart += (DWORD)current->buf_len;
    }

    // Get the result of all the asynchronous read operations
    for (int i = 0; i < successful_read_count; ++i) {
        DWORD bytes_transferred = 0;
        if (!GetOverlappedResult(handle, &read_operations[i],
                                 &bytes_transferred, true)) {
            DWORD win_error = GetLastError();

            if (win_error != ERROR_HANDLE_EOF)
                error = convert_windows_error_code(win_error);
            else
                total_bytes_read += (size_t)bytes_transferred;

            CancelIo(handle);

            for (int j = i + 1; j < iovcnt; ++j) {
                GetOverlappedResult(handle, &read_operations[j],
                                    &bytes_transferred, true);
            }
            break;
        }

        total_bytes_read += (size_t)bytes_transferred;
    }

    *nwritten = total_bytes_read;

    BH_FREE(read_operations);
    return error;
}

__wasi_errno_t
os_preadv(os_file_handle handle, const struct __wasi_iovec_t *iov, int iovcnt,
          __wasi_filesize_t offset, size_t *nread)
{
    CHECK_VALID_FILE_HANDLE(handle);

    return read_data_at_offset(handle->raw.handle, iov, iovcnt, offset, nread);
}

__wasi_errno_t
os_readv(os_file_handle handle, const struct __wasi_iovec_t *iov, int iovcnt,
         size_t *nread)
{
    CHECK_VALID_HANDLE(handle);

    LARGE_INTEGER current_offset = { .QuadPart = 0 };

    // Seek to the current offset before reading
    int ret = SetFilePointerEx(handle->raw.handle, current_offset,
                               &current_offset, FILE_CURRENT);
    if (ret == 0)
        return convert_windows_error_code(GetLastError());

    __wasi_errno_t error =
        read_data_at_offset(handle->raw.handle, iov, iovcnt,
                            (__wasi_filesize_t)current_offset.QuadPart, nread);

    if (error != __WASI_ESUCCESS)
        return error;

    current_offset.QuadPart += (LONGLONG)(*nread);

    // Update the current offset to match how many bytes we've read
    ret =
        SetFilePointerEx(handle->raw.handle, current_offset, NULL, FILE_BEGIN);

    if (ret == 0)
        error = convert_windows_error_code(GetLastError());

    return error;
}

static __wasi_errno_t
write_data_at_offset(HANDLE handle, const struct __wasi_ciovec_t *iov,
                     int iovcnt, __wasi_filesize_t offset, size_t *nwritten)
{
    OVERLAPPED *write_operations =
        BH_MALLOC((uint32_t)(sizeof(OVERLAPPED) * (uint32_t)iovcnt));

    if (write_operations == NULL)
        return __WASI_ENOMEM;

    ULARGE_INTEGER query_offset = { .QuadPart = offset };
    __wasi_errno_t error = __WASI_ESUCCESS;
    size_t total_bytes_written = 0;

    const __wasi_ciovec_t *current = iov;
    int successful_write_count = 0;
    for (int i = 0; i < iovcnt; ++i, ++current) {
        write_operations[i].Internal = 0;
        write_operations[i].InternalHigh = 0;
        write_operations[i].Offset = query_offset.LowPart;
        write_operations[i].OffsetHigh = query_offset.HighPart;
        write_operations[i].hEvent = NULL;

        if (!WriteFileEx(handle, current->buf, (DWORD)current->buf_len,
                         &write_operations[i], NULL)) {
            DWORD win_error = GetLastError();
            if (win_error != ERROR_IO_PENDING) {
                error = convert_windows_error_code(win_error);
                break;
            }
        }
        ++successful_write_count;
        query_offset.QuadPart += (DWORD)current->buf_len;
    }

    // Get the result of all the asynchronous writes
    for (int i = 0; i < successful_write_count; ++i) {
        DWORD bytes_transferred = 0;
        if (!GetOverlappedResult(handle, &write_operations[i],
                                 &bytes_transferred, true)) {
            error = convert_windows_error_code(GetLastError());
            CancelIo(handle);

            for (int j = i + 1; j < iovcnt; ++j) {
                GetOverlappedResult(handle, &write_operations[j],
                                    &bytes_transferred, true);
            }
            break;
        }

        total_bytes_written += (size_t)bytes_transferred;
    }

    *nwritten = total_bytes_written;

    BH_FREE(write_operations);
    return error;
}

__wasi_errno_t
os_pwritev(os_file_handle handle, const struct __wasi_ciovec_t *iov, int iovcnt,
           __wasi_filesize_t offset, size_t *nwritten)
{
    CHECK_VALID_FILE_HANDLE(handle);

    return write_data_at_offset(handle->raw.handle, iov, iovcnt, offset,
                                nwritten);
}

__wasi_errno_t
os_writev(os_file_handle handle, const struct __wasi_ciovec_t *iov, int iovcnt,
          size_t *nwritten)
{
    CHECK_VALID_HANDLE(handle);

    bool append = (handle->fdflags & __WASI_FDFLAG_APPEND) != 0;
    LARGE_INTEGER write_offset = { .QuadPart = 0 };
    DWORD move_method = append ? FILE_END : FILE_CURRENT;

    int ret = SetFilePointerEx(handle->raw.handle, write_offset, &write_offset,
                               move_method);
    if (ret == 0)
        return convert_windows_error_code(GetLastError());

    __wasi_errno_t error = write_data_at_offset(
        handle->raw.handle, iov, iovcnt,
        (__wasi_filesize_t)write_offset.QuadPart, nwritten);

    if (error != __WASI_ESUCCESS)
        return error;

    write_offset.QuadPart += (LONGLONG)(*nwritten);

    // Update the write offset to match how many bytes we've written
    ret = SetFilePointerEx(handle->raw.handle, write_offset, NULL, FILE_BEGIN);

    if (ret == 0)
        error = convert_windows_error_code(GetLastError());

    return error;
}

__wasi_errno_t
os_fallocate(os_file_handle handle, __wasi_filesize_t offset,
             __wasi_filesize_t length)
{
    CHECK_VALID_FILE_HANDLE(handle);

    LARGE_INTEGER current_file_size;
    int ret = GetFileSizeEx(handle->raw.handle, &current_file_size);

    if (ret == 0)
        return convert_windows_error_code(GetLastError());

    if (offset > INT64_MAX || length > INT64_MAX || offset + length > INT64_MAX)
        return __WASI_EINVAL;

    // The best we can do here is to increase the size of the file if it's less
    // than the offset + length.
    const LONGLONG requested_size = (LONGLONG)(offset + length);

    FILE_END_OF_FILE_INFO end_of_file_info;
    end_of_file_info.EndOfFile.QuadPart = requested_size;

    if (requested_size <= current_file_size.QuadPart)
        return __WASI_ESUCCESS;

    bool success =
        SetFileInformationByHandle(handle->raw.handle, FileEndOfFileInfo,
                                   &end_of_file_info, sizeof(end_of_file_info));

    return success ? __WASI_ESUCCESS
                   : convert_windows_error_code(GetLastError());
}

__wasi_errno_t
os_ftruncate(os_file_handle handle, __wasi_filesize_t size)
{
    CHECK_VALID_FILE_HANDLE(handle);

    FILE_END_OF_FILE_INFO end_of_file_info;
    end_of_file_info.EndOfFile.QuadPart = (LONGLONG)size;

    bool success =
        SetFileInformationByHandle(handle->raw.handle, FileEndOfFileInfo,
                                   &end_of_file_info, sizeof(end_of_file_info));

    return success ? __WASI_ESUCCESS
                   : convert_windows_error_code(GetLastError());
}

static __wasi_errno_t
set_file_times(HANDLE handle, __wasi_timestamp_t access_time,
               __wasi_timestamp_t modification_time, __wasi_fstflags_t fstflags)
{
    FILETIME atim = { 0, 0 };
    FILETIME mtim = { 0, 0 };

    if ((fstflags & __WASI_FILESTAT_SET_ATIM) != 0) {
        atim = convert_wasi_timestamp_to_filetime(access_time);
    }
    else if ((fstflags & __WASI_FILESTAT_SET_ATIM_NOW) != 0) {
        GetSystemTimePreciseAsFileTime(&atim);
    }

    if ((fstflags & __WASI_FILESTAT_SET_MTIM) != 0) {
        mtim = convert_wasi_timestamp_to_filetime(modification_time);
    }
    else if ((fstflags & __WASI_FILESTAT_SET_MTIM_NOW) != 0) {
        GetSystemTimePreciseAsFileTime(&mtim);
    }

    bool success = SetFileTime(handle, NULL, &atim, &mtim);

    return success ? __WASI_ESUCCESS
                   : convert_windows_error_code(GetLastError());
}

__wasi_errno_t
os_futimens(os_file_handle handle, __wasi_timestamp_t access_time,
            __wasi_timestamp_t modification_time, __wasi_fstflags_t fstflags)
{
    CHECK_VALID_FILE_HANDLE(handle);

    return set_file_times(handle->raw.handle, access_time, modification_time,
                          fstflags);
}

__wasi_errno_t
os_utimensat(os_file_handle handle, const char *path,
             __wasi_timestamp_t access_time,
             __wasi_timestamp_t modification_time, __wasi_fstflags_t fstflags,
             __wasi_lookupflags_t lookup_flags)
{
    CHECK_VALID_FILE_HANDLE(handle);

    wchar_t absolute_path[PATH_MAX];
    __wasi_errno_t error = get_absolute_filepath(handle->raw.handle, path,
                                                 absolute_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    HANDLE resolved_handle = create_handle(
        absolute_path, is_directory(absolute_path),
        (lookup_flags & __WASI_LOOKUP_SYMLINK_FOLLOW) != 0, false);

    if (resolved_handle == INVALID_HANDLE_VALUE)
        return convert_windows_error_code(GetLastError());

    error = set_file_times(resolved_handle, access_time, modification_time,
                           fstflags);

    CloseHandle(resolved_handle);

    return error;
}

__wasi_errno_t
os_readlinkat(os_file_handle handle, const char *path, char *buf,
              size_t bufsize, size_t *nread)
{
    CHECK_VALID_FILE_HANDLE(handle);

    wchar_t symlink_path[PATH_MAX];
    __wasi_errno_t error =
        get_absolute_filepath(handle->raw.handle, path, symlink_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    DWORD symlink_attributes = GetFileAttributesW(symlink_path);

    if (!has_symlink_attribute(symlink_attributes))
        return __WASI_EINVAL;

    HANDLE link_handle = create_handle(
        symlink_path, has_directory_attribute(symlink_attributes), false, true);

    if (link_handle == INVALID_HANDLE_VALUE)
        return convert_windows_error_code(GetLastError());

#if WINAPI_PARTITION_DESKTOP != 0
// MinGW32 already has a definition for REPARSE_DATA_BUFFER
#if defined(_MSC_VER) || defined(__MINGW64_VERSION_MAJOR)
    // See
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer
    // for more details.
    typedef struct _REPARSE_DATA_BUFFER {
        ULONG ReparseTag;
        USHORT ReparseDataLength;
        USHORT Reserved;
        union {
            struct {
                USHORT SubstituteNameOffset;
                USHORT SubstituteNameLength;
                USHORT PrintNameOffset;
                USHORT PrintNameLength;
                ULONG Flags;
                WCHAR PathBuffer[1];
            } SymbolicLinkReparseBuffer;
            struct {
                USHORT SubstituteNameOffset;
                USHORT SubstituteNameLength;
                USHORT PrintNameOffset;
                USHORT PrintNameLength;
                WCHAR PathBuffer[1];
            } MountPointReparseBuffer;
            struct {
                UCHAR DataBuffer[1];
            } GenericReparseBuffer;
        } DUMMYUNIONNAME;
    } REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;
#endif

    char buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];

    REPARSE_DATA_BUFFER *reparse_data = (REPARSE_DATA_BUFFER *)buffer;

    if (!DeviceIoControl(link_handle, FSCTL_GET_REPARSE_POINT, NULL, 0, &buffer,
                         sizeof(buffer), NULL, NULL)) {
        error = convert_windows_error_code(GetLastError());
        goto fail;
    }

    int wbufsize = 0;
    wchar_t *wbuf = NULL;

    // The following checks are taken from the libuv windows filesystem
    // implementation,
    // https://github.com/libuv/libuv/blob/v1.x/src/win/fs.c#L181-L244. Real
    // symlinks can contain pretty much anything, but the only thing we really
    // care about is undoing the implicit conversion to an NT namespaced path
    // that CreateSymbolicLink will perform on absolute paths.
    if (reparse_data->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        wbuf = reparse_data->SymbolicLinkReparseBuffer.PathBuffer
               + (reparse_data->SymbolicLinkReparseBuffer.SubstituteNameOffset
                  / sizeof(wchar_t));
        wbufsize = reparse_data->SymbolicLinkReparseBuffer.SubstituteNameLength
                   / sizeof(wchar_t);

        if (wbufsize >= 4 && wbuf[0] == L'\\' && wbuf[1] == L'?'
            && wbuf[2] == L'?' && wbuf[3] == L'\\') {
            // Starts with \??\ 
            if (wbufsize >= 6
                && ((wbuf[4] >= L'A' && wbuf[4] <= L'Z')
                    || (wbuf[4] >= L'a' && wbuf[4] <= L'z'))
                && wbuf[5] == L':' && (wbufsize == 6 || wbuf[6] == L'\\'))
                {
                    // \??\<drive>:\ 
                    wbuf += 4;
                    wbufsize -= 4;
                }
                else if (wbufsize >= 8 && (wbuf[4] == L'U' || wbuf[4] == L'u')
                         && (wbuf[5] == L'N' || wbuf[5] == L'n')
                         && (wbuf[6] == L'C' || wbuf[6] == L'c')
                         && wbuf[7] == L'\\')
                {
                    // \??\UNC\<server>\<share>\ - make sure the final path looks like \\<server>\<share>\ 
                    wbuf += 6;
                    wbuf[0] = L'\\';
                    wbufsize -= 6;
                }
        }
    }
    else if (reparse_data->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
        // Junction
        wbuf = reparse_data->MountPointReparseBuffer.PathBuffer
               + (reparse_data->MountPointReparseBuffer.SubstituteNameOffset
                  / sizeof(wchar_t));
        wbufsize = reparse_data->MountPointReparseBuffer.SubstituteNameLength
                   / sizeof(wchar_t);

        // Only treat junctions that look like \??\<drive>:\ as a symlink.
        if (!(wbufsize >= 6 && wbuf[0] == L'\\' && wbuf[1] == L'?'
              && wbuf[2] == L'?' && wbuf[3] == L'\\'
              && ((wbuf[4] >= L'A' && wbuf[4] <= L'Z')
                  || (wbuf[4] >= L'a' && wbuf[4] <= L'z'))
              && wbuf[5] == L':' && (wbufsize == 6 || wbuf[6] == L'\\'))) {
            error = __WASI_EINVAL;
            goto fail;
        }

        /* Remove leading \??\ */
        wbuf += 4;
        wbufsize -= 4;
    }
    else {
        error = __WASI_EINVAL;
        goto fail;
    }

    if (wbuf != NULL)
        *nread = (size_t)WideCharToMultiByte(CP_UTF8, 0, wbuf, wbufsize, buf,
                                             (int)bufsize, NULL, NULL);

    if (*nread == 0 && wbuf != NULL) {
        DWORD win_error = GetLastError();
        if (win_error == ERROR_INSUFFICIENT_BUFFER)
            *nread = bufsize;
        else
            error = convert_windows_error_code(win_error);
    }
#else
    error = __WASI_ENOTSUP;
#endif /* end of WINAPI_PARTITION_DESKTOP == 0 */
fail:
    CloseHandle(link_handle);
    return error;
}

__wasi_errno_t
os_linkat(os_file_handle from_handle, const char *from_path,
          os_file_handle to_handle, const char *to_path,
          __wasi_lookupflags_t lookup_flags)
{
#if WINAPI_PARTITION_DESKTOP == 0
    return __WASI_ENOSYS;
#else
    CHECK_VALID_FILE_HANDLE(from_handle);
    CHECK_VALID_FILE_HANDLE(to_handle);

    wchar_t absolute_from_path[PATH_MAX];
    __wasi_errno_t error = get_absolute_filepath(
        from_handle->raw.handle, from_path, absolute_from_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    wchar_t absolute_to_path[PATH_MAX];
    error = get_absolute_filepath(to_handle->raw.handle, to_path,
                                  absolute_to_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    size_t to_path_len = strlen(to_path);

    // Windows doesn't throw an error in the case that the new path has a
    // trailing slash but the target to link to is a file.
    if (to_path[to_path_len - 1] == '/'
        || to_path[to_path_len - 1] == '\\'
               && !is_directory(absolute_from_path)) {
        return __WASI_ENOENT;
    }

    int ret = CreateHardLinkW(absolute_to_path, absolute_from_path, NULL);

    if (ret == 0)
        error = convert_windows_error_code(GetLastError());

    return error;
#endif /* end of WINAPI_PARTITION_DESKTOP == 0 */
}

__wasi_errno_t
os_symlinkat(const char *old_path, os_file_handle handle, const char *new_path)
{
#if WINAPI_PARTITION_DESKTOP == 0
    return __WASI_ENOSYS;
#else
    CHECK_VALID_FILE_HANDLE(handle);

    wchar_t absolute_new_path[PATH_MAX];
    __wasi_errno_t error = get_absolute_filepath(handle->raw.handle, new_path,
                                                 absolute_new_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    DWORD target_type = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;

    wchar_t old_wpath[PATH_MAX];
    size_t old_path_len = 0;

    error = convert_to_wchar(old_path, old_wpath, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        goto fail;

    wchar_t absolute_old_path[PATH_MAX];
    error = get_absolute_filepath(handle->raw.handle, old_path,
                                  absolute_old_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        goto fail;

    if (is_directory(absolute_old_path))
        target_type |= SYMBOLIC_LINK_FLAG_DIRECTORY;

    bool success =
        CreateSymbolicLinkW(absolute_new_path, old_wpath, target_type);

    if (!success) {
        DWORD win_error = GetLastError();

        // Return a more useful error code if a file/directory already exists at
        // the symlink location.
        if (win_error == ERROR_ACCESS_DENIED || win_error == ERROR_INVALID_NAME)
            error = __WASI_ENOENT;
        else
            error = convert_windows_error_code(GetLastError());
    }
fail:
    return error;
#endif /* end of WINAPI_PARTITION_DESKTOP == 0 */
}

__wasi_errno_t
os_mkdirat(os_file_handle handle, const char *path)
{
    CHECK_VALID_FILE_HANDLE(handle);

    wchar_t absolute_path[PATH_MAX];
    __wasi_errno_t error = get_absolute_filepath(handle->raw.handle, path,
                                                 absolute_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    bool success = CreateDirectoryW(absolute_path, NULL);

    if (!success)
        error = convert_windows_error_code(GetLastError());

    return error;
}

__wasi_errno_t
os_renameat(os_file_handle old_handle, const char *old_path,
            os_file_handle new_handle, const char *new_path)
{
    CHECK_VALID_FILE_HANDLE(old_handle);
    CHECK_VALID_FILE_HANDLE(new_handle);

    wchar_t old_absolute_path[PATH_MAX];
    __wasi_errno_t error = get_absolute_filepath(
        old_handle->raw.handle, old_path, old_absolute_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    wchar_t new_absolute_path[PATH_MAX];
    error = get_absolute_filepath(new_handle->raw.handle, new_path,
                                  new_absolute_path, PATH_MAX);

    if (error != __WASI_ESUCCESS)
        return error;

    int ret = MoveFileExW(old_absolute_path, new_absolute_path,
                          MOVEFILE_REPLACE_EXISTING);
    if (ret == 0)
        error = convert_windows_error_code(GetLastError());

    return error;
}

__wasi_errno_t
os_isatty(os_file_handle handle)
{
    CHECK_VALID_HANDLE(handle);

    DWORD console_mode;
    return GetConsoleMode(handle->raw.handle, &console_mode) ? __WASI_ESUCCESS
                                                             : __WASI_ENOTTY;
}

static os_file_handle
create_stdio_handle(HANDLE raw_stdio_handle, DWORD stdio)
{
    os_file_handle stdio_handle = BH_MALLOC(sizeof(windows_handle));

    if (stdio_handle == NULL)
        return NULL;

    stdio_handle->type = windows_handle_type_file;
    stdio_handle->access_mode =
        windows_access_mode_read | windows_access_mode_write;
    stdio_handle->fdflags = 0;

    if (raw_stdio_handle == INVALID_HANDLE_VALUE)
        raw_stdio_handle = GetStdHandle(stdio);

    stdio_handle->raw.handle = raw_stdio_handle;

    return stdio_handle;
}

bool
os_is_stdin_handle(os_file_handle fd)
{
    return fd->raw.handle == GetStdHandle(STD_INPUT_HANDLE);
}

bool
os_is_stdout_handle(os_file_handle fd)
{
    return fd->raw.handle == GetStdHandle(STD_OUTPUT_HANDLE);
}

bool
os_is_stderr_handle(os_file_handle fd)
{
    return fd->raw.handle == GetStdHandle(STD_ERROR_HANDLE);
}

os_file_handle
os_convert_stdin_handle(os_raw_file_handle raw_stdin)
{
    return create_stdio_handle(raw_stdin, STD_INPUT_HANDLE);
}

os_file_handle
os_convert_stdout_handle(os_raw_file_handle raw_stdout)
{
    return create_stdio_handle(raw_stdout, STD_OUTPUT_HANDLE);
}

os_file_handle
os_convert_stderr_handle(os_raw_file_handle raw_stderr)
{
    return create_stdio_handle(raw_stderr, STD_ERROR_HANDLE);
}

__wasi_errno_t
os_unlinkat(os_file_handle handle, const char *path, bool is_dir)
{
    CHECK_VALID_FILE_HANDLE(handle);

    wchar_t absolute_path[PATH_MAX];
    __wasi_errno_t error = get_absolute_filepath(handle->raw.handle, path,
                                                 absolute_path, PATH_MAX);

    DWORD attributes = GetFileAttributesW(absolute_path);

    if (attributes != INVALID_FILE_ATTRIBUTES
        && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        // Override is_dir for symlinks. A symlink to a directory counts as a
        // directory itself in Windows.
        is_dir = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    if (error != __WASI_ESUCCESS)
        return error;

    int ret =
        is_dir ? RemoveDirectoryW(absolute_path) : DeleteFileW(absolute_path);

    if (ret == 0)
        error = convert_windows_error_code(GetLastError());

    return error;
}

__wasi_errno_t
os_lseek(os_file_handle handle, __wasi_filedelta_t offset,
         __wasi_whence_t whence, __wasi_filesize_t *new_offset)
{
    CHECK_VALID_FILE_HANDLE(handle);
    DWORD sys_whence = 0;

    switch (whence) {
        case __WASI_WHENCE_SET:
            sys_whence = FILE_BEGIN;
            break;
        case __WASI_WHENCE_END:
            sys_whence = FILE_END;
            break;
        case __WASI_WHENCE_CUR:
            sys_whence = FILE_CURRENT;
            break;
        default:
            return __WASI_EINVAL;
    }

    LARGE_INTEGER distance_to_move = { .QuadPart = offset };
    LARGE_INTEGER updated_offset = { .QuadPart = 0 };

    int ret = SetFilePointerEx(handle->raw.handle, distance_to_move,
                               &updated_offset, sys_whence);

    if (ret == 0)
        return convert_windows_error_code(GetLastError());

    *new_offset = (__wasi_filesize_t)updated_offset.QuadPart;
    return __WASI_ESUCCESS;
}

__wasi_errno_t
os_fadvise(os_file_handle handle, __wasi_filesize_t offset,
           __wasi_filesize_t length, __wasi_advice_t advice)
{
    CHECK_VALID_FILE_HANDLE(handle);
    // Advisory information can be safely ignored if not supported
    switch (advice) {
        case __WASI_ADVICE_DONTNEED:
        case __WASI_ADVICE_NOREUSE:
        case __WASI_ADVICE_NORMAL:
        case __WASI_ADVICE_RANDOM:
        case __WASI_ADVICE_SEQUENTIAL:
        case __WASI_ADVICE_WILLNEED:
            return __WASI_ESUCCESS;
        default:
            return __WASI_EINVAL;
    }
}

__wasi_errno_t
os_fdopendir(os_file_handle handle, os_dir_stream *dir_stream)
{
    CHECK_VALID_FILE_HANDLE(handle);

    // Check the handle is a directory handle first
    DWORD windows_filetype = GetFileType(handle->raw.handle);

    __wasi_filetype_t filetype = __WASI_FILETYPE_UNKNOWN;
    __wasi_errno_t error =
        convert_windows_filetype(handle, windows_filetype, &filetype);

    if (error != __WASI_ESUCCESS)
        return error;

    if (filetype != __WASI_FILETYPE_DIRECTORY)
        return __WASI_ENOTDIR;

    *dir_stream = BH_MALLOC(sizeof(windows_dir_stream));

    if (*dir_stream == NULL)
        return __WASI_ENOMEM;

    init_dir_stream(*dir_stream, handle);

    return error;
}

__wasi_errno_t
os_rewinddir(os_dir_stream dir_stream)
{
    CHECK_VALID_WIN_DIR_STREAM(dir_stream);

    reset_dir_stream(dir_stream);

    return __WASI_ESUCCESS;
}

__wasi_errno_t
os_seekdir(os_dir_stream dir_stream, __wasi_dircookie_t position)
{
    CHECK_VALID_WIN_DIR_STREAM(dir_stream);

    if (dir_stream->cookie == position)
        return __WASI_ESUCCESS;

    if (dir_stream->cookie > position) {
        reset_dir_stream(dir_stream);
    }

    while (dir_stream->cookie < position) {
        __wasi_errno_t error = read_next_dir_entry(dir_stream, NULL);

        if (error != __WASI_ESUCCESS)
            return error;

        // We've reached the end of the directory.
        if (dir_stream->cookie == 0) {
            break;
        }
    }
    return __WASI_ESUCCESS;
}

__wasi_errno_t
os_readdir(os_dir_stream dir_stream, __wasi_dirent_t *entry,
           const char **d_name)
{
    CHECK_VALID_WIN_DIR_STREAM(dir_stream);

    FILE_ID_BOTH_DIR_INFO *file_id_both_dir_info = NULL;

    __wasi_errno_t error =
        read_next_dir_entry(dir_stream, &file_id_both_dir_info);

    if (error != __WASI_ESUCCESS || file_id_both_dir_info == NULL)
        return error;

    entry->d_ino = (__wasi_inode_t)file_id_both_dir_info->FileId.QuadPart;
    entry->d_namlen = (__wasi_dirnamlen_t)(file_id_both_dir_info->FileNameLength
                                           / (sizeof(wchar_t) / sizeof(char)));
    entry->d_next = (__wasi_dircookie_t)dir_stream->cookie;
    entry->d_type = get_disk_filetype(file_id_both_dir_info->FileAttributes);

    *d_name = dir_stream->current_entry_name;

    return __WASI_ESUCCESS;
}

__wasi_errno_t
os_closedir(os_dir_stream dir_stream)
{
    CHECK_VALID_WIN_DIR_STREAM(dir_stream);

    bool success = CloseHandle(dir_stream->handle->raw.handle);

    if (!success) {
        DWORD win_error = GetLastError();

        if (win_error == ERROR_INVALID_HANDLE)
            BH_FREE(dir_stream);
        return convert_windows_error_code(win_error);
    }

    BH_FREE(dir_stream);

    return __WASI_ESUCCESS;
}

os_dir_stream
os_get_invalid_dir_stream()
{
    return NULL;
}

bool
os_is_dir_stream_valid(os_dir_stream *dir_stream)
{
    assert(dir_stream != NULL);

    if (((*dir_stream) == NULL) || ((*dir_stream)->handle == NULL)
        || ((*dir_stream)->handle->type != windows_handle_type_file)
        || ((*dir_stream)->handle->raw.handle == INVALID_HANDLE_VALUE))
        return false;

    return true;
}

bool
os_is_handle_valid(os_file_handle *handle)
{
    assert(handle != NULL);

    CHECK_VALID_HANDLE_WITH_RETURN_VALUE(*handle, false);

    return true;
}

char *
os_realpath(const char *path, char *resolved_path)
{
    resolved_path = _fullpath(resolved_path, path, PATH_MAX);

    // Check the file/directory actually exists
    DWORD attributes = GetFileAttributesA(resolved_path);

    if (attributes == INVALID_FILE_ATTRIBUTES)
        return NULL;

    return resolved_path;
}

os_raw_file_handle
os_invalid_raw_handle(void)
{
    return INVALID_HANDLE_VALUE;
}
