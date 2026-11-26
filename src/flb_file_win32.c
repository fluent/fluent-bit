/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_mem.h>

#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <winternl.h>

#define FILE_SAFE_SHARE (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define FILE_REMOVE_MAX_DEPTH 64

/* The user-mode SDK omits this information class and function declaration. */
#define FLB_FILE_RENAME_INFORMATION ((FILE_INFORMATION_CLASS) 10)

NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(HANDLE file, PIO_STATUS_BLOCK io_status,
                                             PVOID information, ULONG length,
                                             FILE_INFORMATION_CLASS information_class);

struct flb_file_rename_information {
    BOOLEAN replace_if_exists;
    HANDLE root_directory;
    ULONG file_name_length;
    WCHAR file_name[1];
};

static void file_set_errno(DWORD error)
{
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        errno = ENOENT;
        break;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
        errno = EEXIST;
        break;
    case ERROR_DIRECTORY:
        errno = ENOTDIR;
        break;
    case ERROR_DIR_NOT_EMPTY:
        errno = ENOTEMPTY;
        break;
    case ERROR_FILENAME_EXCED_RANGE:
        errno = ENAMETOOLONG;
        break;
    case ERROR_INVALID_NAME:
    case ERROR_INVALID_PARAMETER:
        errno = EINVAL;
        break;
    case ERROR_NOT_SAME_DEVICE:
        errno = EXDEV;
        break;
    case ERROR_DISK_FULL:
        errno = ENOSPC;
        break;
    default:
        errno = EACCES;
        break;
    }
}

/* Normalize separators and resolve the working directory before walking.
 * Reject parent traversal before GetFullPathNameW can erase it. */
static wchar_t *file_absolute_path(const char *root, const char *path, UINT code_page)
{
    wchar_t wide_root[MAX_PATH];
    wchar_t *input;
    wchar_t *absolute = NULL;
    wchar_t *cursor;
    const wchar_t *component;
    DWORD capacity;
    DWORD length;
    int count;
    int root_count;
    int prefix_length = 0;

    if (path == NULL || *path == '\0') {
        errno = EINVAL;
        return NULL;
    }
    if (root != NULL) {
        if (*root == '\0' || *path == '\\' || *path == '/' || strchr(path, ':') != NULL) {
            errno = EINVAL;
            return NULL;
        }
        root_count = MultiByteToWideChar(code_page, MB_ERR_INVALID_CHARS, root, -1, NULL, 0);
        if (root_count == 0 || root_count > MAX_PATH) {
            errno = root_count == 0 ? EINVAL : ENAMETOOLONG;
            return NULL;
        }
        if (MultiByteToWideChar(code_page, MB_ERR_INVALID_CHARS, root, -1,
                                wide_root, root_count) == 0) {
            errno = EINVAL;
            return NULL;
        }
        prefix_length = root_count - 1;
        /* A bare drive designator is relative to that drive's current directory. */
        if (prefix_length == 2 && wide_root[1] == L':') {
            errno = EINVAL;
            return NULL;
        }
        /* Inspect characters, since a multibyte trail byte can be 0x5c. */
        if (wide_root[prefix_length - 1] != L'\\' && wide_root[prefix_length - 1] != L'/') {
            wide_root[prefix_length++] = L'\\';
        }
    }

    count = MultiByteToWideChar(code_page, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (count == 0 || count > 32767) {
        errno = count == 0 ? EINVAL : ENAMETOOLONG;
        return NULL;
    }
    if (root != NULL && prefix_length + count > MAX_PATH) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    count += prefix_length;
    input = flb_malloc(count * sizeof(wchar_t));
    if (input == NULL) {
        return NULL;
    }
    if (prefix_length > 0) {
        memcpy(input, wide_root, prefix_length * sizeof(wchar_t));
    }
    if (MultiByteToWideChar(code_page, MB_ERR_INVALID_CHARS, path, -1,
                            input + prefix_length, count - prefix_length) == 0) {
        errno = EINVAL;
        goto done;
    }

    for (cursor = input; *cursor != L'\0'; cursor++) {
        if (*cursor == L'/') {
            *cursor = L'\\';
        }
    }
    cursor = input;
    if (wcsncmp(cursor, L"\\\\?\\", 4) == 0) {
        cursor += 4;
        if (_wcsnicmp(cursor, L"UNC\\", 4) == 0) {
            cursor += 2;
            cursor[0] = L'\\';
            cursor[1] = L'\\';
        }
        else if (wcslen(cursor) < 3 || cursor[1] != L':' || cursor[2] != L'\\') {
            errno = EINVAL;
            goto done;
        }
    }
    if (wcsncmp(cursor, L"\\\\.\\", 4) == 0 ||
        wcsncmp(cursor, L"\\\\?\\", 4) == 0) {
        errno = EINVAL;
        goto done;
    }
    component = cursor;
    if (*component != L'\0' && component[1] == L':') {
        component += 2;
    }
    if (wcspbrk(component, L":*?\"<>|") != NULL) {
        errno = EINVAL;
        goto done;
    }
    while (*component != L'\0') {
        length = (DWORD) wcscspn(component, L"\\");
        if (length == 2 && wcsncmp(component, L"..", 2) == 0) {
            errno = EACCES;
            goto done;
        }
        if (length > 0 && (length != 1 || *component != L'.') &&
            (component[length - 1] == L'.' || component[length - 1] == L' ')) {
            errno = EINVAL;
            goto done;
        }
        component += length;
        if (*component != L'\0') {
            component++;
        }
    }

    capacity = GetFullPathNameW(cursor, 0, NULL, NULL);
    if (capacity == 0 || capacity > 32767) {
        file_set_errno(capacity == 0 ? GetLastError() : ERROR_FILENAME_EXCED_RANGE);
        goto done;
    }
    absolute = flb_malloc(capacity * sizeof(wchar_t));
    if (absolute != NULL) {
        length = GetFullPathNameW(cursor, capacity, absolute, NULL);
        if (length == 0 || length >= capacity) {
            file_set_errno(length == 0 ? GetLastError() : ERROR_FILENAME_EXCED_RANGE);
            flb_free(absolute);
            absolute = NULL;
        }
    }

done:
    flb_free(input);
    return absolute;
}

/* Open a single component against a held parent, with reparse processing
 * disabled. The caller can inspect or remove a reparse entry by handle. */
static HANDLE file_open_at(HANDLE parent, const wchar_t *name, ACCESS_MASK access,
                           ULONG disposition, ULONG options)
{
    HANDLE handle;
    UNICODE_STRING object_name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    size_t bytes;
    ULONG share;

    bytes = wcslen(name) * sizeof(wchar_t);
    object_name.Buffer = (wchar_t *) name;
    object_name.Length = (USHORT) bytes;
    object_name.MaximumLength = object_name.Length;
    InitializeObjectAttributes(&attributes, &object_name, OBJ_CASE_INSENSITIVE, parent, NULL);
    share = FILE_SAFE_SHARE;
    if (access & DELETE) {
        /* Keep the entry from being moved while a deletion or rename is in progress. */
        share &= ~FILE_SHARE_DELETE;
    }
    status = NtCreateFile(&handle, access | SYNCHRONIZE, &attributes, &io_status, NULL,
                          FILE_ATTRIBUTE_NORMAL, share, disposition,
                          options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL, 0);
    if (status < 0) {
        file_set_errno(RtlNtStatusToDosError(status));
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

/* Opening an existing entry should not require permission to create it. */
static HANDLE file_open_or_create_at(HANDLE parent, const wchar_t *name, ACCESS_MASK access,
                                     ULONG disposition, ULONG options)
{
    HANDLE handle;

    if (disposition != FILE_OPEN_IF) {
        return file_open_at(parent, name, access, disposition, options);
    }
    handle = file_open_at(parent, name, access, FILE_OPEN, options);
    if (handle == INVALID_HANDLE_VALUE && errno == ENOENT) {
        handle = file_open_at(parent, name, access, FILE_CREATE, options);
        if (handle == INVALID_HANDLE_VALUE && errno == EEXIST) {
            handle = file_open_at(parent, name, access, FILE_OPEN, options);
        }
    }
    return handle;
}

static int file_type(HANDLE handle, DWORD *attributes)
{
    FILE_ATTRIBUTE_TAG_INFO info;

    if (GetFileType(handle) != FILE_TYPE_DISK) {
        errno = EINVAL;
        return -1;
    }
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info))) {
        file_set_errno(GetLastError());
        return -1;
    }
    *attributes = info.FileAttributes;
    return 0;
}

static HANDLE file_check_type(HANDLE handle, int directory)
{
    DWORD attributes;

    if (handle != INVALID_HANDLE_VALUE) {
        if (file_type(handle, &attributes) == 0) {
            if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                !!(attributes & FILE_ATTRIBUTE_DIRECTORY) == directory) {
                return handle;
            }
            errno = EACCES;
        }
        CloseHandle(handle);
    }
    return INVALID_HANDLE_VALUE;
}

static HANDLE file_walk(wchar_t *path, wchar_t **leaf, int create_parents)
{
    wchar_t *component;
    wchar_t *next;
    wchar_t first;
    size_t share_length;
    HANDLE parent;
    HANDLE child;

    /* Start from a drive root or a UNC share. Device namespaces are excluded
     * by file_absolute_path; a share root must also open as a disk directory. */
    if (path[0] == L'\\' && path[1] == L'\\') {
        component = wcschr(path + 2, L'\\');
        if (component == NULL || component == path + 2 || component[1] == L'\0' ||
            component[1] == L'\\' ||
            (component == path + 3 && (path[2] == L'.' || path[2] == L'?'))) {
            errno = EINVAL;
            return INVALID_HANDLE_VALUE;
        }
        component++;
        share_length = wcscspn(component, L"\\");
        if ((share_length == 4 && _wcsnicmp(component, L"pipe", 4) == 0) ||
            (share_length == 8 && _wcsnicmp(component, L"mailslot", 8) == 0)) {
            errno = EINVAL;
            return INVALID_HANDLE_VALUE;
        }
        component += share_length;
        if (*component == L'\\') {
            component++;
        }
    }
    else if (((path[0] >= L'A' && path[0] <= L'Z') ||
              (path[0] >= L'a' && path[0] <= L'z')) && path[1] == L':' && path[2] == L'\\') {
        component = path + 3;
    }
    else {
        errno = EINVAL;
        return INVALID_HANDLE_VALUE;
    }

    first = *component;
    *component = L'\0';
    /* Request attributes for the reparse check. Windows enforces traversal
     * during child lookup, including the caller's bypass-traverse privilege. */
    parent = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SAFE_SHARE, NULL, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (parent == INVALID_HANDLE_VALUE) {
        file_set_errno(GetLastError());
    }
    *component = first;
    parent = file_check_type(parent, 1);
    if (parent == INVALID_HANDLE_VALUE) {
        return parent;
    }

    while ((next = wcschr(component, L'\\')) != NULL) {
        *next++ = L'\0';
        if (*component != L'\0') {
            child = file_open_or_create_at(parent, component, FILE_READ_ATTRIBUTES,
                                           create_parents ? FILE_OPEN_IF : FILE_OPEN,
                                           FILE_DIRECTORY_FILE);
            child = file_check_type(child, 1);
            CloseHandle(parent);
            if (child == INVALID_HANDLE_VALUE) {
                return child;
            }
            parent = child;
        }
        component = next;
    }
    *leaf = component;
    return parent;
}

static HANDLE file_open_path(const char *root, const char *path, UINT code_page,
                             ACCESS_MASK access, ULONG disposition, ULONG options,
                             int create_parents)
{
    wchar_t *absolute;
    wchar_t *leaf;
    HANDLE parent;
    HANDLE handle = INVALID_HANDLE_VALUE;

    absolute = file_absolute_path(root, path, code_page);
    if (absolute == NULL) {
        return INVALID_HANDLE_VALUE;
    }
    parent = file_walk(absolute, &leaf, create_parents);
    if (parent != INVALID_HANDLE_VALUE) {
        if (*leaf != L'\0') {
            handle = file_open_or_create_at(parent, leaf, access, disposition, options);
        }
        else {
            errno = EISDIR;
        }
        CloseHandle(parent);
    }
    flb_free(absolute);
    return handle;
}

static HANDLE file_open_safe_handle(const char *root, const char *path, int flags,
                                    int mkdir_mode, UINT code_page)
{
    ACCESS_MASK access = FILE_READ_ATTRIBUTES;
    ULONG disposition = FILE_OPEN;
    HANDLE handle;
    LARGE_INTEGER zero = {0};

    if ((flags & O_WRONLY) == 0) {
        access |= GENERIC_READ;
    }
    if (flags & (O_WRONLY | O_RDWR)) {
        access |= GENERIC_WRITE;
    }
    if (flags & O_CREAT) {
        disposition = (flags & O_EXCL) ? FILE_CREATE : FILE_OPEN_IF;
    }

    handle = file_open_path(root, path, code_page, access, disposition,
                            FILE_NON_DIRECTORY_FILE, mkdir_mode != 0);
    handle = file_check_type(handle, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    if ((flags & O_TRUNC) &&
        (!SetFilePointerEx(handle, zero, NULL, FILE_BEGIN) || !SetEndOfFile(handle))) {
        file_set_errno(GetLastError());
        CloseHandle(handle);
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

HANDLE flb_file_open_safe_for_read(const char *path, UINT code_page)
{
    return file_open_safe_handle(NULL, path, O_RDONLY, 0, code_page);
}

static int file_open_safe(const char *root, const char *path, int flags,
                          int mkdir_mode, UINT code_page)
{
    HANDLE handle;
    int fd;

    handle = file_open_safe_handle(root, path, flags, mkdir_mode, code_page);
    if (handle == INVALID_HANDLE_VALUE) {
        return -1;
    }
    if ((flags & O_TEXT) == 0) {
        flags |= O_BINARY;
    }
    fd = _open_osfhandle((intptr_t) handle, flags | O_NOINHERIT);
    if (fd < 0) {
        CloseHandle(handle);
    }
    return fd;
}

int flb_file_open_safe(const char *root, const char *path, int flags,
                       int mode, int mkdir_mode)
{
    (void) mode;
    return file_open_safe(root, path, flags, mkdir_mode, CP_ACP);
}

int flb_file_open_safe_utf8(const char *path, int flags)
{
    return file_open_safe(NULL, path, flags, 0, CP_UTF8);
}

int flb_file_mkdir_safe(const char *path, int mode)
{
    wchar_t *absolute;
    wchar_t *leaf;
    HANDLE parent;
    HANDLE child;

    absolute = file_absolute_path(NULL, path, CP_ACP);
    if (absolute == NULL) {
        return -1;
    }
    parent = file_walk(absolute, &leaf, mode != 0);
    if (parent == INVALID_HANDLE_VALUE) {
        flb_free(absolute);
        return -1;
    }
    if (*leaf != L'\0') {
        child = file_open_or_create_at(parent, leaf, FILE_READ_ATTRIBUTES,
                                       mode ? FILE_OPEN_IF : FILE_OPEN, FILE_DIRECTORY_FILE);
        CloseHandle(parent);
        parent = file_check_type(child, 1);
    }
    flb_free(absolute);
    if (parent == INVALID_HANDLE_VALUE) {
        return -1;
    }
    CloseHandle(parent);
    return 0;
}

int flb_file_rename_safe(const char *source, const char *destination)
{
    wchar_t *absolute;
    wchar_t *source_path;
    wchar_t *leaf;
    wchar_t *source_leaf;
    HANDLE source_handle;
    HANDLE source_parent;
    HANDLE parent;
    struct flb_file_rename_information *rename_info;
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    size_t bytes;
    size_t size;
    size_t parent_length;
    int same_parent;
    int ret = -1;

    absolute = file_absolute_path(NULL, destination, CP_ACP);
    if (absolute == NULL) {
        return -1;
    }
    source_path = file_absolute_path(NULL, source, CP_ACP);
    if (source_path == NULL) {
        flb_free(absolute);
        return -1;
    }
    source_leaf = wcsrchr(source_path, L'\\');
    leaf = wcsrchr(absolute, L'\\');
    if (leaf == NULL || source_leaf == NULL || source_leaf[1] == L'\0') {
        errno = EINVAL;
        goto release_path;
    }
    source_leaf++;
    parent_length = leaf + 1 - absolute;
    same_parent = (size_t) (source_leaf - source_path) == parent_length &&
                  wcsncmp(source_path, absolute, parent_length) == 0;

    parent = file_walk(absolute, &leaf, 0);
    if (parent == INVALID_HANDLE_VALUE) {
        goto release_path;
    }
    if (*leaf == L'\0') {
        errno = EINVAL;
        goto release_parent;
    }
    source_parent = parent;
    if (!same_parent) {
        source_parent = file_walk(source_path, &source_leaf, 0);
        if (source_parent == INVALID_HANDLE_VALUE) {
            goto release_parent;
        }
        if (*source_leaf == L'\0') {
            CloseHandle(source_parent);
            errno = EINVAL;
            goto release_parent;
        }
    }
    source_handle = file_open_at(source_parent, source_leaf, DELETE, FILE_OPEN,
                                 FILE_NON_DIRECTORY_FILE);
    if (!same_parent) {
        CloseHandle(source_parent);
    }
    if (source_handle == INVALID_HANDLE_VALUE) {
        goto release_parent;
    }

    bytes = wcslen(leaf) * sizeof(wchar_t);
    size = sizeof(*rename_info) + bytes;
    rename_info = flb_calloc(1, size);
    if (rename_info != NULL) {
        rename_info->replace_if_exists = TRUE;
        /* A simple name is relative to the source directory when this field is NULL. */
        rename_info->root_directory = same_parent ? NULL : parent;
        rename_info->file_name_length = (ULONG) bytes;
        memcpy(rename_info->file_name, leaf, bytes);
        status = NtSetInformationFile(source_handle, &io_status, rename_info, (ULONG) size,
                                      FLB_FILE_RENAME_INFORMATION);
        if (status >= 0) {
            ret = 0;
        }
        else {
            file_set_errno(RtlNtStatusToDosError(status));
        }
        flb_free(rename_info);
    }
    CloseHandle(source_handle);
release_parent:
    CloseHandle(parent);
release_path:
    flb_free(source_path);
    flb_free(absolute);
    return ret;
}

static int file_delete(HANDLE handle)
{
    FILE_DISPOSITION_INFO disposition = {TRUE};

    if (!SetFileInformationByHandle(handle, FileDispositionInfo, &disposition,
                                    sizeof(disposition))) {
        file_set_errno(GetLastError());
        return -1;
    }
    return 0;
}

int flb_file_unlink_safe(const char *path)
{
    HANDLE handle;
    int ret;

    handle = file_open_path(NULL, path, CP_ACP, DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        return -1;
    }
    ret = file_delete(handle);
    CloseHandle(handle);
    return ret;
}

static int file_remove_entry(HANDLE parent, const wchar_t *name, unsigned int depth);

static int file_remove_children(HANDLE directory, unsigned int depth)
{
    FILE_ID_BOTH_DIR_INFO *entries;
    FILE_ID_BOTH_DIR_INFO *entry;
    wchar_t name[MAX_PATH];
    size_t length;
    DWORD error;
    FILE_INFO_BY_HANDLE_CLASS query = FileIdBothDirectoryRestartInfo;
    int ret = -1;

    entries = flb_malloc(4096);
    if (entries == NULL) {
        return -1;
    }
    while (GetFileInformationByHandleEx(directory, query, entries, 4096)) {
        query = FileIdBothDirectoryInfo;
        entry = entries;
        while (1) {
            length = entry->FileNameLength / sizeof(wchar_t);
            if (length >= sizeof(name) / sizeof(name[0])) {
                errno = ENAMETOOLONG;
                goto done;
            }
            memcpy(name, entry->FileName, entry->FileNameLength);
            name[length] = L'\0';
            if (wcscmp(name, L".") != 0 && wcscmp(name, L"..") != 0 &&
                file_remove_entry(directory, name, depth + 1) != 0) {
                goto done;
            }
            if (entry->NextEntryOffset == 0) {
                break;
            }
            entry = (FILE_ID_BOTH_DIR_INFO *) ((char *) entry + entry->NextEntryOffset);
        }
    }
    error = GetLastError();
    if (error == ERROR_NO_MORE_FILES) {
        ret = 0;
    }
    else {
        file_set_errno(error);
    }
done:
    flb_free(entries);
    return ret;
}

static int file_remove_entry(HANDLE parent, const wchar_t *name, unsigned int depth)
{
    HANDLE handle;
    HANDLE directory;
    DWORD attributes;
    int ret;

    if (depth >= FILE_REMOVE_MAX_DEPTH) {
        errno = ELOOP;
        return -1;
    }
    handle = file_open_at(parent, name, DELETE | FILE_READ_ATTRIBUTES, FILE_OPEN, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        return -1;
    }
    ret = file_type(handle, &attributes);
    if (ret == 0 && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !(attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        /* An empty relative name reopens the directory represented by handle. */
        directory = file_open_at(handle, L"", FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                                 FILE_OPEN, FILE_DIRECTORY_FILE);
        directory = file_check_type(directory, 1);
        if (directory == INVALID_HANDLE_VALUE) {
            ret = -1;
        }
        else {
            ret = file_remove_children(directory, depth);
            CloseHandle(directory);
        }
    }
    if (ret == 0) {
        ret = file_delete(handle);
    }
    CloseHandle(handle);
    return ret;
}

int flb_file_remove_tree_safe(const char *path)
{
    wchar_t *absolute;
    wchar_t *leaf;
    HANDLE parent;
    int ret = -1;

    absolute = file_absolute_path(NULL, path, CP_ACP);
    if (absolute == NULL) {
        return -1;
    }
    parent = file_walk(absolute, &leaf, 0);
    if (parent != INVALID_HANDLE_VALUE) {
        if (*leaf != L'\0') {
            ret = file_remove_entry(parent, leaf, 0);
        }
        else {
            errno = EINVAL;
        }
        CloseHandle(parent);
    }
    flb_free(absolute);
    return ret;
}

