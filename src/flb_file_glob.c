/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fluent-bit/flb_file_glob.h>
#include <fluent-bit/flb_mem.h>

#include <stdint.h>
#include <string.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <fluent-bit/flb_compat.h>

wchar_t *flb_file_win32_utf8_to_wide(const char *str)
{
    int len;
    wchar_t *buf;

    if (str == NULL) {
        return NULL;
    }

    len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                              str, -1, NULL, 0);
    if (len == 0) {
        return NULL;
    }

    buf = flb_calloc(len, sizeof(wchar_t));
    if (buf == NULL) {
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            str, -1, buf, len) == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

char *flb_file_win32_wide_to_utf8(const wchar_t *str)
{
    int len;
    char *buf;

    if (str == NULL) {
        return NULL;
    }

    len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                              str, -1, NULL, 0, NULL, NULL);
    if (len == 0) {
        return NULL;
    }

    buf = flb_calloc(len, sizeof(char));
    if (buf == NULL) {
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                            str, -1, buf, len, NULL, NULL) == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

static int glob_windows(const char *path, int utf8,
                        flb_file_glob_callback callback, void *data)
{
    const char *star;
    const char *component;
    const char *suffix;
    char *pattern;
    char *candidate;
    char *converted;
    const char *filename;
    wchar_t *wide_pattern;
    size_t prefix_len;
    size_t pattern_len;
    size_t name_len;
    size_t suffix_len;
    size_t candidate_len;
    int status = FLB_FILE_GLOB_NO_MATCHES;
    int result;
    DWORD attributes = INVALID_FILE_ATTRIBUTES;
    HANDLE search = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAA entry;
    WIN32_FIND_DATAW wide_entry;

    if (!utf8 && strlen(path) >= MAX_PATH) {
        return FLB_FILE_GLOB_INVALID_PATH;
    }

    star = strchr(path, '*');
    component = star;
    suffix = star;
    if (star == NULL) {
        suffix = path + strlen(path);
    }
    else {
        while (component > path && component[-1] != '\\' && component[-1] != '/') {
            component--;
        }
        while (*suffix && *suffix != '\\' && *suffix != '/') {
            suffix++;
        }
    }

    pattern_len = suffix - path;
    pattern = flb_malloc(pattern_len + 1);
    if (pattern == NULL) {
        return FLB_FILE_GLOB_NO_MEMORY;
    }
    memcpy(pattern, path, pattern_len);
    pattern[pattern_len] = '\0';

    if (utf8) {
        wide_pattern = flb_file_win32_utf8_to_wide(pattern);
        if (wide_pattern == NULL) {
            flb_free(pattern);
            return FLB_FILE_GLOB_INVALID_PATH;
        }
        if (star == NULL) {
            attributes = GetFileAttributesW(wide_pattern);
        }
        else {
            search = FindFirstFileW(wide_pattern, &wide_entry);
        }
        flb_free(wide_pattern);
    }
    else if (star == NULL) {
        attributes = GetFileAttributesA(pattern);
    }
    else {
        search = FindFirstFileA(pattern, &entry);
    }

    if (star == NULL) {
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            callback(pattern, data);
            status = FLB_FILE_GLOB_SUCCESS;
        }
        flb_free(pattern);
        return status;
    }
    flb_free(pattern);

    if (search == INVALID_HANDLE_VALUE) {
        return FLB_FILE_GLOB_NO_MATCHES;
    }

    prefix_len = component - path;
    suffix_len = strlen(suffix);
    do {
        converted = NULL;
        if (utf8) {
            converted = flb_file_win32_wide_to_utf8(wide_entry.cFileName);
            if (converted == NULL) {
                continue;
            }
            filename = converted;
        }
        else {
            filename = entry.cFileName;
        }

        if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0 ||
            strchr(filename, '*')) {
            flb_free(converted);
            continue;
        }

        name_len = strlen(filename);
        candidate_len = prefix_len + name_len + suffix_len;
        if (!utf8 && candidate_len >= MAX_PATH) {
            flb_free(converted);
            continue;
        }

        candidate = flb_malloc(candidate_len + 1);
        if (candidate == NULL) {
            flb_free(converted);
            status = FLB_FILE_GLOB_NO_MEMORY;
            break;
        }

        memcpy(candidate, path, prefix_len);
        memcpy(candidate + prefix_len, filename, name_len);
        memcpy(candidate + prefix_len + name_len, suffix, suffix_len + 1);
        flb_free(converted);

        if (suffix_len > 0) {
            result = glob_windows(candidate, utf8, callback, data);
            flb_free(candidate);
            if (result == FLB_FILE_GLOB_NO_MEMORY) {
                status = result;
                break;
            }
            if (result == FLB_FILE_GLOB_SUCCESS) {
                status = result;
            }
        }
        else {
            callback(candidate, data);
            flb_free(candidate);
            status = FLB_FILE_GLOB_SUCCESS;
        }
    } while (utf8 ? FindNextFileW(search, &wide_entry) : FindNextFileA(search, &entry));

    FindClose(search);
    return status;
}
#else
#include <glob.h>
#ifndef GLOB_TILDE
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>

static int expand_tilde(const char *path, char **expanded)
{
    const char *suffix;
    const char *directory;
    char *user = NULL;
    char *buffer = NULL;
    char *new_buffer;
    struct passwd entry;
    struct passwd *account;
    size_t user_len;
    size_t directory_len;
    size_t buffer_size = 1024;
    size_t suffix_len;
    int result = FLB_FILE_GLOB_SUCCESS;
    int lookup;

    *expanded = NULL;
    if (path[0] != '~') {
        return result;
    }

    suffix = strchr(path, '/');
    if (suffix == NULL) {
        suffix = path + strlen(path);
    }
    user_len = suffix - (path + 1);
    if (user_len == 0) {
        directory = getenv("HOME");
    }
    else {
        user = flb_malloc(user_len + 1);
        if (user == NULL) {
            return FLB_FILE_GLOB_NO_MEMORY;
        }
        memcpy(user, path + 1, user_len);
        user[user_len] = '\0';

        do {
            new_buffer = flb_realloc(buffer, buffer_size);
            if (new_buffer == NULL) {
                result = FLB_FILE_GLOB_NO_MEMORY;
                goto done;
            }
            buffer = new_buffer;
            lookup = getpwnam_r(user, &entry, buffer, buffer_size, &account);
            if (lookup == ERANGE) {
                if (buffer_size > SIZE_MAX / 2) {
                    result = FLB_FILE_GLOB_NO_MEMORY;
                    goto done;
                }
                buffer_size *= 2;
            }
        } while (lookup == ERANGE);

        directory = lookup == 0 && account != NULL ? entry.pw_dir : NULL;
    }

    /* Fall back to the borrowed input if the home directory is unavailable. */
    if (directory != NULL) {
        directory_len = strlen(directory);
        suffix_len = strlen(suffix);
        *expanded = flb_malloc(directory_len + suffix_len + 1);
        if (*expanded == NULL) {
            result = FLB_FILE_GLOB_NO_MEMORY;
            goto done;
        }
        memcpy(*expanded, directory, directory_len);
        memcpy(*expanded + directory_len, suffix, suffix_len + 1);
    }

done:
    flb_free(buffer);
    flb_free(user);
    return result;
}
#endif

static int glob_posix(const char *pattern, unsigned int flags,
                      flb_file_glob_callback callback, void *data)
{
    int result;
    int native_flags = GLOB_ERR;
    size_t i;
    glob_t matches = {0};
#ifndef GLOB_TILDE
    char *expanded = NULL;
#endif

    if (flags & FLB_FILE_GLOB_EXPAND_TILDE) {
#ifdef GLOB_TILDE
        native_flags |= GLOB_TILDE;
#else
        result = expand_tilde(pattern, &expanded);
        if (result != FLB_FILE_GLOB_SUCCESS) {
            return result;
        }
        if (expanded != NULL) {
            pattern = expanded;
        }
#endif
    }

    result = glob(pattern, native_flags, NULL, &matches);
#ifndef GLOB_TILDE
    flb_free(expanded);
#endif
    if (result == 0) {
        for (i = 0; i < matches.gl_pathc; i++) {
            callback(matches.gl_pathv[i], data);
        }
    }
    globfree(&matches);

    switch (result) {
    case 0:
        return FLB_FILE_GLOB_SUCCESS;
    case GLOB_NOMATCH:
        return FLB_FILE_GLOB_NO_MATCHES;
    case GLOB_NOSPACE:
        return FLB_FILE_GLOB_NO_MEMORY;
    default:
        return FLB_FILE_GLOB_ABORTED;
    }
}
#endif

int flb_file_glob(const char *pattern, unsigned int flags,
                  flb_file_glob_callback callback, void *data)
{
    if (pattern == NULL || callback == NULL || *pattern == '\0') {
        return FLB_FILE_GLOB_INVALID_PATH;
    }

#ifdef FLB_SYSTEM_WINDOWS
    return glob_windows(pattern, flags & FLB_FILE_GLOB_WINDOWS_UTF8, callback, data);
#else
    return glob_posix(pattern, flags, callback, data);
#endif
}
