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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_input_plugin.h>
#include <msgpack.h>
#include <sddl.h>
#include <locale.h>
#include "winlog.h"

#define REGKEY_MAXLEN 256
#define FMT_ISO8601 "%Y-%m-%d %H:%M:%S %z"
#define FMT_EVTLOG L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\%S\\%s"
#define FMT_EVTALT L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\%s"

/* 127 is the max number of function params */
#define PARAM_MAXNUM 127

#define SRCNAME(evt) ((wchar_t *) ((char *) (evt) + sizeof(EVENTLOGRECORD)))
#define BINDATA(evt) ((unsigned char *) (evt) + (evt)->DataOffset)

static void pack_nullstr(msgpack_packer *mp_pck)
{
    msgpack_pack_str(mp_pck, 0);
    msgpack_pack_str_body(mp_pck, "", 0);
}

static int pack_wstr(msgpack_packer *mp_pck, wchar_t *wstr, int use_ansi)
{
    int size;
    char *buf;
    UINT codePage = CP_UTF8;
    if (use_ansi) {
        codePage = CP_ACP;
    }

    /* Compute the buffer size first */
    size = WideCharToMultiByte(codePage, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (size == 0) {
        return -1;
    }

    buf = flb_malloc(size);
    if (buf == NULL) {
        flb_errno();
        return -1;
    }

    /* Convert UTF-16 into UTF-8/System code Page encoding */
    size = WideCharToMultiByte(codePage, 0, wstr, -1, buf, size, NULL, NULL);
    if (size == 0) {
        flb_free(buf);
        return -1;
    }

    /* Pack buf except the trailing '\0' */
    msgpack_pack_str(mp_pck, size - 1);
    msgpack_pack_str_body(mp_pck, buf, size - 1);
    flb_free(buf);
    return 0;
}

static int pack_time(msgpack_packer *mp_pck, int time)
{
    size_t len;
    struct tm tm;
    char buf[64];
    _locale_t locale;

    if (_localtime32_s(&tm, &time)) {
        flb_errno();
        return -1;
    }

    locale = _get_current_locale();
    if (locale == NULL) {
        return -1;
    }

    len = _strftime_l(buf, 64, FMT_ISO8601, &tm, locale);
    if (len == 0) {
        flb_errno();
        _free_locale(locale);
        return -1;
    }
    _free_locale(locale);
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, buf, len);

    return 0;
}

static int pack_event_type(msgpack_packer *mp_pck, int type)
{
    switch (type) {
    case EVENTLOG_SUCCESS:
        msgpack_pack_str(mp_pck, 7);
        msgpack_pack_str_body(mp_pck, "Success", 7);
        break;
    case EVENTLOG_INFORMATION_TYPE:
        msgpack_pack_str(mp_pck, 11);
        msgpack_pack_str_body(mp_pck, "Information", 11);
        break;
    case EVENTLOG_WARNING_TYPE:
        msgpack_pack_str(mp_pck, 7);
        msgpack_pack_str_body(mp_pck, "Warning", 7);
        break;
    case EVENTLOG_ERROR_TYPE:
        msgpack_pack_str(mp_pck, 5);
        msgpack_pack_str_body(mp_pck, "Error", 5);
        break;
    case EVENTLOG_AUDIT_SUCCESS:
        msgpack_pack_str(mp_pck, 12);
        msgpack_pack_str_body(mp_pck, "SuccessAudit", 12);
        break;
    case EVENTLOG_AUDIT_FAILURE:
        msgpack_pack_str(mp_pck, 12);
        msgpack_pack_str_body(mp_pck, "FailureAudit", 12);
        break;
    default:
        return -1;
    }
    return 0;
}

static int pack_binary(msgpack_packer *mp_pck, unsigned char *bin, int len)
{
    const char *hex = "0123456789abcdef";
    char *buf;
    int size = len * 2;
    int i;

    if (len == 0) {
        pack_nullstr(mp_pck);
        return 0;
    }

    buf = flb_malloc(size);
    if (buf == NULL) {
        flb_errno();
        return -1;
    }

    for (i = 0; i < len; i++) {
        buf[2*i]   = hex[bin[i] / 16];
        buf[2*i+1] = hex[bin[i] % 16];
    }
    msgpack_pack_str(mp_pck, size);
    msgpack_pack_str_body(mp_pck, buf, size);
    flb_free(buf);
    return 0;
}

static int pack_sid(msgpack_packer *mp_pck, PEVENTLOGRECORD evt,
                    struct winlog_config *ctx)
{
    size_t size;
    char *buf;
    char *sid = (char *) evt + evt->UserSidOffset;

    if (evt->UserSidLength == 0) {
        pack_nullstr(mp_pck);
        return 0;
    }

    if (!ConvertSidToStringSidA(sid, &buf)) {
        flb_plg_error(ctx->ins, "fail to convert SID: %i", GetLastError());
        return -1;
    }

    size = strlen(buf);
    msgpack_pack_str(mp_pck, size);
    msgpack_pack_str_body(mp_pck, buf, size);

    LocalFree(buf);
    return 0;
}

static wchar_t *read_registry(HKEY hkey, wchar_t *key, wchar_t *val)
{
    int ret;
    int size;
    wchar_t *buf;
    unsigned int flags = RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ;

    /* Get the buffer size first */
    ret = RegGetValueW(hkey, key, val, flags, NULL, NULL, &size);
    if (ret != ERROR_SUCCESS) {
        return NULL;
    }

    buf = flb_malloc(size);
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }

    /* Read data into buffer */
    ret = RegGetValueW(hkey, key, val, flags, NULL, buf, &size);
    if (ret != ERROR_SUCCESS) {
        flb_free(buf);
        return NULL;
    }
    return buf;
}

static wchar_t *query_guid(wchar_t *guid)
{
    int ret;
    wchar_t key[REGKEY_MAXLEN];

    ret = swprintf_s(key, REGKEY_MAXLEN, FMT_EVTALT, guid);
    if (ret == -1) {
        flb_errno();
        return NULL;
    }

    return read_registry(HKEY_LOCAL_MACHINE, key, L"MessageFileName");
}

static int pack_message(msgpack_packer *mp_pck, PEVENTLOGRECORD evt,
                        struct winlog_channel *ch, struct winlog_config *ctx)
{
    int ret;
    int i;
    HMODULE hfile;
    wchar_t key[REGKEY_MAXLEN];
    wchar_t *msg;
    wchar_t *paths;
    wchar_t *path;
    wchar_t *guid;
    wchar_t *state;
    wchar_t *tmp;
    DWORD_PTR *args = NULL;

    ret = swprintf_s(key, REGKEY_MAXLEN, FMT_EVTLOG, ch->name, SRCNAME(evt));
    if (ret == -1) {
        flb_errno();
        return -1;
    }

    guid = read_registry(HKEY_LOCAL_MACHINE, key, L"ProviderGuid");
    if (guid) {
        paths = query_guid(guid);
        flb_free(guid);
    }
    else {
        paths = read_registry(HKEY_LOCAL_MACHINE, key, L"EventMessageFile");
    }

    if (paths == NULL) {
        return -1;
    }

    if (evt->NumStrings) {
        args = flb_calloc(PARAM_MAXNUM, sizeof(DWORD_PTR));
        if (args == NULL) {
            flb_errno();
            flb_free(paths);
            return -1;
        }

        tmp = (wchar_t *) ((char *) evt + evt->StringOffset);
        for (i = 0; i < evt->NumStrings; i++) {
            args[i] = (DWORD_PTR) tmp;
            tmp += wcslen(tmp) + 1;
        }
    }

    path = paths;
    wcstok_s(path, L";", &state);
    while (path) {
        hfile = LoadLibraryExW(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
        if (hfile == NULL) {
            path = wcstok_s(NULL , L";", &state);
            continue;
        }

        ret = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE |
                             FORMAT_MESSAGE_ALLOCATE_BUFFER |
                             FORMAT_MESSAGE_ARGUMENT_ARRAY,
                             hfile,        /* lpSource */
                             evt->EventID, /* dwMessageId */
                             0,            /* dwLanguageId */
                             (LPWSTR) &msg,/* lpBuffer */
                             0,            /* nSize */
                             (va_list *) args);
        if (ret > 0) {
            ret = pack_wstr(mp_pck, msg, ctx->use_ansi);
            LocalFree(msg);
            FreeLibrary(hfile);
            flb_free(paths);
            flb_free(args);
            return ret;
        }
        FreeLibrary(hfile);
        path = wcstok_s(NULL , L";", &state);
    }

    flb_free(paths);
    flb_free(args);
    return -1;
}

static void pack_strings(msgpack_packer *mp_pck, PEVENTLOGRECORD evt, int use_ansi)
{
    int i;
    int len;
    wchar_t *wstr = (wchar_t *) ((char *) evt + evt->StringOffset);

    msgpack_pack_array(mp_pck, evt->NumStrings);

    for (i = 0; i < evt->NumStrings; i++) {
        if (pack_wstr(mp_pck, wstr, use_ansi)) {
            pack_nullstr(mp_pck);
        }
        wstr += wcslen(wstr) + 1;
    }
}

void winlog_pack_event(msgpack_packer *mp_pck, PEVENTLOGRECORD evt,
                       struct winlog_channel *ch, struct winlog_config *ctx)
{
    wchar_t *source_name = SRCNAME(evt);
    wchar_t *computer_name = source_name + wcslen(source_name) + 1;
    size_t len;
    int count = 13;

    if (ctx->string_inserts) {
        count++;
    }

    msgpack_pack_array(mp_pck, 2);
    flb_pack_time_now(mp_pck);

    msgpack_pack_map(mp_pck, count);

    /* RecordNumber */
    msgpack_pack_str(mp_pck, 12);
    msgpack_pack_str_body(mp_pck, "RecordNumber", 12);
    msgpack_pack_uint32(mp_pck, evt->RecordNumber);

    /* TimeGenerated */
    msgpack_pack_str(mp_pck, 13);
    msgpack_pack_str_body(mp_pck, "TimeGenerated", 13);
    if (pack_time(mp_pck, evt->TimeGenerated)) {
        flb_plg_error(ctx->ins, "invalid TimeGenerated %i", evt->TimeGenerated);
        pack_nullstr(mp_pck);
    }

    /* TimeWritten */
    msgpack_pack_str(mp_pck, 11);
    msgpack_pack_str_body(mp_pck, "TimeWritten", 11);
    if (pack_time(mp_pck, evt->TimeWritten)) {
        flb_plg_error(ctx->ins, "invalid TimeWritten %i", evt->TimeWritten);
        pack_nullstr(mp_pck);
    }

    /* EventId */
    msgpack_pack_str(mp_pck, 7);
    msgpack_pack_str_body(mp_pck, "EventID", 7);
    msgpack_pack_uint16(mp_pck, evt->EventID & 0xffff);

    /* Qualifiers */
    msgpack_pack_str(mp_pck, 10);
    msgpack_pack_str_body(mp_pck, "Qualifiers", 10);
    msgpack_pack_uint16(mp_pck, evt->EventID >> 16);

    /* EventType */
    msgpack_pack_str(mp_pck, 9);
    msgpack_pack_str_body(mp_pck, "EventType", 9);
    if (pack_event_type(mp_pck, evt->EventType)) {
        flb_plg_error(ctx->ins, "invalid EventType %i", evt->EventType);
        pack_nullstr(mp_pck);
    }

    /* EventCategory */
    msgpack_pack_str(mp_pck, 13);
    msgpack_pack_str_body(mp_pck, "EventCategory", 13);
    msgpack_pack_uint16(mp_pck, evt->EventCategory);

    /* Channel */
    len = strlen(ch->name);
    msgpack_pack_str(mp_pck, 7);
    msgpack_pack_str_body(mp_pck, "Channel", 7);
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, ch->name, len);

    /* Source Name */
    msgpack_pack_str(mp_pck, 10);
    msgpack_pack_str_body(mp_pck, "SourceName", 10);
    if (pack_wstr(mp_pck, source_name, ctx->use_ansi)) {
        flb_plg_error(ctx->ins, "invalid SourceName '%ls'", source_name);
        pack_nullstr(mp_pck);
    }

    /* Computer Name */
    msgpack_pack_str(mp_pck, 12);
    msgpack_pack_str_body(mp_pck, "ComputerName", 12);
    if (pack_wstr(mp_pck, computer_name, ctx->use_ansi)) {
        flb_plg_error(ctx->ins, "invalid ComputerName '%ls'", computer_name);
        pack_nullstr(mp_pck);
    }

    /* Event-specific Data */
    msgpack_pack_str(mp_pck, 4);
    msgpack_pack_str_body(mp_pck, "Data", 4);
    if (pack_binary(mp_pck, BINDATA(evt), evt->DataLength)) {
        pack_nullstr(mp_pck);
    }

    /* Sid */
    msgpack_pack_str(mp_pck, 3);
    msgpack_pack_str_body(mp_pck, "Sid", 3);
    if (pack_sid(mp_pck, evt, ctx)) {
        pack_nullstr(mp_pck);
    }

    /* Message */
    msgpack_pack_str(mp_pck, 7);
    msgpack_pack_str_body(mp_pck, "Message", 7);
    if (pack_message(mp_pck, evt, ch, ctx)) {
        pack_nullstr(mp_pck);
    }

    /* StringInserts (optional) */
    if (ctx->string_inserts) {
        msgpack_pack_str(mp_pck, 13);
        msgpack_pack_str_body(mp_pck, "StringInserts", 13);
        pack_strings(mp_pck, evt, ctx->use_ansi);
    }
}
