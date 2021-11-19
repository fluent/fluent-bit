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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_input_plugin.h>
#include <msgpack.h>
#include <sddl.h>
#include <locale.h>
#include "winevtlog.h"

#define FORMAT_ISO8601 "%Y-%m-%d %H:%M:%S %z"

#define BINDATA(evt) ((unsigned char *) (evt) + (evt)->DataOffset)

static void pack_nullstr(msgpack_packer *mp_pck)
{
    msgpack_pack_str(mp_pck, 0);
    msgpack_pack_str_body(mp_pck, "", 0);
}

static int pack_wstr(msgpack_packer *mp_pck, const wchar_t *wstr, struct winevtlog_config *ctx)
{
    int size;
    char *buf;
    UINT code_page = CP_UTF8;
    LPCSTR defaultChar = L" ";

    if (ctx->use_ansi) {
        code_page = CP_ACP;
    }

    /* Compute the buffer size first */
    size = WideCharToMultiByte(code_page, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (size == 0) {
        return -1;
    }

    buf = flb_malloc(size);
    if (buf == NULL) {
        flb_errno();
        return -1;
    }

    /* Convert UTF-16 into UTF-8 */
    size = WideCharToMultiByte(code_page, 0, wstr, -1, buf, size, defaultChar, NULL);
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

static int pack_binary(msgpack_packer *mp_pck, PBYTE bin, size_t length)
{
    const char *HEX_TABLE = "0123456789ABCDEF";
    char *buffer;
    int size = length * 2;
    size_t i, j;
    unsigned int idx = 0;

    if (length == 0) {
        pack_nullstr(mp_pck);
        return 0;
    }

    buffer = flb_malloc(size);
    if (buffer == NULL) {
        flb_errno();
        return -1;
    }

    for (i = 0; i < length; i++) {
        for (j = 0; j < 2; j++) {
            idx = (unsigned int)(bin[i] >> (j * 4) & 0x0F);
            buffer[2*i+(1-j)] = HEX_TABLE[idx];
        }
    }
    msgpack_pack_str(mp_pck, size);
    msgpack_pack_str_body(mp_pck, buffer, size);
    flb_free(buffer);

    return 0;
}

static int pack_guid(msgpack_packer *mp_pck, const GUID *guid, struct winevtlog_config *ctx)
{
    LPOLESTR p = NULL;

    if (FAILED(StringFromCLSID(guid, &p))) {
        return -1;
    }
    if (pack_wstr(mp_pck, p, ctx)) {
        CoTaskMemFree(p);
        return -1;
    }

    CoTaskMemFree(p);

    return 0;
}

static int pack_hex32(msgpack_packer *mp_pck, int32_t hex)
{
    CHAR buffer[32];
    size_t size = _countof(buffer);

    _snprintf_s(buffer,
                size,
                _TRUNCATE,
                "0x%lx",
                hex);
    size = strlen(buffer);
    if (size > 0) {
        msgpack_pack_str(mp_pck, size);
        msgpack_pack_str_body(mp_pck, buffer, size);

        return 0;
    }

    return -1;
}

static int pack_hex64(msgpack_packer *mp_pck, int64_t hex)
{
    CHAR buffer[32];
    size_t size = _countof(buffer);

    _snprintf_s(buffer,
                size,
                _TRUNCATE,
                "0x%llx",
                hex);

    size = strlen(buffer);
    if (size > 0) {
        msgpack_pack_str(mp_pck, size);
        msgpack_pack_str_body(mp_pck, buffer, size);

        return 0;
    }

    return -1;
}


static int pack_keywords(msgpack_packer *mp_pck, uint64_t keywords)
{
    CHAR buffer[32];
    size_t size = _countof(buffer);

    _snprintf_s(buffer,
                size,
                _TRUNCATE,
                "0x%llx",
                keywords);

    size = strlen(buffer);
    msgpack_pack_str(mp_pck, size);
    msgpack_pack_str_body(mp_pck, buffer, size);

    return 0;
}

static int pack_systemtime(msgpack_packer *mp_pck, SYSTEMTIME *st)
{
    CHAR buf[64];
    size_t len = 0;
    _locale_t locale;
    TIME_ZONE_INFORMATION tzi;
    SYSTEMTIME st_local;

    GetTimeZoneInformation(&tzi);

    locale = _get_current_locale();
    if (locale == NULL) {
        return -1;
    }
    if (st != NULL) {
        SystemTimeToTzSpecificLocalTime(&tzi, st, &st_local);

        struct tm tm = {st_local.wSecond,
                        st_local.wMinute,
                        st_local.wHour,
                        st_local.wDay,
                        st_local.wMonth-1,
                        st_local.wYear-1900,
                        st_local.wDayOfWeek, 0, 0};
        len = _strftime_l(buf, 64, FORMAT_ISO8601, &tm, locale);
        if (len == 0) {
            flb_errno();
            _free_locale(locale);
            return -1;
        }
        _free_locale(locale);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, buf, len);
    }
    else {
        return -1;
    }

    return 0;
}

static int pack_filetime(msgpack_packer *mp_pck, ULONGLONG filetime)
{
    LARGE_INTEGER timestamp;
    CHAR buf[64];
    size_t len = 0;
    FILETIME ft, ft_local;
    SYSTEMTIME st;
    _locale_t locale;

    locale = _get_current_locale();
    if (locale == NULL) {
        return -1;
    }
    timestamp.QuadPart = filetime;
    ft.dwHighDateTime = timestamp.HighPart;
    ft.dwLowDateTime = timestamp.LowPart;
    FileTimeToLocalFileTime(&ft, &ft_local);
    if (FileTimeToSystemTime(&ft_local, &st)) {
        struct tm tm = {st.wSecond, st.wMinute, st.wHour, st.wDay, st.wMonth-1, st.wYear-1900, st.wDayOfWeek, 0, 0};
        len = _strftime_l(buf, 64, FORMAT_ISO8601, &tm, locale);
        if (len == 0) {
            flb_errno();
            _free_locale(locale);
            return -1;
        }
        _free_locale(locale);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, buf, len);
    }
    else {
        return -1;
    }

    return 0;
}

static int pack_sid(msgpack_packer *mp_pck, PSID sid, struct winevtlog_config *ctx)
{
    size_t size;
    LPWSTR pSid = NULL;
    int ret = -1;

    if (ConvertSidToStringSidW(sid, &pSid)) {
        ret = pack_wstr(mp_pck, pSid, ctx);

        LocalFree(pSid);
        return ret;
    }

    return ret;
}

static void pack_string_inserts(msgpack_packer *mp_pck, PEVT_VARIANT pValues, DWORD propCount, struct winevtlog_config *ctx)
{
    int i;

    msgpack_pack_array(mp_pck, propCount);

    for (i = 0; i < propCount; i++) {
        if (pValues[i].Type & EVT_VARIANT_TYPE_ARRAY)
            continue;

        switch (pValues[i].Type & EVT_VARIANT_TYPE_MASK) {
        case EvtVarTypeNull:
            pack_nullstr(mp_pck);
            break;
        case EvtVarTypeString:
            if (pack_wstr(mp_pck, pValues[i].StringVal, ctx)) {
                pack_nullstr(mp_pck);
            }
            break;
        case EvtVarTypeAnsiString:
            if (pack_wstr(mp_pck, pValues[i].AnsiStringVal, ctx)) {
                pack_nullstr(mp_pck);
            }
            break;
        case EvtVarTypeSByte:
            msgpack_pack_int8(mp_pck, pValues[i].SByteVal);
            break;
        case EvtVarTypeByte:
            msgpack_pack_uint8(mp_pck, pValues[i].ByteVal);
            break;
        case EvtVarTypeInt16:
            msgpack_pack_int16(mp_pck, pValues[i].Int16Val);
            break;
        case EvtVarTypeUInt16:
            msgpack_pack_uint16(mp_pck, pValues[i].UInt16Val);
            break;
        case EvtVarTypeInt32:
            msgpack_pack_int32(mp_pck, pValues[i].Int32Val);
            break;
        case EvtVarTypeUInt32:
            msgpack_pack_uint32(mp_pck, pValues[i].UInt32Val);
            break;
        case EvtVarTypeInt64:
            msgpack_pack_int64(mp_pck, pValues[i].Int64Val);
            break;
        case EvtVarTypeUInt64:
            msgpack_pack_uint64(mp_pck, pValues[i].UInt64Val);
            break;
        case EvtVarTypeSingle:
            msgpack_pack_float(mp_pck, pValues[i].SingleVal);
            break;
        case EvtVarTypeDouble:
            msgpack_pack_double(mp_pck, pValues[i].DoubleVal);
            break;
        case EvtVarTypeBoolean:
            if (pValues[i].BooleanVal) {
                msgpack_pack_true(mp_pck);
            }
            else {
                msgpack_pack_false(mp_pck);
            }
            break;
        case EvtVarTypeGuid:
            if (pack_guid(mp_pck, pValues[i].GuidVal, ctx)) {
                pack_nullstr(mp_pck);
            }
            break;
        case EvtVarTypeSizeT:
            msgpack_pack_uint64(mp_pck, pValues[i].SizeTVal);
            break;
        case EvtVarTypeFileTime:
            if (pack_filetime(mp_pck, pValues[i].FileTimeVal)) {
                pack_nullstr(mp_pck);
            }
            break;
        case EvtVarTypeSysTime:
            if (pack_systemtime(mp_pck, pValues[i].SysTimeVal)) {
                pack_nullstr(mp_pck);
            }
            break;
        case EvtVarTypeSid:
            if (pack_sid(mp_pck, pValues[i].SidVal, ctx)) {
                pack_nullstr(mp_pck);
            }
            break;
        case EvtVarTypeHexInt32:
            if (pack_hex32(mp_pck, pValues[i].Int32Val)) {
                pack_nullstr(mp_pck);
            }
            break;
        case EvtVarTypeHexInt64:
            if (pack_hex64(mp_pck, pValues[i].Int64Val)) {
                pack_nullstr(mp_pck);
            }
            break;
        case EvtVarTypeEvtXml:
            if (pack_wstr(mp_pck, pValues[i].XmlVal, ctx)) {
                pack_nullstr(mp_pck);
            }
            break;
        case EvtVarTypeBinary:
            if (pack_binary(mp_pck, pValues[i].BinaryVal, pValues[i].Count)) {
                pack_nullstr(mp_pck);
            }
        default:
            msgpack_pack_str(mp_pck, 1);
            msgpack_pack_str_body(mp_pck, "?", 1);
        }
    }
}

void winevtlog_pack_xml_event(msgpack_packer *mp_pck, WCHAR *wSystem, WCHAR *wMessage,
                              PEVT_VARIANT pValues, UINT countInserts, struct winevtlog_channel *ch,
                              struct winevtlog_config *ctx)
{
    int count = 2;

    msgpack_pack_array(mp_pck, 2);
    flb_pack_time_now(mp_pck);

    if (ctx->string_inserts) {
        count++;
    }

    msgpack_pack_map(mp_pck, count);

    msgpack_pack_str(mp_pck, 6);
    msgpack_pack_str_body(mp_pck, "System", 6);
    if (pack_wstr(mp_pck, wSystem, ctx)) {
        pack_nullstr(mp_pck);
    }
    msgpack_pack_str(mp_pck, 7);
    msgpack_pack_str_body(mp_pck, "Message", 7);
    if (pack_wstr(mp_pck, wMessage, ctx)) {
        pack_nullstr(mp_pck);
    }
    if (ctx->string_inserts) {
        msgpack_pack_str(mp_pck, 13);
        msgpack_pack_str_body(mp_pck, "StringInserts", 13);
        pack_string_inserts(mp_pck, pValues, countInserts, ctx);
    }
}

void winevtlog_pack_event(msgpack_packer *mp_pck, PEVT_VARIANT pSystem, WCHAR *wMessage,
                          PEVT_VARIANT pValues, UINT countInserts, struct winevtlog_channel *ch,
                          struct winevtlog_config *ctx)
{
    size_t len;
    int count = 19;

    if (ctx->string_inserts) {
        count++;
    }

    msgpack_pack_array(mp_pck, 2);
    flb_pack_time_now(mp_pck);

    msgpack_pack_map(mp_pck, count);

    /* ProviderName */
    msgpack_pack_str(mp_pck, 12);
    msgpack_pack_str_body(mp_pck, "ProviderName", 12);
    if (pack_wstr(mp_pck, pSystem[EvtSystemProviderName].StringVal, ctx)) {
        pack_nullstr(mp_pck);
    }

    /* ProviderGuid */
    msgpack_pack_str(mp_pck, 12);
    msgpack_pack_str_body(mp_pck, "ProviderGuid", 12);
    if (EvtVarTypeNull != pSystem[EvtSystemProviderGuid].Type) {
        if (pack_guid(mp_pck, pSystem[EvtSystemProviderGuid].GuidVal, ctx)) {
            pack_nullstr(mp_pck);
        }
    }
    else {
        pack_nullstr(mp_pck);
    }

    /* Qualifiers */
    msgpack_pack_str(mp_pck, 10);
    msgpack_pack_str_body(mp_pck, "Qualifiers", 10);
    if (EvtVarTypeNull != pSystem[EvtSystemQualifiers].Type) {
        msgpack_pack_uint16(mp_pck, pSystem[EvtSystemQualifiers].UInt16Val);
    }
    else {
        pack_nullstr(mp_pck);
    }

    /* EventID */
    msgpack_pack_str(mp_pck, 7);
    msgpack_pack_str_body(mp_pck, "EventID", 7);
    if (EvtVarTypeNull != pSystem[EvtSystemEventID].Type) {
        msgpack_pack_uint16(mp_pck, pSystem[EvtSystemEventID].UInt16Val);
    }
    else {
        pack_nullstr(mp_pck);
    }

    /* Version */
    msgpack_pack_str(mp_pck, 7);
    msgpack_pack_str_body(mp_pck, "Version", 7);
    if (EvtVarTypeNull != pSystem[EvtSystemVersion].Type) {
        msgpack_pack_uint8(mp_pck, pSystem[EvtSystemVersion].ByteVal);
    }
    else {
        msgpack_pack_uint8(mp_pck, 0);
    }

    /* Level */
    msgpack_pack_str(mp_pck, 5);
    msgpack_pack_str_body(mp_pck, "Level", 5);
    if (EvtVarTypeNull != pSystem[EvtSystemLevel].Type) {
        msgpack_pack_uint8(mp_pck, pSystem[EvtSystemLevel].ByteVal);
    }
    else {
        msgpack_pack_uint8(mp_pck, 0);
    }

    /* Task */
    msgpack_pack_str(mp_pck, 4);
    msgpack_pack_str_body(mp_pck, "Task", 4);
    if (EvtVarTypeNull != pSystem[EvtSystemTask].Type) {
        msgpack_pack_uint16(mp_pck, pSystem[EvtSystemTask].UInt16Val);
    }
    else {
        msgpack_pack_uint16(mp_pck, 0);
    }

    /* Opcode */
    msgpack_pack_str(mp_pck, 6);
    msgpack_pack_str_body(mp_pck, "Opcode", 6);
    if (EvtVarTypeNull != pSystem[EvtSystemOpcode].Type) {
        msgpack_pack_uint8(mp_pck, pSystem[EvtSystemOpcode].ByteVal);
    }
    else {
        msgpack_pack_uint8(mp_pck, 0);
    }

    /* Keywords */
    msgpack_pack_str(mp_pck, 8);
    msgpack_pack_str_body(mp_pck, "Keywords", 8);
    if (EvtVarTypeNull != pSystem[EvtSystemKeywords].Type) {
        pack_keywords(mp_pck, pSystem[EvtSystemKeywords].UInt64Val);
    }
    else {
        msgpack_pack_uint64(mp_pck, 0);
    }

    /* TimeCreated */
    msgpack_pack_str(mp_pck, 11);
    msgpack_pack_str_body(mp_pck, "TimeCreated", 11);
    if (pack_filetime(mp_pck, pSystem[EvtSystemTimeCreated].FileTimeVal)) {
        pack_nullstr(mp_pck);
    }

    /* EventRecordID */
    msgpack_pack_str(mp_pck, 13);
    msgpack_pack_str_body(mp_pck, "EventRecordID", 13);
    if (EvtVarTypeNull != pSystem[EvtSystemEventRecordId].Type) {
        msgpack_pack_uint64(mp_pck, pSystem[EvtSystemEventRecordId].UInt64Val);
    }
    else {
        msgpack_pack_uint64(mp_pck, 0);
    }

    /* ActivityID */
    msgpack_pack_str(mp_pck, 10);
    msgpack_pack_str_body(mp_pck, "ActivityID", 10);
    if (pack_guid(mp_pck, pSystem[EvtSystemActivityID].GuidVal, ctx)) {
        pack_nullstr(mp_pck);
    }

    /* Related ActivityID */
    msgpack_pack_str(mp_pck, 17);
    msgpack_pack_str_body(mp_pck, "RelatedActivityID", 17);
    if (pack_guid(mp_pck, pSystem[EvtSystemRelatedActivityID].GuidVal, ctx)) {
        pack_nullstr(mp_pck);
    }

    /* ProcessID */
    msgpack_pack_str(mp_pck, 9);
    msgpack_pack_str_body(mp_pck, "ProcessID", 9);
    if (EvtVarTypeNull != pSystem[EvtSystemProcessID].Type) {
        msgpack_pack_uint32(mp_pck, pSystem[EvtSystemProcessID].UInt32Val);
    }
    else {
        msgpack_pack_uint32(mp_pck, 0);
    }

    /* ThreadID */
    msgpack_pack_str(mp_pck, 8);
    msgpack_pack_str_body(mp_pck, "ThreadID", 8);
    if (EvtVarTypeNull != pSystem[EvtSystemThreadID].Type) {
        msgpack_pack_uint32(mp_pck, pSystem[EvtSystemThreadID].UInt32Val);
    }
    else {
        msgpack_pack_uint32(mp_pck, 0);
    }

    /* Channel */
    msgpack_pack_str(mp_pck, 7);
    msgpack_pack_str_body(mp_pck, "Channel", 7);
    if (pack_wstr(mp_pck, pSystem[EvtSystemChannel].StringVal, ctx)) {
        pack_nullstr(mp_pck);
    }
    /* Computer */
    msgpack_pack_str(mp_pck, 8);
    msgpack_pack_str_body(mp_pck, "Computer", 8);
    if (pack_wstr(mp_pck, pSystem[EvtSystemComputer].StringVal, ctx)) {
        pack_nullstr(mp_pck);
    }

    /* UserID */
    msgpack_pack_str(mp_pck, 6);
    msgpack_pack_str_body(mp_pck, "UserID", 6);
    if (pack_sid(mp_pck, pSystem[EvtSystemUserID].SidVal, ctx)) {
        pack_nullstr(mp_pck);
    }

    /* Message */
    msgpack_pack_str(mp_pck, 7);
    msgpack_pack_str_body(mp_pck, "Message", 7);
    if (pack_wstr(mp_pck, wMessage, ctx)) {
        pack_nullstr(mp_pck);
    }

    /* String Inserts */
    if (ctx->string_inserts) {
        msgpack_pack_str(mp_pck, 13);
        msgpack_pack_str_body(mp_pck, "StringInserts", 13);
        pack_string_inserts(mp_pck, pValues, countInserts, ctx);
    }
}
