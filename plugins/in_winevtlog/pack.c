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

static int pack_nullstr(struct winevtlog_config *ctx)
{
    return flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "");
}

static int pack_wstr(struct winevtlog_config *ctx, const wchar_t *wstr)
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
    flb_log_event_encoder_append_body_string(ctx->log_encoder, buf, size - 1);

    flb_free(buf);
    return 0;
}

static int pack_binary(struct winevtlog_config *ctx, PBYTE bin, size_t length)
{
    const char *HEX_TABLE = "0123456789ABCDEF";
    char *buffer;
    int size = length * 2;
    size_t i, j;
    unsigned int idx = 0;

    if (length == 0) {
        pack_nullstr(ctx);
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

    flb_log_event_encoder_append_body_string(ctx->log_encoder, buffer, size);

    flb_free(buffer);

    return 0;
}

static int pack_guid(struct winevtlog_config *ctx, const GUID *guid)
{
    LPOLESTR p = NULL;

    if (FAILED(StringFromCLSID(guid, &p))) {
        return -1;
    }
    if (pack_wstr(ctx, p)) {
        CoTaskMemFree(p);
        return -1;
    }

    CoTaskMemFree(p);

    return 0;
}

static int pack_hex32(struct winevtlog_config *ctx, int32_t hex)
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
        flb_log_event_encoder_append_body_cstring(ctx->log_encoder, buffer);

        return 0;
    }

    return -1;
}

static int pack_hex64(struct winevtlog_config *ctx, int64_t hex)
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
        flb_log_event_encoder_append_body_cstring(ctx->log_encoder, buffer);

        return 0;
    }

    return -1;
}


static int pack_keywords(struct winevtlog_config *ctx, uint64_t keywords)
{
    CHAR buffer[32];
    size_t size = _countof(buffer);

    _snprintf_s(buffer,
                size,
                _TRUNCATE,
                "0x%llx",
                keywords);

    size = strlen(buffer);

    flb_log_event_encoder_append_body_cstring(ctx->log_encoder, buffer);

    return 0;
}

static int pack_systemtime(struct winevtlog_config *ctx, SYSTEMTIME *st)
{
    CHAR buf[64];
    size_t len = 0;
    _locale_t locale;
    DYNAMIC_TIME_ZONE_INFORMATION dtzi;
    SYSTEMTIME st_local;

    GetDynamicTimeZoneInformation(&dtzi);

    locale = _get_current_locale();
    if (locale == NULL) {
        return -1;
    }
    if (st != NULL) {
        SystemTimeToTzSpecificLocalTimeEx(&dtzi, st, &st_local);

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

        flb_log_event_encoder_append_body_string(ctx->log_encoder, buf, len);
    }
    else {
        return -1;
    }

    return 0;
}

static int pack_filetime(struct winevtlog_config *ctx, ULONGLONG filetime)
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

        flb_log_event_encoder_append_body_string(ctx->log_encoder, buf, len);
    }
    else {
        return -1;
    }

    return 0;
}

static int pack_sid(struct winevtlog_config *ctx, PSID sid, int extract_sid)
{
#define MAX_NAME 256
    size_t size;
    LPWSTR wide_sid = NULL;
    DWORD len = MAX_NAME, err = ERROR_SUCCESS;
    int ret = -1;
    SID_NAME_USE sid_type = SidTypeUnknown;
    char account[MAX_NAME];
    char domain[MAX_NAME];
    PSID pSID = NULL;
    DWORD result_len = 0;
    flb_sds_t formatted = NULL;

    if (ConvertSidToStringSidW(sid, &wide_sid)) {
        if (extract_sid == FLB_TRUE) {
            /* Skip to translate SID for capability SIDs.
             * ref: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
             * See also: https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/sids-not-resolve-into-friendly-names
             */
            if (wcsnicmp(wide_sid, L"S-1-15-3-", 9) == 0) {
                flb_plg_debug(ctx->ins, "This SID is one of the capability SIDs. Skip.");

                goto not_mapped_error;
            }
            if (!LookupAccountSidA(NULL, sid,
                                   account, &len, domain,
                                   &len, &sid_type)) {
                err = GetLastError();
                if (err == ERROR_NONE_MAPPED) {
                    flb_plg_debug(ctx->ins, "AccountSid is not mapped. code: %u", err);

                    goto not_mapped_error;
                }
                else {
                    flb_plg_warn(ctx->ins, "LookupAccountSid Error %u", err);
                }

                goto error;
            }

            result_len = strlen(domain) + 1 + strlen(account) + 1;
            formatted = flb_sds_create_size(result_len);
            if (formatted == NULL) {
                flb_plg_warn(ctx->ins, "create result buffer failed");

                ret = -1;

                goto error;
            }

            _snprintf_s(formatted, result_len, _TRUNCATE, "%s\\%s", domain, account);

            size = strlen(formatted);

            if (size > 0) {
                flb_log_event_encoder_append_body_cstring(ctx->log_encoder, formatted);

                ret = 0;
            }
            else {
                flb_plg_warn(ctx->ins, "format domain\\account failed");
                flb_sds_destroy(formatted);

                ret = -1;

                goto error;
            }

            LocalFree(wide_sid);
            flb_sds_destroy(formatted);

            return ret;
        }
        else {
            ret = pack_wstr(ctx, wide_sid);
            LocalFree(wide_sid);

            return ret;
        }

    not_mapped_error:
        ret = pack_wstr(ctx, wide_sid);

        LocalFree(wide_sid);

        return ret;

    error:
        LocalFree(wide_sid);

        return ret;
    }

    return ret;
#undef MAX_NAME
}

static void pack_string_inserts(struct winevtlog_config *ctx, PEVT_VARIANT values, DWORD count)
{
    int i;
    int ret;

    ret = flb_log_event_encoder_body_begin_array(ctx->log_encoder);

    for (i = 0; i < count; i++) {
        if (values[i].Type & EVT_VARIANT_TYPE_ARRAY) {
            continue;
        }

        switch (values[i].Type & EVT_VARIANT_TYPE_MASK) {
        case EvtVarTypeNull:
            pack_nullstr(ctx);
            break;
        case EvtVarTypeString:
            if (pack_wstr(ctx, values[i].StringVal)) {
                pack_nullstr(ctx);
            }
            break;
        case EvtVarTypeAnsiString:
            if (pack_wstr(ctx, values[i].AnsiStringVal)) {
                pack_nullstr(ctx);
            }
            break;
        case EvtVarTypeSByte:
            flb_log_event_encoder_append_body_int8(ctx->log_encoder, values[i].SByteVal);
            break;
        case EvtVarTypeByte:
            flb_log_event_encoder_append_body_uint8(ctx->log_encoder, values[i].ByteVal);
            break;
        case EvtVarTypeInt16:
            flb_log_event_encoder_append_body_int16(ctx->log_encoder, values[i].Int16Val);
            break;
        case EvtVarTypeUInt16:
            flb_log_event_encoder_append_body_uint16(ctx->log_encoder, values[i].UInt16Val);
            break;
        case EvtVarTypeInt32:
            flb_log_event_encoder_append_body_int32(ctx->log_encoder, values[i].Int32Val);
            break;
        case EvtVarTypeUInt32:
            flb_log_event_encoder_append_body_uint32(ctx->log_encoder, values[i].UInt32Val);
            break;
        case EvtVarTypeInt64:
            flb_log_event_encoder_append_body_int64(ctx->log_encoder, values[i].Int64Val);
            break;
        case EvtVarTypeUInt64:
            flb_log_event_encoder_append_body_uint64(ctx->log_encoder, values[i].UInt64Val);
            break;
        case EvtVarTypeSingle:
            flb_log_event_encoder_append_body_double(ctx->log_encoder, values[i].SingleVal);
            break;
        case EvtVarTypeDouble:
            flb_log_event_encoder_append_body_double(ctx->log_encoder, values[i].DoubleVal);
            break;
        case EvtVarTypeBoolean:
            flb_log_event_encoder_append_body_boolean(ctx->log_encoder, (int) values[i].BooleanVal);
            break;
        case EvtVarTypeGuid:
            if (pack_guid(ctx, values[i].GuidVal)) {
                pack_nullstr(ctx);
            }
            break;
        case EvtVarTypeSizeT:
            flb_log_event_encoder_append_body_uint64(ctx->log_encoder, values[i].SizeTVal);
            break;
        case EvtVarTypeFileTime:
            if (pack_filetime(ctx, values[i].FileTimeVal)) {
                pack_nullstr(ctx);
            }
            break;
        case EvtVarTypeSysTime:
            if (pack_systemtime(ctx, values[i].SysTimeVal)) {
                pack_nullstr(ctx);
            }
            break;
        case EvtVarTypeSid:
            if (pack_sid(ctx, values[i].SidVal, FLB_FALSE)) {
                pack_nullstr(ctx);
            }
            break;
        case EvtVarTypeHexInt32:
            if (pack_hex32(ctx, values[i].Int32Val)) {
                pack_nullstr(ctx);
            }
            break;
        case EvtVarTypeHexInt64:
            if (pack_hex64(ctx, values[i].Int64Val)) {
                pack_nullstr(ctx);
            }
            break;
        case EvtVarTypeEvtXml:
            if (pack_wstr(ctx, values[i].XmlVal)) {
                pack_nullstr(ctx);
            }
            break;
        case EvtVarTypeBinary:
            if (pack_binary(ctx, values[i].BinaryVal, values[i].Count)) {
                pack_nullstr(ctx);
            }
            break;
        default:
            flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "?");
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_body_commit_array(ctx->log_encoder);
    }

}

void winevtlog_pack_xml_event(WCHAR *system_xml, WCHAR *message,
                              PEVT_VARIANT string_inserts, UINT count_inserts, struct winevtlog_channel *ch,
                              struct winevtlog_config *ctx)
{
    int ret;

    ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
    }


    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "System");

    if (pack_wstr(ctx, system_xml)) {
        pack_nullstr(ctx);
    }

    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Message");

    if (pack_wstr(ctx, message)) {
        pack_nullstr(ctx);
    }

    if (ctx->string_inserts) {
        ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "StringInserts");

        pack_string_inserts(ctx, string_inserts, count_inserts);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }
}

void winevtlog_pack_event(PEVT_VARIANT system, WCHAR *message,
                          PEVT_VARIANT string_inserts, UINT count_inserts, struct winevtlog_channel *ch,
                          struct winevtlog_config *ctx)
{
    int ret;
    size_t len;
    int count = 19;

    if (ctx->string_inserts) {
        count++;
    }

    ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
    }

    /* ProviderName */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "ProviderName");

    if (pack_wstr(ctx, system[EvtSystemProviderName].StringVal)) {
        pack_nullstr(ctx);
    }

    /* ProviderGuid */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "ProviderGuid");

    if (EvtVarTypeNull != system[EvtSystemProviderGuid].Type) {
        if (pack_guid(ctx, system[EvtSystemProviderGuid].GuidVal)) {
            pack_nullstr(ctx);
        }
    }
    else {
        pack_nullstr(ctx);
    }

    /* Qualifiers */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Qualifiers");

    if (EvtVarTypeNull != system[EvtSystemQualifiers].Type) {
        flb_log_event_encoder_append_body_uint16(ctx->log_encoder, system[EvtSystemQualifiers].UInt16Val);
    }
    else {
        pack_nullstr(ctx);
    }

    /* EventID */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "EventID");

    if (EvtVarTypeNull != system[EvtSystemEventID].Type) {
        flb_log_event_encoder_append_body_uint16(ctx->log_encoder, system[EvtSystemEventID].UInt16Val);
    }
    else {
        pack_nullstr(ctx);
    }

    /* Version */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Version");

    if (EvtVarTypeNull != system[EvtSystemVersion].Type) {
        flb_log_event_encoder_append_body_uint8(ctx->log_encoder, system[EvtSystemVersion].ByteVal);
    }
    else {
        flb_log_event_encoder_append_body_uint8(ctx->log_encoder, 0);
    }

    /* Level */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Level");

    if (EvtVarTypeNull != system[EvtSystemLevel].Type) {
        flb_log_event_encoder_append_body_uint8(ctx->log_encoder, system[EvtSystemLevel].ByteVal);
    }
    else {
        flb_log_event_encoder_append_body_uint8(ctx->log_encoder, 0);
    }

    /* Task */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Task");

    if (EvtVarTypeNull != system[EvtSystemTask].Type) {
        flb_log_event_encoder_append_body_uint16(ctx->log_encoder, system[EvtSystemTask].UInt16Val);
    }
    else {
        flb_log_event_encoder_append_body_uint16(ctx->log_encoder, 0);
    }

    /* Opcode */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Opcode");

    if (EvtVarTypeNull != system[EvtSystemOpcode].Type) {
        flb_log_event_encoder_append_body_uint8(ctx->log_encoder, system[EvtSystemOpcode].ByteVal);
    }
    else {
        flb_log_event_encoder_append_body_uint8(ctx->log_encoder, 0);
    }

    /* Keywords */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Keywords");

    if (EvtVarTypeNull != system[EvtSystemKeywords].Type) {
        pack_keywords(ctx, system[EvtSystemKeywords].UInt64Val);
    }
    else {
        flb_log_event_encoder_append_body_uint64(ctx->log_encoder, 0);
    }

    /* TimeCreated */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "TimeCreated");

    if (pack_filetime(ctx, system[EvtSystemTimeCreated].FileTimeVal)) {
        pack_nullstr(ctx);
    }

    /* EventRecordID */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "EventRecordID");

    if (EvtVarTypeNull != system[EvtSystemEventRecordId].Type) {
        flb_log_event_encoder_append_body_uint64(ctx->log_encoder, system[EvtSystemEventRecordId].UInt64Val);
    }
    else {
        flb_log_event_encoder_append_body_uint64(ctx->log_encoder, 0);
    }

    /* ActivityID */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "ActivityID");

    if (pack_guid(ctx, system[EvtSystemActivityID].GuidVal)) {
        pack_nullstr(ctx);
    }

    /* Related ActivityID */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "RelatedActivityID");

    if (pack_guid(ctx, system[EvtSystemRelatedActivityID].GuidVal)) {
        pack_nullstr(ctx);
    }

    /* ProcessID */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "ProcessID");

    if (EvtVarTypeNull != system[EvtSystemProcessID].Type) {
        flb_log_event_encoder_append_body_uint32(ctx->log_encoder, system[EvtSystemProcessID].UInt32Val);
    }
    else {
        flb_log_event_encoder_append_body_uint32(ctx->log_encoder, 0);
    }

    /* ThreadID */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "ThreadID");

    if (EvtVarTypeNull != system[EvtSystemThreadID].Type) {
        flb_log_event_encoder_append_body_uint32(ctx->log_encoder, system[EvtSystemThreadID].UInt32Val);
    }
    else {
        flb_log_event_encoder_append_body_uint32(ctx->log_encoder, 0);
    }

    /* Channel */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Channel");

    if (pack_wstr(ctx, system[EvtSystemChannel].StringVal)) {
        pack_nullstr(ctx);
    }

    /* Computer */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Computer");

    if (pack_wstr(ctx, system[EvtSystemComputer].StringVal)) {
        pack_nullstr(ctx);
    }

    /* UserID */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "UserID");

    if (pack_sid(ctx, system[EvtSystemUserID].SidVal, FLB_TRUE)) {
        pack_nullstr(ctx);
    }

    /* Message */
    ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "Message");

    if (pack_wstr(ctx, message)) {
        pack_nullstr(ctx);
    }

    /* String Inserts */
    if (ctx->string_inserts) {
        ret = flb_log_event_encoder_append_body_cstring(ctx->log_encoder, "StringInserts");

        pack_string_inserts(ctx, string_inserts, count_inserts);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }
}
