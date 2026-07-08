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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>

#include <cmetrics/cmt_gauge.h>
#include <msgpack.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <objbase.h>

#include "etw.h"

#define FLB_IN_ETW_UNIX_EPOCH_IN_100NS 116444736000000000ULL
#define FLB_IN_ETW_PROVIDER_MAP_SIZE   14
#define FLB_IN_ETW_DEFAULT_KERNEL_FLAGS "process,thread,image_load"

static const GUID flb_etw_system_trace_control_guid = {
    0x9e814aad,
    0x3204,
    0x11d2,
    {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}
};

static void pack_cstr(msgpack_packer *mp_pck, const char *str)
{
    size_t len;

    len = strlen(str);
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, str, len);
}

static int guid_to_string(const GUID *guid, char *buf, size_t size)
{
    int ret;

    ret = snprintf(buf, size,
                   "{%08" PRIx32 "-%04x-%04x-%02x%02x-"
                   "%02x%02x%02x%02x%02x%02x}",
                   (uint32_t) guid->Data1,
                   guid->Data2,
                   guid->Data3,
                   guid->Data4[0],
                   guid->Data4[1],
                   guid->Data4[2],
                   guid->Data4[3],
                   guid->Data4[4],
                   guid->Data4[5],
                   guid->Data4[6],
                   guid->Data4[7]);

    if (ret < 0 || (size_t) ret >= size) {
        return -1;
    }

    return 0;
}

static int parse_guid(const char *str, GUID *guid)
{
    unsigned int d1;
    unsigned int d2;
    unsigned int d3;
    unsigned int d4[8];
    int ret;

    ret = sscanf(str,
                 "{%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x}",
                 &d1, &d2, &d3,
                 &d4[0], &d4[1], &d4[2], &d4[3],
                 &d4[4], &d4[5], &d4[6], &d4[7]);

    if (ret != 11) {
        ret = sscanf(str,
                     "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
                     &d1, &d2, &d3,
                     &d4[0], &d4[1], &d4[2], &d4[3],
                     &d4[4], &d4[5], &d4[6], &d4[7]);
    }

    if (ret != 11) {
        return -1;
    }

    guid->Data1 = d1;
    guid->Data2 = (unsigned short) d2;
    guid->Data3 = (unsigned short) d3;
    guid->Data4[0] = (unsigned char) d4[0];
    guid->Data4[1] = (unsigned char) d4[1];
    guid->Data4[2] = (unsigned char) d4[2];
    guid->Data4[3] = (unsigned char) d4[3];
    guid->Data4[4] = (unsigned char) d4[4];
    guid->Data4[5] = (unsigned char) d4[5];
    guid->Data4[6] = (unsigned char) d4[6];
    guid->Data4[7] = (unsigned char) d4[7];

    return 0;
}

static int parse_uint64(const char *str, ULONGLONG *out)
{
    char *end;
    unsigned long long value;

    if (str == NULL || str[0] == '\0') {
        return -1;
    }

    value = strtoull(str, &end, 0);
    if (end == str || *end != '\0') {
        return -1;
    }

    *out = value;

    return 0;
}

static char *trim_token(char *str)
{
    char *end;

    while (isspace((unsigned char) *str)) {
        str++;
    }

    if (*str == '\0') {
        return str;
    }

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) {
        *end = '\0';
        end--;
    }

    return str;
}

static int has_empty_csv_token(const char *str)
{
    const char *p;
    int has_token;

    has_token = FLB_FALSE;
    for (p = str; *p != '\0'; p++) {
        if (*p == ',') {
            if (has_token == FLB_FALSE) {
                return FLB_TRUE;
            }
            has_token = FLB_FALSE;
            continue;
        }

        if (!isspace((unsigned char) *p)) {
            has_token = FLB_TRUE;
        }
    }

    return has_token == FLB_FALSE;
}

static int parse_session_type(struct flb_etw *ctx)
{
    if (ctx->session_type_str == NULL ||
        strcasecmp(ctx->session_type_str, "provider") == 0) {
        ctx->session_type = FLB_IN_ETW_SESSION_PROVIDER;
        return 0;
    }

    if (strcasecmp(ctx->session_type_str, "system") == 0) {
        ctx->session_type = FLB_IN_ETW_SESSION_SYSTEM;
        return 0;
    }

    flb_plg_error(ctx->ins,
                  "invalid session_type '%s' (expected 'provider' or 'system')",
                  ctx->session_type_str);

    return -1;
}

static int parse_stale_session_action(struct flb_etw *ctx)
{
    if (ctx->stale_session_action_str == NULL ||
        strcasecmp(ctx->stale_session_action_str, "stop") == 0) {
        ctx->stale_session_action = FLB_IN_ETW_STALE_ACTION_STOP;
        return 0;
    }

    if (strcasecmp(ctx->stale_session_action_str, "fail") == 0) {
        ctx->stale_session_action = FLB_IN_ETW_STALE_ACTION_FAIL;
        return 0;
    }

    flb_plg_error(ctx->ins,
                  "invalid stale_session_action '%s' (expected 'stop' or 'fail')",
                  ctx->stale_session_action_str);

    return -1;
}

static int kernel_flag_from_name(const char *name, ULONG *flag)
{
    if (strcasecmp(name, "process") == 0) {
        *flag = EVENT_TRACE_FLAG_PROCESS;
        return 0;
    }

    if (strcasecmp(name, "thread") == 0) {
        *flag = EVENT_TRACE_FLAG_THREAD;
        return 0;
    }

    if (strcasecmp(name, "image_load") == 0 ||
        strcasecmp(name, "image") == 0) {
        *flag = EVENT_TRACE_FLAG_IMAGE_LOAD;
        return 0;
    }

    if (strcasecmp(name, "cswitch") == 0 ||
        strcasecmp(name, "context_switch") == 0) {
        *flag = EVENT_TRACE_FLAG_CSWITCH;
        return 0;
    }

    if (strcasecmp(name, "disk_io") == 0 ||
        strcasecmp(name, "disk") == 0) {
        *flag = EVENT_TRACE_FLAG_DISK_IO;
        return 0;
    }

    if (strcasecmp(name, "tcpip") == 0 ||
        strcasecmp(name, "network_tcpip") == 0) {
        *flag = EVENT_TRACE_FLAG_NETWORK_TCPIP;
        return 0;
    }

    return -1;
}

static int parse_kernel_flags(struct flb_etw *ctx)
{
    ULONG flag;
    ULONGLONG numeric_flags;
    char *tmp;
    char *token;
    char *context;

    if (ctx->session_type != FLB_IN_ETW_SESSION_SYSTEM) {
        return 0;
    }

    if (parse_uint64(ctx->kernel_flags_str, &numeric_flags) == 0) {
        if (numeric_flags > ULONG_MAX) {
            flb_plg_error(ctx->ins, "kernel_flags numeric value is too large");
            return -1;
        }
        if (numeric_flags == 0) {
            flb_plg_error(ctx->ins, "kernel_flags must enable at least one flag");
            return -1;
        }
        ctx->kernel_flags = (ULONG) numeric_flags;
        return 0;
    }

    if (has_empty_csv_token(ctx->kernel_flags_str)) {
        flb_plg_error(ctx->ins, "kernel_flags contains an empty token");
        return -1;
    }

    tmp = flb_strdup(ctx->kernel_flags_str);
    if (tmp == NULL) {
        flb_errno();
        return -1;
    }

    token = strtok_s(tmp, ",", &context);
    while (token != NULL) {
        token = trim_token(token);
        if (token[0] == '\0') {
            flb_plg_error(ctx->ins, "kernel_flags contains an empty token");
            flb_free(tmp);
            return -1;
        }

        if (kernel_flag_from_name(token, &flag) != 0) {
            flb_plg_error(ctx->ins, "unknown kernel_flags token '%s'", token);
            flb_free(tmp);
            return -1;
        }

        ctx->kernel_flags |= flag;
        token = strtok_s(NULL, ",", &context);
    }

    flb_free(tmp);

    if (ctx->kernel_flags == 0) {
        flb_plg_error(ctx->ins, "kernel_flags must enable at least one flag");
        return -1;
    }

    return 0;
}

static WCHAR *utf8_to_wide(const char *str)
{
    int size;
    WCHAR *buf;

    size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (size == 0) {
        return NULL;
    }

    buf = flb_calloc(size, sizeof(WCHAR));
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, size) == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

static char *wide_to_utf8(const WCHAR *str, int bytes, int *out_len)
{
    int wide_len;
    int size;
    char *buf;

    if (str == NULL) {
        return NULL;
    }

    if (bytes > 0) {
        wide_len = bytes / sizeof(WCHAR);
        while (wide_len > 0 && str[wide_len - 1] == L'\0') {
            wide_len--;
        }
    }
    else {
        wide_len = -1;
    }

    size = WideCharToMultiByte(CP_UTF8, 0, str, wide_len, NULL, 0, NULL, NULL);
    if (size == 0) {
        return NULL;
    }

    buf = flb_malloc(size + 1);
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, str, wide_len, buf, size, NULL, NULL) == 0) {
        flb_free(buf);
        return NULL;
    }

    buf[size] = '\0';
    *out_len = size;

    return buf;
}

static void pack_wide_string(msgpack_packer *mp_pck, const WCHAR *str, int bytes)
{
    int len;
    char *utf8;

    utf8 = wide_to_utf8(str, bytes, &len);
    if (utf8 == NULL) {
        msgpack_pack_nil(mp_pck);
        return;
    }

    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, utf8, len);
    flb_free(utf8);
}

static int resolve_provider_name(struct flb_etw *ctx, const WCHAR *name, GUID *guid)
{
    ULONG size;
    TDHSTATUS status;
    PROVIDER_ENUMERATION_INFO *providers;
    PROVIDER_ENUMERATION_INFO *new_providers;
    TRACE_PROVIDER_INFO *info;
    WCHAR *provider_name;
    ULONG i;

    size = 0;
    providers = NULL;

    while (1) {
        status = TdhEnumerateProviders(providers, &size);
        if (status == ERROR_SUCCESS) {
            break;
        }

        if (status != ERROR_INSUFFICIENT_BUFFER) {
            flb_plg_error(ctx->ins,
                          "TdhEnumerateProviders failed while resolving '%S' (status=%lu)",
                          name, status);
            flb_free(providers);
            return -1;
        }

        new_providers = flb_realloc(providers, size);
        if (new_providers == NULL) {
            flb_errno();
            flb_free(providers);
            return -1;
        }
        providers = new_providers;
    }

    for (i = 0; i < providers->NumberOfProviders; i++) {
        info = &providers->TraceProviderInfoArray[i];
        provider_name = (WCHAR *) ((char *) providers + info->ProviderNameOffset);

        if (_wcsicmp(provider_name, name) == 0) {
            *guid = info->ProviderGuid;
            flb_free(providers);
            return 0;
        }
    }

    flb_plg_error(ctx->ins,
                  "ETW provider_name '%S' was not found in registered providers",
                  name);
    flb_free(providers);

    return -1;
}

static EVENT_TRACE_PROPERTIES *create_trace_properties(struct flb_etw *ctx)
{
    size_t name_size;
    size_t props_size;
    EVENT_TRACE_PROPERTIES *props;

    name_size = (wcslen(ctx->session_name_wide) + 1) * sizeof(WCHAR);
    props_size = sizeof(EVENT_TRACE_PROPERTIES) + name_size;

    props = flb_calloc(1, props_size);
    if (props == NULL) {
        flb_errno();
        return NULL;
    }

    props->Wnode.BufferSize = (ULONG) props_size;
    if (ctx->session_type == FLB_IN_ETW_SESSION_SYSTEM) {
        props->Wnode.Guid = flb_etw_system_trace_control_guid;
    }
    else {
        props->Wnode.Guid = ctx->session_guid;
    }
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 2;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    if (ctx->session_type == FLB_IN_ETW_SESSION_SYSTEM) {
        props->LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
        props->EnableFlags = ctx->kernel_flags;
    }
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    if (ctx->buffer_size > 0) {
        props->BufferSize = (ULONG) ctx->buffer_size;
    }
    if (ctx->minimum_buffers > 0) {
        props->MinimumBuffers = (ULONG) ctx->minimum_buffers;
    }
    if (ctx->maximum_buffers > 0) {
        props->MaximumBuffers = (ULONG) ctx->maximum_buffers;
    }
    if (ctx->flush_timer > 0) {
        props->FlushTimer = (ULONG) ctx->flush_timer;
    }
    memcpy((char *) props + props->LoggerNameOffset, ctx->session_name_wide, name_size);

    return props;
}

static void etw_timestamp_to_flb_time(const EVENT_HEADER *header, struct flb_time *tm)
{
    ULONGLONG ts;
    ULONGLONG unix_100ns;

    ts = (ULONGLONG) header->TimeStamp.QuadPart;
    if (ts <= FLB_IN_ETW_UNIX_EPOCH_IN_100NS) {
        flb_time_get(tm);
        return;
    }

    unix_100ns = ts - FLB_IN_ETW_UNIX_EPOCH_IN_100NS;
    flb_time_set(tm,
                 (time_t) (unix_100ns / 10000000ULL),
                 (long) ((unix_100ns % 10000000ULL) * 100ULL));
}

static void pack_guid_value(msgpack_packer *mp_pck, const GUID *guid)
{
    char buf[64];

    if (guid_to_string(guid, buf, sizeof(buf)) == 0) {
        pack_cstr(mp_pck, buf);
    }
    else {
        msgpack_pack_nil(mp_pck);
    }
}

static void pack_filetime_value(msgpack_packer *mp_pck, const FILETIME *filetime)
{
    ULONGLONG ts;
    ULONGLONG unix_100ns;

    ts = (((ULONGLONG) filetime->dwHighDateTime) << 32) | filetime->dwLowDateTime;
    if (ts <= FLB_IN_ETW_UNIX_EPOCH_IN_100NS) {
        msgpack_pack_nil(mp_pck);
        return;
    }

    unix_100ns = ts - FLB_IN_ETW_UNIX_EPOCH_IN_100NS;
    msgpack_pack_uint64(mp_pck, unix_100ns / 10000000ULL);
}

static int pack_nil_if_property_too_small(msgpack_packer *mp_pck, ULONG size,
                                          size_t expected)
{
    if (size < expected) {
        msgpack_pack_nil(mp_pck);
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static void pack_property_value(msgpack_packer *mp_pck, USHORT in_type,
                                BYTE *buf, ULONG size)
{
    char *str;
    size_t len;

    switch (in_type) {
    case TDH_INTYPE_UNICODESTRING:
        pack_wide_string(mp_pck, (WCHAR *) buf, size);
        break;
    case TDH_INTYPE_ANSISTRING:
        len = strnlen((char *) buf, size);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, (char *) buf, len);
        break;
    case TDH_INTYPE_INT8:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(INT8))) {
            break;
        }
        msgpack_pack_int8(mp_pck, *((INT8 *) buf));
        break;
    case TDH_INTYPE_UINT8:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(UINT8))) {
            break;
        }
        msgpack_pack_uint8(mp_pck, *((UINT8 *) buf));
        break;
    case TDH_INTYPE_INT16:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(INT16))) {
            break;
        }
        msgpack_pack_int16(mp_pck, *((INT16 *) buf));
        break;
    case TDH_INTYPE_UINT16:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(UINT16))) {
            break;
        }
        msgpack_pack_uint16(mp_pck, *((UINT16 *) buf));
        break;
    case TDH_INTYPE_INT32:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(INT32))) {
            break;
        }
        msgpack_pack_int32(mp_pck, *((INT32 *) buf));
        break;
    case TDH_INTYPE_UINT32:
    case TDH_INTYPE_HEXINT32:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(UINT32))) {
            break;
        }
        msgpack_pack_uint32(mp_pck, *((UINT32 *) buf));
        break;
    case TDH_INTYPE_INT64:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(INT64))) {
            break;
        }
        msgpack_pack_int64(mp_pck, *((INT64 *) buf));
        break;
    case TDH_INTYPE_UINT64:
    case TDH_INTYPE_HEXINT64:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(UINT64))) {
            break;
        }
        msgpack_pack_uint64(mp_pck, *((UINT64 *) buf));
        break;
    case TDH_INTYPE_BOOLEAN:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(BOOL))) {
            break;
        }
        if (*((BOOL *) buf)) {
            msgpack_pack_true(mp_pck);
        }
        else {
            msgpack_pack_false(mp_pck);
        }
        break;
    case TDH_INTYPE_FLOAT:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(float))) {
            break;
        }
        msgpack_pack_float(mp_pck, *((float *) buf));
        break;
    case TDH_INTYPE_DOUBLE:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(double))) {
            break;
        }
        msgpack_pack_double(mp_pck, *((double *) buf));
        break;
    case TDH_INTYPE_GUID:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(GUID))) {
            break;
        }
        pack_guid_value(mp_pck, (GUID *) buf);
        break;
    case TDH_INTYPE_FILETIME:
        if (pack_nil_if_property_too_small(mp_pck, size, sizeof(FILETIME))) {
            break;
        }
        pack_filetime_value(mp_pck, (FILETIME *) buf);
        break;
    case TDH_INTYPE_POINTER:
        if (size == sizeof(UINT64)) {
            msgpack_pack_uint64(mp_pck, *((UINT64 *) buf));
        }
        else if (size == sizeof(UINT32)) {
            msgpack_pack_uint32(mp_pck, *((UINT32 *) buf));
        }
        else {
            msgpack_pack_nil(mp_pck);
        }
        break;
    default:
        if (size == 0) {
            msgpack_pack_nil(mp_pck);
        }
        else {
            str = (char *) buf;
            msgpack_pack_bin(mp_pck, size);
            msgpack_pack_bin_body(mp_pck, str, size);
        }
        break;
    }
}

static void pack_payload_property(msgpack_packer *mp_pck, PEVENT_RECORD record,
                                  TRACE_EVENT_INFO *info, ULONG index)
{
    ULONG size;
    TDHSTATUS status;
    BYTE *buf;
    PROPERTY_DATA_DESCRIPTOR desc;
    EVENT_PROPERTY_INFO *prop;

    prop = &info->EventPropertyInfoArray[index];
    if (prop->Flags & PropertyStruct) {
        msgpack_pack_nil(mp_pck);
        return;
    }

    memset(&desc, 0, sizeof(desc));
    desc.PropertyName = (ULONGLONG) ((char *) info + prop->NameOffset);
    desc.ArrayIndex = ULONG_MAX;

    size = 0;
    status = TdhGetPropertySize(record, 0, NULL, 1, &desc, &size);
    if (status != ERROR_SUCCESS || size == 0) {
        msgpack_pack_nil(mp_pck);
        return;
    }

    buf = flb_malloc(size);
    if (buf == NULL) {
        flb_errno();
        msgpack_pack_nil(mp_pck);
        return;
    }

    status = TdhGetProperty(record, 0, NULL, 1, &desc, size, buf);
    if (status == ERROR_SUCCESS) {
        pack_property_value(mp_pck, prop->nonStructType.InType, buf, size);
    }
    else {
        msgpack_pack_nil(mp_pck);
    }

    flb_free(buf);
}

static void pack_payload(msgpack_packer *mp_pck, PEVENT_RECORD record)
{
    ULONG size;
    ULONG i;
    TDHSTATUS status;
    TRACE_EVENT_INFO *info;
    EVENT_PROPERTY_INFO *prop;
    WCHAR *name;
    char fallback[32];

    size = 0;
    status = TdhGetEventInformation(record, 0, NULL, NULL, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        msgpack_pack_map(mp_pck, 0);
        return;
    }

    info = flb_malloc(size);
    if (info == NULL) {
        flb_errno();
        msgpack_pack_map(mp_pck, 0);
        return;
    }

    status = TdhGetEventInformation(record, 0, NULL, info, &size);
    if (status != ERROR_SUCCESS) {
        flb_free(info);
        msgpack_pack_map(mp_pck, 0);
        return;
    }

    msgpack_pack_map(mp_pck, info->TopLevelPropertyCount);
    for (i = 0; i < info->TopLevelPropertyCount; i++) {
        prop = &info->EventPropertyInfoArray[i];
        if (prop->NameOffset > 0) {
            name = (WCHAR *) ((char *) info + prop->NameOffset);
            pack_wide_string(mp_pck, name, 0);
        }
        else {
            snprintf(fallback, sizeof(fallback), "property_%lu", i);
            pack_cstr(mp_pck, fallback);
        }

        pack_payload_property(mp_pck, record, info, i);
    }

    flb_free(info);
}

static void pack_related_activity_id(msgpack_packer *mp_pck, PEVENT_RECORD record)
{
    USHORT i;
    PEVENT_HEADER_EXTENDED_DATA_ITEM item;
    PEVENT_EXTENDED_ITEM_RELATED_ACTIVITYID related;

    for (i = 0; i < record->ExtendedDataCount; i++) {
        item = &record->ExtendedData[i];
        if (item->ExtType != EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID) {
            continue;
        }

        if (item->DataPtr == 0 ||
            item->DataSize < sizeof(EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID)) {
            msgpack_pack_nil(mp_pck);
            return;
        }

        related = (PEVENT_EXTENDED_ITEM_RELATED_ACTIVITYID) (uintptr_t) item->DataPtr;
        pack_guid_value(mp_pck, &related->RelatedActivityId);
        return;
    }

    msgpack_pack_nil(mp_pck);
}

static TRACEHANDLE etw_exchange_trace(struct flb_etw *ctx, TRACEHANDLE value)
{
    TRACEHANDLE previous;

    EnterCriticalSection(&ctx->handle_lock);
    previous = ctx->trace;
    ctx->trace = value;
    LeaveCriticalSection(&ctx->handle_lock);

    return previous;
}

static TRACEHANDLE etw_exchange_session(struct flb_etw *ctx, TRACEHANDLE value)
{
    TRACEHANDLE previous;

    EnterCriticalSection(&ctx->handle_lock);
    previous = ctx->session;
    ctx->session = value;
    LeaveCriticalSection(&ctx->handle_lock);

    return previous;
}

static TRACEHANDLE etw_get_session(struct flb_etw *ctx)
{
    TRACEHANDLE session;

    EnterCriticalSection(&ctx->handle_lock);
    session = ctx->session;
    LeaveCriticalSection(&ctx->handle_lock);

    return session;
}

static int etw_update_loss_metrics(struct flb_etw *ctx)
{
    ULONG status;
    TRACEHANDLE session;
    uint64_t timestamp;
    char *name;
    LONG query_errors;

    if (ctx->cmt_events_lost == NULL ||
        ctx->cmt_realtime_buffers_lost == NULL ||
        ctx->properties == NULL) {
        return 0;
    }

    session = etw_get_session(ctx);
    if (session == 0) {
        return 0;
    }

    status = ControlTraceW(session,
                           ctx->session_name_wide,
                           ctx->properties,
                           EVENT_TRACE_CONTROL_QUERY);
    if (status != ERROR_SUCCESS) {
        query_errors = InterlockedIncrement(&ctx->query_errors);
        if (query_errors == 1 || query_errors % 1000 == 0) {
            flb_plg_warn(ctx->ins,
                         "ControlTrace query failed for session '%S' (status=%lu)",
                         ctx->session_name_wide, status);
        }
        return -1;
    }

    name = (char *) flb_input_name(ctx->ins);
    timestamp = cfl_time_now();

    cmt_gauge_set(ctx->cmt_events_lost,
                  timestamp,
                  (double) ctx->properties->EventsLost,
                  1, (char *[]) {name});
    cmt_gauge_set(ctx->cmt_realtime_buffers_lost,
                  timestamp,
                  (double) ctx->properties->RealTimeBuffersLost,
                  1, (char *[]) {name});

    return 0;
}

static int etw_loss_metrics_collect(struct flb_input_instance *in,
                                    struct flb_config *config, void *data)
{
    struct flb_etw *ctx;

    ctx = data;
    etw_update_loss_metrics(ctx);

    return 0;
}

static VOID WINAPI etw_event_callback(PEVENT_RECORD record)
{
    struct flb_etw *ctx;
    struct flb_time timestamp;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    LONG append_errors;
    int ret;

    ctx = (struct flb_etw *) record->UserContext;
    if (ctx == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&ctx->paused, 0, 0) ||
        InterlockedCompareExchange(&ctx->exiting, 0, 0)) {
        return;
    }

    etw_timestamp_to_flb_time(&record->EventHeader, &timestamp);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_time_append_to_msgpack(&timestamp, &mp_pck, FLB_TIME_ETFMT_INT);
    msgpack_pack_map(&mp_pck, FLB_IN_ETW_PROVIDER_MAP_SIZE);

    pack_cstr(&mp_pck, "provider_guid");
    pack_guid_value(&mp_pck, &record->EventHeader.ProviderId);

    pack_cstr(&mp_pck, "provider_name");
    if (ctx->provider_name != NULL) {
        pack_cstr(&mp_pck, ctx->provider_name);
    }
    else {
        msgpack_pack_nil(&mp_pck);
    }

    pack_cstr(&mp_pck, "event_id");
    msgpack_pack_uint16(&mp_pck, record->EventHeader.EventDescriptor.Id);

    pack_cstr(&mp_pck, "version");
    msgpack_pack_uint8(&mp_pck, record->EventHeader.EventDescriptor.Version);

    pack_cstr(&mp_pck, "channel");
    msgpack_pack_uint8(&mp_pck, record->EventHeader.EventDescriptor.Channel);

    pack_cstr(&mp_pck, "level");
    msgpack_pack_uint8(&mp_pck, record->EventHeader.EventDescriptor.Level);

    pack_cstr(&mp_pck, "task");
    msgpack_pack_uint16(&mp_pck, record->EventHeader.EventDescriptor.Task);

    pack_cstr(&mp_pck, "opcode");
    msgpack_pack_uint8(&mp_pck, record->EventHeader.EventDescriptor.Opcode);

    pack_cstr(&mp_pck, "keywords");
    msgpack_pack_uint64(&mp_pck, record->EventHeader.EventDescriptor.Keyword);

    pack_cstr(&mp_pck, "process_id");
    msgpack_pack_uint32(&mp_pck, record->EventHeader.ProcessId);

    pack_cstr(&mp_pck, "thread_id");
    msgpack_pack_uint32(&mp_pck, record->EventHeader.ThreadId);

    pack_cstr(&mp_pck, "activity_id");
    pack_guid_value(&mp_pck, &record->EventHeader.ActivityId);

    pack_cstr(&mp_pck, "related_activity_id");
    pack_related_activity_id(&mp_pck, record);

    pack_cstr(&mp_pck, "payload");
    pack_payload(&mp_pck, record);

    ret = flb_input_log_append(ctx->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    if (ret == -1) {
        append_errors = InterlockedIncrement(&ctx->append_errors);
        if (append_errors == 1 || append_errors % 1000 == 0) {
            flb_plg_warn(ctx->ins,
                         "failed to append ETW event record (%ld failures)",
                         append_errors);
        }
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
}

static void etw_close_trace(struct flb_etw *ctx)
{
    TRACEHANDLE trace;

    trace = etw_exchange_trace(ctx, INVALID_PROCESSTRACE_HANDLE);
    if (trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(trace);
    }
}

static ULONG etw_stop_session_by_name(struct flb_etw *ctx)
{
    return ControlTraceW(0,
                         ctx->session_name_wide,
                         ctx->properties,
                         EVENT_TRACE_CONTROL_STOP);
}

static void etw_disable_provider(struct flb_etw *ctx, TRACEHANDLE session)
{
    ULONG status;

    if (session == 0 || ctx->session_type == FLB_IN_ETW_SESSION_SYSTEM) {
        return;
    }

    status = EnableTraceEx2(session,
                            &ctx->provider_guid,
                            EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                            (UCHAR) ctx->level,
                            ctx->match_any_keyword,
                            ctx->match_all_keyword,
                            0,
                            NULL);
    if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
        flb_plg_warn(ctx->ins, "EnableTraceEx2 disable failed (status=%lu)", status);
    }
}

static void etw_stop_session(struct flb_etw *ctx)
{
    TRACEHANDLE session;
    ULONG status;

    session = etw_exchange_session(ctx, 0);
    if (session != 0 && ctx->properties != NULL) {
        etw_disable_provider(ctx, session);
        status = ControlTraceW(session,
                               ctx->session_name_wide,
                               ctx->properties,
                               EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
            flb_plg_warn(ctx->ins, "ControlTrace stop failed (status=%lu)", status);
        }
    }
}

static ULONG etw_start_session(struct flb_etw *ctx)
{
    ULONG status;
    TRACEHANDLE session;

    session = 0;
    status = StartTraceW(&session, ctx->session_name_wide, ctx->properties);
    if (status != ERROR_ALREADY_EXISTS) {
        if (status == ERROR_SUCCESS) {
            etw_exchange_session(ctx, session);
        }
        return status;
    }

    if (ctx->stale_session_action == FLB_IN_ETW_STALE_ACTION_FAIL) {
        return ERROR_ALREADY_EXISTS;
    }

    flb_plg_warn(ctx->ins,
                 "ETW session '%S' already exists; stopping stale session and retrying",
                 ctx->session_name_wide);

    status = etw_stop_session_by_name(ctx);
    if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
        flb_plg_error(ctx->ins,
                      "could not stop existing ETW session '%S' (status=%lu)",
                      ctx->session_name_wide, status);
        return ERROR_ALREADY_EXISTS;
    }

    session = 0;
    status = StartTraceW(&session, ctx->session_name_wide, ctx->properties);
    if (status == ERROR_SUCCESS) {
        etw_exchange_session(ctx, session);
    }

    return status;
}

static void *etw_worker(void *data)
{
    ULONG status;
    TRACEHANDLE session;
    TRACEHANDLE trace;
    EVENT_TRACE_LOGFILEW logfile;
    struct flb_etw *ctx;

    ctx = data;

    status = etw_start_session(ctx);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ALREADY_EXISTS) {
            flb_plg_error(ctx->ins,
                          "ETW session '%S' already exists and could not be reused",
                          ctx->session_name_wide);
        }
        else {
            flb_plg_error(ctx->ins, "StartTrace failed for session '%S' (status=%lu)",
                          ctx->session_name_wide, status);
        }
        return NULL;
    }

    if (ctx->session_type == FLB_IN_ETW_SESSION_PROVIDER) {
        session = etw_get_session(ctx);

        status = EnableTraceEx2(session,
                                &ctx->provider_guid,
                                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                (UCHAR) ctx->level,
                                ctx->match_any_keyword,
                                ctx->match_all_keyword,
                                0,
                                NULL);
        if (status != ERROR_SUCCESS) {
            flb_plg_error(ctx->ins, "EnableTraceEx2 failed (status=%lu)", status);
            etw_stop_session(ctx);
            return NULL;
        }
    }

    memset(&logfile, 0, sizeof(logfile));
    logfile.LoggerName = ctx->session_name_wide;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = etw_event_callback;
    logfile.Context = ctx;

    trace = OpenTraceW(&logfile);
    etw_exchange_trace(ctx, trace);
    if (trace == INVALID_PROCESSTRACE_HANDLE) {
        flb_plg_error(ctx->ins, "OpenTrace failed (error=%lu)", GetLastError());
        etw_stop_session(ctx);
        return NULL;
    }

    status = ProcessTrace(&trace, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && !InterlockedCompareExchange(&ctx->exiting, 0, 0)) {
        flb_plg_error(ctx->ins, "ProcessTrace failed (status=%lu)", status);
    }

    etw_close_trace(ctx);

    if (!InterlockedCompareExchange(&ctx->exiting, 0, 0)) {
        etw_stop_session(ctx);
    }

    return NULL;
}

static void etw_config_destroy(struct flb_etw *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->thread_created) {
        InterlockedExchange(&ctx->exiting, 1);
        etw_close_trace(ctx);
        etw_stop_session(ctx);
        pthread_join(ctx->thread, NULL);
    }

    if (ctx->session_name_wide != NULL) {
        flb_free(ctx->session_name_wide);
    }

    if (ctx->properties != NULL) {
        flb_free(ctx->properties);
    }

    DeleteCriticalSection(&ctx->handle_lock);

    flb_free(ctx);
}

static int configure_provider(struct flb_etw *ctx)
{
    WCHAR *provider_name_wide;
    GUID name_guid;
    char guid_buf[64];
    int have_guid;
    int have_name;

    have_guid = ctx->provider_guid_str != NULL && ctx->provider_guid_str[0] != '\0';
    have_name = ctx->provider_name != NULL && ctx->provider_name[0] != '\0';

    if (ctx->session_type == FLB_IN_ETW_SESSION_SYSTEM) {
        if (have_guid || have_name) {
            flb_plg_error(ctx->ins,
                          "provider_guid/provider_name cannot be used with session_type system");
            return -1;
        }
        return 0;
    }

    if (!have_guid && !have_name) {
        flb_plg_error(ctx->ins, "either provider_guid or provider_name must be set");
        return -1;
    }

    if (have_guid && parse_guid(ctx->provider_guid_str, &ctx->provider_guid) != 0) {
        flb_plg_error(ctx->ins, "invalid provider_guid '%s'", ctx->provider_guid_str);
        return -1;
    }

    if (!have_name) {
        return 0;
    }

    provider_name_wide = utf8_to_wide(ctx->provider_name);
    if (provider_name_wide == NULL) {
        flb_plg_error(ctx->ins, "could not convert provider_name '%s' to UTF-16",
                      ctx->provider_name);
        return -1;
    }

    if (resolve_provider_name(ctx, provider_name_wide, &name_guid) != 0) {
        flb_free(provider_name_wide);
        return -1;
    }
    flb_free(provider_name_wide);

    if (have_guid && memcmp(&ctx->provider_guid, &name_guid, sizeof(GUID)) != 0) {
        guid_to_string(&name_guid, guid_buf, sizeof(guid_buf));
        flb_plg_error(ctx->ins,
                      "provider_name '%s' resolves to %s, which does not match provider_guid '%s'",
                      ctx->provider_name, guid_buf, ctx->provider_guid_str);
        return -1;
    }

    ctx->provider_guid = name_guid;

    return 0;
}

static int configure_session_properties(struct flb_etw *ctx)
{
    if (ctx->buffer_size < 0) {
        flb_plg_error(ctx->ins, "buffer_size must be zero or greater");
        return -1;
    }

    if (ctx->minimum_buffers < 0) {
        flb_plg_error(ctx->ins, "minimum_buffers must be zero or greater");
        return -1;
    }

    if (ctx->maximum_buffers < 0) {
        flb_plg_error(ctx->ins, "maximum_buffers must be zero or greater");
        return -1;
    }

    if (ctx->flush_timer < 0) {
        flb_plg_error(ctx->ins, "flush_timer must be zero or greater");
        return -1;
    }

    if (ctx->minimum_buffers > 0 &&
        ctx->maximum_buffers > 0 &&
        ctx->minimum_buffers > ctx->maximum_buffers) {
        flb_plg_error(ctx->ins,
                      "minimum_buffers must be less than or equal to maximum_buffers");
        return -1;
    }

    return 0;
}

static int configure_session_name(struct flb_etw *ctx)
{
    if (ctx->session_type != FLB_IN_ETW_SESSION_SYSTEM) {
        return 0;
    }

    if (ctx->session_name == NULL ||
        strcmp(ctx->session_name, FLB_IN_ETW_DEFAULT_SESSION_NAME) == 0 ||
        strcmp(ctx->session_name, KERNEL_LOGGER_NAMEA) == 0) {
        return 0;
    }

    flb_plg_error(ctx->ins,
                  "session_type system requires session_name '%s'",
                  KERNEL_LOGGER_NAMEA);

    return -1;
}

static const char *effective_session_name(struct flb_etw *ctx)
{
    if (ctx->session_type == FLB_IN_ETW_SESSION_SYSTEM &&
        ctx->session_name != NULL &&
        strcmp(ctx->session_name, FLB_IN_ETW_DEFAULT_SESSION_NAME) == 0) {
        return KERNEL_LOGGER_NAMEA;
    }

    return ctx->session_name;
}

static int configure_loss_metrics(struct flb_etw *ctx, struct flb_config *config)
{
    int ret;
    time_t interval;

    ctx->loss_metrics_collector_id = -1;

    if (ctx->ins->cmt == NULL) {
        return 0;
    }

    ctx->cmt_events_lost = cmt_gauge_create(ctx->ins->cmt,
                                            "fluentbit", "input",
                                            "etw_events_lost",
                                            "Number of ETW events lost by the session.",
                                            1, (char *[]) {"name"});
    if (ctx->cmt_events_lost == NULL) {
        flb_plg_error(ctx->ins, "could not create ETW events lost metric");
        return -1;
    }

    ctx->cmt_realtime_buffers_lost =
        cmt_gauge_create(ctx->ins->cmt,
                         "fluentbit", "input",
                         "etw_realtime_buffers_lost",
                         "Number of ETW real-time buffers lost by the session.",
                         1, (char *[]) {"name"});
    if (ctx->cmt_realtime_buffers_lost == NULL) {
        flb_plg_error(ctx->ins, "could not create ETW real-time buffers lost metric");
        return -1;
    }

    interval = ctx->flush_timer > 0 ? ctx->flush_timer : 1;
    ret = flb_input_set_collector_time(ctx->ins,
                                       etw_loss_metrics_collect,
                                       interval, 0,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set ETW loss metrics collector");
        return -1;
    }

    ctx->loss_metrics_collector_id = ret;

    return 0;
}

static int in_etw_init(struct flb_input_instance *in,
                       struct flb_config *config, void *data)
{
    HRESULT hres;
    int ret;
    const char *session_name;
    struct flb_etw *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_etw));
    if (ctx == NULL) {
        flb_errno();
        return -1;
    }

    ctx->ins = in;
    ctx->trace = INVALID_PROCESSTRACE_HANDLE;
    ctx->loss_metrics_collector_id = -1;
    InitializeCriticalSection(&ctx->handle_lock);

    ret = flb_input_config_map_set(in, ctx);
    if (ret == -1) {
        etw_config_destroy(ctx);
        return -1;
    }

    if (parse_session_type(ctx) != 0) {
        etw_config_destroy(ctx);
        return -1;
    }

    if (parse_stale_session_action(ctx) != 0) {
        etw_config_destroy(ctx);
        return -1;
    }

    if (ctx->level < 0 || ctx->level > 255) {
        flb_plg_error(ctx->ins, "level must be between 0 and 255");
        etw_config_destroy(ctx);
        return -1;
    }

    if (parse_uint64(ctx->match_any_keyword_str, &ctx->match_any_keyword) != 0) {
        flb_plg_error(ctx->ins, "invalid match_any_keyword '%s'",
                      ctx->match_any_keyword_str);
        etw_config_destroy(ctx);
        return -1;
    }

    if (parse_uint64(ctx->match_all_keyword_str, &ctx->match_all_keyword) != 0) {
        flb_plg_error(ctx->ins, "invalid match_all_keyword '%s'",
                      ctx->match_all_keyword_str);
        etw_config_destroy(ctx);
        return -1;
    }

    if (parse_kernel_flags(ctx) != 0) {
        etw_config_destroy(ctx);
        return -1;
    }

    if (configure_session_properties(ctx) != 0) {
        etw_config_destroy(ctx);
        return -1;
    }

    if (configure_session_name(ctx) != 0) {
        etw_config_destroy(ctx);
        return -1;
    }

    if (configure_provider(ctx) != 0) {
        etw_config_destroy(ctx);
        return -1;
    }

    session_name = effective_session_name(ctx);
    ctx->session_name_wide = utf8_to_wide(session_name);
    if (ctx->session_name_wide == NULL) {
        flb_plg_error(ctx->ins, "could not convert session_name '%s' to UTF-16",
                      session_name);
        etw_config_destroy(ctx);
        return -1;
    }

    hres = CoCreateGuid(&ctx->session_guid);
    if (FAILED(hres)) {
        flb_plg_error(ctx->ins, "could not generate ETW session GUID (hr=0x%08lx)",
                      (unsigned long) hres);
        etw_config_destroy(ctx);
        return -1;
    }

    ctx->properties = create_trace_properties(ctx);
    if (ctx->properties == NULL) {
        etw_config_destroy(ctx);
        return -1;
    }

    flb_input_set_context(in, ctx);

    if (configure_loss_metrics(ctx, config) != 0) {
        etw_config_destroy(ctx);
        return -1;
    }

    ret = pthread_create(&ctx->thread, NULL, etw_worker, ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not create ETW worker thread");
        etw_config_destroy(ctx);
        return -1;
    }
    ctx->thread_created = FLB_TRUE;

    return 0;
}

static void in_etw_pause(void *data, struct flb_config *config)
{
    struct flb_etw *ctx;

    ctx = data;
    InterlockedExchange(&ctx->paused, 1);
    if (ctx->loss_metrics_collector_id >= 0) {
        flb_input_collector_pause(ctx->loss_metrics_collector_id, ctx->ins);
    }
}

static void in_etw_resume(void *data, struct flb_config *config)
{
    struct flb_etw *ctx;

    ctx = data;
    InterlockedExchange(&ctx->paused, 0);
    if (ctx->loss_metrics_collector_id >= 0) {
        flb_input_collector_resume(ctx->loss_metrics_collector_id, ctx->ins);
    }
}

static int in_etw_exit(void *data, struct flb_config *config)
{
    struct flb_etw *ctx;

    ctx = data;
    etw_config_destroy(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_STR, "provider_guid", NULL,
      0, FLB_TRUE, offsetof(struct flb_etw, provider_guid_str),
      "ETW provider GUID to enable"
    },
    {
      FLB_CONFIG_MAP_STR, "provider_name", NULL,
      0, FLB_TRUE, offsetof(struct flb_etw, provider_name),
      "ETW provider name to resolve and enable"
    },
    {
      FLB_CONFIG_MAP_STR, "session_name", FLB_IN_ETW_DEFAULT_SESSION_NAME,
      0, FLB_TRUE, offsetof(struct flb_etw, session_name),
      "ETW real-time session name. When session_type is system and this value "
      "is left as the default, the plugin uses the Windows kernel logger "
      "session name 'NT Kernel Logger'."
    },
    {
      FLB_CONFIG_MAP_STR, "session_type", FLB_IN_ETW_DEFAULT_SESSION_TYPE,
      0, FLB_TRUE, offsetof(struct flb_etw, session_type_str),
      "ETW session type: provider for a real-time provider consumer, or system "
      "for a system logger session using kernel_flags."
    },
    {
      FLB_CONFIG_MAP_STR, "stale_session_action", FLB_IN_ETW_DEFAULT_STALE_ACTION,
      0, FLB_TRUE, offsetof(struct flb_etw, stale_session_action_str),
      "Action when the ETW session already exists: stop stops the existing "
      "session and retries; fail returns an error without stopping it."
    },
    {
      FLB_CONFIG_MAP_INT, "level", FLB_IN_ETW_DEFAULT_LEVEL,
      0, FLB_TRUE, offsetof(struct flb_etw, level),
      "ETW provider level"
    },
    {
      FLB_CONFIG_MAP_STR, "match_any_keyword", FLB_IN_ETW_DEFAULT_MATCH_ANY,
      0, FLB_TRUE, offsetof(struct flb_etw, match_any_keyword_str),
      "ETW MatchAnyKeyword mask"
    },
    {
      FLB_CONFIG_MAP_STR, "match_all_keyword", FLB_IN_ETW_DEFAULT_MATCH_ALL,
      0, FLB_TRUE, offsetof(struct flb_etw, match_all_keyword_str),
      "ETW MatchAllKeyword mask"
    },
    {
      FLB_CONFIG_MAP_STR, "kernel_flags", FLB_IN_ETW_DEFAULT_KERNEL_FLAGS,
      0, FLB_TRUE, offsetof(struct flb_etw, kernel_flags_str),
      "Comma-separated kernel flags used with session_type system. Supported "
      "names: process, thread, image_load, cswitch, tcpip, disk_io. A numeric "
      "EVENT_TRACE_FLAG_* mask is also accepted."
    },
    {
      FLB_CONFIG_MAP_INT, "buffer_size", FLB_IN_ETW_DEFAULT_BUFFER_SIZE,
      0, FLB_TRUE, offsetof(struct flb_etw, buffer_size),
      "ETW session buffer size in kilobytes. The session buffer memory upper "
      "bound is buffer_size KB * maximum_buffers; the default is 64 KB * 32 "
      "= 2048 KB. Zero uses the Windows default."
    },
    {
      FLB_CONFIG_MAP_INT, "minimum_buffers", FLB_IN_ETW_DEFAULT_MIN_BUFFERS,
      0, FLB_TRUE, offsetof(struct flb_etw, minimum_buffers),
      "Minimum number of ETW session buffers. Zero uses the Windows default."
    },
    {
      FLB_CONFIG_MAP_INT, "maximum_buffers", FLB_IN_ETW_DEFAULT_MAX_BUFFERS,
      0, FLB_TRUE, offsetof(struct flb_etw, maximum_buffers),
      "Maximum number of ETW session buffers. The session buffer memory upper "
      "bound is buffer_size KB * maximum_buffers; the default is 64 KB * 32 "
      "= 2048 KB. Zero uses the Windows default."
    },
    {
      FLB_CONFIG_MAP_INT, "flush_timer", FLB_IN_ETW_DEFAULT_FLUSH_TIMER,
      0, FLB_TRUE, offsetof(struct flb_etw, flush_timer),
      "ETW session flush timer in seconds. Zero uses the Windows default."
    },
    {0}
};

struct flb_input_plugin in_etw_plugin = {
    .name         = "event_tracing_windows",
    .description  = "Event Tracing for Windows",
    .cb_init      = in_etw_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = in_etw_pause,
    .cb_resume    = in_etw_resume,
    .cb_exit      = in_etw_exit,
    .config_map   = config_map
};
