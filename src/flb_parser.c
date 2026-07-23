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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_parser_decoder.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_strptime.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>
#include <fluent-bit/multiline/flb_ml_rule.h>

#include <cfl/cfl.h>
#include <cfl/cfl_kvlist.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef FLB_SYSTEM_WINDOWS
struct windows_time_zone {
    DYNAMIC_TIME_ZONE_INFORMATION dtzi;
};

static int utf8_to_wide(const char *str, wchar_t *buf, int buf_size)
{
    int ret;

    ret = MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, buf_size);
    if (ret == 0) {
        return -1;
    }

    return 0;
}

static int windows_time_zone_lookup(const char *windows_zone,
                                    DYNAMIC_TIME_ZONE_INFORMATION *dtzi)
{
    DWORD index;
    DWORD ret;
    wchar_t wide_zone[128];

    if (windows_zone == NULL || dtzi == NULL) {
        return -1;
    }

    if (utf8_to_wide(windows_zone, wide_zone,
                     sizeof(wide_zone) / sizeof(wide_zone[0])) != 0) {
        return -1;
    }

    for (index = 0; ; index++) {
        memset(dtzi, 0, sizeof(DYNAMIC_TIME_ZONE_INFORMATION));
        ret = EnumDynamicTimeZoneInformation(index, dtzi);
        if (ret == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (ret != ERROR_SUCCESS) {
            continue;
        }
        if (wcscmp(dtzi->TimeZoneKeyName, wide_zone) == 0) {
            return 0;
        }
    }

    return -1;
}

static int windows_systemtime_from_tm(const struct tm *tm, SYSTEMTIME *st)
{
    int year;

    year = tm->tm_year + 1900;
    if (year < 1601 || year > 30827) {
        return -1;
    }

    memset(st, 0, sizeof(SYSTEMTIME));
    st->wYear = (WORD) year;
    st->wMonth = (WORD) (tm->tm_mon + 1);
    st->wDay = (WORD) tm->tm_mday;
    st->wHour = (WORD) tm->tm_hour;
    st->wMinute = (WORD) tm->tm_min;
    st->wSecond = (WORD) tm->tm_sec;

    return 0;
}

static int windows_time_zone_load(const char *iana_zone, struct windows_time_zone *tz)
{
    int ret;
    const char *windows_zone;

    windows_zone = flb_time_iana_zone_to_windows(iana_zone);
    if (windows_zone == NULL) {
        return -1;
    }

    ret = windows_time_zone_lookup(windows_zone, &tz->dtzi);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

static time_t windows_tm2time_zone(const struct flb_tm *src, struct windows_time_zone *tz)
{
    int ret;
    struct tm utc_tm;
    SYSTEMTIME local_st;
    SYSTEMTIME utc_st;
    TIME_ZONE_INFORMATION tzi;

    if (tz == NULL) {
        return (time_t) -1;
    }

    ret = GetTimeZoneInformationForYear(src->tm.tm_year + 1900, &tz->dtzi, &tzi);
    if (ret == 0) {
        return (time_t) -1;
    }

    ret = windows_systemtime_from_tm(&src->tm, &local_st);
    if (ret != 0) {
        return (time_t) -1;
    }

    ret = TzSpecificLocalTimeToSystemTime(&tzi, &local_st, &utc_st);
    if (ret == 0) {
        return (time_t) -1;
    }

    memset(&utc_tm, 0, sizeof(struct tm));
    utc_tm.tm_year = utc_st.wYear - 1900;
    utc_tm.tm_mon = utc_st.wMonth - 1;
    utc_tm.tm_mday = utc_st.wDay;
    utc_tm.tm_hour = utc_st.wHour;
    utc_tm.tm_min = utc_st.wMinute;
    utc_tm.tm_sec = utc_st.wSecond;
    utc_tm.tm_isdst = 0;

    return timegm(&utc_tm);
}

static int windows_time2tm_zone(time_t time, struct windows_time_zone *tz,
                                struct tm *out_tm)
{
    int ret;
    struct tm utc_tm;
    SYSTEMTIME utc_st;
    SYSTEMTIME local_st;
    TIME_ZONE_INFORMATION tzi;

    if (tz == NULL) {
        return -1;
    }

    gmtime_r(&time, &utc_tm);

    ret = GetTimeZoneInformationForYear(utc_tm.tm_year + 1900, &tz->dtzi, &tzi);
    if (ret == 0) {
        return -1;
    }

    if (windows_systemtime_from_tm(&utc_tm, &utc_st) != 0) {
        return -1;
    }

    ret = SystemTimeToTzSpecificLocalTime(&tzi, &utc_st, &local_st);
    if (ret == 0) {
        return -1;
    }

    memset(out_tm, 0, sizeof(struct tm));
    out_tm->tm_year = local_st.wYear - 1900;
    out_tm->tm_mon = local_st.wMonth - 1;
    out_tm->tm_mday = local_st.wDay;
    out_tm->tm_hour = local_st.wHour;
    out_tm->tm_min = local_st.wMinute;
    out_tm->tm_sec = local_st.wSecond;

    return 0;
}
#endif

#ifndef FLB_SYSTEM_WINDOWS
struct tzif_type {
    int32_t gmtoff;
    unsigned char isdst;
};

struct tzif {
    int timecnt;
    int typecnt;
    int default_type;
    int64_t *transitions;
    unsigned char *transition_types;
    struct tzif_type *types;
};

static int zoneinfo_file_exists(const char *iana_zone)
{
    int ret;
    size_t len;
    char path[PATH_MAX];
    const char *tzdir;
    struct stat st;

    tzdir = getenv("TZDIR");
    if (tzdir == NULL || tzdir[0] == '\0') {
        tzdir = "/usr/share/zoneinfo";
    }

    ret = snprintf(path, sizeof(path), "%s/%s", tzdir, iana_zone);
    if (ret < 0) {
        return FLB_FALSE;
    }

    len = (size_t) ret;
    if (len >= sizeof(path)) {
        return FLB_FALSE;
    }

    if (stat(path, &st) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int zoneinfo_path(const char *iana_zone, char *path, size_t path_size)
{
    int ret;
    size_t len;
    const char *tzdir;

    tzdir = getenv("TZDIR");
    if (tzdir == NULL || tzdir[0] == '\0') {
        tzdir = "/usr/share/zoneinfo";
    }

    ret = snprintf(path, path_size, "%s/%s", tzdir, iana_zone);
    if (ret < 0) {
        return -1;
    }

    len = (size_t) ret;
    if (len >= path_size) {
        return -1;
    }

    return 0;
}

static uint32_t read_be32(const unsigned char *buf)
{
    return ((uint32_t) buf[0] << 24) |
           ((uint32_t) buf[1] << 16) |
           ((uint32_t) buf[2] << 8) |
           (uint32_t) buf[3];
}

static int32_t read_be32s(const unsigned char *buf)
{
    return (int32_t) read_be32(buf);
}

static int64_t read_be64s(const unsigned char *buf)
{
    uint64_t value;

    value = ((uint64_t) buf[0] << 56) |
            ((uint64_t) buf[1] << 48) |
            ((uint64_t) buf[2] << 40) |
            ((uint64_t) buf[3] << 32) |
            ((uint64_t) buf[4] << 24) |
            ((uint64_t) buf[5] << 16) |
            ((uint64_t) buf[6] << 8) |
            (uint64_t) buf[7];

    return (int64_t) value;
}

static void tzif_destroy(struct tzif *tz)
{
    if (tz == NULL) {
        return;
    }

    flb_free(tz->transitions);
    flb_free(tz->transition_types);
    flb_free(tz->types);
}

static int tzif_data_size(const unsigned char *header, int time_size,
                          size_t *out_size)
{
    uint32_t isutcnt;
    uint32_t isstdcnt;
    uint32_t leapcnt;
    uint32_t timecnt;
    uint32_t typecnt;
    uint32_t charcnt;
    size_t size;

    isutcnt = read_be32(header + 20);
    isstdcnt = read_be32(header + 24);
    leapcnt = read_be32(header + 28);
    timecnt = read_be32(header + 32);
    typecnt = read_be32(header + 36);
    charcnt = read_be32(header + 40);

    size = ((size_t) timecnt * (size_t) time_size) +
           (size_t) timecnt +
           ((size_t) typecnt * 6) +
           (size_t) charcnt +
           ((size_t) leapcnt * ((size_t) time_size + 4)) +
           (size_t) isstdcnt +
           (size_t) isutcnt;

    *out_size = size;
    return 0;
}

static int tzif_parse_data(const unsigned char *buf, size_t size,
                           int time_size, struct tzif *tz)
{
    int i;
    int type;
    size_t off;
    uint32_t timecnt;
    uint32_t typecnt;

    if (size < 44) {
        return -1;
    }

    timecnt = read_be32(buf + 32);
    typecnt = read_be32(buf + 36);
    if (typecnt == 0 || timecnt > INT_MAX || typecnt > INT_MAX) {
        return -1;
    }

    off = 44;
    if (off + ((size_t) timecnt * (size_t) time_size) > size) {
        return -1;
    }

    memset(tz, 0, sizeof(struct tzif));
    tz->timecnt = (int) timecnt;
    tz->typecnt = (int) typecnt;
    tz->default_type = 0;

    if (timecnt > 0) {
        tz->transitions = flb_calloc(timecnt, sizeof(int64_t));
        if (tz->transitions == NULL) {
            return -1;
        }
    }

    for (i = 0; i < (int) timecnt; i++) {
        if (time_size == 8) {
            tz->transitions[i] = read_be64s(buf + off);
        }
        else {
            tz->transitions[i] = read_be32s(buf + off);
        }
        off += time_size;
    }

    if (off + timecnt > size) {
        tzif_destroy(tz);
        return -1;
    }

    if (timecnt > 0) {
        tz->transition_types = flb_malloc(timecnt);
        if (tz->transition_types == NULL) {
            tzif_destroy(tz);
            return -1;
        }
        memcpy(tz->transition_types, buf + off, timecnt);
    }
    off += timecnt;

    if (off + ((size_t) typecnt * 6) > size) {
        tzif_destroy(tz);
        return -1;
    }

    tz->types = flb_calloc(typecnt, sizeof(struct tzif_type));
    if (tz->types == NULL) {
        tzif_destroy(tz);
        return -1;
    }

    for (i = 0; i < (int) typecnt; i++) {
        tz->types[i].gmtoff = read_be32s(buf + off);
        tz->types[i].isdst = buf[off + 4];
        off += 6;
    }

    for (i = 0; i < (int) timecnt; i++) {
        type = tz->transition_types[i];
        if (type < 0 || type >= (int) typecnt) {
            tzif_destroy(tz);
            return -1;
        }
    }

    for (i = 0; i < (int) typecnt; i++) {
        if (tz->types[i].isdst == 0) {
            tz->default_type = i;
            break;
        }
    }

    return 0;
}

static int tzif_load(const char *iana_zone, struct tzif *tz)
{
    int ret;
    char path[PATH_MAX];
    FILE *fp;
    long file_size;
    size_t read_size;
    size_t block_size;
    unsigned char *buf;
    const unsigned char *header;
    const unsigned char *parse_header;
    unsigned char version;

    if (zoneinfo_path(iana_zone, path, sizeof(path)) != 0) {
        return -1;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    file_size = ftell(fp);
    if (file_size <= 0) {
        fclose(fp);
        return -1;
    }

    rewind(fp);

    buf = flb_malloc((size_t) file_size);
    if (buf == NULL) {
        fclose(fp);
        return -1;
    }

    read_size = fread(buf, 1, (size_t) file_size, fp);
    fclose(fp);
    if (read_size != (size_t) file_size) {
        flb_free(buf);
        return -1;
    }

    if ((size_t) file_size < 44 || memcmp(buf, "TZif", 4) != 0) {
        flb_free(buf);
        return -1;
    }

    header = buf;
    version = header[4];
    parse_header = header;

    if (version == '2' || version == '3' || version == '4') {
        ret = tzif_data_size(header, 4, &block_size);
        if (ret != 0 || 44 + block_size + 44 > (size_t) file_size) {
            flb_free(buf);
            return -1;
        }

        parse_header = buf + 44 + block_size;
        if (memcmp(parse_header, "TZif", 4) != 0) {
            flb_free(buf);
            return -1;
        }

        ret = tzif_parse_data(parse_header,
                              (size_t) file_size - (size_t) (parse_header - buf),
                              8, tz);
    }
    else {
        ret = tzif_parse_data(parse_header, (size_t) file_size, 4, tz);
    }

    flb_free(buf);
    return ret;
}

static int tzif_type_at_utc(struct tzif *tz, int64_t utc)
{
    int lo;
    int hi;
    int mid;

    if (tz->timecnt == 0 || utc < tz->transitions[0]) {
        return tz->default_type;
    }

    lo = 0;
    hi = tz->timecnt - 1;
    while (lo <= hi) {
        mid = lo + ((hi - lo) / 2);
        if (tz->transitions[mid] <= utc) {
            lo = mid + 1;
        }
        else {
            hi = mid - 1;
        }
    }

    return tz->transition_types[hi];
}

static time_t tzif_tm2time(struct tzif *tz, const struct flb_tm *src)
{
    int i;
    int type;
    int64_t local_epoch;
    int64_t candidate;
    struct tm tmp;

    tmp = src->tm;
    tmp.tm_isdst = 0;
    local_epoch = (int64_t) timegm(&tmp);

    for (i = 0; i < tz->typecnt; i++) {
        candidate = local_epoch - (int64_t) tz->types[i].gmtoff;
        type = tzif_type_at_utc(tz, candidate);
        if (type >= 0 && type < tz->typecnt &&
            tz->types[type].gmtoff == tz->types[i].gmtoff) {
            return (time_t) candidate;
        }
    }

    type = tzif_type_at_utc(tz, local_epoch);
    if (type < 0 || type >= tz->typecnt) {
        return (time_t) -1;
    }

    return (time_t) (local_epoch - (int64_t) tz->types[type].gmtoff);
}

static int tzif_time2tm(struct tzif *tz, time_t time, struct tm *out_tm)
{
    int type;
    time_t local_time;

    type = tzif_type_at_utc(tz, (int64_t) time);
    if (type < 0 || type >= tz->typecnt) {
        return -1;
    }

    local_time = time + tz->types[type].gmtoff;
    gmtime_r(&local_time, out_tm);

    return 0;
}
#endif

static int validate_time_zone(const char *iana_zone)
{
#ifdef FLB_SYSTEM_WINDOWS
    DYNAMIC_TIME_ZONE_INFORMATION dtzi;
#endif
    const char *windows_zone;

    if (iana_zone == NULL || iana_zone[0] == '\0') {
        return 0;
    }

    /*
     * Validate against Fluent Bit's built-in IANA timezone index first. On
     * Windows the same entry also gives us the native timezone key.
     */
    windows_zone = flb_time_iana_zone_to_windows(iana_zone);
    if (windows_zone == NULL) {
        return -1;
    }

#ifdef FLB_SYSTEM_WINDOWS
    /* Ensure the mapped native timezone is available on this Windows host. */
    if (windows_time_zone_lookup(windows_zone, &dtzi) != 0) {
        return -1;
    }
#else
    if (zoneinfo_file_exists(iana_zone) == FLB_FALSE) {
        return -1;
    }
#endif

    return 0;
}

static void *time_zone_data_create(const char *iana_zone)
{
#ifdef FLB_SYSTEM_WINDOWS
    struct windows_time_zone *tz;

    tz = flb_calloc(1, sizeof(struct windows_time_zone));
    if (tz == NULL) {
        return NULL;
    }

    if (windows_time_zone_load(iana_zone, tz) != 0) {
        flb_free(tz);
        return NULL;
    }

    return tz;
#else
    struct tzif *tz;

    tz = flb_calloc(1, sizeof(struct tzif));
    if (tz == NULL) {
        return NULL;
    }

    if (tzif_load(iana_zone, tz) != 0) {
        flb_free(tz);
        return NULL;
    }

    return tz;
#endif
}

static void time_zone_data_destroy(void *data)
{
    if (data == NULL) {
        return;
    }

#ifndef FLB_SYSTEM_WINDOWS
    tzif_destroy((struct tzif *) data);
#endif
    flb_free(data);
}

time_t flb_parser_tm2time_parser(const struct flb_tm *src, struct flb_parser *parser)
{
    if (parser->time_zone && parser->time_with_tz == FLB_FALSE) {
#ifdef FLB_SYSTEM_WINDOWS
        return windows_tm2time_zone(src, parser->time_zone_data);
#else
        return tzif_tm2time(parser->time_zone_data, src);
#endif
    }

    return flb_parser_tm2time(src, parser->time_system_timezone);
}

static inline uint32_t digits10(uint64_t v) {
    if (v < 10) return 1;
    if (v < 100) return 2;
    if (v < 1000) return 3;
    if (v < 1000000000000UL) {
        if (v < 100000000UL) {
            if (v < 1000000) {
                if (v < 10000) return 4;
                return 5 + (v >= 100000);
            }
            return 7 + (v >= 10000000UL);
        }
        if (v < 10000000000UL) {
            return 9 + (v >= 1000000000UL);
        }
        return 11 + (v >= 100000000000UL);
    }
    return 12 + digits10(v / 1000000000000UL);
}

static unsigned u64_to_str(uint64_t value, char* dst) {
    static const char digits[201] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    uint32_t const length = digits10(value);
    uint32_t next = length - 1;
    while (value >= 100) {
        int const i = (value % 100) * 2;
        value /= 100;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
        next -= 2;
    }

    /* Handle last 1-2 digits */
    if (value < 10) {
        dst[next] = '0' + (uint32_t) value;
    } else {
        int i = (uint32_t) value * 2;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
    }
    return length;
}

int flb_parser_regex_do(struct flb_parser *parser,
                        const char *buf, size_t length,
                        void **out_buf, size_t *out_size,
                        struct flb_time *out_time);

int flb_parser_json_do(struct flb_parser *parser,
                       const char *buf, size_t length,
                       void **out_buf, size_t *out_size,
                       struct flb_time *out_time);

int flb_parser_ltsv_do(struct flb_parser *parser,
                       const char *buf, size_t length,
                       void **out_buf, size_t *out_size,
                       struct flb_time *out_time);

int flb_parser_logfmt_do(struct flb_parser *parser,
                         const char *buf, size_t length,
                         void **out_buf, size_t *out_size,
                         struct flb_time *out_time);

int flb_parser_tskv_do(struct flb_parser *parser,
                         const char *buf, size_t length,
                         void **out_buf, size_t *out_size,
                         struct flb_time *out_time);
/*
 * This function is used to free all aspects of a parser
 * which is provided by the caller of flb_create_parser.
 * Specifically, this function frees all but parser.types and
 * parser.decoders from a parser.
 *
 * This function is only to be used in parser creation routines.
 */
static void flb_interim_parser_destroy(struct flb_parser *parser)
{
    if (parser->type == FLB_PARSER_REGEX) {
        flb_regex_destroy(parser->regex);
        flb_free(parser->p_regex);
    }

    flb_free(parser->name);
    if (parser->time_fmt) {
        flb_free(parser->time_fmt);
    }
    if (parser->time_fmt_year) {
        flb_free(parser->time_fmt_year);
    }
    if (parser->time_fmt_full) {
        flb_free(parser->time_fmt_full);
    }
    if (parser->time_key) {
        flb_free(parser->time_key);
    }
    if (parser->time_zone) {
        flb_free(parser->time_zone);
    }
    if (parser->time_zone_data) {
        time_zone_data_destroy(parser->time_zone_data);
    }

    mk_list_del(&parser->_head);
    flb_free(parser);
}

struct flb_parser *flb_parser_create_with_time_zone(const char *name,
                                     const char *format,
                                     const char *p_regex,
                                     int skip_empty,
                                     const char *time_fmt,
                                     const char *time_key,
                                     const char *time_offset,
                                     int time_keep,
                                     int time_strict,
                                     int time_system_timezone,
                                     const char *time_zone,
                                     int logfmt_no_bare_keys,
                                     struct flb_parser_types *types,
                                     int types_len,
                                     struct mk_list *decoders,
                                     struct flb_config *config)
{
    int ret;
    int len;
    int diff = 0;
    int size;
    int is_epoch = FLB_FALSE;
    char *tmp;
    char *timeptr;
    struct mk_list *head;
    struct flb_parser *p;
    struct flb_regex *regex;

    /* Iterate current parsers and make sure the new one don't exists */
    mk_list_foreach(head, &config->parsers) {
        p = mk_list_entry(head, struct flb_parser, _head);
        if (p->name && strcmp(p->name, name) == 0) {
            flb_error("[parser] parser named '%s' already exists, skip.",
                      name);
            return NULL;
        }
    }

    /* Allocate context */
    p = flb_calloc(1, sizeof(struct flb_parser));
    if (!p) {
        flb_errno();
        return NULL;
    }
    p->decoders = decoders;
    mk_list_add(&p->_head, &config->parsers);

    /* Format lookup */
    if (strcasecmp(format, "regex") == 0) {
        p->type = FLB_PARSER_REGEX;
    }
    else if (strcasecmp(format, "json") == 0) {
        p->type = FLB_PARSER_JSON;
    }
    else if (strcasecmp(format, "ltsv") == 0) {
        p->type = FLB_PARSER_LTSV;
    }
    else if (strcasecmp(format, "logfmt") == 0) {
        p->type = FLB_PARSER_LOGFMT;
    }
    else if (strcmp(format, "tskv") == 0) {
        p->type = FLB_PARSER_TSKV;
    }
    else {
        flb_error("[parser:%s] Invalid format %s", name, format);
        mk_list_del(&p->_head);
        flb_free(p);
        return NULL;
    }

    if (p->type == FLB_PARSER_REGEX) {
        if (!p_regex) {
            flb_error("[parser:%s] Invalid regex pattern", name);
            mk_list_del(&p->_head);
            flb_free(p);
            return NULL;
        }

        regex = flb_regex_create(p_regex);
        if (!regex) {
            flb_error("[parser:%s] Invalid regex pattern %s", name, p_regex);
            mk_list_del(&p->_head);
            flb_free(p);
            return NULL;
        }
        p->regex = regex;
        p->skip_empty = skip_empty;
        p->p_regex = flb_strdup(p_regex);
    }

    p->name = flb_strdup(name);

    if (time_zone && time_zone[0] && !time_fmt) {
        flb_error("[parser:%s] time_zone requires time_format", name);
        flb_interim_parser_destroy(p);
        return NULL;
    }

    if (time_fmt) {
        p->time_fmt_full = flb_strdup(time_fmt);
        if (!p->time_fmt_full) {
            flb_error("[parser:%s] could not duplicate time fmt full", name);
            flb_interim_parser_destroy(p);
            return NULL;
        }
        p->time_fmt = flb_strdup(time_fmt);
        if (!p->time_fmt) {
            flb_error("[parser:%s] could not duplicate time fmt", name);
            flb_interim_parser_destroy(p);
            return NULL;
        }

        /* Check if the format is considering the year */
        if (strstr(p->time_fmt, "%Y") || strstr(p->time_fmt, "%y")) {
            p->time_with_year = FLB_TRUE;
        }
        else if (strstr(p->time_fmt, "%s")) {
            is_epoch = FLB_TRUE;
            p->time_with_year = FLB_TRUE;
        }
        else {
            size = strlen(p->time_fmt);
            p->time_with_year = FLB_FALSE;
            p->time_fmt_year = flb_malloc(size + 4);
            if (!p->time_fmt_year) {
                flb_errno();
                flb_interim_parser_destroy(p);
                return NULL;
            }

            /* Append the year at the beginning */
            tmp = p->time_fmt_year;
            *tmp++ = '%';
            *tmp++ = 'Y';
            *tmp++ = ' ';

            memcpy(tmp, p->time_fmt, size);
            tmp += size;
            *tmp++ = '\0';
        }

        /* Check if the format contains a timezone (%z) */
        if (strstr(p->time_fmt, "%z") || strstr(p->time_fmt, "%Z") ||
            strstr(p->time_fmt, "%SZ") || strstr(p->time_fmt, "%S.%LZ")) {
#if defined(FLB_HAVE_GMTOFF) || !defined(FLB_HAVE_SYSTEM_STRPTIME)
            p->time_with_tz = FLB_TRUE;
#else
            flb_error("[parser] timezone offset not supported");
            flb_error("[parser] you cannot use %%z/%%Z on this platform");
            flb_interim_parser_destroy(p);
            return NULL;
#endif
        }

        /*
         * Check if the format expect fractional seconds
         *
         * Since strptime(3) does not support fractional seconds, this
         * requires a workaround/hack in our parser. This is a known
         * issue and addressed in different ways in other languages.
         *
         * The following links are a good reference:
         *
         * - http://stackoverflow.com/questions/7114690/how-to-parse-syslog-timestamp
         * - http://code.activestate.com/lists/python-list/521885
         */
        if (is_epoch == FLB_TRUE || p->time_with_year == FLB_TRUE) {
            timeptr = p->time_fmt;
        }
        else {
            timeptr = p->time_fmt_year;
        }

        tmp = strstr(timeptr, "%L");
        if (tmp) {
            tmp[0] = '\0';
            tmp[1] = '\0';
            p->time_frac_secs = (tmp + 2);
        }

        /*
         * Fall back to the system timezone
         * if there is no zone parsed from the log.
         */
        p->time_system_timezone = time_system_timezone;

        if (time_zone && time_zone[0]) {
            if (time_system_timezone) {
                flb_error("[parser:%s] time_zone cannot be combined with "
                          "time_system_timezone",
                          name);
                flb_interim_parser_destroy(p);
                return NULL;
            }
            if (time_offset && time_offset[0]) {
                flb_error("[parser:%s] time_zone cannot be combined with "
                          "time_offset",
                          name);
                flb_interim_parser_destroy(p);
                return NULL;
            }
            if (validate_time_zone(time_zone) != 0) {
                flb_error("[parser:%s] invalid or unavailable time_zone '%s'",
                          name, time_zone);
                flb_interim_parser_destroy(p);
                return NULL;
            }
            p->time_zone = flb_strdup(time_zone);
            if (!p->time_zone) {
                flb_interim_parser_destroy(p);
                return NULL;
            }
            p->time_zone_data = time_zone_data_create(time_zone);
            if (p->time_zone_data == NULL) {
                flb_error("[parser:%s] could not load time_zone '%s'",
                          name, time_zone);
                flb_interim_parser_destroy(p);
                return NULL;
            }
        }

        /*
         * Optional fixed timezone offset, only applied if
         * not falling back to system timezone or an IANA time_zone.
         */
        if (!p->time_system_timezone && !p->time_zone && time_offset) {
            diff = 0;
            len = strlen(time_offset);
            ret = flb_parser_tzone_offset(time_offset, len, &diff);
            if (ret == -1) {
                flb_interim_parser_destroy(p);
                return NULL;
            }
            p->time_offset = diff;
        }
    }

    if (time_key) {
        p->time_key = flb_strdup(time_key);
    }

    p->time_keep = time_keep;
    p->time_strict = time_strict;
    p->logfmt_no_bare_keys = logfmt_no_bare_keys;
    p->types = types;
    p->types_len = types_len;
    return p;
}

struct flb_parser *flb_parser_create(const char *name, const char *format,
                                     const char *p_regex,
                                     int skip_empty,
                                     const char *time_fmt, const char *time_key,
                                     const char *time_offset,
                                     int time_keep,
                                     int time_strict,
                                     int time_system_timezone,
                                     int logfmt_no_bare_keys,
                                     struct flb_parser_types *types,
                                     int types_len,
                                     struct mk_list *decoders,
                                     struct flb_config *config)
{
    return flb_parser_create_with_time_zone(name, format, p_regex, skip_empty,
                                            time_fmt, time_key, time_offset,
                                            time_keep, time_strict,
                                            time_system_timezone, NULL,
                                            logfmt_no_bare_keys, types,
                                            types_len, decoders, config);
}

void flb_parser_destroy(struct flb_parser *parser)
{
    int i = 0;

    if (parser->type == FLB_PARSER_REGEX) {
        flb_regex_destroy(parser->regex);
        flb_free(parser->p_regex);
    }

    flb_free(parser->name);
    if (parser->time_fmt) {
        flb_free(parser->time_fmt);
        flb_free(parser->time_fmt_full);
    }
    if (parser->time_fmt_year) {
        flb_free(parser->time_fmt_year);
    }
    if (parser->time_key) {
        flb_free(parser->time_key);
    }
    if (parser->time_zone) {
        flb_free(parser->time_zone);
    }
    if (parser->time_zone_data) {
        time_zone_data_destroy(parser->time_zone_data);
    }
    if (parser->types_len != 0) {
        for (i=0; i<parser->types_len; i++){
            flb_free(parser->types[i].key);
        }
        flb_free(parser->types);
    }

    if (parser->decoders) {
        flb_parser_decoder_list_destroy(parser->decoders);
    }

    mk_list_del(&parser->_head);
    flb_free(parser);
}

void flb_parser_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_parser *parser;

    /* release 'parsers' */
    mk_list_foreach_safe(head, tmp, &config->parsers) {
        parser = mk_list_entry(head, struct flb_parser, _head);
        flb_parser_destroy(parser);
    }

    /* release 'multiline parsers' */
    flb_ml_exit(config);
}

static int proc_types_str(const char *types_str, struct flb_parser_types **types)
{
    int i = 0;
    int types_num = 0;
    char *type_str = NULL;
    size_t len;
    struct mk_list *split;
    struct mk_list *head;
    struct flb_split_entry *sentry;

    split = flb_utils_split(types_str, ' ', 256);
    types_num = mk_list_size(split);
    *types = flb_malloc(sizeof(struct flb_parser_types) * types_num);

    for(i=0; i<types_num; i++){
        (*types)[i].key = NULL;
        (*types)[i].type = FLB_PARSER_TYPE_STRING;
    }
    i = 0;
    mk_list_foreach(head ,split) {
        sentry = mk_list_entry(head, struct flb_split_entry ,_head);
        type_str = strchr(sentry->value ,':');

        if (type_str == NULL) {
            i++;
            continue;
        }
        len = type_str - sentry->value;
        (*types)[i].key = flb_strndup(sentry->value, len);
        (*types)[i].key_len = len;

        type_str++;
        if (!strcasecmp(type_str, "integer")) {
            (*types)[i].type = FLB_PARSER_TYPE_INT;
        }
        else if(!strcasecmp(type_str, "bool")) {
            (*types)[i].type = FLB_PARSER_TYPE_BOOL;
        }
        else if(!strcasecmp(type_str, "float")){
            (*types)[i].type = FLB_PARSER_TYPE_FLOAT;
        }
        else if(!strcasecmp(type_str, "hex")){
            (*types)[i].type = FLB_PARSER_TYPE_HEX;
        }
        else {
            (*types)[i].type = FLB_PARSER_TYPE_STRING;
        }
        i++;
    }
    flb_utils_split_free(split);

    return i;
}

static flb_sds_t get_parser_key(struct flb_config *config,
                                struct flb_cf *cf, struct flb_cf_section *s,
                                char *key)

{
    flb_sds_t tmp;
    flb_sds_t val;

    tmp = flb_cf_section_property_get_string(cf, s, key);
    if (!tmp) {
        return NULL;
    }

    val = flb_env_var_translate(config->env, tmp);
    if (!val) {
        flb_sds_destroy(tmp);
        return NULL;
    }

    if (flb_sds_len(val) == 0) {
        flb_sds_destroy(val);
        flb_sds_destroy(tmp);
        return NULL;
    }

    flb_sds_destroy(tmp);
    return val;
}

/* Load each parser definition set in 'struct flb_cf *cf' */
int flb_parser_load_parser_definitions(const char *cfg, struct flb_cf *cf,
                                       struct flb_config *config)
{
    int i = 0;
    flb_sds_t name;
    flb_sds_t format;
    flb_sds_t regex;
    flb_sds_t time_fmt;
    flb_sds_t time_key;
    flb_sds_t time_offset;
    flb_sds_t time_zone;
    flb_sds_t types_str;
    flb_sds_t tmp_str;
    int skip_empty;
    int time_keep;
    int time_strict;
    int time_system_timezone;
    int logfmt_no_bare_keys;
    int types_len;
    struct mk_list *head;
    struct mk_list *decoders = NULL;
    struct flb_cf_section *s;
    struct flb_parser_types *types = NULL;

    /* Read all 'parser' sections */
    mk_list_foreach(head, &cf->parsers) {
        name = NULL;
        format = NULL;
        regex = NULL;
        time_fmt = NULL;
        time_key = NULL;
        time_offset = NULL;
        time_zone = NULL;
        types_str = NULL;
        tmp_str = NULL;

        /* retrieve the section context */
        s = mk_list_entry(head, struct flb_cf_section, _head_section);

        /* name */
        name = get_parser_key(config, cf, s, "name");
        if (!name) {
            flb_error("[parser] no parser 'name' found in file '%s'", cfg);
            goto fconf_early_error;
        }

        /* format */
        format = get_parser_key(config, cf, s, "format");
        if (!format) {
            flb_error("[parser] no parser 'format' found for '%s' in file '%s'",
                      name, cfg);
            goto fconf_early_error;
        }

        /* regex (if 'format' == 'regex') */
        regex = get_parser_key(config, cf, s, "regex");
        if (!regex && strcmp(format, "regex") == 0) {
            flb_error("[parser] no parser 'regex' found for '%s' in file '%s",
                      name, cfg);
            goto fconf_early_error;
        }

        /* skip_empty_values */
        skip_empty = FLB_TRUE;
        tmp_str = get_parser_key(config, cf, s, "skip_empty_values");
        if (tmp_str) {
            skip_empty = flb_utils_bool(tmp_str);
            flb_sds_destroy(tmp_str);
        }

        /* time_format */
        time_fmt = get_parser_key(config, cf, s, "time_format");

        /* time_key */
        time_key = get_parser_key(config, cf, s, "time_key");

        /* time_keep */
        time_keep = FLB_FALSE;
        tmp_str = get_parser_key(config, cf, s, "time_keep");
        if (tmp_str) {
            time_keep = flb_utils_bool(tmp_str);
            flb_sds_destroy(tmp_str);
        }

        /* time_strict */
        time_strict = FLB_TRUE;
        tmp_str = get_parser_key(config, cf, s, "time_strict");
        if (tmp_str) {
            time_strict = flb_utils_bool(tmp_str);
            flb_sds_destroy(tmp_str);
        }

        time_system_timezone = FLB_FALSE;
        tmp_str = get_parser_key(config, cf, s, "time_system_timezone");
        if (tmp_str) {
            time_system_timezone = flb_utils_bool(tmp_str);
            flb_sds_destroy(tmp_str);
        }

        /* time_offset (UTC offset) */
        time_offset = get_parser_key(config, cf, s, "time_offset");

        /* time_zone (IANA name for naive timestamps) */
        time_zone = get_parser_key(config, cf, s, "time_zone");

        /* logfmt_no_bare_keys */
        logfmt_no_bare_keys = FLB_FALSE;
        tmp_str = get_parser_key(config, cf, s, "logfmt_no_bare_keys");
        if (tmp_str) {
            logfmt_no_bare_keys = flb_utils_bool(tmp_str);
            flb_sds_destroy(tmp_str);
        }

        /* types */
        types_str = get_parser_key(config, cf, s, "types");
        if (types_str) {
            types_len = proc_types_str(types_str, &types);
        }
        else {
            types_len = 0;
        }

        /* Decoders */
        decoders = flb_parser_decoder_list_create(s);

        /* Create the parser context */
        if (!flb_parser_create_with_time_zone(name, format, regex, skip_empty,
                               time_fmt, time_key, time_offset, time_keep, time_strict,
                               time_system_timezone, time_zone, logfmt_no_bare_keys,
                               types, types_len, decoders, config)) {
            goto fconf_error;
        }

        flb_debug("[parser] new parser registered: %s", name);

        flb_sds_destroy(name);
        flb_sds_destroy(format);

        if (regex) {
            flb_sds_destroy(regex);
        }
        if (time_fmt) {
            flb_sds_destroy(time_fmt);
        }
        if (time_key) {
            flb_sds_destroy(time_key);
        }
        if (time_offset) {
            flb_sds_destroy(time_offset);
        }
        if (time_zone) {
            flb_sds_destroy(time_zone);
        }
        if (types_str) {
            flb_sds_destroy(types_str);
        }
        decoders = NULL;
    }

    return 0;

 /* Use early exit before call to flb_parser_create */
 fconf_early_error:
    if (name) {
        flb_sds_destroy(name);
    }
    if (format) {
        flb_sds_destroy(format);
    }
    if (regex) {
        flb_sds_destroy(regex);
    }
    return -1;

 fconf_error:
    flb_sds_destroy(name);
    flb_sds_destroy(format);
    if (regex) {
        flb_sds_destroy(regex);
    }
    if (time_fmt) {
        flb_sds_destroy(time_fmt);
    }
    if (time_key) {
        flb_sds_destroy(time_key);
    }
    if (time_offset) {
        flb_sds_destroy(time_offset);
    }
    if (time_zone) {
        flb_sds_destroy(time_zone);
    }
    if (types_str) {
        flb_sds_destroy(types_str);
    }
    if (types_len) {
        for (i=0; i<types_len; i++){
            if (types[i].key != NULL) {
                flb_free(types[i].key);
            }
        }
        flb_free(types);
    }
    if (decoders) {
        flb_parser_decoder_list_destroy(decoders);
    }
    return -1;
}

static int multiline_rule_create(struct flb_ml_parser *ml_parser,
                                 char *from_state,
                                 char *regex_pattern,
                                 char *to_state)
{
    int ret;

    ret = flb_ml_rule_create(ml_parser, from_state, regex_pattern, to_state, NULL);
    return ret;
}

static int multiline_load_regex_rules(struct flb_ml_parser *ml_parser,
                                      struct flb_cf_section *section,
                                      struct flb_config *config)
{
    int ret;
    char *to_state = NULL;
    struct mk_list list;
    struct cfl_list *head;
    struct cfl_kvpair *entry;
    struct flb_slist_entry *from_state;
    struct flb_slist_entry *regex_pattern;
    struct flb_slist_entry *tmp;
    struct mk_list *g_head;
    struct flb_cf_group *group;
    struct cfl_variant *var_state;
    struct cfl_variant *var_regex;
    struct cfl_variant *var_next_state;

    /* Check if we have groups (coming from Yaml style config */
    mk_list_foreach(g_head, &section->groups) {
        /* Every group is a rule */
        group = cfl_list_entry(g_head, struct flb_cf_group, _head);

        var_state = cfl_kvlist_fetch(group->properties, "state");
        if (!var_state || var_state->type != CFL_VARIANT_STRING) {
            flb_error("[multiline parser: %s] invalid 'state' key", ml_parser->name);
            return -1;
        }

        var_regex = cfl_kvlist_fetch(group->properties, "regex");
        if (!var_regex || var_regex->type != CFL_VARIANT_STRING) {
            flb_error("[multiline parser: %s] invalid 'regex' key", ml_parser->name);
            return -1;
        }

        var_next_state = cfl_kvlist_fetch(group->properties, "next_state");
        if (!var_next_state || var_next_state->type != CFL_VARIANT_STRING) {
            flb_error("[multiline parser: %s] invalid 'next_state' key", ml_parser->name);
            return -1;
        }

        ret = multiline_rule_create(ml_parser,
                                    var_state->data.as_string,
                                    var_regex->data.as_string,
                                    var_next_state->data.as_string);

        if (ret == -1) {
            flb_error("[multiline parser: %s] error creating rule", ml_parser->name);
            return -1;
        }
    }

    /* Multiline rules set by a Fluent Bit classic mode config */
    cfl_list_foreach(head, &section->properties->list) {
        entry = cfl_list_entry(head, struct cfl_kvpair, _head);

        /* only process 'rule' keys */
        if (strcasecmp(entry->key, "rule") != 0) {
            continue;
        }

        mk_list_init(&list);
        ret = flb_slist_split_tokens(&list, entry->val->data.as_string, 3);
        if (ret == -1) {
            flb_error("[multiline parser: %s] invalid section on key '%s'",
                    ml_parser->name, entry->key);
            return -1;
        }

        /* Get entries from the line */
        from_state    = flb_slist_entry_get(&list, 0);
        regex_pattern = flb_slist_entry_get(&list, 1);
        tmp = flb_slist_entry_get(&list, 2);
        if (tmp) {
            to_state  = tmp->str;
        }
        else {
            to_state = NULL;
        }

        if (!from_state) {
            flb_error("[multiline parser: %s] 'from_state' is mandatory",
                      ml_parser->name);
            flb_slist_destroy(&list);
            return -1;
        }

        if (!regex_pattern) {
            flb_error("[multiline parser: %s] 'regex_pattern' is mandatory",
                      ml_parser->name);
            flb_slist_destroy(&list);
            return -1;
        }

        ret = multiline_rule_create(ml_parser,
                                    from_state->str,
                                    regex_pattern->str,
                                    to_state);
        if (ret == -1) {
            flb_error("[multiline parser: %s] error creating rule",
                      ml_parser->name);
            flb_slist_destroy(&list);
            return -1;
        }

        flb_slist_destroy(&list);
    }

    /* Map the rules (mandatory for regex rules) */
    ret = flb_ml_parser_init(ml_parser);
    if (ret != 0) {
        flb_error("[multiline parser: %s] invalid mapping rules, check the states",
                  ml_parser->name);
        return -1;
    }

    return 0;
}


/* config file: read 'multiline_parser' sections */
int flb_parser_load_multiline_parser_definitions(const char *cfg, struct flb_cf *cf,
                                                 struct flb_config *config)
{
    int ret;
    int type;
    flb_sds_t name;
    flb_sds_t match_string;
    int negate;
    flb_sds_t key_content;
    flb_sds_t key_pattern;
    flb_sds_t key_group;
    flb_sds_t parser;
    flb_sds_t tmp;
    int flush_timeout;
    struct flb_parser *parser_ctx = NULL;
    struct mk_list *head;
    struct flb_cf_section *s;
    struct flb_ml_parser *ml_parser;

    /*
     * debug content of cf: flb_cf_dump(cf);
     */

    /* read all 'multiline_parser' sections */
    mk_list_foreach(head, &cf->multiline_parsers) {
        ml_parser = NULL;
        name = NULL;
        type = -1;
        match_string = NULL;
        negate = FLB_FALSE;
        key_content = NULL;
        key_pattern = NULL;
        key_group = NULL;
        parser = NULL;
        flush_timeout = -1;
        tmp = NULL;

        s = mk_list_entry(head, struct flb_cf_section, _head_section);

        /* name */
        name = get_parser_key(config, cf, s, "name");
        if (!name) {
            flb_error("[multiline_parser] no 'name' defined in file '%s'", cfg);
            goto fconf_error;
        }

        /* type */
        tmp = get_parser_key(config, cf, s, "type");
        if (!tmp) {
            flb_error("[multiline_parser] no 'type' defined in file '%s'", cfg);
            goto fconf_error;
        }
        else {
            type = flb_ml_type_lookup(tmp);
            if (type == -1) {
                flb_error("[multiline_parser] invalid type '%s'", tmp);
                goto fconf_error;
            }
            flb_sds_destroy(tmp);
        }

        /* match_string */
        match_string = get_parser_key(config, cf, s, "match_string");

        /* negate */
        tmp = get_parser_key(config, cf, s, "negate");
        if (tmp) {
            negate = flb_utils_bool(tmp);
            flb_sds_destroy(tmp);
        }

        /* key_content */
        key_content = get_parser_key(config, cf, s, "key_content");

        /* key_pattern */
        key_pattern = get_parser_key(config, cf, s, "key_pattern");

        /* key_group */
        key_group = get_parser_key(config, cf, s, "key_group");

        /* parser */
        parser = get_parser_key(config, cf, s, "parser");

        /* flush_timeout */
        tmp = get_parser_key(config, cf, s, "flush_timeout");
        if (tmp) {
            flush_timeout = atoi(tmp);
        }

        if (parser) {
            parser_ctx = flb_parser_get(parser, config);
        }
        ml_parser = flb_ml_parser_create(config, name, type, match_string,
                                         negate, flush_timeout, key_content,
                                         key_group, key_pattern,
                                         parser_ctx, parser);
        if (!ml_parser) {
            goto fconf_error;
        }

        /* if type is regex, process rules */
        if (type == FLB_ML_REGEX) {
            ret = multiline_load_regex_rules(ml_parser, s, config);
            if (ret != 0) {
                goto fconf_error;
            }
        }

        flb_sds_destroy(name);
        flb_sds_destroy(match_string);
        flb_sds_destroy(key_content);
        flb_sds_destroy(key_pattern);
        flb_sds_destroy(key_group);
        flb_sds_destroy(parser);
        flb_sds_destroy(tmp);
    }

    return 0;

 fconf_error:
    if (ml_parser) {
        flb_ml_parser_destroy(ml_parser);
    }
    flb_sds_destroy(name);
    flb_sds_destroy(match_string);
    flb_sds_destroy(key_content);
    flb_sds_destroy(key_pattern);
    flb_sds_destroy(key_group);
    flb_sds_destroy(parser);
    flb_sds_destroy(tmp);

    return -1;
}

int flb_parser_conf_file_stat(const char *file, struct flb_config *config)
{
    int ret;
    struct stat st;

    ret = stat(file, &st);
    if (ret == -1 && errno == ENOENT) {
        /* Try to resolve the real path (if exists) */
        if (file[0] == '/') {
            flb_utils_error(FLB_ERR_CFG_PARSER_FILE);
            return -1;
        }

        if (config->conf_path) {
            /* Handle as special case here. */
            return -2;
        }

        return -1;
    }

    return 0;
}

/* Load parsers from a configuration file */
int flb_parser_conf_file(const char *file, struct flb_config *config)
{
    int ret;
    char tmp[PATH_MAX + 1];
    char *cfg = NULL;
    struct flb_cf *cf = NULL;

#ifndef FLB_HAVE_STATIC_CONF
    ret = flb_parser_conf_file_stat(file, config);
    if (ret == -1) {
        return -1;
    }
    else if (ret == -2) {
        snprintf(tmp, PATH_MAX, "%s%s", config->conf_path, file);
        cfg = tmp;
    }
    else {
        cfg = (char *) file;
    }

    cf = flb_cf_create_from_file(NULL, cfg);
#else
    cf = flb_config_static_open(file);
#endif

    if (!cf) {
        return -1;
    }

    /* load the parser definitions */
    ret = flb_parser_load_parser_definitions(cfg, cf, config);
    if (ret == -1) {
        flb_cf_destroy(cf);
        return -1;
    }

    /* processs 'multiline_parser' sections */
    ret = flb_parser_load_multiline_parser_definitions(cfg, cf, config);
    if (ret == -1) {
        flb_cf_destroy(cf);
        return -1;
    }

    /* link the 'cf parser' context to the config list */
    mk_list_add(&cf->_head, &config->cf_parsers_list);
    return 0;
}

struct flb_parser *flb_parser_get(const char *name, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_parser *parser;

    if (config == NULL || mk_list_size(&config->parsers) <= 0) {
        return NULL;
    }

    mk_list_foreach(head, &config->parsers) {
        parser = mk_list_entry(head, struct flb_parser, _head);
        if (parser == NULL || parser->name == NULL) {
            continue;
        }
        if (strcmp(parser->name, name) == 0) {
            return parser;
        }
    }

    return NULL;
}

int flb_parser_do(struct flb_parser *parser, const char *buf, size_t length,
                  void **out_buf, size_t *out_size, struct flb_time *out_time)
{

    if (parser->type == FLB_PARSER_REGEX) {
        return flb_parser_regex_do(parser, buf, length,
                                   out_buf, out_size, out_time);
    }
    else if (parser->type == FLB_PARSER_JSON) {
        return flb_parser_json_do(parser, buf, length,
                                  out_buf, out_size, out_time);
    }
    else if (parser->type == FLB_PARSER_LTSV) {
        return flb_parser_ltsv_do(parser, buf, length,
                                  out_buf, out_size, out_time);
    }
    else if (parser->type == FLB_PARSER_LOGFMT) {
        return flb_parser_logfmt_do(parser, buf, length,
                                  out_buf, out_size, out_time);
    }
    else if (parser->type == FLB_PARSER_TSKV) {
        return flb_parser_tskv_do(parser, buf, length,
                                  out_buf, out_size, out_time);
    }


    return -1;
}

/* Given a timezone string, return it numeric offset */
int flb_parser_tzone_offset(const char *str, int len, int *tmdiff)
{
    int neg;
    long hour;
    long min;
    const char *end;
    const char *p = str;

    /* Check timezones */
    if (*p == 'Z') {
        /* This is UTC, no changes required */
        *tmdiff = 0;
        return 0;
    }

    /* Unexpected timezone string */
    if (*p != '+' && *p != '-') {
        *tmdiff = 0;
        return -1;
    }

    /* Ensure there is enough data */
    if (len < 4) {
        *tmdiff = 0;
        return -1;
    }

    /* Negative value ? */
    neg = (*p++ == '-');

    /* Locate end */
    end = str + len;

    /* Gather hours and minutes */
    hour = ((p[0] - '0') * 10) + (p[1] - '0');
    if (end - p == 5 && p[2] == ':') {
        /* Ensure there is enough data */
        if (len < 5) {
            *tmdiff = 0;
            return -1;
        }
        min = ((p[3] - '0') * 10) + (p[4] - '0');
    }
    else {
        min = ((p[2] - '0') * 10) + (p[3] - '0');
    }

    if (hour < 0 || hour > 59 || min < 0 || min > 59) {
        return -1;
    }

    *tmdiff = ((hour * 3600) + (min * 60));
    if (neg) {
        *tmdiff = -*tmdiff;
    }

    return 0;
}

/*
 * Parse the '%L' (subseconds) part into `subsec`.
 *
 *   2020-10-23 12:00:31.415213 JST
 *                       ----------
 *
 * Return the number of characters consumed, or -1 on error.
 */
static int parse_subseconds(char *str, int len, double *subsec)
{
    char buf[16];
    char *end;
    int consumed;
    int digits = 9;  /* 1 ns = 000000001 (9 digits) */

    if (len < digits) {
        digits = len;
    }
    memcpy(buf, "0.", 2);
    memcpy(buf + 2, str, digits);
    buf[digits + 2] = '\0';

    *subsec = strtod(buf, &end);

    consumed = end - buf - 2;
    if (consumed <= 0) {
        return -1;
    }
    return consumed;
}

int flb_parser_time_lookup(const char *time_str, size_t tsize,
                           time_t now,
                           struct flb_parser *parser,
                           struct flb_tm *tm, double *ns)
{
    int ret;
    time_t time_now;
    char *p = NULL;
    char *fmt;
    int time_len = tsize;
    const char *time_ptr = time_str;
    char tmp[64];
    struct tm tmy;

    *ns = 0;

    if (tsize > sizeof(tmp) - 1) {
        flb_error("[parser] time string length is too long");
        return -1;
    }

    /*
     * Some records coming from old Syslog messages do not contain the
     * year, so it's required to ingest this information in the value
     * to be parsed.
     */
    if (parser->time_with_year == FLB_FALSE) {
        /* Given time string is too long */
        if (time_len + 6 >= sizeof(tmp)) {
            return -1;
        }

        /*
         * This is not the most elegant way but for now it let
         * get the work done.
         */
        if (now <= 0) {
            time_now = time(NULL);
        }
        else {
            time_now = now;
        }

        if (parser->time_zone && parser->time_with_tz == FLB_FALSE) {
#ifdef FLB_SYSTEM_WINDOWS
            ret = windows_time2tm_zone(time_now, parser->time_zone_data, &tmy);
            if (ret != 0) {
                return -1;
            }
#else
            ret = tzif_time2tm(parser->time_zone_data, time_now, &tmy);
            if (ret != 0) {
                return -1;
            }
#endif
        }
        else if (parser->time_system_timezone == FLB_TRUE) {
            localtime_r(&time_now, &tmy);
        }
        else {
            gmtime_r(&time_now, &tmy);
        }

        /* Make the timestamp default to today */
        tm->tm.tm_mon = tmy.tm_mon;
        tm->tm.tm_mday = tmy.tm_mday;

        uint64_t t = tmy.tm_year + 1900;

        fmt = tmp;
        u64_to_str(t, fmt);
        fmt += 4;
        *fmt++ = ' ';

        memcpy(fmt, time_ptr, time_len);
        fmt += time_len;
        *fmt++ = '\0';

        time_ptr = tmp;
        time_len = strlen(tmp);
        p = flb_strptime(time_ptr, parser->time_fmt_year, tm);
    }
    else {
        /*
         * We must ensure string passed to flb_strptime is
         * null-terminated, which time_ptr is not guaranteed
         * to be. So we use tmp to hold our string.
         */
        if (time_len >= sizeof(tmp)) {
            return -1;
        }
        memcpy(tmp, time_ptr, time_len);
        tmp[time_len] = '\0';
        time_ptr = tmp;
        time_len = strlen(tmp);

        p = flb_strptime(time_ptr, parser->time_fmt, tm);
    }

    if (p == NULL) {
        if (parser->time_strict) {
            flb_error("[parser] cannot parse '%.*s'", (int)tsize, time_str);
            return -1;
        }
        flb_debug("[parser] non-exact match '%.*s'", (int)tsize, time_str);
        return 0;
    }

    if (parser->time_frac_secs) {
        ret = parse_subseconds(p, time_len - (p - time_ptr), ns);
        if (ret < 0) {
            if (parser->time_strict) {
                flb_error("[parser] cannot parse %%L for '%.*s'", (int)tsize, time_str);
                return -1;
            }
            flb_debug("[parser] non-exact match on %%L '%.*s'", (int)tsize, time_str);
            return 0;
        }
        p += ret;

        /* Parse the remaining part after %L */
        p = flb_strptime(p, parser->time_frac_secs, tm);
        if (p == NULL) {
            if (parser->time_strict) {
                flb_error("[parser] cannot parse '%.*s' after %%L", (int)tsize, time_str);
                return -1;
            }
            flb_debug("[parser] non-exact match after %%L '%.*s'", (int)tsize, time_str);
            return 0;
        }
    }

    if (parser->time_with_tz == FLB_FALSE && !parser->time_zone) {
        flb_tm_gmtoff(tm) = parser->time_offset;
    }

    return 0;
}

int flb_parser_typecast(const char *key, int key_len,
                        const char *val, int val_len,
                        msgpack_packer *pck,
                        struct flb_parser_types *types,
                        int types_len)
{
    int i;
    int error = FLB_FALSE;
    char *tmp_str;
    int casted = FLB_FALSE;

    for(i=0; i<types_len; i++){
        if (types[i].key != NULL
            && key_len == types[i].key_len &&
            !strncmp(key, types[i].key, key_len)) {

            casted = FLB_TRUE;

            msgpack_pack_str(pck, key_len);
            msgpack_pack_str_body(pck, key, key_len);

            switch (types[i].type) {
            case FLB_PARSER_TYPE_INT:
                {
                    long long lval;

                    /* msgpack char is not null terminated.
                       So make a temporary copy.
                     */
                    tmp_str = flb_strndup(val, val_len);
                    lval = atoll(tmp_str);
                    flb_free(tmp_str);
                    msgpack_pack_int64(pck, lval);
                }
                break;
            case FLB_PARSER_TYPE_HEX:
                {
                    unsigned long long lval;
                    tmp_str = flb_strndup(val, val_len);
                    lval = strtoull(tmp_str, NULL, 16);
                    flb_free(tmp_str);
                    msgpack_pack_uint64(pck, lval);
                }
                break;

            case FLB_PARSER_TYPE_FLOAT:
                {
                    double dval;
                    tmp_str = flb_strndup(val, val_len);
                    dval = atof(tmp_str);
                    flb_free(tmp_str);
                    msgpack_pack_double(pck, dval);
                }
                break;
            case FLB_PARSER_TYPE_BOOL:
                if (val_len >= 4 && !strncasecmp(val, "true", 4)) {
                    msgpack_pack_true(pck);
                }
                else if(val_len >= 5 && !strncasecmp(val, "false", 5)){
                    msgpack_pack_false(pck);
                }
                else {
                    error = FLB_TRUE;
                }
                break;
            case FLB_PARSER_TYPE_STRING:
                msgpack_pack_str(pck, val_len);
                msgpack_pack_str_body(pck, val, val_len);
                break;
            default:
                error = FLB_TRUE;
            }
            if (error == FLB_TRUE) {
                /* We need to null-terminate key for flb_warn, as it expects
                 * a null-terminated string, which key is not guaranteed
                 * to be */
                char *nt_key = flb_malloc(key_len + 1);
                if (nt_key != NULL) {
                    memcpy(nt_key, key, key_len);
                    nt_key[key_len] = '\0';
                    flb_warn("[PARSER] key=%s cast error. save as string.", nt_key);
                    flb_free(nt_key);
                }
                msgpack_pack_str(pck, val_len);
                msgpack_pack_str_body(pck, val, val_len);
            }
            break;
        }
    }

    if (casted == FLB_FALSE) {
        msgpack_pack_str(pck, key_len);
        msgpack_pack_str_body(pck, key, key_len);
        msgpack_pack_str(pck, val_len);
        msgpack_pack_str_body(pck, val, val_len);
    }
    return 0;
}
