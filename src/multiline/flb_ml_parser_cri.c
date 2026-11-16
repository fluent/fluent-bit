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
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

#include <string.h>
#include <limits.h>

#define FLB_ML_CRI_REGEX                                                \
  "^(?<time>.+?) (?<stream>stdout|stderr) (?<_p>F|P) (?<log>.*)$"
#define FLB_ML_CRI_TIME                         \
  "%Y-%m-%dT%H:%M:%S.%L%z"

/*
 * Native decoder
 * --------------
 * A CRI line has a fixed layout that does not need a regular expression:
 *
 *   TIME (stdout|stderr) (F|P) LOG
 *
 * The functions below split a line, resolve its timestamp and serialize the
 * fields generating exactly the same result than the regex parser defined
 * above, which is kept as the reference and used as a fallback for anything
 * that is not handled here.
 */

/* length of ' stdout F ', the shortest content expected after the time */
#define CRI_FIXED_LEN        10

int flb_ml_parser_cri_decode(const char *buf, size_t size,
                             struct flb_ml_cri_record *record)
{
    const char *p;
    const char *end;
    const char *limit;

    if (size > INT_MAX) {
        return FLB_ML_CRI_FALLBACK;
    }

    /*
     * The regex anchors work per line: if the content has line breaks let the
     * regex parser to deal with it.
     */
    if (size > 0 && memchr(buf, '\n', size) != NULL) {
        return FLB_ML_CRI_FALLBACK;
    }

    /* the time takes at least one byte */
    if (size < CRI_FIXED_LEN + 1) {
        return FLB_ML_CRI_NO_MATCH;
    }

    end = buf + size;

    /* last position where the delimiter after the time can be located */
    limit = end - CRI_FIXED_LEN;
    p = buf + 1;

    /*
     * The time is the shortest prefix followed by the stream name and the
     * 'partial' flag, look for the first space that satisfies that.
     */
    while (p <= limit) {
        p = memchr(p, ' ', (limit - p) + 1);
        if (p == NULL) {
            break;
        }

        if (p[1] == 's' && p[2] == 't' && p[3] == 'd' &&
            ((p[4] == 'o' && p[5] == 'u' && p[6] == 't') ||
             (p[4] == 'e' && p[5] == 'r' && p[6] == 'r')) &&
            p[7] == ' ' && (p[8] == 'F' || p[8] == 'P') && p[9] == ' ') {

            record->time = buf;
            record->time_len = p - buf;
            record->stream = p + 1;
            record->flag = p + 8;
            record->log = p + CRI_FIXED_LEN;
            record->log_len = end - record->log;

            return FLB_ML_CRI_OK;
        }
        p++;
    }

    return FLB_ML_CRI_NO_MATCH;
}

static inline int cri_two_digits(const char *p)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') {
        return -1;
    }

    return (p[0] - '0') * 10 + (p[1] - '0');
}

/* Number of days since 1970-01-01 for a date of the Gregorian calendar */
static inline int64_t cri_days_from_civil(int64_t y, int m, int d)
{
    int64_t era;
    int64_t yoe;
    int64_t doy;
    int64_t doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    return era * 146097 + doe - 719468;
}

/*
 * Resolve the most common timestamp layout without going through strptime:
 *
 *   YYYY-MM-DDTHH:MM:SS.f{1,9}(Z|[+-]HH:MM)
 *
 * Returns 0 on success or -1 if the generic lookup must be used.
 */
static int cri_time_fast(const char *s, size_t len, struct flb_time *out)
{
    static const double scale[] = {
        1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0,
        100000000.0, 1000000000.0
    };
    int i;
    int year;
    int mon;
    int day;
    int hour;
    int min;
    int sec;
    int digits = 0;
    int off_hour;
    int off_min;
    int64_t offset = 0;
    int64_t frac = 0;
    double subsec;
    const char *p;
    const char *end = s + len;

    /* 2026-11-15T10:00:00.0Z */
    if (len < 22 || len > 35) {
        return -1;
    }

    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != '.') {
        return -1;
    }

    year = 0;
    for (i = 0; i < 4; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
        year = (year * 10) + (s[i] - '0');
    }

    mon = cri_two_digits(s + 5);
    day = cri_two_digits(s + 8);
    hour = cri_two_digits(s + 11);
    min = cri_two_digits(s + 14);
    sec = cri_two_digits(s + 17);

    if (year < 1970 || mon < 1 || mon > 12 || day < 1 || day > 31 ||
        hour < 0 || hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 59) {
        return -1;
    }

    /* fractional seconds */
    p = s + 20;
    while (p < end && *p >= '0' && *p <= '9' && digits < 9) {
        frac = (frac * 10) + (*p - '0');
        digits++;
        p++;
    }

    if (digits == 0 || p == end) {
        return -1;
    }

    /* timezone */
    if (*p == 'Z') {
        if (p + 1 != end) {
            return -1;
        }
    }
    else if (*p == '+' || *p == '-') {
        if (end - p != 6 || p[3] != ':') {
            return -1;
        }

        off_hour = cri_two_digits(p + 1);
        off_min = cri_two_digits(p + 4);
        if (off_hour < 0 || off_min < 0) {
            return -1;
        }

        offset = (off_hour * 3600) + (off_min * 60);
        if (*p == '-') {
            offset = -offset;
        }
    }
    else {
        return -1;
    }

    /*
     * The fractional part goes through the same floating point operations
     * done by the parser, so the nanoseconds are rounded in the same way.
     */
    subsec = (double) frac / scale[digits];

    out->tm.tv_sec = (cri_days_from_civil(year, mon, day) * 86400) +
                     (hour * 3600) + (min * 60) + sec - offset;
    out->tm.tv_nsec = (subsec * 1000000000);

    return 0;
}

int flb_ml_parser_cri_time(struct flb_parser *parser,
                           struct flb_ml_cri_record *record,
                           struct flb_time *out_time)
{
    int ret;
    double frac = 0;
    struct flb_tm tm = {0};

    if (cri_time_fast(record->time, record->time_len, out_time) == 0) {
        return 0;
    }

    /* same steps done by the regex parser for the time key */
    ret = flb_parser_time_lookup(record->time, record->time_len,
                                 0, parser, &tm, &frac);
    if (ret == -1) {
        return -1;
    }

    out_time->tm.tv_sec = flb_parser_tm2time_parser(&tm, parser);
    out_time->tm.tv_nsec = (frac * 1000000000);

    return 0;
}

static inline char *cri_pack_str(char *out, const char *str, size_t len)
{
    if (len < 32) {
        *out++ = (char) (0xa0 | len);
    }
    else if (len < 256) {
        *out++ = (char) 0xd9;
        *out++ = (char) len;
    }
    else if (len < 65536) {
        *out++ = (char) 0xda;
        *out++ = (char) (len >> 8);
        *out++ = (char) len;
    }
    else {
        *out++ = (char) 0xdb;
        *out++ = (char) (len >> 24);
        *out++ = (char) (len >> 16);
        *out++ = (char) (len >> 8);
        *out++ = (char) len;
    }

    memcpy(out, str, len);
    return out + len;
}

size_t flb_ml_parser_cri_map_size(struct flb_ml_cri_record *record)
{
    /* map header, keys, fixed values and the headers of time and log */
    return 1 + 5 + 7 + 7 + 3 + 2 + 4 + 5 + record->time_len + 5 +
           record->log_len;
}

size_t flb_ml_parser_cri_map_pack(struct flb_ml_cri_record *record, char *out)
{
    char *p = out;

    *p++ = (char) 0x84;
    p = cri_pack_str(p, "time", 4);
    p = cri_pack_str(p, record->time, record->time_len);
    p = cri_pack_str(p, "stream", 6);
    p = cri_pack_str(p, record->stream, 6);
    p = cri_pack_str(p, "_p", 2);
    p = cri_pack_str(p, record->flag, 1);
    p = cri_pack_str(p, "log", 3);
    p = cri_pack_str(p, record->log, record->log_len);

    return p - out;
}

/* Creates a parser for the CRI format, used as reference and fallback */
static struct flb_parser *cri_parser_create(struct flb_config *config)
{
    struct flb_parser *p;

    p = flb_parser_create("_ml_cri",               /* parser name */
                          "regex",                 /* backend type */
                          FLB_ML_CRI_REGEX,        /* regex */
                          FLB_FALSE,               /* skip_empty */
                          FLB_ML_CRI_TIME,         /* time format */
                          "time",                  /* time key */
                          NULL,                    /* time offset */
                          FLB_TRUE,                /* time keep */
                          FLB_FALSE,               /* time strict */
                          FLB_FALSE,               /* time system timezone */
                          FLB_FALSE,               /* no bare keys */
                          NULL,                    /* parser types */
                          0,                       /* types len */
                          NULL,                    /* decoders */
                          config);                 /* Fluent Bit context */
    return p;
}

struct flb_ml_parser *flb_ml_parser_cri(struct flb_config *config)
{
    struct flb_parser *parser;
    struct flb_ml_parser *mlp;

    parser = cri_parser_create(config);
    if (!parser) {
        return NULL;
    }

    mlp = flb_ml_parser_create(config,
                               "cri",                /* name      */
                               FLB_ML_EQ,            /* type      */
                               "F",                  /* match_str */
                               FLB_FALSE,            /* negate    */
                               FLB_ML_FLUSH_TIMEOUT, /* flush_ms  */
                               "log",                /* key_content */
                               "stream",             /* key_group   */
                               "_p",                 /* key_pattern */
                               parser,               /* parser ctx  */
                               NULL);                /* parser name */

    if (!mlp) {
        flb_error("[multiline] could not create 'cri mode'");
        return NULL;
    }

    /* complete lines can be decoded without the regex parser */
    mlp->native = FLB_ML_NATIVE_CRI;

    return mlp;
}
