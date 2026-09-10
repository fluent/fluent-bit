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

#include <fluent-bit/flb_http_retry_after.h>

#include <limits.h>
#include <stdint.h>
#include <string.h>

#define FLB_RETRY_AFTER_NAME       "Retry-After"
#define FLB_RETRY_AFTER_NAME_LEN   11

static int ascii_equal_ci(const char *value, const char *expected, size_t length)
{
    size_t index;
    unsigned char left;
    unsigned char right;

    for (index = 0; index < length; index++) {
        left = (unsigned char) value[index];
        right = (unsigned char) expected[index];

        if (left >= 'A' && left <= 'Z') {
            left = (unsigned char) (left + ('a' - 'A'));
        }
        if (right >= 'A' && right <= 'Z') {
            right = (unsigned char) (right + ('a' - 'A'));
        }
        if (left != right) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int parse_digits(const char *value, size_t length, int *result)
{
    size_t index;
    int number;

    number = 0;
    for (index = 0; index < length; index++) {
        if (value[index] < '0' || value[index] > '9') {
            return -1;
        }
        number = number * 10 + value[index] - '0';
    }

    *result = number;
    return 0;
}

static int parse_month(const char *value)
{
    static const char months[][4] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    int index;

    for (index = 0; index < 12; index++) {
        if (ascii_equal_ci(value, months[index], 3)) {
            return index + 1;
        }
    }

    return -1;
}

static int parse_weekday(const char *value, size_t length)
{
    static const char short_names[][4] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    static const char *long_names[] = {
        "Sunday", "Monday", "Tuesday", "Wednesday",
        "Thursday", "Friday", "Saturday"
    };
    size_t expected_length;
    int index;

    for (index = 0; index < 7; index++) {
        if (length == 3 && ascii_equal_ci(value, short_names[index], 3)) {
            return index;
        }

        expected_length = strlen(long_names[index]);
        if (length == expected_length &&
            ascii_equal_ci(value, long_names[index], length)) {
            return index;
        }
    }

    return -1;
}

static int is_leap_year(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int days_in_month(int year, int month)
{
    static const int days[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };

    if (month == 2 && is_leap_year(year)) {
        return 29;
    }

    return days[month - 1];
}

/* Return the number of days since 1970-01-01. */
static int64_t days_from_civil(int year, int month, int day)
{
    int era;
    unsigned int year_of_era;
    unsigned int day_of_year;
    unsigned int day_of_era;

    year -= month <= 2;
    era = (year >= 0 ? year : year - 399) / 400;
    year_of_era = (unsigned int) (year - era * 400);
    day_of_year = (153U * (unsigned int) (month + (month > 2 ? -3 : 9)) + 2U) / 5U +
                  (unsigned int) day - 1U;
    day_of_era = year_of_era * 365U + year_of_era / 4U - year_of_era / 100U +
                 day_of_year;

    return (int64_t) era * 146097 + (int64_t) day_of_era - 719468;
}

static int year_from_days(int64_t days)
{
    int era;
    int year;
    unsigned int day_of_era;
    unsigned int year_of_era;

    days += 719468;
    era = (int) ((days >= 0 ? days : days - 146096) / 146097);
    day_of_era = (unsigned int) (days - (int64_t) era * 146097);
    year_of_era = (day_of_era - day_of_era / 1460U + day_of_era / 36524U -
                   day_of_era / 146096U) / 365U;
    year = (int) year_of_era + era * 400;

    return year + (day_of_era - (365U * year_of_era + year_of_era / 4U -
                                 year_of_era / 100U) < 306U);
}

static int validate_date(int year, int month, int day, int hour, int minute,
                         int second, int weekday)
{
    int calculated_weekday;
    int64_t days;

    if (year < 0 || year > 9999 || month < 1 || month > 12 || day < 1 ||
        day > days_in_month(year, month) || hour < 0 || hour > 23 ||
        minute < 0 || minute > 59 || second < 0 || second > 59) {
        return -1;
    }

    days = days_from_civil(year, month, day);
    calculated_weekday = (int) ((days + 4) % 7);
    if (calculated_weekday < 0) {
        calculated_weekday += 7;
    }
    if (calculated_weekday != weekday) {
        return -1;
    }

    return 0;
}

static int parse_time(const char *value, int *hour, int *minute, int *second)
{
    if (value[2] != ':' || value[5] != ':' ||
        parse_digits(value, 2, hour) != 0 ||
        parse_digits(value + 3, 2, minute) != 0 ||
        parse_digits(value + 6, 2, second) != 0) {
        return -1;
    }

    return 0;
}

static int parse_http_date(const char *value, size_t length,
                           int64_t received_wall_time_ms, int64_t *date_ms)
{
    const char *comma;
    size_t weekday_length;
    int weekday;
    int day;
    int month;
    int year;
    int hour;
    int minute;
    int second;
    int current_year;
    int64_t days;

    day = -1;
    month = -1;
    year = -1;
    hour = -1;
    minute = -1;
    second = -1;

    if (length == 29 && value[3] == ',' && value[4] == ' ' &&
        value[7] == ' ' && value[11] == ' ' && value[16] == ' ' &&
        value[25] == ' ' && ascii_equal_ci(value + 26, "GMT", 3)) {
        weekday = parse_weekday(value, 3);
        month = parse_month(value + 8);
        if (weekday < 0 || month < 0 || parse_digits(value + 5, 2, &day) != 0 ||
            parse_digits(value + 12, 4, &year) != 0 ||
            parse_time(value + 17, &hour, &minute, &second) != 0) {
            return -1;
        }
    }
    else if (length >= 30 && length <= 33) {
        comma = memchr(value, ',', length);
        if (comma == NULL) {
            return -1;
        }
        weekday_length = (size_t) (comma - value);
        if (weekday_length < 6 || weekday_length > 9 ||
            length != weekday_length + 24 || comma[1] != ' ' || comma[4] != '-' ||
            comma[8] != '-' || comma[11] != ' ' || comma[20] != ' ' ||
            !ascii_equal_ci(comma + 21, "GMT", 3)) {
            return -1;
        }
        weekday = parse_weekday(value, weekday_length);
        month = parse_month(comma + 5);
        if (weekday < 0 || month < 0 || parse_digits(comma + 2, 2, &day) != 0 ||
            parse_digits(comma + 9, 2, &year) != 0 ||
            parse_time(comma + 12, &hour, &minute, &second) != 0) {
            return -1;
        }

        current_year = year_from_days(received_wall_time_ms / 1000 / 86400);
        year += (current_year / 100) * 100;
        if (year > current_year + 50) {
            year -= 100;
        }
    }
    else if (length == 24 && value[3] == ' ' && value[7] == ' ' &&
             value[10] == ' ' && value[19] == ' ') {
        weekday = parse_weekday(value, 3);
        month = parse_month(value + 4);
        if (value[8] == ' ' && value[9] >= '0' && value[9] <= '9') {
            day = value[9] - '0';
        }
        else if (parse_digits(value + 8, 2, &day) != 0) {
            return -1;
        }
        if (weekday < 0 || month < 0 ||
            parse_time(value + 11, &hour, &minute, &second) != 0 ||
            parse_digits(value + 20, 4, &year) != 0) {
            return -1;
        }
    }
    else {
        return -1;
    }

    if (validate_date(year, month, day, hour, minute, second, weekday) != 0) {
        return -1;
    }

    days = days_from_civil(year, month, day);
    *date_ms = (days * 86400 + hour * 3600 + minute * 60 + second) * 1000;

    return 0;
}

int flb_http_retry_after_parse(const char *value, size_t length,
                               int64_t received_wall_time_ms, uint64_t *delay_ms)
{
    size_t start;
    size_t end;
    size_t index;
    uint64_t seconds;
    int64_t date_ms;
    int saturated;

    if (value == NULL || delay_ms == NULL || length == 0) {
        return FLB_RETRY_AFTER_INVALID;
    }

    start = 0;
    end = length;
    while (start < end && (value[start] == ' ' || value[start] == '\t')) {
        start++;
    }
    while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t')) {
        end--;
    }
    if (start == end || memchr(value + start, '\0', end - start) != NULL) {
        return FLB_RETRY_AFTER_INVALID;
    }

    seconds = 0;
    saturated = FLB_FALSE;
    for (index = start; index < end; index++) {
        if (value[index] < '0' || value[index] > '9') {
            break;
        }
        if (saturated == FLB_FALSE) {
            if (seconds > (UINT64_MAX - (uint64_t) (value[index] - '0')) / 10) {
                saturated = FLB_TRUE;
            }
            else {
                seconds = seconds * 10 + (uint64_t) (value[index] - '0');
            }
        }
    }
    if (index == end) {
        if (saturated == FLB_TRUE || seconds > UINT64_MAX / 1000) {
            *delay_ms = UINT64_MAX;
            return FLB_RETRY_AFTER_SATURATED;
        }
        *delay_ms = seconds * 1000;
        return FLB_RETRY_AFTER_VALID;
    }

    if (parse_http_date(value + start, end - start,
                        received_wall_time_ms, &date_ms) != 0) {
        return FLB_RETRY_AFTER_INVALID;
    }
    if (date_ms <= received_wall_time_ms) {
        *delay_ms = 0;
    }
    else if (received_wall_time_ms >= 0) {
        *delay_ms = (uint64_t) date_ms - (uint64_t) received_wall_time_ms;
    }
    else if (date_ms < 0) {
        *delay_ms = (uint64_t) (date_ms - (received_wall_time_ms + 1)) + 1;
    }
    else {
        *delay_ms = (uint64_t) date_ms +
                    (uint64_t) (-(received_wall_time_ms + 1)) + 1;
    }

    return FLB_RETRY_AFTER_VALID;
}

int flb_http_retry_after_parse_headers(const char *headers, size_t length,
                                       int64_t received_wall_time_ms,
                                       uint64_t *delay_ms, size_t *invalid_count)
{
    size_t offset;
    size_t line_end;
    size_t colon;
    size_t invalid;
    uint64_t parsed_delay;
    uint64_t largest_delay;
    int parsed_status;
    int result;
    int found;

    if (invalid_count != NULL) {
        *invalid_count = 0;
    }
    if (headers == NULL || delay_ms == NULL) {
        return FLB_RETRY_AFTER_INVALID;
    }

    offset = 0;
    invalid = 0;
    largest_delay = 0;
    result = FLB_RETRY_AFTER_ABSENT;
    found = FLB_FALSE;

    while (offset < length) {
        for (line_end = offset; line_end + 1 < length; line_end++) {
            if (headers[line_end] == '\r' && headers[line_end + 1] == '\n') {
                break;
            }
        }
        if (line_end + 1 >= length) {
            break;
        }
        if (line_end == offset) {
            break;
        }

        colon = offset;
        while (colon < line_end && headers[colon] != ':') {
            colon++;
        }
        if (colon < line_end &&
            colon - offset == FLB_RETRY_AFTER_NAME_LEN &&
            ascii_equal_ci(headers + offset, FLB_RETRY_AFTER_NAME,
                           FLB_RETRY_AFTER_NAME_LEN)) {
            found = FLB_TRUE;
            parsed_status = flb_http_retry_after_parse(headers + colon + 1,
                                                       line_end - colon - 1,
                                                       received_wall_time_ms,
                                                       &parsed_delay);
            if (parsed_status == FLB_RETRY_AFTER_VALID ||
                parsed_status == FLB_RETRY_AFTER_SATURATED) {
                if (result == FLB_RETRY_AFTER_ABSENT ||
                    result == FLB_RETRY_AFTER_INVALID || parsed_delay > largest_delay) {
                    largest_delay = parsed_delay;
                    result = parsed_status;
                }
            }
            else {
                invalid++;
            }
        }

        offset = line_end + 2;
    }

    if (invalid_count != NULL) {
        *invalid_count = invalid;
    }
    if (result == FLB_RETRY_AFTER_VALID || result == FLB_RETRY_AFTER_SATURATED) {
        *delay_ms = largest_delay;
        return result;
    }
    if (found) {
        return FLB_RETRY_AFTER_INVALID;
    }

    return FLB_RETRY_AFTER_ABSENT;
}
