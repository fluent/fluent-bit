/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <string.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_strptime.h>
#include "flb_tests_internal.h"

void check_tm_datetime(const struct tm *ptm, int year, int mon, int mday, int hour, int min, int sec) {
    TEST_CHECK((year - 1900 ) == ptm->tm_year);
    TEST_CHECK((mon - 1) == ptm->tm_mon);
    TEST_CHECK(mday == ptm->tm_mday);
    TEST_CHECK(hour == ptm->tm_hour);
    TEST_CHECK(min == ptm->tm_min);
    TEST_CHECK(sec == ptm->tm_sec);
}

void check_tm_datetime_wday_yday(const struct tm *ptm, int year, int mon, int mday, int hour, int min, int sec, int wday, int yday) {
    check_tm_datetime(ptm, year, mon, mday, hour, min, sec);
    if (wday != -1) 
        TEST_CHECK(wday == ptm->tm_wday);
    if (yday != -1) 
        TEST_CHECK(yday == ptm->tm_yday);
}

void test_basic_date_time(void) {
    struct flb_tm my_tm;
    char *ret;
    const char *buf = "2023-05-12 10:30:45";
    const char *fmt = "%Y-%m-%d %H:%M:%S";

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime(buf, fmt, &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK('\0' == *ret);
        check_tm_datetime(&my_tm.tm, 2023, 5, 12, 10, 30, 45);
        TEST_CHECK(0 == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(-1 == my_tm.tm.tm_isdst);
    }
}

void test_textual_month_day(void) {
    struct flb_tm my_tm;
    char *ret;
    const char *buf = "May 12 2023 Friday";
    const char *fmt = "%b %d %Y %A";

    memset(&my_tm, 0, sizeof(my_tm));

    ret = flb_strptime(buf, fmt, &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK('\0' == *ret);
        TEST_CHECK((2023 - 1900) == my_tm.tm.tm_year);
        TEST_CHECK((5 - 1) == my_tm.tm.tm_mon);
        TEST_CHECK(12 == my_tm.tm.tm_mday);
        TEST_CHECK(5 == my_tm.tm.tm_wday);
    }
}

void test_year_variations(void) {
    struct flb_tm my_tm;
    char *ret;

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("15", "%y", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) 
        TEST_CHECK((2015 - 1900) == my_tm.tm.tm_year);

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("99", "%y", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) 
        TEST_CHECK((1999 - 1900) == my_tm.tm.tm_year);

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("20 15", "%C %y", &my_tm); /* Century 20, year 15 -> 2015 */
    TEST_CHECK(ret != NULL);
    if (ret) 
        TEST_CHECK((2015 - 1900) == my_tm.tm.tm_year);

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("19 99", "%C %y", &my_tm); /* Century 19, year 99 -> 1999 */
    TEST_CHECK(ret != NULL);
    if (ret) 
        TEST_CHECK((1999 - 1900) == my_tm.tm.tm_year);
}

void test_am_pm(void) {
    struct flb_tm my_tm;
    char *ret;

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("01:00:00 AM", "%I:%M:%S %p", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) 
        TEST_CHECK(1 == my_tm.tm.tm_hour);

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("12:00:00 AM", "%I:%M:%S %p", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret)
        TEST_CHECK(0 == my_tm.tm.tm_hour);

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("01:00:00 PM", "%I:%M:%S %p", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret)
        TEST_CHECK(13 == my_tm.tm.tm_hour);

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("12:00:00 PM", "%I:%M:%S %p", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret)
        TEST_CHECK(12 == my_tm.tm.tm_hour);

    memset(&my_tm, 0, sizeof(my_tm));
    my_tm.tm.tm_hour = 13;
    ret = flb_strptime("AM", "%p", &my_tm);
    TEST_CHECK(ret == NULL);

    memset(&my_tm, 0, sizeof(my_tm));
    my_tm.tm.tm_hour = 13;
    ret = flb_strptime("PM", "%p", &my_tm);
    TEST_CHECK(ret == NULL);
}

void test_seconds_since_epoch(void) {
    struct flb_tm my_tm;
    char *ret;
    const char *buf = "0";
    
    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime(buf, "%s", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        check_tm_datetime_wday_yday(&my_tm.tm, 1970, 1, 1, 0, 0, 0, 4, 0);
        TEST_CHECK(0 == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
        TEST_CHECK(strncmp("UTC", flb_tm_zone(&my_tm), 3) == 0);
    }

    const char *buf2 = "1678608000"; /* Corresponds to 2023-03-12 08:00:00 UTC */
    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime(buf2, "%s", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        check_tm_datetime_wday_yday(&my_tm.tm, 2023, 3, 12, 8, 0, 0, 0 /* Sunday */, 70);
        TEST_CHECK(0 == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
    }
}

void test_recursive_formats(void) {
    struct flb_tm my_tm;
    char *ret;

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("2024-01-20", "%F", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((2024 - 1900) == my_tm.tm.tm_year);
        TEST_CHECK(0 == my_tm.tm.tm_mon); /* Jan */
        TEST_CHECK(20 == my_tm.tm.tm_mday);
    }
}

void test_timezone_z_numeric(void) {
    struct flb_tm my_tm;
    char *ret;

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("2023-05-12 10:30:00Z", "%Y-%m-%d %H:%M:%S%z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        check_tm_datetime(&my_tm.tm, 2023, 5, 12, 10, 30, 0);
        TEST_CHECK(0 == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
        TEST_CHECK(flb_tm_zone(&my_tm) != NULL &&
            (strcmp(flb_tm_zone(&my_tm), "UTC") == 0 ||
             strcmp(flb_tm_zone(&my_tm), "Z") == 0 ||
             strcmp(flb_tm_zone(&my_tm), "utc") == 0));
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("10:30:00+0530", "%H:%M:%S%z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK(10 == my_tm.tm.tm_hour);
        TEST_CHECK((long)(5.5 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("10:30:00-0800", "%H:%M:%S%z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK(10 == my_tm.tm.tm_hour);
        TEST_CHECK((-8 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
    }
    
    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("10:30:00+05:30", "%H:%M:%S%z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK(10 == my_tm.tm.tm_hour);
        TEST_CHECK((long)(5.5 * 3600) == flb_tm_gmtoff(&my_tm));
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("10:30:00+05", "%H:%M:%S%z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK(10 == my_tm.tm.tm_hour);
        TEST_CHECK((5 * 3600) == flb_tm_gmtoff(&my_tm));
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("14:00:00 +01", "%H:%M:%S %z", &my_tm); /* TZ=Africa/Casablanca */
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((1 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
    }
}

void test_timezone_z_named_rfc822(void) {
    struct flb_tm my_tm;
    char *ret;

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("10:30:00GMT", "%H:%M:%S%z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK(0 == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
        TEST_CHECK(strncmp("GMT", flb_tm_zone(&my_tm), 3) == 0);
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("10:30:00EST", "%H:%M:%S%z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((-5 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
        TEST_CHECK(strncmp("EST", flb_tm_zone(&my_tm), 3) == 0);
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("10:30:00EDT", "%H:%M:%S%z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((-4 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(1 == my_tm.tm.tm_isdst);
        TEST_CHECK(strncmp("EDT", flb_tm_zone(&my_tm), 3) == 0);
    }
}


void test_timezone_Z_known_list(void) {
    struct flb_tm my_tm;
    char *ret;

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("2023-01-10 10:00:00 PST", "%Y-%m-%d %H:%M:%S %Z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((-8 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst); /* PST is standard */
        TEST_CHECK(strncmp("PST", flb_tm_zone(&my_tm), 3) == 0);
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("14:00:00 cest", "%H:%M:%S %Z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((2 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(1 == my_tm.tm.tm_isdst); /* CEST is daylight */
        TEST_CHECK(strncmp("CEST", flb_tm_zone(&my_tm), 3) == 0);
    }
    
    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("JST", "%Z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((9 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("ICT", "%Z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((7 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("WIB", "%Z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((7 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("K", "%Z", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((10 * 3600) == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("PSTX", "%Z", &my_tm);
    TEST_CHECK(ret == NULL);
}

void test_timezone_Z_fallback_gmt_utc(void) {
    struct flb_tm my_tm;
    char *ret;

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("GMT", "%Z", &my_tm);
    TEST_CHECK(ret != NULL);
    if(ret) {
        TEST_CHECK(0 == flb_tm_gmtoff(&my_tm));
        TEST_CHECK(0 == my_tm.tm.tm_isdst);
        TEST_CHECK(strncmp("GMT", flb_tm_zone(&my_tm), 3) == 0);
    }
}

void test_invalid_inputs(void) {
    struct flb_tm my_tm;
    char *ret;

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("", "%Y", &my_tm);
    TEST_CHECK(ret == NULL);

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("2023", "", &my_tm);
    TEST_CHECK(ret != NULL);
    TEST_CHECK(strncmp(ret, "2023", 4) == 0);

    /* Mismatch */
    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("abc", "%Y", &my_tm);
    TEST_CHECK(ret == NULL);

    /* Invalid month number */
    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("2023-13-01", "%Y-%m-%d", &my_tm);
    TEST_CHECK(ret == NULL);
}

void test_whitespace_handling(void) {
    struct flb_tm my_tm;
    char *ret;

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("  2023-05-12  10:30:45  ", " %Y-%m-%d %H:%M:%S ", &my_tm);
    TEST_CHECK(ret != NULL);
    if(ret) {
        check_tm_datetime(&my_tm.tm, 2023, 5, 12, 10, 30, 45);

        TEST_CHECK('\0' == *ret);
    }

    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("2023-05-12T10:30:45", "%Y-%m-%dT%H:%M:%S", &my_tm);
    TEST_CHECK(ret != NULL);
    if(ret) {
        check_tm_datetime(&my_tm.tm, 2023, 5, 12, 10, 30, 45);
    }
}

void test_fill_yday_wday(void) {
    struct flb_tm my_tm;
    char *ret;

    /* 2023-01-01 is a Sunday (wday=0), yday=0 */
    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("2023-01-01", "%Y-%m-%d", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((2023 - 1900) == my_tm.tm.tm_year);
        TEST_CHECK(0 == my_tm.tm.tm_mon);
        TEST_CHECK(1 == my_tm.tm.tm_mday);
        TEST_CHECK(0 == my_tm.tm.tm_yday); /* yday is 0-indexed */
        TEST_CHECK(0 == my_tm.tm.tm_wday); /* Sunday */
    }

    /* 2023-12-31 is a Sunday (wday=0), yday=364 */
    memset(&my_tm, 0, sizeof(my_tm));
    ret = flb_strptime("2023-12-31", "%Y-%m-%d", &my_tm);
    TEST_CHECK(ret != NULL);
    if (ret) {
        TEST_CHECK((2023 - 1900) == my_tm.tm.tm_year);
        TEST_CHECK(11 == my_tm.tm.tm_mon);
        TEST_CHECK(31 == my_tm.tm.tm_mday);
        TEST_CHECK(364 == my_tm.tm.tm_yday);
        TEST_CHECK(0 == my_tm.tm.tm_wday); /* Sunday */
    }
}


TEST_LIST = {
    { "basic_date_time", test_basic_date_time },
    { "textual_month_day", test_textual_month_day },
    { "year_variations", test_year_variations },
    { "am_pm", test_am_pm },
    { "seconds_since_epoch", test_seconds_since_epoch },
    { "recursive_formats", test_recursive_formats },
    { "timezone_z_numeric", test_timezone_z_numeric },
    { "timezone_z_named_rfc822", test_timezone_z_named_rfc822 },
    { "timezone_Z_known_list", test_timezone_Z_known_list },
    { "timezone_Z_fallback_gmt_utc", test_timezone_Z_fallback_gmt_utc },
    { "invalid_inputs", test_invalid_inputs },
    { "whitespace_handling", test_whitespace_handling },
    { "fill_yday_wday", test_fill_yday_wday },
    { NULL, NULL }
};