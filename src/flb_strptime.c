/*	$OpenBSD: strptime.c,v 1.30 2019/05/12 12:49:52 schwarze Exp $ */
/*	$NetBSD: strptime.c,v 1.12 1998/01/20 21:39:40 mycroft Exp $	*/
/*-
 * Copyright (c) 1997, 1998, 2005, 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code was contributed to The NetBSD Foundation by Klaus Klein.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file provides a portable implementation of strptime(2), based
 * on the work of OpenSBD project. Since various platforms implement
 * strptime differently, this one should work as a fallback.
 */

#include <ctype.h>
#include <locale.h>
#include <stdint.h>
#include <string.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_langinfo.h>
#include <fluent-bit/flb_time.h>

#define	_ctloc(x)		(nl_langinfo(x))

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ if (alt_format & ~(x)) return (0); }

/*
 * Copied from libc/time/private.h and libc/time/tzfile.h
 */
#define TM_YEAR_BASE	1900
#define DAYSPERNYEAR	365
#define DAYSPERLYEAR	366
#define DAYSPERWEEK		7
#define MONSPERYEAR		12
#define EPOCH_YEAR		1970
#define EPOCH_WDAY		4	/* Thursday */
#define SECSPERHOUR		3600
#define SECSPERMIN  	60

#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

/*
 * We keep track of some of the fields we set in order to compute missing ones.
 */
#define FIELD_TM_MON	(1 << 0)
#define FIELD_TM_MDAY	(1 << 1)
#define FIELD_TM_WDAY	(1 << 2)
#define FIELD_TM_YDAY	(1 << 3)
#define FIELD_TM_YEAR	(1 << 4)

static char gmt[] = { "GMT" };
static char utc[] = { "UTC" };

/* RFC-822/RFC-2822 */
static const char * const nast[5] = {
       "EST",    "CST",    "MST",    "PST",    "\0\0\0"
};
static const char * const nadt[5] = {
       "EDT",    "CDT",    "MDT",    "PDT",    "\0\0\0"
};

/* New structure for known timezone abbreviations */
typedef struct {
	const char *abbr;
	int offset_sec;
	int is_dst;
} flb_tz_abbr_info_t;

/* Comprehensive list of known timezone abbreviations */
static const flb_tz_abbr_info_t flb_known_timezones[] = {
    /* UTC/GMT and Zulu */
    {"GMT", 0, 0},
    {"UTC", 0, 0},
    {"Z", 0, 0}, /* Zulu Time (UTC) */
    {"UT", 0, 0},

    /* North American Timezones */
    {"EST", -5*SECSPERHOUR, 0}, /* Eastern Standard Time */
    {"EDT", -4*SECSPERHOUR, 1}, /* Eastern Daylight Time */
    {"CST", -6*SECSPERHOUR, 0}, /* Central Standard Time (North America) */
    {"CDT", -5*SECSPERHOUR, 1}, /* Central Daylight Time (North America) */
    {"MST", -7*SECSPERHOUR, 0}, /* Mountain Standard Time */
    {"MDT", -6*SECSPERHOUR, 1}, /* Mountain Daylight Time */
    {"PST", -8*SECSPERHOUR, 0}, /* Pacific Standard Time */
    {"PDT", -7*SECSPERHOUR, 1}, /* Pacific Daylight Time */
    {"AKST", -9*SECSPERHOUR, 0}, /* Alaska Standard Time */
    {"AKDT", -8*SECSPERHOUR, 1}, /* Alaska Daylight Time */
    {"HST", -10*SECSPERHOUR, 0}, /* Hawaii Standard Time */
    {"HADT", -9*SECSPERHOUR, 1}, /* Hawaii-Aleutian Daylight Time (rarely used for Hawaii proper) */
    {"AST", -4*SECSPERHOUR, 0}, /* Atlantic Standard Time (e.g., Canada, Caribbean) */
    {"ADT", -3*SECSPERHOUR, 1}, /* Atlantic Daylight Time */
    {"NST", (long)(-3.5*SECSPERHOUR), 0}, /* Newfoundland Standard Time */
    {"NDT", (long)(-2.5*SECSPERHOUR), 1}, /* Newfoundland Daylight Time */

    /* European Timezones */
    {"WET",   0*SECSPERHOUR, 0}, /* Western European Time */
    {"WEST",  1*SECSPERHOUR, 1}, /* Western European Summer Time */
    {"CET",   1*SECSPERHOUR, 0}, /* Central European Time */
    {"CEST",  2*SECSPERHOUR, 1}, /* Central European Summer Time */
    {"EET",   2*SECSPERHOUR, 0}, /* Eastern European Time */
    {"EEST",  3*SECSPERHOUR, 1}, /* Eastern European Summer Time */
    {"MSK",   3*SECSPERHOUR, 0}, /* Moscow Standard Time */
    /* {"MSD",   4*SECSPERHOUR, 1}, */ /* Moscow Summer Time (historical) */

    /* South American Timezones */
    {"ART", -3*SECSPERHOUR, 0}, /* Argentina Time */
    {"BRT", -3*SECSPERHOUR, 0}, /* Brazil Time (main population areas, can vary by region/DST) */
    {"BRST", -2*SECSPERHOUR, 1}, /* Brazil Summer Time (historical, not currently observed by all) */
    {"CLT", -4*SECSPERHOUR, 0}, /* Chile Standard Time */
    {"CLST", -3*SECSPERHOUR, 1}, /* Chile Summer Time */

    /* Australasian / Oceanian Timezones */
    {"AEST", 10*SECSPERHOUR, 0}, /* Australian Eastern Standard Time */
    {"AEDT", 11*SECSPERHOUR, 1}, /* Australian Eastern Daylight Time */
    {"ACST", (long)(9.5*SECSPERHOUR), 0}, /* Australian Central Standard Time */
    {"ACDT", (long)(10.5*SECSPERHOUR), 1}, /* Australian Central Daylight Time */
    {"AWST",  8*SECSPERHOUR, 0}, /* Australian Western Standard Time */
    {"NZST", 12*SECSPERHOUR, 0}, /* New Zealand Standard Time */
    {"NZDT", 13*SECSPERHOUR, 1}, /* New Zealand Daylight Time */

    /* Asian Timezones */
    {"JST",   9*SECSPERHOUR, 0}, /* Japan Standard Time */
    {"KST",   9*SECSPERHOUR, 0}, /* Korea Standard Time */
    {"SGT",   8*SECSPERHOUR, 0}, /* Singapore Time */
    {"IST", (long)(5.5*SECSPERHOUR), 0}, /* India Standard Time */
    {"GST",   4*SECSPERHOUR, 0}, /* Gulf Standard Time (e.g., UAE, Oman) */
    {"ICT",   7*SECSPERHOUR, 0}, /* Indochina Time (Thailand, Vietnam, Laos, Cambodia) */
    {"WIB",   7*SECSPERHOUR, 0}, /* Western Indonesian Time */
    {"WITA",  8*SECSPERHOUR, 0}, /* Central Indonesian Time */
    {"WIT",   9*SECSPERHOUR, 0}, /* Eastern Indonesian Time */
    {"MYT",   8*SECSPERHOUR, 0}, /* Malaysia Time */
    {"BDT",   6*SECSPERHOUR, 0}, /* Bangladesh Standard Time */
    {"NPT", (long)(5.75*SECSPERHOUR), 0}, /* Nepal Time */

    /* African Timezones */
    {"WAT",   1*SECSPERHOUR, 0}, /* West Africa Time */
    {"CAT",   2*SECSPERHOUR, 0}, /* Central Africa Time */
    {"EAT",   3*SECSPERHOUR, 0}, /* East Africa Time */
    {"SAST",  2*SECSPERHOUR, 0}, /* South Africa Standard Time */

    /* Military Timezones */
    /* These are single letters. 'J' (Juliett) is local time of the observer and not included. */
    /* 'Z' (Zulu) is UTC, already listed. */
    {"A",   1*SECSPERHOUR, 0}, /* Alpha Time Zone */
    {"B",   2*SECSPERHOUR, 0}, /* Bravo Time Zone */
    {"C",   3*SECSPERHOUR, 0}, /* Charlie Time Zone */
    {"D",   4*SECSPERHOUR, 0}, /* Delta Time Zone */
    {"E",   5*SECSPERHOUR, 0}, /* Echo Time Zone */
    {"F",   6*SECSPERHOUR, 0}, /* Foxtrot Time Zone */
    {"G",   7*SECSPERHOUR, 0}, /* Golf Time Zone */
    {"H",   8*SECSPERHOUR, 0}, /* Hotel Time Zone */
    {"I",   9*SECSPERHOUR, 0}, /* India Time Zone (Military, not India Standard Time) */
    {"K",  10*SECSPERHOUR, 0}, /* Kilo Time Zone */
    {"L",  11*SECSPERHOUR, 0}, /* Lima Time Zone */
    {"M",  12*SECSPERHOUR, 0}, /* Mike Time Zone */
    {"N",  -1*SECSPERHOUR, 0}, /* November Time Zone */
    {"O",  -2*SECSPERHOUR, 0}, /* Oscar Time Zone */
    {"P",  -3*SECSPERHOUR, 0}, /* Papa Time Zone */
    {"Q",  -4*SECSPERHOUR, 0}, /* Quebec Time Zone */
    {"R",  -5*SECSPERHOUR, 0}, /* Romeo Time Zone */
    {"S",  -6*SECSPERHOUR, 0}, /* Sierra Time Zone */
    {"T",  -7*SECSPERHOUR, 0}, /* Tango Time Zone */
    {"U",  -8*SECSPERHOUR, 0}, /* Uniform Time Zone */
    {"V",  -9*SECSPERHOUR, 0}, /* Victor Time Zone */
    {"W", -10*SECSPERHOUR, 0}, /* Whiskey Time Zone */
    {"X", -11*SECSPERHOUR, 0}, /* X-ray Time Zone */
    {"Y", -12*SECSPERHOUR, 0}, /* Yankee Time Zone */

    {NULL, 0, 0}
};

static const int mon_lengths[2][MONSPERYEAR] = {
        { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
        { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static nl_item day[] = {
        DAY_1, DAY_2, DAY_3, DAY_4, DAY_5, DAY_6, DAY_7
};

static nl_item mon[] = {
        MON_1, MON_2, MON_3, MON_4, MON_5, MON_6, MON_7, MON_8, MON_9,
        MON_10, MON_11, MON_12
};

static nl_item abday[] = {
        ABDAY_1, ABDAY_2, ABDAY_3, ABDAY_4, ABDAY_5, ABDAY_6, ABDAY_7
};

static nl_item abmon[] = {
        ABMON_1, ABMON_2, ABMON_3, ABMON_4, ABMON_5, ABMON_6, ABMON_7,
        ABMON_8, ABMON_9, ABMON_10, ABMON_11, ABMON_12
};

static	int _conv_num64(const unsigned char **, int64_t *, int64_t, int64_t);
static	int _conv_num(const unsigned char **, int *, int, int);
static	int leaps_thru_end_of(const int y);
static	char *_flb_strptime(const char *, const char *, struct flb_tm *, int);
static	const u_char *_find_string(const u_char *, int *, const char * const *,
	    const char * const *, int);

/*
 * FreeBSD does not support `timezone` in time.h.
 * https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=24590
 */
#ifdef __FreeBSD__
int flb_timezone(void)
{
    struct tm tm;
    time_t t = 0;
    tzset();
    localtime_r(&t, &tm);
    return -(tm.tm_gmtoff);
}
#define timezone (flb_timezone())
#endif

char *
flb_strptime(const char *buf, const char *fmt, struct flb_tm *tm)
{
	return(_flb_strptime(buf, fmt, tm, 1));
}

static char *
_flb_strptime(const char *buf, const char *fmt, struct flb_tm *tm, int initialize)
{
	unsigned char c;
	const unsigned char *bp, *ep;
	size_t len = 0;
	int alt_format, i, offs;
	int neg = 0;
	static int century, relyear, fields;

	if (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
		fields = 0;
		flb_tm_gmtoff(tm) = 0;
		tm->tm.tm_isdst = -1;
	}

	bp = (const unsigned char *)buf;
	while ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		if (isspace(c)) {
			while (isspace(*bp))
				bp++;

			fmt++;
			continue;
		}

        /*
         * Having increased bp we need to ensure we are not
         * moving beyond bounds.
         */
        if (*bp == '\0')
           return (NULL);

		if ((c = *fmt++) != '%')
			goto literal;


again:		switch (c = *fmt++) {
		case '%':	/* "%%" is converted to "%". */
literal:
		if (c != *bp++)
			return (NULL);

		break;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		case 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			goto again;

		case 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			goto again;

		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
		case 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, _ctloc(D_T_FMT), tm, 0)))
				return (NULL);
			break;

		case 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, "%m/%d/%y", tm, 0)))
				return (NULL);
			break;

		case 'F':	/* The date as "%Y-%m-%d". */
			_LEGAL_ALT(0);
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, "%Y-%m-%d", tm, 0)))
				return (NULL);
			continue;

		case 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, "%H:%M", tm, 0)))
				return (NULL);
			break;

		case 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, "%I:%M:%S %p", tm, 0)))
				return (NULL);
			break;

		case 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, "%H:%M:%S", tm, 0)))
				return (NULL);
			break;

		case 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, _ctloc(T_FMT), tm, 0)))
				return (NULL);
			break;

		case 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, _ctloc(D_FMT), tm, 0)))
				return (NULL);
			break;

		/*
		 * "Elementary" conversion rules.
		 */
		case 'A':	/* The day of week, using the locale's form. */
		case 'a':
			_LEGAL_ALT(0);
			for (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				if (strncasecmp(_ctloc(day[i]), (const char *)bp, len) == 0)
					break;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				if (strncasecmp(_ctloc(abday[i]), (const char *)bp, len) == 0)
					break;
			}

			/* Nothing matched. */
			if (i == 7)
				return (NULL);

			tm->tm.tm_wday = i;
			bp += len;
			fields |= FIELD_TM_WDAY;
			break;

		case 'B':	/* The month, using the locale's form. */
		case 'b':
		case 'h':
			_LEGAL_ALT(0);
			for (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				if (strncasecmp(_ctloc(mon[i]), (const char *)bp, len) == 0)
					break;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				if (strncasecmp(_ctloc(abmon[i]), (const char *)bp, len) == 0)
					break;
			}

			/* Nothing matched. */
			if (i == 12)
				return (NULL);

			tm->tm.tm_mon = i;
			bp += len;
			fields |= FIELD_TM_MON;
			break;

		case 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			if (!(_conv_num(&bp, &i, 0, 99)))
				return (NULL);

			century = i * 100;
			break;

		case 'e':	/* The day of month. */
			if (isspace(*bp))
				bp++;
			/* FALLTHROUGH */
		case 'd':
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm.tm_mday, 1, 31)))
				return (NULL);
			fields |= FIELD_TM_MDAY;
			break;

		case 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'H':
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm.tm_hour, 0, 23)))
				return (NULL);
			break;

		case 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'I':
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm.tm_hour, 1, 12)))
				return (NULL);
			break;

		case 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			if (!(_conv_num(&bp, &tm->tm.tm_yday, 1, 366)))
				return (NULL);
			tm->tm.tm_yday--;
			fields |= FIELD_TM_YDAY;
			break;

		case 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm.tm_min, 0, 59)))
				return (NULL);
			break;

		case 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm.tm_mon, 1, 12)))
				return (NULL);
			tm->tm.tm_mon--;
			fields |= FIELD_TM_MON;
			break;

		case 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(AM_STR));
			if (strncasecmp(_ctloc(AM_STR), (const char *)bp, len) == 0) {
				if (tm->tm.tm_hour > 12)	/* i.e., 13:00 AM ?! */
					return (NULL);
				else if (tm->tm.tm_hour == 12)
					tm->tm.tm_hour = 0;

				bp += len;
				break;
			}
			/* PM? */
			len = strlen(_ctloc(PM_STR));
			if (strncasecmp(_ctloc(PM_STR), (const char *)bp, len) == 0) {
				if (tm->tm.tm_hour > 12)	/* i.e., 13:00 PM ?! */
					return (NULL);
				else if (tm->tm.tm_hour < 12)
					tm->tm.tm_hour += 12;

				bp += len;
				break;
			}

			/* Nothing matched. */
			return (NULL);

		case 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm.tm_sec, 0, 60)))
				return (NULL);
			break;
		case 's':	/* Seconds since epoch */
			{
				int64_t i64;
				if (!(_conv_num64(&bp, &i64, 0, INT64_MAX)))
					return (NULL);
				if (!gmtime_r((const time_t *) &i64, &tm->tm))
					return (NULL);
				flb_tm_gmtoff(tm) = 0;
				tm->tm.tm_isdst = 0;
				flb_tm_zone(tm) = utc;
				/* %s format does not handle timezone */
				fields = 0xffff;         /* everything */
			}
			break;
		case 'U':	/* The week of year, beginning on sunday. */
		case 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 if (!(_conv_num(&bp, &i, 0, 53)))
				return (NULL);
			 break;

		case 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm.tm_wday, 0, 6)))
				return (NULL);
			fields |= FIELD_TM_WDAY;
			break;

		case 'u':	/* The day of week, monday = 1. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &i, 1, 7)))
				return (NULL);
			tm->tm.tm_wday = i % 7;
			fields |= FIELD_TM_WDAY;
			continue;

		case 'g':	/* The year corresponding to the ISO week
				 * number but without the century.
				 */
			if (!(_conv_num(&bp, &i, 0, 99)))
				return (NULL);
			continue;

		case 'G':	/* The year corresponding to the ISO week
				 * number with century.
				 */
			do
				bp++;
			while (isdigit(*bp));
			continue;

		case 'V':	/* The ISO 8601:1988 week number as decimal */
			if (!(_conv_num(&bp, &i, 0, 53)))
				return (NULL);
			continue;

		case 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			if (!(_conv_num(&bp, &i, 0, 9999)))
				return (NULL);

			relyear = -1;
			tm->tm.tm_year = i - TM_YEAR_BASE;
			fields |= FIELD_TM_YEAR;
			break;

		case 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			if (!(_conv_num(&bp, &relyear, 0, 99)))
				return (NULL);
			break;

		case 'Z':
		{
			const flb_tz_abbr_info_t *tz_info;
			int found_in_known = FLB_FALSE;
			size_t abbr_len;

			for (tz_info = flb_known_timezones; tz_info->abbr != NULL; ++tz_info) {
				abbr_len = strlen(tz_info->abbr);
				if (strncasecmp(tz_info->abbr, (const char *)bp, abbr_len) == 0) {
					if (!isalnum((unsigned char)bp[abbr_len])) {
						tm->tm.tm_isdst = tz_info->is_dst;
						flb_tm_gmtoff(tm) = tz_info->offset_sec;
						flb_tm_zone(tm) = tz_info->abbr;
						bp += abbr_len;
						found_in_known = FLB_TRUE;
						break;
					}
				}
			}

			if (!found_in_known) {
				/* Fallback to original logic using system's tzname, gmt, utc */
#if defined(_WIN32) || defined(_WIN64)
				_tzset(); /* Windows */
#else
				tzset(); /* POSIX */
#endif
				/* Check original gmt/utc static arrays first, as per original logic */
				if (strncmp((const char *)bp, gmt, 3) == 0) {
					tm->tm.tm_isdst = 0;
					flb_tm_gmtoff(tm) = 0;
					flb_tm_zone(tm) = gmt;
					bp += 3;
				} else if (strncmp((const char *)bp, utc, 3) == 0) {
					tm->tm.tm_isdst = 0;
					flb_tm_gmtoff(tm) = 0;
					flb_tm_zone(tm) = utc;
					bp += 3;
				} else {
					ep = _find_string(bp, &i, (const char * const *)tzname, NULL, 2);
					if (ep == NULL)
						return (NULL);

					tm->tm.tm_isdst = i;
					/* 'timezone' global variable. Handled by flb_timezone() macro on FreeBSD.
					   On Windows, _tzset sets _timezone (seconds WEST of UTC).
					   On other POSIX, tzset sets timezone (seconds WEST of UTC). */
#if defined(_WIN32) || defined(_WIN64)
					long win_timezone_val;
					_get_timezone(&win_timezone_val); /* Use a more robust way to get Windows timezone offset */
					flb_tm_gmtoff(tm) = -(win_timezone_val);
					/* Check _daylight and i for more accurate DST offset if needed */
					if (_daylight && i == 1) {
						long dst_bias = 0;
						_get_dstbias(&dst_bias); /* dst_bias is offset FROM standard, usually negative, e.g. -3600 */
						flb_tm_gmtoff(tm) = -(win_timezone_val + dst_bias);
					}

#else
					flb_tm_gmtoff(tm) = -(timezone);
#endif
					flb_tm_zone(tm) = tzname[i];
					bp = ep;
				}
			}
			continue;
		}
		case 'z':
			/*
			 * We recognize all ISO 8601 formats:
			 * Z	= Zulu time/UTC
			 * [+-]hhmm
			 * [+-]hh:mm
			 * [+-]hh
			 * We recognize all RFC-822/RFC-2822 formats:
			 * UT|GMT
			 *          North American : UTC offsets
			 * E[DS]T = Eastern : -4 | -5
			 * C[DS]T = Central : -5 | -6
			 * M[DS]T = Mountain: -6 | -7
			 * P[DS]T = Pacific : -7 | -8
			 */
			while (isspace(*bp))
				bp++;
			neg = 0;
			switch (*bp++) {
			case 'G':
				if (*bp++ != 'M')
					return NULL;
				/*FALLTHROUGH*/
				if (*bp++ != 'T')
					return NULL;
				tm->tm.tm_isdst = 0;
				flb_tm_gmtoff(tm) = 0;
				flb_tm_zone(tm) = gmt; /* Original had global gmt array */
				continue;
			case 'U':
				if (*bp++ != 'T')
					return NULL;
				/*FALLTHROUGH*/
				if (*bp == 'C')
					bp++; /* Allow "UTC" */
				tm->tm.tm_isdst = 0;
				flb_tm_gmtoff(tm) = 0;
				flb_tm_zone(tm) = utc; /* Original had global utc array */
				continue;
			case 'Z':
				tm->tm.tm_isdst = 0;
				flb_tm_gmtoff(tm) = 0;
				flb_tm_zone(tm) = utc;
				continue;
			case '+':
				neg = 0;
				break;
			case '-':
				neg = 1;
				break;
			default:
				--bp;
				ep = _find_string(bp, &i, nast, NULL, 4);
				if (ep != NULL) {
					flb_tm_gmtoff(tm) = (-5 - i) * SECSPERHOUR;
					tm->tm.tm_isdst = 0;
					flb_tm_zone(tm)  = (char *)nast[i];
					bp = ep;
					continue;
				}
				ep = _find_string(bp, &i, nadt, NULL, 4);
				if (ep != NULL) {
					tm->tm.tm_isdst = 1;
					flb_tm_gmtoff(tm) = (-4 - i) * SECSPERHOUR;
					flb_tm_zone(tm)  = (char *)nadt[i];
					bp = ep;
					continue;
				}
				return NULL;
			}
			if (!isdigit(bp[0]) || !isdigit(bp[1]))
				return NULL;
			offs = ((bp[0]-'0') * 10 + (bp[1]-'0')) * SECSPERHOUR;
			bp += 2;
			if (*bp == ':')
				bp++;
			if (isdigit(*bp)) {
				offs += (*bp++ - '0') * 10 * SECSPERMIN;
				if (!isdigit(*bp))
					return NULL;
				offs += (*bp++ - '0') * SECSPERMIN;
			}
			if (neg)
				offs = -offs;
			tm->tm.tm_isdst = 0;	/* XXX */
			flb_tm_gmtoff(tm) = offs;
			flb_tm_zone(tm) = NULL;	/* XXX */
			continue;

		/*
		 * Miscellaneous conversions.
		 */
		case 'n':	/* Any kind of white-space. */
		case 't':
			_LEGAL_ALT(0);
			while (isspace(*bp))
				bp++;
			break;


		default:	/* Unknown/unsupported conversion. */
			return (NULL);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	if (relyear != -1) {
		if (century == TM_YEAR_BASE) {
			if (relyear <= 68)
				tm->tm.tm_year = relyear + 2000 - TM_YEAR_BASE;
			else
				tm->tm.tm_year = relyear + 1900 - TM_YEAR_BASE;
		} else {
			tm->tm.tm_year = relyear + century - TM_YEAR_BASE;
		}
		fields |= FIELD_TM_YEAR;
	}

	/* Compute some missing values when possible. */
	if (fields & FIELD_TM_YEAR) {
		const int year = (unsigned int)tm->tm.tm_year + (unsigned int)TM_YEAR_BASE;
		const int *mon_lens = mon_lengths[isleap(year)];
		if (!(fields & FIELD_TM_YDAY) &&
		    (fields & FIELD_TM_MON) && (fields & FIELD_TM_MDAY)) {
			tm->tm.tm_yday = tm->tm.tm_mday - 1;
			for (i = 0; i < tm->tm.tm_mon; i++)
				tm->tm.tm_yday += mon_lens[i];
			fields |= FIELD_TM_YDAY;
		}
		if (fields & FIELD_TM_YDAY) {
			int days = tm->tm.tm_yday;
			if (!(fields & FIELD_TM_WDAY)) {
				tm->tm.tm_wday = EPOCH_WDAY +
				    ((year - EPOCH_YEAR) % DAYSPERWEEK) *
				    (DAYSPERNYEAR % DAYSPERWEEK) +
				    leaps_thru_end_of(year - 1) -
				    leaps_thru_end_of(EPOCH_YEAR - 1) +
				    tm->tm.tm_yday;
				tm->tm.tm_wday %= DAYSPERWEEK;
				if (tm->tm.tm_wday < 0)
					tm->tm.tm_wday += DAYSPERWEEK;
			}
			if (!(fields & FIELD_TM_MON)) {
				tm->tm.tm_mon = 0;
				while (tm->tm.tm_mon < MONSPERYEAR && days >= mon_lens[tm->tm.tm_mon])
					days -= mon_lens[tm->tm.tm_mon++];
			}
			if (!(fields & FIELD_TM_MDAY))
				tm->tm.tm_mday = days + 1;
		}
	}

	return ((char *)bp);
}


static int
_conv_num(const unsigned char **buf, int *dest, int llim, int ulim)
{
	int result = 0;
	int rulim = ulim;

	if (**buf < '0' || **buf > '9')
		return (0);

	/* we use rulim to break out of the loop when we run out of digits */
	do {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} while ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	if (result < llim || result > ulim)
		return (0);

	*dest = result;
	return (1);
}

static int
_conv_num64(const unsigned char **buf, int64_t *dest, int64_t llim, int64_t ulim)
{
	int64_t result = 0;
	int64_t rulim = ulim;

	if (**buf < '0' || **buf > '9')
		return (0);

	/* we use rulim to break out of the loop when we run out of digits */
	do {
		/* Avoid overflow: result > ((2**64)/2.0) / 10.0 */
		if (result > 922337203685477580) {
			return (0);
		}
		result *= 10;

		/* Avoid overflow: result > ((2**64)/2.0) - 48 */
		if (result > 9223372036854775760) {
			return (0);
		}
		result += *(*buf)++ - '0';
		rulim /= 10;
        /* watch out for overflows. If value gets above
         * ((2**64)/2.0)/10.0 then we will overflow. So instead
         * we return 0 */
        if (result >= 922337203685477580) {
            return (0);
        }
	} while ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	if (result < llim || result > ulim)
		return (0);

	*dest = result;
	return (1);
}

static const u_char *
_find_string(const u_char *bp, int *tgt, const char * const *n1,
		const char * const *n2, int c)
{
	int i;
	unsigned int len;

	/* check full name - then abbreviated ones */
	for (; n1 != NULL; n1 = n2, n2 = NULL) {
		for (i = 0; i < c; i++, n1++) {
			len = strlen(*n1);
			if (strncasecmp(*n1, (const char *)bp, len) == 0) {
				*tgt = i;
				return bp + len;
			}
		}
	}

	/* Nothing matched */
	return NULL;
}

static int
leaps_thru_end_of(const int y)
{
	return (y >= 0) ? (y / 4 - y / 100 + y / 400) :
		-(leaps_thru_end_of(-(y + 1)) + 1);
}
