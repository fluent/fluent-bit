/*	$OpenBSD: strptime.c,v 1.24 2019/01/22 11:09:03 cheloha Exp $ */
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
#define TM_GMTOFF		tm_gmtoff
#define TM_ZONE			tm_zone

#define TM_YEAR_BASE	1900
#define DAYSPERNYEAR	365
#define DAYSPERLYEAR	366
#define DAYSPERWEEK		7
#define MONSPERYEAR		12
#define EPOCH_YEAR		1970
#define EPOCH_WDAY		4	/* Thursday */

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

static const int mon_lengths[2][MONSPERYEAR] = {
        { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
        { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static nl_item list_day[] = {
        DAY_1, DAY_2, DAY_3, DAY_4, DAY_5, DAY_6, DAY_7
};

static nl_item list_mon[] = {
        MON_1, MON_2, MON_3, MON_4, MON_5, MON_6, MON_7, MON_8, MON_9,
        MON_10, MON_11, MON_12
};

static nl_item list_abday[] = {
        ABDAY_1, ABDAY_2, ABDAY_3, ABDAY_4, ABDAY_5, ABDAY_6, ABDAY_7
};

static nl_item list_abmon[] = {
        ABMON_1, ABMON_2, ABMON_3, ABMON_4, ABMON_5, ABMON_6, ABMON_7,
        ABMON_8, ABMON_9, ABMON_10, ABMON_11, ABMON_12
};

static	int _conv_num64(const unsigned char **, int64_t *, int64_t, int64_t);
static	int _conv_num(const unsigned char **, int *, int, int);
static	int leaps_thru_end_of(const int y);
static	char *_flb_strptime(const char *, const char *, struct tm *, int);
static	const u_char *_find_string(const u_char *, int *, const char * const *,
	    const char * const *, int);


char *
flb_strptime(const char *buf, const char *fmt, struct tm *tm)
{
	return(_flb_strptime(buf, fmt, tm, 1));
}

static char *
_flb_strptime(const char *buf, const char *fmt, struct tm *tm, int initialize)
{
	unsigned char c;
	const unsigned char *bp, *ep;
	size_t len;
	int alt_format, i, offs;
	int neg = 0;
	static int century, relyear, fields;

	if (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
		fields = 0;
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
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, nl_langinfo(D_T_FMT), tm, 0)))
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
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, nl_langinfo(T_FMT), tm, 0)))
				return (NULL);
			break;

		case 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			if (!(bp = (const unsigned char *)_flb_strptime((const char *)bp, nl_langinfo(D_FMT), tm, 0)))
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
				len = strlen(nl_langinfo(list_day[i]));
				if (strncasecmp(nl_langinfo(list_day[i]), (const char *)bp, len) == 0)
					break;

				/* Abbreviated name. */
				len = strlen(nl_langinfo(list_abday[i]));
				if (strncasecmp(nl_langinfo(list_abday[i]), (const char *)bp, len) == 0)
					break;
			}

			/* Nothing matched. */
			if (i == 7)
				return (NULL);

			tm->tm_wday = i;
			bp += len;
			fields |= FIELD_TM_WDAY;
			break;

		case 'B':	/* The month, using the locale's form. */
		case 'b':
		case 'h':
			_LEGAL_ALT(0);
			for (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(nl_langinfo(list_mon[i]));
				if (strncasecmp(nl_langinfo(list_mon[i]), (const char *)bp, len) == 0)
					break;

				/* Abbreviated name. */
				len = strlen(nl_langinfo(list_abmon[i]));
				if (strncasecmp(nl_langinfo(list_abmon[i]), (const char *)bp, len) == 0)
					break;
			}

			/* Nothing matched. */
			if (i == 12)
				return (NULL);

			tm->tm_mon = i;
			bp += len;
			fields |= FIELD_TM_MON;
			break;

		case 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			if (!(_conv_num(&bp, &i, 0, 99)))
				return (NULL);

			century = i * 100;
			break;

		case 'd':	/* The day of month. */
		case 'e':
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_mday, 1, 31)))
				return (NULL);
			fields |= FIELD_TM_MDAY;
			break;

		case 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'H':
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_hour, 0, 23)))
				return (NULL);
			break;

		case 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'I':
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_hour, 1, 12)))
				return (NULL);
			break;

		case 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			if (!(_conv_num(&bp, &tm->tm_yday, 1, 366)))
				return (NULL);
			tm->tm_yday--;
			fields |= FIELD_TM_YDAY;
			break;

		case 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_min, 0, 59)))
				return (NULL);
			break;

		case 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_mon, 1, 12)))
				return (NULL);
			tm->tm_mon--;
			fields |= FIELD_TM_MON;
			break;

		case 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(nl_langinfo(AM_STR));
			if (strncasecmp(nl_langinfo(AM_STR), (const char *)bp, len) == 0) {
				if (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					return (NULL);
				else if (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				break;
			}
			/* PM? */
			len = strlen(nl_langinfo(PM_STR));
			if (strncasecmp(nl_langinfo(PM_STR), (const char *)bp, len) == 0) {
				if (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					return (NULL);
				else if (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				break;
			}

			/* Nothing matched. */
			return (NULL);

		case 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_sec, 0, 60)))
				return (NULL);
			break;
		case 's':	/* Seconds since epoch */
			{
				int64_t i64;
				if (!(_conv_num64(&bp, &i64, 0, INT64_MAX)))
					return (NULL);
				if (!gmtime_r(&i64, tm))
					return (NULL);
				fields = 0xffff;	 /* everything */
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
			if (!(_conv_num(&bp, &tm->tm_wday, 0, 6)))
				return (NULL);
			fields |= FIELD_TM_WDAY;
			break;

		case 'u':	/* The day of week, monday = 1. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &i, 1, 7)))
				return (NULL);
			tm->tm_wday = i % 7;
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
			tm->tm_year = i - TM_YEAR_BASE;
			fields |= FIELD_TM_YEAR;
			break;

		case 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			if (!(_conv_num(&bp, &relyear, 0, 99)))
				return (NULL);
			break;

		case 'Z':
			tzset();
			if (strncmp((const char *)bp, gmt, 3) == 0) {
				tm->tm_isdst = 0;
#ifdef FLB_HAVE_GMTOFF
				tm->TM_GMTOFF = 0;
#endif
#ifdef FLB_HAVE_ZONE
				tm->TM_ZONE = gmt;
#endif
				bp += 3;
			} else if (strncmp((const char *)bp, utc, 3) == 0) {
				tm->tm_isdst = 0;
#ifdef FLB_HAVE_GMTOFF
				tm->TM_GMTOFF = 0;
#endif
#ifdef FLB_HAVE_ZONE
				tm->TM_ZONE = utc;
#endif
				bp += 3;
			} else {
				ep = _find_string(bp, &i,
					       	 (const char * const *)tzname,
					       	  NULL, 2);
				if (ep == NULL)
					return (NULL);

				tm->tm_isdst = i;
#ifdef FLB_HAVE_GMTOFF
				tm->TM_GMTOFF = -(timezone);
#endif
#ifdef FLB_HAVE_ZONE
				tm->TM_ZONE = tzname[i];
#endif
				bp = ep;
			}
			continue;

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
			 *          Military
			 * [A-IL-M] = -1 ... -9 (J not used)
			 * [N-Y]  = +1 ... +12
			 */
			while (isspace(*bp))
				bp++;

			switch (*bp++) {
			case 'G':
				if (*bp++ != 'M')
					return NULL;
				/*FALLTHROUGH*/
			case 'U':
				if (*bp++ != 'T')
					return NULL;
				/*FALLTHROUGH*/
			case 'Z':
				tm->tm_isdst = 0;
#ifdef FLB_HAVE_GMTOFF
				tm->TM_GMTOFF = 0;
#endif
#ifdef FLB_HAVE_ZONE
				tm->TM_ZONE = utc;
#endif
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
#ifdef FLB_HAVE_GMTOFF
					tm->TM_GMTOFF = (-5 - i) * 3600;
#endif
#ifdef FLB_HAVE_ZONE
					tm->TM_ZONE = (char *)nast[i];
#endif
					bp = ep;
					continue;
				}
				ep = _find_string(bp, &i, nadt, NULL, 4);
				if (ep != NULL) {
					tm->tm_isdst = 1;
#ifdef FLB_HAVE_GMTOFF
					tm->TM_GMTOFF = (-4 - i) * 3600;
#endif
#ifdef FLB_HAVE_ZONE
					tm->TM_ZONE = (char *)nadt[i];
#endif
					bp = ep;
					continue;
				}

				if ((*bp >= 'A' && *bp <= 'I') ||
				    (*bp >= 'L' && *bp <= 'Y')) {
#ifdef FLB_HAVE_GMTOFF
					/* Argh! No 'J'! */
					if (*bp >= 'A' && *bp <= 'I')
						tm->TM_GMTOFF =
						    (('A' - 1) - (int)*bp) * 3600;
					else if (*bp >= 'L' && *bp <= 'M')
						tm->TM_GMTOFF = ('A' - (int)*bp) * 3600;
					else if (*bp >= 'N' && *bp <= 'Y')
						tm->TM_GMTOFF = ((int)*bp - 'M') * 3600;
#endif
#ifdef FLB_HAVE_ZONE
					tm->TM_ZONE = NULL; /* XXX */
#endif
					bp++;
					continue;
				}
				return NULL;
			}
			offs = 0;
			for (i = 0; i < 4; ) {
				if (isdigit(*bp)) {
					offs = offs * 10 + (*bp++ - '0');
					i++;
					continue;
				}
				if (i == 2 && *bp == ':') {
					bp++;
					continue;
				}
				break;
			}
			switch (i) {
			case 2:
				offs *= 3600;
				break;
			case 4:
				i = offs % 100;
				if (i >= 60)
					return NULL;
				/* Convert hours/minutes into seconds */
				offs = (offs / 100) * 3600 + i * 60;
				break;
			default:
				return NULL;
			}
			if (neg)
				offs = -offs;
			tm->tm_isdst = 0;	/* XXX */
#ifdef FLB_HAVE_GMTOFF
			tm->TM_GMTOFF = offs;
#endif
#ifdef FLB_HAVE_ZONE
			tm->TM_ZONE = NULL;	/* XXX */
#endif
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
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			else
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} else {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
		fields |= FIELD_TM_YEAR;
	}

	/* Compute some missing values when possible. */
	if (fields & FIELD_TM_YEAR) {
		const int year = tm->tm_year + TM_YEAR_BASE;
		const int *mon_lens = mon_lengths[isleap(year)];
		if (!(fields & FIELD_TM_YDAY) &&
		    (fields & FIELD_TM_MON) && (fields & FIELD_TM_MDAY)) {
			tm->tm_yday = tm->tm_mday - 1;
			for (i = 0; i < tm->tm_mon; i++)
				tm->tm_yday += mon_lens[i];
			fields |= FIELD_TM_YDAY;
		}
		if (fields & FIELD_TM_YDAY) {
			int days = tm->tm_yday;
			if (!(fields & FIELD_TM_WDAY)) {
				tm->tm_wday = EPOCH_WDAY +
				    ((year - EPOCH_YEAR) % DAYSPERWEEK) *
				    (DAYSPERNYEAR % DAYSPERWEEK) +
				    leaps_thru_end_of(year - 1) -
				    leaps_thru_end_of(EPOCH_YEAR - 1) +
				    tm->tm_yday;
				tm->tm_wday %= DAYSPERWEEK;
				if (tm->tm_wday < 0)
					tm->tm_wday += DAYSPERWEEK;
			}
			if (!(fields & FIELD_TM_MON)) {
				tm->tm_mon = 0;
				while (tm->tm_mon < MONSPERYEAR && days >= mon_lens[tm->tm_mon])
					days -= mon_lens[tm->tm_mon++];
			}
			if (!(fields & FIELD_TM_MDAY))
				tm->tm_mday = days + 1;
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
	int result = 0;
	int64_t rulim = ulim;

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
