/*
	libxbee - a C/C++ library to aid the use of Digi's XBee wireless modules
	          running in API mode.

	Copyright (C) 2009 onwards  Attie Grande (attie@attie.co.uk)

	libxbee is free software: you can redistribute it and/or modify it
	under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	libxbee is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with libxbee. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "internal.h"
#include "log.h"
#include "xbee_int.h"

#ifdef XBEE_DISABLE_LOGGING

EXPORT xbee_err _xbee_logDev(const char * const file, const int line, const char * const function, struct xbee * const xbee, const int minLevel, const char * const format, ...) {
	return XBEE_ENOTIMPLEMENTED;
}
EXPORT xbee_err xbee_logTargetSet(struct xbee *xbee, FILE *f) {
	return XBEE_ENOTIMPLEMENTED;
}
EXPORT xbee_err xbee_logTargetGet(struct xbee *xbee, FILE **f) {
	return XBEE_ENOTIMPLEMENTED;
}
EXPORT xbee_err xbee_logLevelSet(struct xbee *xbee, int level) {
	return XBEE_ENOTIMPLEMENTED;
}
EXPORT xbee_err xbee_logLevelGet(struct xbee *xbee, int *level) {
	return XBEE_ENOTIMPLEMENTED;
}

/* ######################################################################### */
#else /* XBEE_DISABLE_LOGGING */
/* ######################################################################### */

xbee_err xbee_logAlloc(struct xbee_log **nLog, int defLevel, FILE *defFile) {
	size_t memSize;
	struct xbee_log *log;
	
	if (!nLog) return XBEE_EMISSINGPARAM;
	
	memSize = sizeof(*log);
	
	if (!(log = malloc(memSize))) return XBEE_ENOMEM;
	
	memset(log, 0, memSize);
	
	xsys_mutex_init(&log->mutex);
	log->logLevel = defLevel;
	log->f = defFile;
	
	*nLog = log;
	
	return XBEE_ENONE;
}

xbee_err xbee_logFree(struct xbee_log *log) {
	if (!log) return XBEE_EMISSINGPARAM;
	
	xsys_mutex_destroy(&log->mutex);
	free(log);
	
	return XBEE_ENONE;
}

/* ######################################################################### */

EXPORT xbee_err xbee_logTargetSet(struct xbee *xbee, FILE *f) {
	if (!xbee) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	if (!xbee->log) return XBEE_ENOTIMPLEMENTED;
	
	xbee_mutex_lock(&xbee->log->mutex);
	xbee->log->f = f;
	xbee_mutex_unlock(&xbee->log->mutex);
	xbee_log(xbee->log->logLevel, "Set log target to: %p (fd:%d)", f, xsys_fileno(f));
	
	return XBEE_ENONE;
}

EXPORT xbee_err xbee_logTargetGet(struct xbee *xbee, FILE **f) {
	if (!xbee) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	if (!xbee->log) return XBEE_ENOTIMPLEMENTED;
	
	*f = xbee->log->f;
	
	return XBEE_ENONE;
}

EXPORT xbee_err xbee_logLevelSet(struct xbee *xbee, int level) {
	if (!xbee) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	if (!xbee->log) return XBEE_ENOTIMPLEMENTED;
	
	xbee_mutex_lock(&xbee->log->mutex);
	xbee->log->logLevel = level;
	xbee_mutex_unlock(&xbee->log->mutex);
	xbee_log(xbee->log->logLevel, "Set log level to: %d", level);
	
	return XBEE_ENONE;
}

EXPORT xbee_err xbee_logLevelGet(struct xbee *xbee, int *level) {
	if (!xbee) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	if (!xbee->log) return XBEE_ENOTIMPLEMENTED;
	
	*level = xbee->log->logLevel;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

xbee_err _xbee_logWrite(struct xbee_log *log, const char *file, int line, const char *function, struct xbee *xbee, int minLevel, char *preStr, char *format, va_list ap) {
	char tBuf[XBEE_LOG_MAXLEN];
	int len;
	const char * const truncStr = XBEE_LOG_TRUNC_STR;
	static int truncLen = 0;
	
	if (!log || !file || !function || !xbee || !preStr || !format) return XBEE_EMISSINGPARAM;
	if (!log->f) return XBEE_EINVAL;
	
	len = vsnprintf(tBuf, XBEE_LOG_MAXLEN, format, ap);
	
	if (len >= XBEE_LOG_MAXLEN) {
		if (truncLen == 0) {
			truncLen = strlen(truncStr);
		}
		strcpy(&(tBuf[XBEE_LOG_MAXLEN - (truncLen + 1)]), truncStr);
	}
	
	xbee_mutex_lock(&log->mutex);
	
#ifndef XBEE_LOG_NO_COLOR
	if (!xbee) {
		fprintf(log->f, "%s%c[36m%3d%c[90m#[%c[32m%s:%d%c[90m]%c[33m %s()%c[90m:%c[0m %s\n",
			preStr, 27, minLevel, 27, 27, file, line, 27, 27, function, 27, 27,                   tBuf);
	} else if (xbee_validate(xbee) == XBEE_ENONE) {
		fprintf(log->f, "%s%c[36m%3d%c[90m#[%c[32m%s:%d%c[90m]%c[33m %s()%c[0m %c[35m%p%c[90m:%c[0m %s\n",
			preStr, 27, minLevel, 27, 27, file, line, 27, 27, function, 27, 27, xbee, 27, 27,     tBuf);
	} else {
		fprintf(log->f, "%s%c[36m%3d%c[90m#[%c[32m%s:%d%c[90m]%c[33m %s()%c[31m !%c[35m%p%c[31m!%c[90m:%c[0m %s\n",
			preStr, 27, minLevel, 27, 27, file, line, 27, 27, function, 27, 27, xbee, 27, 27, 27, tBuf);
	}
#else
	if (!xbee) {
		fprintf(log->f, "%s%3d#[%s:%d] %s(): %s\n",      preStr, minLevel, file, line, function,       tBuf);
	} else if (xbee_validate(xbee) == XBEE_ENONE) {
		fprintf(log->f, "%s%3d#[%s:%d] %s() %p: %s\n",   preStr, minLevel, file, line, function, xbee, tBuf);
	} else {
		fprintf(log->f, "%s%3d#[%s:%d] %s() !%p!: %s\n", preStr, minLevel, file, line, function, xbee, tBuf);
	}
#endif
	fflush(log->f);
	
	xbee_mutex_unlock(&log->mutex);
	
	return XBEE_ENONE;
}


EXPORT xbee_err _xbee_logDev(const char *file, int line, const char *function, struct xbee *xbee, int minLevel, char *format, ...) {
	va_list ap;
	xbee_err ret;

	if (!xbee) return XBEE_EMISSINGPARAM;
#ifndef XBEE_DISABLE_STRICT_OBJECTS
	if (xbee_validate(xbee) != XBEE_ENONE) return XBEE_EINVAL;
#endif /* XBEE_DISABLE_STRICT_OBJECTS */
	if (!xbee->log) return XBEE_ENOTIMPLEMENTED;
	if (xbee_logTest(xbee->log->logLevel, minLevel)) return XBEE_ENONE;
	
	va_start(ap, format);
	ret = _xbee_logWrite(xbee->log, file, line, function, xbee, minLevel, "DEV:", format, ap);
	va_end(ap);
	
	return ret;
}

xbee_err _xbee_log(const char *file, int line, const char *function, struct xbee *xbee, int minLevel, char *format, ...) {
	va_list ap;
	xbee_err ret;
	
	if (!xbee) return XBEE_EMISSINGPARAM;
	if (!xbee->log) return XBEE_ENOTIMPLEMENTED;
	if (xbee_logTest(xbee->log->logLevel, minLevel)) return XBEE_ENONE;
	
	va_start(ap, format);
	ret = _xbee_logWrite(xbee->log, file, line, function, xbee, minLevel, "", format, ap);
	va_end(ap);
	
	return ret;
}

xbee_err _xbee_logData(const char *file, int line, const char *function, struct xbee *xbee, int minLevel, char *label, unsigned char *data, size_t length) {
	int i;
	int l;
	/* format:
		0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00  | ........
	*/
	char lineBufA[41];
	char lineBufB[9];
	
	/* prepare the format string */
	for (l = 0; l < sizeof(lineBufA) - 1; l++) {
		switch (l % 5) {
			case 0: case 2: case 3:
				lineBufA[l] = '0'; break;
			case 1:
				lineBufA[l] = 'x'; break;
			case 4:
				lineBufA[l] = ' '; break;
		}
	}
	lineBufA[l] = '\0';
	lineBufB[sizeof(lineBufB) - 1] = '\0';
	
	xbee_log(25, "%s length: %d", label, length);
	
	for (i = 0; i < length; i += l) {
		/* fill in the data */
		for (l = 0; l < 8 && i + l < length; l++) {
			snprintf(&(lineBufA[(5 * l) + 2]), 3, "%02X", data[i + l]);
			lineBufA[(5 * l) + 4] = ' ';
			lineBufB[l] = ((data[i + l] >= ' ' && data[i + l] <= '~')?data[i + l]:'.');
		}
		/* wipe out the unneeded space */
		for (; l < 8; l++) {
			strncpy(&(lineBufA[5 * l]), "     ", 6);
			lineBufB[l] = ' ';
		}
		xbee_log(25, "%s: 0x%04X : %s | %s", label, i, lineBufA, lineBufB);
	}
	
	return XBEE_ENONE;
}

#endif /* XBEE_DISABLE_LOGGING */
