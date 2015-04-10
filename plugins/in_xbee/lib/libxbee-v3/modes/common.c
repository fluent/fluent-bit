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
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../internal.h"
#include "../xbee_int.h"
#include "../ll.h"
#include "../log.h"
#include "common.h"

#if defined(XBEE_API2) && defined(XBEE_API2_DEBUG)
#define ESCAPER_PRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
#define ESCAPER_PRINTF(...)
#endif /* defined(XBEE_API2) && defined(XBEE_API2_DEBUG) */

#define XBEE_MAX_BUFFERLEN 256

/* ######################################################################### */

static xbee_err escaped_read(struct xbee_serialInfo *info, int len, unsigned char *dest, int escaped, int *dieFlag) {
	int pos;
	int rlen;
#ifdef XBEE_API2
	int nextIsEscaped;
#endif
	xbee_err err;
	
	if (!info || !dest) return XBEE_EMISSINGPARAM;
	if (len == 0) return XBEE_EINVAL;
	
	pos = 0;
#ifdef XBEE_API2
	nextIsEscaped = 0;
#endif
	
	ESCAPER_PRINTF("===== escaped_read(%d) =====\n", escaped);
	
	do {
		rlen = len - pos;
		if ((err = xsys_serialRead(info, rlen, &(dest[pos]))) != XBEE_ENONE) {
			if (err == XBEE_ETIMEOUT) {
				/* if we don't have a dieFlag, or it isn't set, then we don't care about the timeout... so loop! */
				if (!dieFlag || !*dieFlag) continue;
				/* otherwise, we were told to die... :( */
				return XBEE_ESHUTDOWN;
			}
			return err;
		}
		
#ifdef XBEE_API2
		/* ########################### */
		
		/* process the escape characters out */
		if (escaped) {
			int i,l,d;
			
			l = pos + rlen;
			d = 0;
			
			ESCAPER_PRINTF("-= escaper =-\n");
			
			for (i = pos; i < l - d; i++) {
				if (d > 0) {
					dest[i] = dest[i + d];
				}
				ESCAPER_PRINTF(" %2d / %2d: 0x%02X", i + 1, len, dest[i]);
				if (nextIsEscaped || dest[i] == 0x7D) {
					if (!nextIsEscaped && i == l - 1) {
						nextIsEscaped = 1;
						ESCAPER_PRINTF(" ---NE---> 0x%02X", dest[i], dest[i] ^ 0x20);
						d++;
					} else {
						if (!nextIsEscaped) {
							d++;
							dest[i] = dest[i + d];
						}
						nextIsEscaped = 0;
						ESCAPER_PRINTF(" -{0x%02X}-> 0x%02X", dest[i], dest[i] ^ 0x20);
						dest[i] ^= 0x20;
					}
					if (dest[i] != 0x7E &&
					    dest[i] != 0x7D &&
					    dest[i] != 0x11 &&
					    dest[i] != 0x13) {
						ESCAPER_PRINTF(" nonsense");
#ifdef XBEE_API2_SAFE_ESCAPE
						dest[i] ^= 0x20;
#endif
					}
				} else {
					if (dest[i] == 0x11 ||
					    dest[i] == 0x13) {
						ESCAPER_PRINTF(" --x-x-x-> 0x%02X", dest[i]);
						i--;
						d++;
					} else {
						ESCAPER_PRINTF(" --------> 0x%02X", dest[i]);
					}
				}
				if (isprint(dest[i])) ESCAPER_PRINTF(" '%c'", dest[i]);
				ESCAPER_PRINTF("\n");
			}
			
			ESCAPER_PRINTF("-= escaper =- - -= lost %d bytes =-\n", d);
			
			rlen -= d;
		}
#endif /* XBEE_API2 */
		
		pos += rlen;
	} while (pos < len);
	
	return XBEE_ENONE;
}

xbee_err xbee_xbeeRxIo(struct xbee *xbee, void *arg, struct xbee_tbuf **buf) {
	struct xbee_tbuf *iBuf;
	void *p;
	
	struct xbee_serialInfo *data;
	
	unsigned char c;
	unsigned char chksumo, chksum;
	int t;
	xbee_err ret;
	
	if (!xbee || !buf) return XBEE_EMISSINGPARAM;
	if (!xbee->mode || !xbee->modeData) return XBEE_EINVAL;
	
	data = xbee->modeData;
	
	if ((iBuf = malloc(sizeof(*iBuf) + XBEE_MAX_BUFFERLEN)) == NULL) return XBEE_ENOMEM;
	xbee_ll_add_tail(needsFree, iBuf);
	
	while (1) {
		/* get the start delimiter (0x7E) */
		do {
			if ((ret = escaped_read(data, 1, &c, 0, &xbee->die)) != XBEE_ENONE) return ret;
			if (c != 0x7E) {
				xbee_log(200, "fluff between packets: 0x%02X\n", c);
			}
		} while (c != 0x7E);
		
		if (clock_gettime(CLOCK_REALTIME, &iBuf->ts) != 0) {
			memset(&iBuf->ts, 0, sizeof(iBuf->ts));
		}
		ESCAPER_PRINTF("======= packet start @ %ld.%09d =======\n", iBuf->ts.tv_sec, iBuf->ts.tv_nsec);
		
		/* get the length (2 bytes) */
		if ((ret = escaped_read(data, 2, iBuf->data, 1, &xbee->die)) != XBEE_ENONE) return ret;
		t = ((iBuf->data[0] << 8) & 0xFF00) | (iBuf->data[1] & 0xFF);
		if (t > XBEE_MAX_BUFFERLEN) {
			xbee_log(1, "OVERSIZED PACKET... data loss has occured (packet length: %d)", t);
			continue;
		}
		iBuf->len = t;
		
		/* get the data! */
		if ((ret = escaped_read(data, iBuf->len, iBuf->data, 1, &xbee->die)) != XBEE_ENONE) return ret;
		
		/* get the checksum */
		if ((ret = escaped_read(data, 1, &chksumo, 1, &xbee->die)) != XBEE_ENONE) return ret;
		chksum = chksumo;
		
		/* check the checksum */
		for (t = 0; t < iBuf->len; t++) {
			chksum += iBuf->data[t];
		}
		if ((chksum & 0xFF) != 0xFF) {
			xbee_log(1, "INVALID CHECKSUM (given: 0x%02X, result: 0x%02X)... data loss has occured (packet length: %d)", chksumo, chksum, iBuf->len);
			for (t = 0; t < iBuf->len; t++) {
				xbee_log(10, "  %3d: 0x%02X  %c", t, iBuf->data[t], ((iBuf->data[t] >= ' ' && iBuf->data[t] <= '~') ? iBuf->data[t] : '.'));
			}
#if !defined(XBEE_API2) || !defined(XBEE_API2_IGNORE_CHKSUM)
			continue;
#endif
		}
		break;
	}
	
	/* resize the memory, and ignore failure */
	xbee_ll_lock(needsFree);
	if ((p = realloc(iBuf, sizeof(*iBuf) + iBuf->len)) != NULL) {
		_xbee_ll_ext_item(needsFree, iBuf, 0);
		_xbee_ll_add_tail(needsFree, p, 0);
		iBuf = p;
	}
	xbee_ll_unlock(needsFree);

	iBuf->data[iBuf->len] = '\0'; /* null terminate the data */
	
	*buf = iBuf;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

/* firstEscaped = -1 - NONE
                   0 - first byte
                   1 - second byte... */
static xbee_err escaped_write(struct xbee_serialInfo *info, int len, unsigned char *src, int firstEscaped) {
	int pos;
#ifdef XBEE_API2
	int esc;
#endif
	int wlen;
	xbee_err err;
	
	if (!info || !src) return XBEE_EMISSINGPARAM;
	if (len == 0) return XBEE_EINVAL;
	
	for (pos = 0; pos < len; pos += wlen) {
#ifdef XBEE_API2
		if (firstEscaped == -1) {
			wlen = len - pos;
		} else {
			/* handle bytes that need escaping */
			
			if (pos >= firstEscaped) {
				/* first munch all bytes that satisfy the criteria (need escaping, and are past the firstEscaped point) */
				while (src[pos] == 0x7E ||
				       src[pos] == 0x7D ||
				       src[pos] == 0x11 ||
				       src[pos] == 0x13) {
					unsigned char c[2];
					c[0] = 0x7D;
					c[1] = src[pos] ^ 0x20;
					if ((err = xsys_serialWrite(info, 2, c)) != XBEE_ENONE) return err;
					pos++;
				}
			}
			/* find the next byte that needs escaping */
			for (esc = pos; esc < len; esc++) {
				if (esc < firstEscaped) continue; /* skip the first x bytes */
				if (src[esc] == 0x7E ||
				    src[esc] == 0x7D ||
				    src[esc] == 0x11 ||
				    src[esc] == 0x13) break;
			}
			wlen = esc - pos;
		}
		if (!wlen) continue;
#else
		wlen = len - pos;
#endif /* XBEE_API2 */
		
		if ((err = xsys_serialWrite(info, wlen, &(src[pos]))) != XBEE_ENONE) return err;
	}
	
	return XBEE_ENONE;
}

xbee_err xbee_xbeeTxIo(struct xbee *xbee, void *arg, struct xbee_sbuf *buf) {
	struct xbee_serialInfo *data;
	size_t txSize;
	size_t memSize;
	struct xbee_sbuf *iBuf;
	unsigned char chksum;
	int pos;

	if (!xbee || !buf) return XBEE_EMISSINGPARAM;
	if (!xbee->mode || !xbee->modeData) return XBEE_EINVAL;
	
	data = xbee->modeData;
	
	/* Delimiter + Length + Payload + Checksum */
	txSize = 4 + buf->len;
	memSize = txSize + sizeof(*iBuf);
	
	if (!data->txBuf || data->txBufSize < memSize) {
		void *p;
		if ((p = realloc(data->txBuf, memSize)) == NULL) return XBEE_ENOMEM;
		data->txBuf = p;
		data->txBufSize = memSize;
	}
	iBuf = data->txBuf;
	
	iBuf->len = txSize;
	iBuf->data[0] = 0x7E;
	iBuf->data[1] = ((buf->len) >> 8) & 0xFF;
	iBuf->data[2] = ((buf->len)     ) & 0xFF;
	
	chksum = 0;
	for (pos = 0; pos < buf->len; pos++) {
		chksum += buf->data[pos];
		iBuf->data[3 + pos] = buf->data[pos];
	}
	iBuf->data[3 + pos] = 0xFF - chksum;
	
#ifdef DEBUG_TX_FULL
{
	int i;
	xbee_log(99, "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-");
	xbee_logData(99, "Raw Tx packet", iBuf->data, iBuf->len);
	xbee_log(99, "x=x=x=x=x=x=x=x=x=x=x=x=x=x=x");
}
#endif

	return escaped_write(data, iBuf->len, iBuf->data, 1);
}
