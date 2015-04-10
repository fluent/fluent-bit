/*
	libxbee - a C library to aid the use of Digi's XBee wireless modules
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
#include <string.h>

#include "../../internal.h"
#include "../../xbee_int.h"
#include "../../mode.h"
#include "../../pkt.h"
#include "../common.h"
#include "identify.h"

xbee_err xbee_s3_identify_rx_func(struct xbee *xbee, void *arg, unsigned char identifier, struct xbee_tbuf *buf, struct xbee_frameInfo *frameInfo, struct xbee_conAddress *address, struct xbee_pkt **pkt) {
	struct xbee_pkt *iPkt;
	xbee_err ret;
	struct xbee_conAddress *addr;

	if (!xbee || !frameInfo || !buf || !address || !pkt) return XBEE_EMISSINGPARAM;
	
	if (buf->len < 30) return XBEE_ELENGTH;
	
	if ((ret = xbee_pktAlloc(&iPkt, NULL, buf->len - 12)) != XBEE_ENONE) return ret;
	
	iPkt->options = buf->data[11];
	
	iPkt->dataLen = buf->len - 12;
	if (iPkt->dataLen > 0) {
		const int NIstart = 10;
		int NIend;

		memcpy(iPkt->data, &(buf->data[12]), iPkt->dataLen);
		
		if (iPkt->dataLen < 10) goto done;
		xbee_pktDataAdd(iPkt, "Address (64-bit)", 0, &(iPkt->data[2]), NULL);
			
		if ((addr = malloc(sizeof(*addr))) != NULL) {
			memset(addr, 0, sizeof(*addr));
			addr->addr64_enabled = 1;
			memcpy(addr->addr64, &(iPkt->data[2]), 8);
			
			if (xbee_pktDataAdd(iPkt, "Address", 0, addr, free) != XBEE_ENONE) {
				free(addr);
			}
		}
		
		if (iPkt->dataLen < 11) goto done;
		/* just point into the packet data */
		xbee_pktDataAdd(iPkt, "NI", 0, &(iPkt->data[NIstart]), NULL);
		for (NIend = NIstart; iPkt->data[NIend] != '\0' && NIend < iPkt->dataLen; NIend++);
		NIend++; /* step over the nul */

		if (iPkt->dataLen < NIend + 3) goto done;
		xbee_pktDataAdd(iPkt, "Device Type", 0, &(iPkt->data[NIend + 3]), NULL);

		if (iPkt->dataLen < NIend + 4) goto done;
		xbee_pktDataAdd(iPkt, "Source Event", 0, &(iPkt->data[NIend + 4]), NULL);

		if (iPkt->dataLen < NIend + 6) goto done;
		xbee_pktDataAdd(iPkt, "Profile ID", 0, &(iPkt->data[NIend + 5]), NULL);

		if (iPkt->dataLen < NIend + 8) goto done;
		xbee_pktDataAdd(iPkt, "Manufacturer ID", 0, &(iPkt->data[NIend + 7]), NULL);

		if (iPkt->dataLen < NIend + 12) {
			if (iPkt->dataLen < NIend + 9) goto done;
			xbee_pktDataAdd(iPkt, "RSSI", 0, &(iPkt->data[NIend + 9]), NULL);
			goto done;
		}
		xbee_pktDataAdd(iPkt, "DD", 0, &(iPkt->data[NIend + 9]), NULL);

		if (iPkt->dataLen < NIend + 13) goto done;
		xbee_pktDataAdd(iPkt, "RSSI", 0, &(iPkt->data[NIend + 13]), NULL);
	}

done:
	iPkt->data[iPkt->dataLen] = '\0';
	
	*pkt = iPkt;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

struct xbee_modeDataHandlerRx xbee_s3_identify_rx  = {
	.identifier = 0x95,
	.func = xbee_s3_identify_rx_func,
};
struct xbee_modeConType xbee_s3_identify = {
	.name = "Identify",
	.allowFrameId = 0,
	.useTimeout = 0,
	.addressRules = ADDR_NONE,
	.rxHandler = &xbee_s3_identify_rx,
	.txHandler = NULL,
};
