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
#include "data.h"

xbee_err xbee_s3_data_rx_func(struct xbee *xbee, void *arg, unsigned char identifier, struct xbee_tbuf *buf, struct xbee_frameInfo *frameInfo, struct xbee_conAddress *address, struct xbee_pkt **pkt) {
	struct xbee_pkt *iPkt;
	xbee_err ret;

	if (!xbee || !frameInfo || !buf || !address || !pkt) return XBEE_EMISSINGPARAM;
	
	if (buf->len < 12) return XBEE_ELENGTH;
	
	if ((ret = xbee_pktAlloc(&iPkt, NULL, buf->len - 12)) != XBEE_ENONE) return ret;
	
	address->addr64_enabled = 1;
	memcpy(address->addr64, &(buf->data[1]), 8);
	
	iPkt->options = buf->data[11];
	
	iPkt->dataLen = buf->len - 12;
	if (iPkt->dataLen > 0) {
		memcpy(iPkt->data, &(buf->data[12]), iPkt->dataLen);
	}
	iPkt->data[iPkt->dataLen] = '\0';
	
	*pkt = iPkt;
	
	return XBEE_ENONE;
}

xbee_err xbee_s3_data_tx_func(struct xbee *xbee, struct xbee_con *con, void *arg, unsigned char identifier, unsigned char frameId, struct xbee_conAddress *address, struct xbee_conSettings *settings, const unsigned char *buf, int len, struct xbee_sbuf **oBuf) {
	struct xbee_sbuf *iBuf;
	size_t bufLen;
	int pos;
	size_t memSize;
	
	if (!xbee || !address || !buf || !oBuf) return XBEE_EMISSINGPARAM;
	if (len > 72) return XBEE_ELENGTH;
	
	if (!address->addr64_enabled) return XBEE_EINVAL;
	
	/* API Identifier + Frame ID + Address (64) + Address (16) + Radius + Options + Payload */
	memSize = 14 + len;
	bufLen = memSize;
	
	memSize += sizeof(*iBuf);
	
	if ((iBuf = malloc(memSize)) == NULL) return XBEE_ENOMEM;
	
	pos = 0;
	iBuf->len = bufLen;
	iBuf->data[pos] = identifier;                         pos++;
	iBuf->data[pos] = frameId;                            pos++;
	if (settings->broadcast) {
		/* 64-bit broadcast address */
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0xFF;                             pos++;
		iBuf->data[pos] = 0xFF;                             pos++;
	} else {
		memcpy(&(iBuf->data[pos]), address->addr64, 8);     pos += 8;
	}
	/* what was the 16-bit address */
	iBuf->data[pos] = 0xFF;                               pos++;
	iBuf->data[pos] = 0xFE;                               pos++;
	iBuf->data[pos] = settings->broadcastRadius;          pos++;
	iBuf->data[pos] = 0;
	if (settings->disableAck)       iBuf->data[pos] |= 0x01;
	if (settings->noRoute)          iBuf->data[pos] |= 0x02;
#warning TODO - currently missing support for NAK and Trace Route messages
	                                                      pos++;

	memcpy(&(iBuf->data[pos]), buf, len);                 pos += len;
	iBuf->data[pos] = '\0';
	
	*oBuf = iBuf;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

struct xbee_modeDataHandlerRx xbee_s3_data_rx  = {
	.identifier = 0x90,
	.func = xbee_s3_data_rx_func,
};
struct xbee_modeDataHandlerTx xbee_s3_data_tx  = {
	.identifier = 0x10,
	.func = xbee_s3_data_tx_func,
};
struct xbee_modeConType xbee_s3_data = {
	.name = "Data",
	.allowFrameId = 1,
	.useTimeout = 0,
	.addressRules = ADDR_64_ONLY,
	.rxHandler = &xbee_s3_data_rx,
	.txHandler = &xbee_s3_data_tx,
};
