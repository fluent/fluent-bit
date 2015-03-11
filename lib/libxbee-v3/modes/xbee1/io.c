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
#include <string.h>

#include "../../internal.h"
#include "../../xbee_int.h"
#include "../../mode.h"
#include "../../pkt.h"
#include "../../log.h"
#include "../common.h"
#include "io.h"

xbee_err xbee_s1_io_parseInputs(struct xbee *xbee, struct xbee_pkt *pkt, unsigned char *data, int len) {
	int sampleCount;
	int sample, channel;
	int ioMask;

	if (len < 3) return XBEE_ELENGTH;

	sampleCount = data[0];
	data++; len--;

	ioMask = ((data[0] << 8) & 0xFF00) | (data[1] & 0xFF);
	data += 2; len-= 2;
	
	for (sample = 0; sample < sampleCount; sample++) {
		int mask;

		if (ioMask & 0x01FF) {
			int digitalValue;
			
			if (len < 2) return XBEE_ELENGTH;
			
			digitalValue = ((data[0] << 8) & 0x0100) | (data[1] & 0xFF);

			mask = 0x0001;
			for (channel = 0; channel <= 8; channel++, mask <<= 1) {
				if (ioMask & mask) {
					if (xbee_pktDigitalAdd(pkt, channel, digitalValue & mask)) {
						xbee_log(1,"Failed to add digital sample information to packet (channel D%d)", channel);
					}
				}
			}
			data += 2; len -= 2;
		}

		mask = 0x0200;
		for (channel = 0; channel <= 5; channel++, mask <<= 1) {
			if (ioMask & mask) {
				
				if (len < 2) return XBEE_ELENGTH;
				
				if (xbee_pktAnalogAdd(pkt, channel, ((data[0] << 8) & 0x3F00) | (data[1] & 0xFF))) {
					xbee_log(1,"Failed to add analog sample information to packet (channel A%d)", channel);
				}
				data += 2; len -= 2;
			}
		}
	}

	return XBEE_ENONE;
}

/* ######################################################################### */

xbee_err xbee_s1_io_rx_func(struct xbee *xbee, void *arg, unsigned char identifier, struct xbee_tbuf *buf, struct xbee_frameInfo *frameInfo, struct xbee_conAddress *address, struct xbee_pkt **pkt) {
	struct xbee_pkt *iPkt;
	xbee_err ret;
	int addrLen;
	
	if (!xbee || !frameInfo || !buf || !address || !pkt) return XBEE_EMISSINGPARAM;
	
	if (buf->len < 1) return XBEE_ELENGTH;
	
	switch (buf->data[0]) {
		case 0x82: addrLen = 8; break;
		case 0x83: addrLen = 2; break;
		default: return XBEE_EINVAL;
	}
	
	if (buf->len < addrLen + 3) return XBEE_ELENGTH;
	
	if ((ret = xbee_pktAlloc(&iPkt, NULL, buf->len - (addrLen + 3))) != XBEE_ENONE) return ret;
	
	if (addrLen == 8) {
		address->addr64_enabled = 1;
		memcpy(address->addr64, &(buf->data[1]), addrLen);
	} else {
		address->addr16_enabled = 1;
		memcpy(address->addr16, &(buf->data[1]), addrLen);
	}
	
	iPkt->rssi = buf->data[addrLen + 1];
	iPkt->options = buf->data[addrLen + 2];
	
	iPkt->dataLen = buf->len - (addrLen + 3);
	if (iPkt->dataLen > 0) {
		memcpy(iPkt->data, &(buf->data[addrLen + 3]), iPkt->dataLen);
	}
	iPkt->data[iPkt->dataLen] = '\0';
	
	*pkt = iPkt;
	
	return XBEE_ENONE;
}

xbee_err xbee_s1_io_rx_funcPost(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt *pkt) {
	xbee_s1_io_parseInputs(xbee, pkt, pkt->data, pkt->dataLen);
	
	return XBEE_ENONE;
}

/* ######################################################################### */

struct xbee_modeDataHandlerRx xbee_s1_16bitIo_rx  = {
	.identifier = 0x83,
	.func = xbee_s1_io_rx_func,
	.funcPost = xbee_s1_io_rx_funcPost,
};
struct xbee_modeConType xbee_s1_16bitIo = {
	.name = "16-bit I/O",
	.allowFrameId = 0,
	.useTimeout = 0,
	.addressRules = ADDR_16_ONLY,
	.rxHandler = &xbee_s1_16bitIo_rx,
	.txHandler = NULL,
};

/* ######################################################################### */

struct xbee_modeDataHandlerRx xbee_s1_64bitIo_rx  = {
	.identifier = 0x82,
	.func = xbee_s1_io_rx_func,
	.funcPost = xbee_s1_io_rx_funcPost,
};
struct xbee_modeConType xbee_s1_64bitIo = {
	.name = "64-bit I/O",
	.allowFrameId = 0,
	.useTimeout = 0,
	.addressRules = ADDR_64_ONLY,
	.rxHandler = &xbee_s1_64bitIo_rx,
	.txHandler = NULL,
};
