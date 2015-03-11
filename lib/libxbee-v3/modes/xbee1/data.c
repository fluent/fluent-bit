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
#include "../../conn.h"
#include "../common.h"
#include "data.h"

xbee_err xbee_s1_data_rx_func(struct xbee *xbee, void *arg, unsigned char identifier, struct xbee_tbuf *buf, struct xbee_frameInfo *frameInfo, struct xbee_conAddress *address, struct xbee_pkt **pkt) {
	struct xbee_pkt *iPkt;
	xbee_err ret;
	int addrLen;

	if (!xbee || !frameInfo || !buf || !address || !pkt) return XBEE_EMISSINGPARAM;
	
	if (buf->len < 1) return XBEE_ELENGTH;
	
	switch (buf->data[0]) {
		case 0x80: addrLen = 8; break;
		case 0x81: addrLen = 2; break;
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
	if (iPkt->options & 0x02) address->broadcast = 1;
	
	iPkt->dataLen = buf->len - (addrLen + 3);
	if (iPkt->dataLen > 0) {
		memcpy(iPkt->data, &(buf->data[addrLen + 3]), iPkt->dataLen);
	}
	iPkt->data[iPkt->dataLen] = '\0';
	
	*pkt = iPkt;
	
	return XBEE_ENONE;
}

xbee_err xbee_s1_data_tx_func(struct xbee *xbee, struct xbee_con *con, void *arg, unsigned char identifier, unsigned char frameId, struct xbee_conAddress *address, struct xbee_conSettings *settings, const unsigned char *buf, int len, struct xbee_sbuf **oBuf) {
	struct xbee_sbuf *iBuf;
	size_t bufLen;
	unsigned char *addr;
	int addrLen;
	int pos;
	size_t memSize;
	
	if (!xbee || !address || !buf || !oBuf) return XBEE_EMISSINGPARAM;
	if (len > 100) return XBEE_ELENGTH;
	
	switch (identifier) {
		case 0x00:
			if (!address->addr64_enabled) return XBEE_EINVAL;
			addr = &(address->addr64[0]);
			addrLen = 8;
			break;
		case 0x01:
			if (!address->addr16_enabled) return XBEE_EINVAL;
			addr = &(address->addr16[0]);
			addrLen = 2;
			break;
		default: return XBEE_EINVAL;
	}
	
	/* API Identifier + Frame ID + Address + Options + Payload */
	memSize = 3 + addrLen + len;
	bufLen = memSize;
	
	memSize += sizeof(*iBuf);
	
	if ((iBuf = malloc(memSize)) == NULL) return XBEE_ENOMEM;
	
	pos = 0;
	iBuf->len = bufLen;
	iBuf->data[pos] = identifier;                         pos++;
	iBuf->data[pos] = frameId;                            pos++;
	memcpy(&(iBuf->data[pos]), addr, addrLen);            pos += addrLen;
	
	iBuf->data[pos] = 0;
	if (settings->disableAck)   iBuf->data[pos] |= 0x01;
	if (settings->broadcast)    iBuf->data[pos] |= 0x04;
	                                                      pos++;

	memcpy(&(iBuf->data[pos]), buf, len);                 pos += len;
	iBuf->data[pos] = '\0';
	
	*oBuf = iBuf;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

struct xbee_modeDataHandlerRx xbee_s1_16bitData_rx  = {
	.identifier = 0x81,
	.func = xbee_s1_data_rx_func,
};
struct xbee_modeDataHandlerTx xbee_s1_16bitData_tx  = {
	.identifier = 0x01,
	.func = xbee_s1_data_tx_func,
};
struct xbee_modeConType xbee_s1_16bitData = {
	.name = "16-bit Data",
	.allowFrameId = 1,
	.useTimeout = 0,
	.addressRules = ADDR_16_ONLY,
	.addressPrep = xbee_conAddressPrepDefault,
	.rxHandler = &xbee_s1_16bitData_rx,
	.txHandler = &xbee_s1_16bitData_tx,
};

/* ######################################################################### */

struct xbee_modeDataHandlerRx xbee_s1_64bitData_rx  = {
	.identifier = 0x80,
	.func = xbee_s1_data_rx_func,
};
struct xbee_modeDataHandlerTx xbee_s1_64bitData_tx  = {
	.identifier = 0x00,
	.func = xbee_s1_data_tx_func,
};
struct xbee_modeConType xbee_s1_64bitData = {
	.name = "64-bit Data",
	.allowFrameId = 1,
	.useTimeout = 0,
	.addressRules = ADDR_64_ONLY,
	.addressPrep = xbee_conAddressPrepDefault,
	.rxHandler = &xbee_s1_64bitData_rx,
	.txHandler = &xbee_s1_64bitData_tx,
};
