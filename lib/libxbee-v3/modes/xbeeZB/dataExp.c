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
#include "../../conn.h"
#include "../common.h"
#include "dataExp.h"

xbee_err xbee_sZB_dataExp_rx_func(struct xbee *xbee, void *arg, unsigned char identifier, struct xbee_tbuf *buf, struct xbee_frameInfo *frameInfo, struct xbee_conAddress *address, struct xbee_pkt **pkt) {
	struct xbee_pkt *iPkt;
	xbee_err ret;

	if (!xbee || !frameInfo || !buf || !address || !pkt) return XBEE_EMISSINGPARAM;
	
	if (buf->len < 18) return XBEE_ELENGTH;
	
	if ((ret = xbee_pktAlloc(&iPkt, NULL, buf->len - 18)) != XBEE_ENONE) return ret;
	
	address->addr64_enabled = 1;
	memcpy(address->addr64, &(buf->data[1]), 8);
	address->addr16_enabled = 1;
	memcpy(address->addr16, &(buf->data[9]), 2);
	address->endpoints_enabled = 1;
	address->endpoint_remote = buf->data[11];
	address->endpoint_local = buf->data[12];
	address->cluster_enabled = 1;
	address->cluster_id = ((buf->data[13] << 8) & 0xFF00) | (buf->data[14] & 0xFF);
	address->profile_enabled = 1;
	address->profile_id = ((buf->data[15] << 8) & 0xFF00) | (buf->data[16] & 0xFF);
	
	iPkt->options = buf->data[17];
	if (iPkt->options & 0x02) address->broadcast = 1;
	
	iPkt->dataLen = buf->len - 18;
	if (iPkt->dataLen > 0) {
		memcpy(iPkt->data, &(buf->data[18]), iPkt->dataLen);
	}
	iPkt->data[iPkt->dataLen] = '\0';
	
	*pkt = iPkt;
	
	return XBEE_ENONE;
}

xbee_err xbee_sZB_dataExp_tx_func(struct xbee *xbee, struct xbee_con *con, void *arg, unsigned char identifier, unsigned char frameId, struct xbee_conAddress *address, struct xbee_conSettings *settings, const unsigned char *buf, int len, struct xbee_sbuf **oBuf) {
	struct xbee_sbuf *iBuf;
	size_t bufLen;
	int pos;
	size_t memSize;
	
	if (!xbee || !address || !buf || !oBuf) return XBEE_EMISSINGPARAM;
	if (len > 72) return XBEE_ELENGTH;
	
	if (!address->addr64_enabled) return XBEE_EINVAL;
	
	/* API Identifier + Frame ID + Address (64) + Address (16) + Radius + Options + Payload */
	memSize = 20 + len;
	bufLen = memSize;
	
	memSize += sizeof(*iBuf);
	
	if ((iBuf = malloc(memSize)) == NULL) return XBEE_ENOMEM;
	
	pos = 0;
	iBuf->len = bufLen;
	iBuf->data[pos] = identifier;                         pos++;
	iBuf->data[pos] = frameId;                            pos++;
	if (address->broadcast) {
		/* 64-bit broadcast address */
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0x00;                             pos++;
		iBuf->data[pos] = 0xFF;                             pos++;
		iBuf->data[pos] = 0xFF;                             pos++;
		/* 16-bit broadcast address */
		iBuf->data[pos] = 0xFF;                             pos++;
		iBuf->data[pos] = 0xFE;                             pos++;
	} else {
		memcpy(&(iBuf->data[pos]), address->addr64, 8);     pos += 8;
		if (address->addr16_enabled) {
			memcpy(&(iBuf->data[pos]), address->addr16, 2);
		} else {
			iBuf->data[pos] = 0xFF;
			iBuf->data[pos+1] = 0xFE;
		}
		                                                    pos += 2;
	}
	if (address->endpoints_enabled) {
		iBuf->data[pos] = address->endpoint_local;          pos++;
		iBuf->data[pos] = address->endpoint_remote;         pos++;
	} else {
		iBuf->data[pos] = 0xE8; /* default to data... */    pos++;
		iBuf->data[pos] = 0xE8; /* ... endpoint */          pos++;
	}
	if (address->cluster_enabled) {
		iBuf->data[pos] = (address->cluster_id >> 8) & 0xFF;  pos++;
		iBuf->data[pos] =  address->cluster_id       & 0xFF;  pos++;
	} else {
		iBuf->data[pos] = 0x00; /* clusterID 0x0011... */   pos++;
		iBuf->data[pos] = 0x11; /* ... (default) */         pos++;
	}
	if (address->profile_enabled) {
		iBuf->data[pos] = (address->profile_id >> 8) & 0xFF;  pos++;
		iBuf->data[pos] =  address->profile_id       & 0xFF;  pos++;
	} else {
		iBuf->data[pos] = 0xC1; /* profileID 0xC105... */   pos++;
		iBuf->data[pos] = 0x05; /* ... (default) */         pos++;
	}
	iBuf->data[pos] = settings->broadcastRadius;          pos++;
	iBuf->data[pos] = 0;
	if (settings->disableRetries)   iBuf->data[pos] |= 0x01;
	if (settings->enableEncryption) iBuf->data[pos] |= 0x20;
	if (settings->extendTimeout)    iBuf->data[pos] |= 0x40;
	                                                      pos++;

	memcpy(&(iBuf->data[pos]), buf, len);                 pos += len;
	iBuf->data[pos] = '\0';
	
	*oBuf = iBuf;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

struct xbee_modeDataHandlerRx xbee_sZB_dataExp_rx  = {
	.identifier = 0x91,
	.func = xbee_sZB_dataExp_rx_func,
};
struct xbee_modeDataHandlerTx xbee_sZB_dataExp_tx  = {
	.identifier = 0x11,
	.func = xbee_sZB_dataExp_tx_func,
};
struct xbee_modeConType xbee_sZB_dataExp = {
	.name = "Data (explicit)",
	.allowFrameId = 1,
	.useTimeout = 0,
	.addressRules = ADDR_64_16OPT_EPOPT,
	.addressPrep = xbee_conAddressPrepDefault,
	.save_addr16 = 1,
	.rxHandler = &xbee_sZB_dataExp_rx,
	.txHandler = &xbee_sZB_dataExp_tx,
};
