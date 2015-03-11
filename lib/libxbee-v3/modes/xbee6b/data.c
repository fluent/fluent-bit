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
#include "data.h"

xbee_err xbee_s6b_data_rx_func(struct xbee *xbee, void *arg, unsigned char identifier, struct xbee_tbuf *buf, struct xbee_frameInfo *frameInfo, struct xbee_conAddress *address, struct xbee_pkt **pkt) {
	struct xbee_pkt *iPkt;
	xbee_err ret;

	if (!xbee || !frameInfo || !buf || !address || !pkt) return XBEE_EMISSINGPARAM;
	
	if (buf->len < 11) return XBEE_ELENGTH;

	/* only accept UDP packets for now */
	if (buf->data[9] != 0) {
  	/* this isn't an error, we just don't handle TCP frames yet... */
  	xbee_log(10, "Skipping incoming TCP frame...");
  	return XBEE_ENONE;
	}
	
	if ((ret = xbee_pktAlloc(&iPkt, NULL, buf->len - 11)) != XBEE_ENONE) return ret;
	
	address->addr64_enabled = 1;
	address->addr64[0] = buf->data[1];
	address->addr64[1] = buf->data[2];
	address->addr64[2] = buf->data[3];
	address->addr64[3] = buf->data[4];
	address->addr64[4] = 0;
	address->addr64[5] = 0;
	address->addr64[6] = 0;
	address->addr64[7] = 0;
	/* the source / destination crossover is done here so that UART XBee moduless can be used too */
	/* profile is used for source port */
	address->profile_enabled = 1;
	address->profile_id = ((buf->data[5] << 8) & 0xFF00) | (buf->data[6] & 0xFF);
	/* cluster is used for destination port */
	address->cluster_enabled = 1;
	address->cluster_id = ((buf->data[7] << 8) & 0xFF00) | (buf->data[8] & 0xFF);
	
	iPkt->dataLen = buf->len - 11;
	if (iPkt->dataLen > 0) {
		memcpy(iPkt->data, &(buf->data[11]), iPkt->dataLen);
	}
	iPkt->data[iPkt->dataLen] = '\0';
	
	*pkt = iPkt;
	
	return XBEE_ENONE;
}

xbee_err xbee_s6b_data_tx_func(struct xbee *xbee, struct xbee_con *con, void *arg, unsigned char identifier, unsigned char frameId, struct xbee_conAddress *address, struct xbee_conSettings *settings, const unsigned char *buf, int len, struct xbee_sbuf **oBuf) {
	struct xbee_sbuf *iBuf;
	size_t bufLen;
	int pos;
	size_t memSize;
	
	if (!xbee || !address || !buf || !oBuf) return XBEE_EMISSINGPARAM;
	if (len > 1400) return XBEE_ELENGTH;

	if (!address->addr64_enabled) return XBEE_EINVAL;
	
	/* API Identifier + Frame ID + Address + Options + Payload */
	memSize = 12 + len;
	bufLen = memSize;
	
	memSize += sizeof(*iBuf);
	
	if ((iBuf = malloc(memSize)) == NULL) return XBEE_ENOMEM;
	
	pos = 0;
	iBuf->len = bufLen;
	iBuf->data[pos] = identifier;                         pos++;
	iBuf->data[pos] = frameId;                            pos++;
	if (settings->broadcast) {
  	/* broadcast IP address this is the only time that libxbee uses UDP at the moment */
  	iBuf->data[pos] = 0xFF;                             pos++;
  	iBuf->data[pos] = 0xFF;                             pos++;
  	iBuf->data[pos] = 0xFF;                             pos++;
  	iBuf->data[pos] = 0xFF;                             pos++;
	} else {
  	iBuf->data[pos] = address->addr64[0];               pos++;
  	iBuf->data[pos] = address->addr64[1];               pos++;
  	iBuf->data[pos] = address->addr64[2];               pos++;
  	iBuf->data[pos] = address->addr64[3];               pos++;
	}
	/* the CLUSTER id is used for the DESTINATION TCP/UDP port number */
	if (address->cluster_enabled) {
  	iBuf->data[pos] = (address->cluster_id >> 8) & 0xFF;  pos++;
  	iBuf->data[pos] =  address->cluster_id       & 0xFF;  pos++;
	} else {
  	iBuf->data[pos] = 0x26; /* dest port 0x2616... */   pos++;
  	iBuf->data[pos] = 0x16; /* ... (default) */         pos++;
	}
	/* the PROFILE id is used for the SOURCE TCP/UDP port number */
	if (address->profile_enabled) {
  	iBuf->data[pos] = (address->profile_id >> 8) & 0xFF;  pos++;
  	iBuf->data[pos] =  address->profile_id       & 0xFF;  pos++;
	} else {
  	iBuf->data[pos] = 0x26; /* src port 0x2616... */    pos++;
  	iBuf->data[pos] = 0x16; /* ... (default) */         pos++;
	}
	iBuf->data[pos] = 0;                                  pos++; /* always use UDP for now */
	iBuf->data[pos] = 0;                                  pos++;

	memcpy(&(iBuf->data[pos]), buf, len);                 pos += len;
	iBuf->data[pos] = '\0';
	
	*oBuf = iBuf;
	
	return XBEE_ENONE;
}

/* matchRating values:
		128 - IPs match
		192 - IPs and the source ports match (source = MY port)
		256 - IPs match and BOTH ports match */
xbee_err xbee_s6b_data_addressCmp(struct xbee_conAddress *addr1, struct xbee_conAddress *addr2, unsigned char *matchRating) {
	unsigned char x;
	/* make it point _somewhere_ to make this code a little cleaner */
	if (matchRating == NULL) matchRating = &x;
	*matchRating = 0;

	if (!addr1->addr64_enabled || !addr2->addr64_enabled) return XBEE_EFAILED;

	/* check the IP addresses - this is the minimum requirement for a compare match */
	if (memcmp(addr1->addr64, addr2->addr64, 8)) return XBEE_EFAILED;
	*matchRating = 128;

	/* check the source ports (that is the port at MY end) */
	if (!addr1->profile_enabled || !addr2->profile_enabled ||
			addr1->profile_id != addr2->profile_id) {
		return XBEE_ENONE;
	}
	*matchRating = 192;

	/* check the destination ports (that is the port at the OTHER end */
	if (!addr1->cluster_enabled || !addr2->cluster_enabled ||
	    addr1->cluster_id != addr2->cluster_id) {
		return XBEE_ENONE;
	}
	*matchRating = 255;

	return XBEE_ENONE;
}

/* ######################################################################### */

struct xbee_modeDataHandlerRx xbee_s6b_data_rx  = {
	.identifier = 0xB0,
	.func = xbee_s6b_data_rx_func,
};
struct xbee_modeDataHandlerTx xbee_s6b_data_tx  = {
	.identifier = 0x20,
	.func = xbee_s6b_data_tx_func,
};
struct xbee_modeConType xbee_s6b_data = {
	.name = "Data",
	.allowFrameId = 1,
	.useTimeout = 0,
	.addressRules = ADDR_64_ONLY,
	.rxHandler = &xbee_s6b_data_rx,
	.txHandler = &xbee_s6b_data_tx,
	.addressCmp = xbee_s6b_data_addressCmp,
};
