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
#include "../../log.h"
#include "../../mode.h"
#include "../../conn.h"
#include "../../pkt.h"
#include "../../ll.h"
#include "../../net_handlers.h"
#include "handlers.h"

xbee_err xbee_net_frontchannel_rx_func(struct xbee *xbee, void *arg, unsigned char identifier, struct xbee_tbuf *buf, struct xbee_frameInfo *frameInfo, struct xbee_conAddress *address, struct xbee_pkt **pkt) {
/* see the counterpart Tx function
		net_handlers.c - xbee_netServer_fc_tx_func() */
	struct xbee_pkt *iPkt;
	xbee_err ret;
	int pos, required;
	int dataLen;
	
	/* required = identifier + conIdentifier(2) + address flags + timestamp(8) + status + options + rssi + frameId */
	required = 16;

	if (!xbee || !buf || !address || !pkt) return XBEE_EMISSINGPARAM;
	if (buf->len < required) return XBEE_ELENGTH;
	
	/* buf->data[0] is identifier
	   buf->data[1] is (conIdentifier >> 8) & 0xFF
	   buf->data[2] is conIdentifier & 0xFF */

	pos = 3;
	
	/* the following data should match the format found in
	    net_callbacks.c - xbee_net_toClient() */

	address->addr16_enabled =     !!(buf->data[pos] & 0x01);
	address->addr64_enabled =     !!(buf->data[pos] & 0x02);
	address->endpoints_enabled =  !!(buf->data[pos] & 0x04);
	address->profile_enabled =    !!(buf->data[pos] & 0x08);
	address->cluster_enabled =    !!(buf->data[pos] & 0x10);
                                                           pos++;

	if (address->addr16_enabled)    required += 2;
	if (address->addr64_enabled)    required += 8;
	if (address->endpoints_enabled) required += 2;
	if (address->profile_enabled)   required += 2;
	if (address->cluster_enabled)   required += 2;
	/* and the AT command */        required += 2;
	
	if (buf->len < required) {
		return XBEE_ELENGTH;
	}
	dataLen = buf->len - required;
	
	if ((ret = xbee_pktAlloc(&iPkt, NULL, dataLen)) != XBEE_ENONE) return ret;
	
	iPkt->dataLen =               dataLen;
	iPkt->timestamp.tv_sec =      (buf->data[pos] << 24);      pos++;
	iPkt->timestamp.tv_sec |=     (buf->data[pos] << 16);      pos++;
	iPkt->timestamp.tv_sec |=     (buf->data[pos] <<  8);      pos++;
	iPkt->timestamp.tv_sec |=     (buf->data[pos]      );      pos++;
	iPkt->timestamp.tv_sec &=     0xFFFFFFFF;
	iPkt->timestamp.tv_nsec =     (buf->data[pos] << 24);      pos++;
	iPkt->timestamp.tv_nsec |=    (buf->data[pos] << 16);      pos++;
	iPkt->timestamp.tv_nsec |=    (buf->data[pos] <<  8);      pos++;
	iPkt->timestamp.tv_nsec |=    (buf->data[pos]      );      pos++;
	iPkt->timestamp.tv_nsec &=    0xFFFFFFFF;
	iPkt->status =                buf->data[pos];              pos++;
	iPkt->options =               buf->data[pos];              pos++;
	iPkt->rssi =                  buf->data[pos];              pos++;
	iPkt->frameId =               buf->data[pos];              pos++;
	/* -- */


	if (address->addr16_enabled) {
		address->addr16[0] = buf->data[pos];                   pos++;
		address->addr16[1] = buf->data[pos];                   pos++;
	}
	if (address->addr64_enabled) {
		address->addr64[0] = buf->data[pos];                   pos++;
		address->addr64[1] = buf->data[pos];                   pos++;
		address->addr64[2] = buf->data[pos];                   pos++;
		address->addr64[3] = buf->data[pos];                   pos++;
		address->addr64[4] = buf->data[pos];                   pos++;
		address->addr64[5] = buf->data[pos];                   pos++;
		address->addr64[6] = buf->data[pos];                   pos++;
		address->addr64[7] = buf->data[pos];                   pos++;
	}
	if (address->endpoints_enabled) {
		address->endpoint_local =  buf->data[pos];             pos++;
		address->endpoint_remote = buf->data[pos];             pos++;
	}
	if (address->profile_enabled) {
		address->profile_id  = ((buf->data[pos] << 8) & 0xFF00); pos++;
		address->profile_id |= ((buf->data[pos]) & 0xFF);        pos++;
	}
	if (address->cluster_enabled) {
		address->cluster_id  = ((buf->data[pos] << 8) & 0xFF00); pos++;
		address->cluster_id |= ((buf->data[pos]) & 0xFF);        pos++;
	}
	iPkt->atCommand[0] = buf->data[pos];                     pos++;
	iPkt->atCommand[1] = buf->data[pos];                     pos++;
	
	if (iPkt->dataLen > 0) {
		memcpy(iPkt->data, &buf->data[pos], iPkt->dataLen);    pos += iPkt->dataLen;
	}
	
	*pkt = iPkt;
	
	return XBEE_ENONE;
}

xbee_err xbee_net_frontchannel_tx_func(struct xbee *xbee, struct xbee_con *con, void *arg, unsigned char identifier, unsigned char frameId, struct xbee_conAddress *address, struct xbee_conSettings *settings, const unsigned char *buf, int len, struct xbee_sbuf **oBuf) {
/* see the counterpart Tx function
		net_handlers.c - xbee_netServer_fc_rx_func() */
	struct xbee_sbuf *iBuf;
	size_t bufLen;
	size_t memSize;
	int pos;
	
	if (!con || !address || !buf || !oBuf) return XBEE_EMISSINGPARAM;
	if (len > 0xFFFF) return XBEE_ELENGTH;
	
	/* identifier + frameId + conId (2 bytes) */
	memSize = 4 + len;
	bufLen = memSize;
	
	memSize += sizeof(*iBuf);
	
	if ((iBuf = malloc(memSize)) == NULL) return XBEE_ENOMEM;
	
	pos = 0;
	iBuf->len = bufLen;
	iBuf->data[pos] = identifier;                         pos++;
	iBuf->data[pos] = frameId;                            pos++;
	iBuf->data[pos] = (con->conIdentifier >> 8) & 0xFF;   pos++;
	iBuf->data[pos] = con->conIdentifier & 0xFF;          pos++;
	memcpy(&(iBuf->data[pos]), buf, len);                 pos += len;
	
	*oBuf = iBuf;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

/* these are allocated at runtime - this is just for reference...

struct xbee_modeDataHandlerRx xbee_net_frontchannel_rx = {
	.identifier = 0x00,
	.func = xbee_net_frontchannel_rx_func,
};

struct xbee_modeDataHandlerTx xbee_net_frontchannel_tx = {
	.identifier = 0x00,
	.func = xbee_net_frontchannel_tx_func,
};
*/

/* this one does not allow frame IDs */
struct xbee_modeConType xbee_net_frontchannel_template = {
	.name = NULL,
	.internal = 0,
	.allowFrameId = 0,
	.useTimeout = 1,
	.timeout = {
		.tv_sec = 5,
		.tv_nsec = 0,
	},
	.rxHandler = NULL,
	.txHandler = NULL,
};

/* this one allows frame IDs */
struct xbee_modeConType xbee_net_frontchannel_template_fid = {
	.name = NULL,
	.internal = 0,
	.allowFrameId = 1,
	.useTimeout = 1,
	.timeout = {
		.tv_sec = 5,
		.tv_nsec = 0,
	},
	.rxHandler = NULL,
	.txHandler = NULL,
};

/* ######################################################################### */

struct xbee_modeConType xbee_net_backchannel = {
	.name = "Backchannel",
	.internal = 1,
	.allowFrameId = 1, /* this needs redeclaring, because this is enabled for the client */
	.useTimeout = 1,
	.timeout = {
		.tv_sec = 5,
		.tv_nsec = 0,
	},
	.rxHandler = &xbee_netServer_backchannel_rx,
	.txHandler = &xbee_netServer_backchannel_tx,
};
