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

#include "internal.h"
#include "xbee_int.h"
#include "net.h"
#include "log.h"
#include "net_handlers.h"
#include "pkt.h"
#include "mode.h"
#include "frame.h"

#ifndef XBEE_NO_NET_SERVER

xbee_err xbee_netServer_fc_rx_func(struct xbee *xbee, void *arg, unsigned char identifier, struct xbee_tbuf *buf, struct xbee_frameInfo *frameInfo, struct xbee_conAddress *address, struct xbee_pkt **pkt) {
/* see the counterpart Tx function
		modes/net/handlers.c - xbee_net_frontchannel_tx_func() */
	struct xbee_pkt *iPkt;
	xbee_err ret;
	int pos;
	
	if (!xbee || !frameInfo || !buf || !address || !pkt) return XBEE_EMISSINGPARAM;
	
	/* identifier + frameId + address (2 bytes) */
	pos = 4;
	if ((ret = xbee_pktAlloc(&iPkt, NULL, buf->len - pos)) != XBEE_ENONE) return ret;
	
	iPkt->frameId = buf->data[1];
	address->addr16_enabled = 1;
	address->addr16[0] = buf->data[2]; /* (conIdentifier >> 8) & 0xFF */
	address->addr16[1] = buf->data[3]; /* conIdentifier & 0xFF */
	
	iPkt->dataLen = buf->len - pos;
	if (iPkt->dataLen > 0) {
		memcpy(iPkt->data, &(buf->data[pos]), iPkt->dataLen);
	}
	iPkt->data[iPkt->dataLen] = '\0';
	
	*pkt = iPkt;
	
	return XBEE_ENONE;
}

xbee_err xbee_netServer_fc_tx_func(struct xbee *xbee, struct xbee_con *con, void *arg, unsigned char identifier, unsigned char frameId, struct xbee_conAddress *address, struct xbee_conSettings *settings, const unsigned char *buf, int len, struct xbee_sbuf **oBuf) {
/* see the counterpart Tx function
		modes/net/handlers.c - xbee_net_frontchannel_rx_func() */
	struct xbee_sbuf *iBuf;
	size_t bufLen;
	size_t memSize;
	int pos;
	
	if (!xbee || !address || !buf || !oBuf) return XBEE_EMISSINGPARAM;
	if (len > 0xFFFF) return XBEE_ELENGTH;
	
	if (!address->addr16_enabled) return XBEE_EINVAL;
	
	/* identifier + address (2 bytes) */
	pos = 3;
	memSize = pos + len;
	bufLen = memSize;
	
	memSize += sizeof(*iBuf);
	
	if ((iBuf = malloc(memSize)) == NULL) return XBEE_ENOMEM;
	
	iBuf->len = bufLen;
	iBuf->data[0] = identifier;
	iBuf->data[1] = address->addr16[0];
	iBuf->data[2] = address->addr16[1];
	memcpy(&(iBuf->data[pos]), buf, len);
	
	*oBuf = iBuf;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

#endif /* XBEE_NO_NET_SERVER - the following code is used by the client too */

xbee_err xbee_netServer_bc_rx_func(struct xbee *xbee, void *arg, unsigned char identifier, struct xbee_tbuf *buf, struct xbee_frameInfo *frameInfo, struct xbee_conAddress *address, struct xbee_pkt **pkt) {
	struct xbee_pkt *iPkt;
	xbee_err ret;
	int pos;
	
	if (!xbee || !frameInfo || !buf || !address || !pkt) return XBEE_EMISSINGPARAM;
	
	if (!arg) {
		if (buf->len < 4) return XBEE_ELENGTH;
		/* only in the client, notify about frameID */
		frameInfo->active = 1;
		frameInfo->id = buf->data[2];
		frameInfo->retVal = buf->data[3];
		pos = 4;
	} else {
		if (buf->len < 3) return XBEE_ELENGTH;
		pos = 3;
	}
	
	if (buf->len == pos && buf->data[1] == 0) {
		/* the 'start' endpoint may not recieve zero data. this is also handy cos its used for the status updates */
		return XBEE_ENONE;
	}
	
	address->endpoints_enabled = 1;
	address->endpoint_local = buf->data[1];
	address->endpoint_remote = buf->data[1];
	
	if ((ret = xbee_pktAlloc(&iPkt, NULL, buf->len - pos)) != XBEE_ENONE) return ret;
	
	iPkt->frameId = buf->data[2];
	
	iPkt->dataLen = buf->len - pos;
	if (iPkt->dataLen > 0) {
		memcpy(iPkt->data, &(buf->data[pos]), iPkt->dataLen);
	}
	iPkt->data[iPkt->dataLen] = '\0';
	
	*pkt = iPkt;
	
	return XBEE_ENONE;
}

xbee_err xbee_netServer_bc_tx_func(struct xbee *xbee, struct xbee_con *con, void *arg, unsigned char identifier, unsigned char frameId, struct xbee_conAddress *address, struct xbee_conSettings *settings, const unsigned char *buf, int len, struct xbee_sbuf **oBuf) {
	struct xbee_sbuf *iBuf;
	size_t bufLen;
	size_t memSize;
	int pos;
	
	if (!xbee || !address || !buf || !oBuf) return XBEE_EMISSINGPARAM;
	if (len > 0xFFFF) return XBEE_ELENGTH;
	
	if (!address->endpoints_enabled) return XBEE_EINVAL;
	
	if (arg) {
		/* the server returns the frameId in the buffer */
		pos = 2;
	} else {
		/* the client sends the frameId from the fBlock */
		pos = 3;
	}
	memSize = pos + len;
	bufLen = memSize;
	
	memSize += sizeof(*iBuf);
	
	if ((iBuf = malloc(memSize)) == NULL) return XBEE_ENOMEM;
	
	iBuf->len = bufLen;
	iBuf->data[0] = identifier;
	iBuf->data[1] = address->endpoint_local;
	if (!arg) {
		iBuf->data[2] = frameId;
	}
	memcpy(&(iBuf->data[pos]), buf, len);

	*oBuf = iBuf;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

/* backchannel (0x00), endpoint 0 (0x00) is ALWAYS the 'start' function
   THIS IS USED BY THE CLIENT CODE TOO */
struct xbee_modeDataHandlerRx xbee_netServer_backchannel_rx = {
	.identifier = 0x00,
	.func = xbee_netServer_bc_rx_func,
};
struct xbee_modeDataHandlerTx xbee_netServer_backchannel_tx = {
	.identifier = 0x00,
	.func = xbee_netServer_bc_tx_func,
};

#ifndef XBEE_NO_NET_SERVER

/* the client has its own version of this */
struct xbee_modeConType xbee_netServer_backchannel = {
	.name = "Backchannel",
	.internal = 1,
	.allowFrameId = 0,
	.useTimeout = 0,
	.rxHandler = &xbee_netServer_backchannel_rx,
	.txHandler = &xbee_netServer_backchannel_tx,
};

/* ######################################################################### */

static const struct xbee_modeConType *conTypes[] = {
	&xbee_netServer_backchannel,
	NULL,
};

const struct xbee_mode xbee_netServerMode = {
	.name = "libxbee Server",
	
	.conTypes = conTypes,
};

#endif /* XBEE_NO_NET_SERVER */
