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

#ifndef XBEE_NO_NET_SERVER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "xbee_int.h"
#include "net.h"
#include "net_callbacks.h"
#include "ll.h"
#include "mode.h"
#include "conn.h"
#include "log.h"

/* ######################################################################### */

void xbee_net_fromClient(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	unsigned char retVal;
	struct xbee_con *rCon;
	
	rCon = *data;
	
	if (xbee_connTx(rCon, &retVal, (*pkt)->data, (*pkt)->dataLen) != XBEE_ENONE) {
		xbee_log(1, "network relay failure (client -> server) - client %p", con->netClient);
		retVal = 0x01;
		goto err;
	}
	
	if (!rCon->conType->allowFrameId || rCon->settings.disableAck) return;
	
	if (!con->netClient || !con->netClient->bc_status) return;
	
err:
	{
		unsigned char buf[2];
		buf[0] = (*pkt)->frameId;
		buf[1] = retVal;
		xbee_connTx(con->netClient->bc_status, NULL, buf, sizeof(buf));
	}
}

void xbee_net_toClient(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	unsigned char *buf;
	int pos;
	size_t memSize;
	
	/* this will need updating if struct xbee_pkt changes */
	/* 13 = address flags + timestamp(8) + status + options + rssi + frameId */
	memSize = 13 + (*pkt)->dataLen;
	if ((*pkt)->address.addr16_enabled)    memSize += 2;
	if ((*pkt)->address.addr64_enabled)    memSize += 8;
	if ((*pkt)->address.endpoints_enabled) memSize += 2;
	if ((*pkt)->address.profile_enabled)   memSize += 2;
	if ((*pkt)->address.cluster_enabled)   memSize += 2;
	/* and the AT command */               memSize += 2;
	
	if ((buf = malloc(memSize)) == NULL) {
		xbee_log(1, "MALLOC FAILED... dataloss has occured");
		return;
	}

	/* the following data should match the format found in
	    modes/net/handlers.c - xbee_net_frontchannel_rx_func() */
	
	pos = 0;
	buf[pos] = 0;
	if ((*pkt)->address.addr16_enabled)     buf[pos] |= 0x01;
	if ((*pkt)->address.addr64_enabled)     buf[pos] |= 0x02;
	if ((*pkt)->address.endpoints_enabled)  buf[pos] |= 0x04;
	if ((*pkt)->address.profile_enabled)    buf[pos] |= 0x08;
	if ((*pkt)->address.cluster_enabled)    buf[pos] |= 0x10;
	                                                     pos++;
	buf[pos] = ((*pkt)->timestamp.tv_sec  >> 24) & 0xFF; pos++;
	buf[pos] = ((*pkt)->timestamp.tv_sec  >> 16) & 0xFF; pos++;
	buf[pos] = ((*pkt)->timestamp.tv_sec  >>  8) & 0xFF; pos++;
	buf[pos] = ((*pkt)->timestamp.tv_sec       ) & 0xFF; pos++;
	buf[pos] = ((*pkt)->timestamp.tv_nsec >> 24) & 0xFF; pos++;
	buf[pos] = ((*pkt)->timestamp.tv_nsec >> 16) & 0xFF; pos++;
	buf[pos] = ((*pkt)->timestamp.tv_nsec >>  8) & 0xFF; pos++;
	buf[pos] = ((*pkt)->timestamp.tv_nsec      ) & 0xFF; pos++;
	buf[pos] = (*pkt)->status;                           pos++;
	buf[pos] = (*pkt)->options;                          pos++;
	buf[pos] = (*pkt)->rssi;                             pos++;
	buf[pos] = (*pkt)->frameId;                          pos++;
	/* -- */
	if ((*pkt)->address.addr16_enabled) {
		buf[pos] = (*pkt)->address.addr16[0];              pos++;
		buf[pos] = (*pkt)->address.addr16[1];              pos++;
	}
	if ((*pkt)->address.addr64_enabled) {
		buf[pos] = (*pkt)->address.addr64[0];              pos++;
		buf[pos] = (*pkt)->address.addr64[1];              pos++;
		buf[pos] = (*pkt)->address.addr64[2];              pos++;
		buf[pos] = (*pkt)->address.addr64[3];              pos++;
		buf[pos] = (*pkt)->address.addr64[4];              pos++;
		buf[pos] = (*pkt)->address.addr64[5];              pos++;
		buf[pos] = (*pkt)->address.addr64[6];              pos++;
		buf[pos] = (*pkt)->address.addr64[7];              pos++;
	}
	if ((*pkt)->address.endpoints_enabled) {
		buf[pos] = (*pkt)->address.endpoint_local;         pos++;
		buf[pos] = (*pkt)->address.endpoint_remote;        pos++;
	}
	if ((*pkt)->address.profile_enabled) {
		buf[pos] = ((*pkt)->address.profile_id >> 8) & 0xFF; pos++;
		buf[pos] = ((*pkt)->address.profile_id) & 0xFF;      pos++;
	}
	if ((*pkt)->address.cluster_enabled) {
		buf[pos] = ((*pkt)->address.cluster_id >> 8) & 0xFF; pos++;
		buf[pos] = ((*pkt)->address.cluster_id) & 0xFF;      pos++;
	}
	buf[pos] = (*pkt)->atCommand[0];                     pos++;
	buf[pos] = (*pkt)->atCommand[1];                     pos++;
	if ((*pkt)->dataLen > 0) {
		if (pos + (*pkt)->dataLen > memSize) {
			xbee_log(1, "Allocated buffer is too small... dataloss has occured");
			free(buf);
			return;
		}
		memcpy(&buf[pos], (*pkt)->data, (*pkt)->dataLen);  pos += (*pkt)->dataLen;
	}
	
	xbee_connTx((struct xbee_con *)(*data), NULL, buf, memSize);
	
	free(buf);
}

/* ######################################################################### */

void xbee_net_start(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	struct xbee_netClientInfo *client;
	int i, o;
	int callbackCount;
	struct xbee_buf *iBuf;
	size_t bufLen;
	size_t memSize;
	
	client = *data;

	if (strncasecmp((char *)(*pkt)->data, libxbee_commit, (*pkt)->dataLen)) {
#ifndef XBEE_NO_NET_STRICT_VERSIONS
		unsigned char buf[2];
		buf[0] = (*pkt)->frameId;
		buf[1] = 0x02;
		xbee_connTx(con, NULL, buf, sizeof(buf));
		client->die = 1;
		return;
#else
		xbee_log(-1, "*** client with mismatched version connected... this may cause instability ***");
#endif
	}

	memSize = 0;
	memSize += strlen(xbee->mode->name) + 1;
	for (i = 1; xbee_netServerCallbacks[i].callback; i++) {
		memSize += strlen(xbee_netServerCallbacks[i].name) + 1;
	}
	callbackCount = i;
	
	memSize += 1; /* for an 8 bit 'count' */
	memSize += 2; /* for the frameId, and return value */
	bufLen = memSize;
	
	memSize += sizeof(*iBuf);
	
	if ((iBuf = malloc(memSize)) == NULL) {
		/* out of memory */
		unsigned char buf[2];
		buf[0] = (*pkt)->frameId;
		buf[1] = 0x01; /* <-- this means intenal error */
		xbee_connTx(con, NULL, buf, sizeof(buf));
		return;
	}
	
	iBuf->len = bufLen;
	iBuf->data[0] = (*pkt)->frameId;
	iBuf->data[1] = 0x00; /* <-- success */
	o = 2;
	o += snprintf((char *)&(iBuf->data[o]), iBuf->len - o, "%s", xbee->mode->name) + 1;
	iBuf->data[o] = callbackCount - 1; o++; /* -1 cos we started at 1, not 0 */
	for (i = 1; i < callbackCount; i++) {
		o += snprintf((char *)&(iBuf->data[o]), iBuf->len - o, "%s", xbee_netServerCallbacks[i].name) + 1;
	}
	
	xbee_connTx(con, NULL, iBuf->data, iBuf->len);
	
	free(iBuf);

	client->started = 1;
}

void xbee_net_echo(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	xbee_connTx(con, NULL, (*pkt)->data, (*pkt)->dataLen);
}

/* ######################################################################### */

void xbee_net_conNew(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	xbee_err ret;
	unsigned char retVal;
	struct xbee_netClientInfo *client;
	struct xbee_conAddress address;
	struct xbee_con *nCon, *lCon, *tCon;
	int conIdentifier;
	struct xbee_modeConType *conType;
	char *conTypeName;
	int i, o;
	unsigned char buf[4];
	client = *data;
	if (!client->started) return;
	
	retVal = 0x01; /* <-- internal error */
	
	nCon = NULL;
	lCon = NULL;
	
	if ((*pkt)->dataLen != 1 + sizeof(address)) {
		retVal = 0x02; /* <-- request error */
		goto err;
	}
	
	conType = NULL;
	for (i = 0, o = 0; xbee->iface.conTypes[i].name; i++) {
		if (xbee->iface.conTypes[i].internal) continue;
		o++;
		if (o != (*pkt)->data[0]) continue;
		conType = &xbee->iface.conTypes[i];
		conTypeName = (char *)xbee->iface.conTypes[i].name;
		break;
	}
	if (!conType) {
		retVal = 0x02;
		goto err;
	}
	
	/* find a conIdentifier */
	conIdentifier = 0;
	for (tCon = NULL; xbee_ll_get_next(conType->conList, tCon, (void **)&tCon) == XBEE_ENONE && tCon; ) {
		if (tCon->conIdentifier == conIdentifier) {
			conIdentifier++;
			tCon = NULL;
			continue;
		}
	}
	if (conIdentifier > 0xFFFF) {
		retVal = 0x03;
		goto err;
	}
	
	/* create the local-side connection */
	memcpy(&address, &((*pkt)->data[1]), sizeof(address));
	if ((ret = xbee_conNew(xbee, &lCon, conTypeName, &address)) != XBEE_ENONE) goto err;
	lCon->conIdentifier = conIdentifier;
	lCon->netClient = client;
	xbee_ll_add_tail(client->conList, lCon);
	
	/* create the network-side connection */
	memset(&address, 0, sizeof(address));
	address.addr16_enabled = 1;
	address.addr16[0] = (lCon->conIdentifier >> 8) & 0xFF;
	address.addr16[1] = lCon->conIdentifier & 0xFF;
	
	if ((ret = _xbee_conNew(xbee, &client->iface, 0, &nCon, conTypeName, &address)) != XBEE_ENONE) goto err;
	nCon->netClient = client;
	
	xbee_conDataSet(lCon, nCon, NULL);
	xbee_conCallbackSet(lCon, xbee_net_toClient, NULL);
	
	xbee_conDataSet(nCon, lCon, NULL);
	xbee_conCallbackSet(nCon, xbee_net_fromClient, NULL);
	
	buf[0] = (*pkt)->frameId;
	buf[1] = 0x00;
	buf[2] = (lCon->conIdentifier >> 8) & 0xFF;
	buf[3] = lCon->conIdentifier & 0xFF;
	
	xbee_connTx(con, NULL, buf, sizeof(buf));
	
	return;
err:
	if (nCon) {
		xbee_conEnd(nCon);
	}
	if (lCon) {
		xbee_ll_ext_item(client->conList, lCon);
		xbee_conEnd(lCon);
	}
	{
		unsigned char buf[2];
		buf[0] = (*pkt)->frameId;
		buf[1] = retVal;
		xbee_connTx(con, NULL, buf, sizeof(buf));
	}
}

void xbee_net_conValidate(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	struct xbee_netClientInfo *client;
	unsigned char retVal;
	int conIdentifier;
	struct xbee_con *iCon;
	client = *data;
	if (!client->started) return;
	
	retVal = 0x02;
	
	if ((*pkt)->dataLen != 2) {
		goto err;
	}
	
	conIdentifier = 0;
	conIdentifier |= (((*pkt)->data[0]) << 8) & 0xFF;
	conIdentifier |= ((*pkt)->data[1]) & 0xFF;
	
	for (iCon = NULL; xbee_ll_get_next(client->conList, iCon, (void**)&iCon) == XBEE_ENONE && iCon; ) {
		if (iCon->conIdentifier == conIdentifier) {
			retVal = 0x00;
			break;
		}
	}
	
err:
	{
		unsigned char buf[2];
		buf[0] = (*pkt)->frameId;
		buf[1] = retVal;
		xbee_connTx(con, NULL, buf, sizeof(buf));
	}
}

/* ######################################################################### */

void xbee_net_conSleep(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	struct xbee_netClientInfo *client;
	unsigned char retVal;
	int conIdentifier;
	enum xbee_conSleepStates newSleep, oldSleep;
	struct xbee_con *iCon;
	unsigned char buf[3];
	client = *data;
	if (!client->started) return;
	
	retVal = 0x02;
	
	if ((*pkt)->dataLen < 2 || (*pkt)->dataLen > 3) {
		goto err;
	}
	
	conIdentifier = 0;
	conIdentifier |= (((*pkt)->data[0]) << 8) & 0xFF;
	conIdentifier |= ((*pkt)->data[1]) & 0xFF;
	if ((*pkt)->dataLen == 3) newSleep = (*pkt)->data[2];
	
	for (iCon = NULL; xbee_ll_get_next(con->conType->conList, iCon, (void**)&iCon) == XBEE_ENONE && iCon; ) {
		if (iCon->conIdentifier == conIdentifier) break;
	}
	if (!iCon) goto err;
	
	if (xbee_conSleepGet(iCon, &oldSleep) != XBEE_ENONE) goto err;
	if ((*pkt)->dataLen == 3 && xbee_conSleepSet(iCon, newSleep) != XBEE_ENONE) {
		retVal = 0x03; /* <-- failed to apply, old value present in reply */
	} else {
		retVal = 0x00;
	}
	
	buf[0] = (*pkt)->frameId;
	buf[1] = retVal;
	buf[2] = oldSleep & 0xFF;
	xbee_connTx(con, NULL, buf, sizeof(buf));
	
	return;
err:
	{
		unsigned char buf[2];
		buf[0] = (*pkt)->frameId;
		buf[1] = retVal;
		xbee_connTx(con, NULL, buf, sizeof(buf));
	}
}

/* ######################################################################### */

void xbee_net_conSettings(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	struct xbee_netClientInfo *client;
	unsigned char retVal;
	xbee_err ret;
	int conIdentifier;
	struct xbee_conSettings oldSettings;
	struct xbee_con *iCon;
	unsigned char buf[5];
	client = *data;
	if (!client->started) return;
	
	retVal = 0x02;
	
	if ((*pkt)->dataLen != 2 && (*pkt)->dataLen != 5) {
		goto err;
	}
	
	/* the following data should match the format found in
	    modes/net/support.c - xbee_netSupport_conSettings() */
	
	conIdentifier = 0;
	conIdentifier |= (((*pkt)->data[0]) << 8) & 0xFF;
	conIdentifier |= ((*pkt)->data[1]) & 0xFF;
	
	for (iCon = NULL; xbee_ll_get_next(con->conType->conList, iCon, (void**)&iCon) == XBEE_ENONE && iCon; ) {
		if (iCon->conIdentifier == conIdentifier) break;
	}
	if (!iCon) goto err;
	
	if ((*pkt)->dataLen == 5) {
		struct xbee_conSettings newSettings;
		
		memset(&newSettings, 0, sizeof(newSettings));
		if ((*pkt)->data[2] & 0x01) newSettings.noBlock = 1;
		if ((*pkt)->data[2] & 0x02) newSettings.catchAll = 1;
		if ((*pkt)->data[2] & 0x04) newSettings.queueChanges = 1;
		if ((*pkt)->data[2] & 0x08) newSettings.disableAck = 1;
		if ((*pkt)->data[2] & 0x10) newSettings.broadcast = 1;
		if ((*pkt)->data[2] & 0x20) newSettings.multicast = 1;
		if ((*pkt)->data[2] & 0x40) newSettings.disableRetries = 1;
		if ((*pkt)->data[3] & 0x80) newSettings.enableEncryption = 1;
		/* - */
		if ((*pkt)->data[3] & 0x01) newSettings.extendTimeout = 1;
		if ((*pkt)->data[3] & 0x02) newSettings.noRoute = 1;
		newSettings.broadcastRadius = (*pkt)->data[4];
		
		ret = xbee_conSettings(iCon, &newSettings, &oldSettings);
	} else {
		ret = xbee_conSettings(iCon, NULL,         &oldSettings);
	}
	
	if (ret != XBEE_ENONE) {
		retVal = 0x03;
	} else {
		retVal = 0x00;
	}
	
	buf[0] = (*pkt)->frameId;
	buf[1] = retVal;
	buf[2] = 0;
	if (iCon->settings.noBlock)          buf[2] |= 0x01;
	if (iCon->settings.catchAll)         buf[2] |= 0x02;
	if (iCon->settings.queueChanges)     buf[2] |= 0x04;
	if (iCon->settings.disableAck)       buf[2] |= 0x08;
	if (iCon->settings.broadcast)        buf[2] |= 0x10;
	if (iCon->settings.multicast)        buf[2] |= 0x20;
	if (iCon->settings.disableRetries)   buf[2] |= 0x40;
	if (iCon->settings.enableEncryption) buf[3] |= 0x80;
	buf[3] = 0;
	if (iCon->settings.extendTimeout)    buf[3] |= 0x01;
	if (iCon->settings.noRoute)          buf[3] |= 0x02;
	buf[4] = iCon->settings.broadcastRadius;
	xbee_connTx(con, NULL, buf, sizeof(buf));
	
	return;
err:
	{
		unsigned char buf[2];
		buf[0] = (*pkt)->frameId;
		buf[1] = retVal;
		xbee_connTx(con, NULL, buf, sizeof(buf));
	}
}

/* ######################################################################### */

void xbee_net_conEnd(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	struct xbee_netClientInfo *client;
	unsigned char retVal;
	int conIdentifier;
	struct xbee_con *iCon;
	client = *data;
	if (!client->started) return;
	
	retVal = 0x02;
	
	if ((*pkt)->dataLen != 2) {
		goto err;
	}
	
	conIdentifier = 0;
	conIdentifier |= (((*pkt)->data[0]) << 8) & 0xFF;
	conIdentifier |= ((*pkt)->data[1]) & 0xFF;
	
	for (iCon = NULL; xbee_ll_get_next(con->conType->conList, iCon, (void**)&iCon) == XBEE_ENONE && iCon; ) {
		if (iCon->conIdentifier == conIdentifier) {
			xbee_ll_ext_item(client->conList, iCon);
			xbee_conEnd(iCon);
			retVal = 0x00;
			break;
		}
	}
	
err:
	{
		unsigned char buf[2];
		buf[0] = (*pkt)->frameId;
		buf[1] = retVal;
		xbee_connTx(con, NULL, buf, sizeof(buf));
	}
}

/* ######################################################################### */

void xbee_net_conGetTypes(struct xbee *xbee, struct xbee_con *con, struct xbee_pkt **pkt, void **data) {
	struct xbee_netClientInfo *client;
	int typeCount;
	struct xbee_buf *iBuf;
	int i, o, p;
	size_t bufLen;
	size_t memSize;
	struct xbee_modeConType *conType;
	
	client = *data;
	
	if (!client->started) return;
	
	memSize = 0;
	typeCount = 0;
	for (i = 0; xbee->iface.conTypes[i].name; i++) {
		if (xbee->iface.conTypes[i].internal) continue;
		typeCount++;
		memSize += strlen(xbee->iface.conTypes[i].name) + 2; /* 1 for '\0', 1 for flags */
	}
	
	memSize += 1; /* for an 8 bit 'count' */
	memSize += 2; /* for the frameId and return value */
	bufLen = memSize;
	
	memSize += sizeof(*iBuf);
	
	if ((iBuf = malloc(memSize)) == NULL) goto err;
	
	iBuf->len = bufLen;
	iBuf->data[0] = (*pkt)->frameId;
	iBuf->data[1] = 0x00; /* <-- success */
	iBuf->data[2] = typeCount;
	for (i = 0, p = 0, o = 3; xbee->iface.conTypes[i].name && p < typeCount; i++) {
		/* this order of conTypes HAS to match up with the order in net.c xbee_netServerThread() */
		if (xbee->iface.conTypes[i].internal) continue;
		p++;
		conType = &(xbee->iface.conTypes[i]);
		iBuf->data[o] = 0;
		if (conType->allowFrameId) iBuf->data[o] |= 0x01;
		if (conType->rxHandler)    iBuf->data[o] |= 0x02;
		if (conType->txHandler)    iBuf->data[o] |= 0x04;
		o++;
		o += snprintf((char *)&(iBuf->data[o]), iBuf->len - o, "%s", conType->name) + 1;
	}
	
	xbee_connTx(con, NULL, iBuf->data, iBuf->len);
	
	free(iBuf);
	
	return;
err:
	{
		unsigned char buf[2];
		buf[0] = (*pkt)->frameId;
		buf[1] = 0x01; /* <-- this means intenal error */
		xbee_connTx(con, NULL, buf, 2);
	}
}

/* ######################################################################### */

#define ADD_NETSERVERCALLBACK(cb) { .name = #cb, .callback = xbee_net_##cb },
const struct xbee_netCallback xbee_netServerCallbacks[] = {
	/* backchannel (0x00), endpoint 0 (0x00) is ALWAYS the 'start' function */
	ADD_NETSERVERCALLBACK(start) /* this MUST BE FIRST */
	/* the rest may be ordered for efficiency...
	   e.g: tx is probrably going to be the most commonly called */
	ADD_NETSERVERCALLBACK(conValidate)
	ADD_NETSERVERCALLBACK(conSleep)
	ADD_NETSERVERCALLBACK(conSettings)
	ADD_NETSERVERCALLBACK(conNew)
	ADD_NETSERVERCALLBACK(conEnd)
	ADD_NETSERVERCALLBACK(conGetTypes)
	/* these are 'system' functions */
	ADD_NETSERVERCALLBACK(echo)
	/* terminate */
	{ NULL, NULL },
};

#endif /* XBEE_NO_NET_SERVER */
