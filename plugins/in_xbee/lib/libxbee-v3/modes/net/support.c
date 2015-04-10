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
#include <stdarg.h>
#include <string.h>

#include "../../internal.h"
#include "../../xbee_int.h"
#include "../../mode.h"
#include "../../conn.h"
#include "../../log.h"
#include "mode.h"
#include "support.h"

static xbee_err getConTypeId(struct xbee_modeConType *conTypes, struct xbee_modeConType *conType, unsigned char *conTypeId) {
	int i;
	
	for (i = 0; conTypes[i].name; i++) {
		if (&conTypes[i] == conType) {
			if (i > 255) return XBEE_ERANGE;
			*conTypeId = i;
			return XBEE_ENONE;
		}
	}
	return XBEE_ENOTEXISTS;
}

/* ######################################################################### */

xbee_err xbee_netSupport_conNew(struct xbee *xbee, struct xbee_interface *interface, struct xbee_modeConType *conType, struct xbee_conAddress *address, int *conIdentifier) {
	xbee_err ret;
	unsigned char *buf;
	int len;
	unsigned char conTypeId;
	unsigned char txRet;
	struct xbee_pkt *pkt;
	struct xbee_modeData *data;
	if (!xbee) return XBEE_EMISSINGPARAM;
	if (!xbee->modeData) return XBEE_EINVAL;
	data = xbee->modeData;
	
	if (getConTypeId(xbee->iface.conTypes, conType, &conTypeId) != XBEE_ENONE) return XBEE_EINVAL;
	if (conTypeId == 0) return XBEE_ENONE; /* backchannel (0) is always successful */
	
	len = 1 + sizeof(*address);
	if ((buf = malloc(len)) == NULL) return XBEE_ENOMEM;
	memset(buf, 0, len);
	
	buf[0] = conTypeId;
	if (address) memcpy(&(buf[1]), address, sizeof(*address));
	
	xbee_connTx(data->bc_conNew, &txRet, buf, len);
	
	free(buf);
	
	if (xbee_conRx(data->bc_conNew, &pkt, NULL) != XBEE_ENONE || !pkt) return XBEE_EREMOTE;
	
	if (txRet == 0 && pkt->dataLen == 2) {
		int conId;
		conId = 0;
		conId |= (pkt->data[0] <<  8) & 0xFF00;
		conId |= (pkt->data[1]      ) & 0xFF;
		*conIdentifier = conId;
		ret = XBEE_ENONE;
	} else {
		ret = XBEE_EREMOTE;
	}
	
	xbee_pktFree(pkt);
	
	return ret;
}

xbee_err xbee_netSupport_conValidate(struct xbee_con *con) {
	unsigned char conTypeId;
	unsigned char buf[2];
	struct xbee_pkt *pkt;
	unsigned char txRet;
	struct xbee_modeData *data;
	if (!con) return XBEE_EMISSINGPARAM;
	if (!con->xbee || !con->xbee->modeData) return XBEE_EINVAL;
	data = con->xbee->modeData;
	if (getConTypeId(con->xbee->iface.conTypes, con->conType, &conTypeId) != XBEE_ENONE) return XBEE_EINVAL;
	if (conTypeId == 0) return XBEE_ENONE; /* backchannel (0) is always successful */
	if (con->conIdentifier == -1) return XBEE_ENONE; /* this indicates that it has been ended remotely */
	
	buf[0] = (con->conIdentifier >> 8) & 0xFF;
	buf[1] = con->conIdentifier & 0xFF;
	
	xbee_connTx(data->bc_conValidate, &txRet, buf, sizeof(buf));
	
	if (xbee_conRx(data->bc_conValidate, &pkt, NULL) != XBEE_ENONE || !pkt) return XBEE_EREMOTE;
	
	xbee_pktFree(pkt);
	
	if (txRet != 0) return XBEE_EREMOTE;
	return XBEE_ENONE;
}

xbee_err xbee_netSupport_conSleepSet(struct xbee_con *con, enum xbee_conSleepStates state) {
	xbee_err ret;
	unsigned char conTypeId;
	unsigned char buf[3];
	unsigned char txRet;
	struct xbee_pkt *pkt;
	struct xbee_modeData *data;
	if (!con) return XBEE_EMISSINGPARAM;
	if (!con->xbee || !con->xbee->modeData) return XBEE_EINVAL;
	data = con->xbee->modeData;
	if (getConTypeId(con->xbee->iface.conTypes, con->conType, &conTypeId) != XBEE_ENONE) return XBEE_EINVAL;
	if (conTypeId == 0) return XBEE_ENONE; /* backchannel (0) is always successful */
	if (con->conIdentifier == -1) return XBEE_EINVAL; /* this indicates that it has been ended remotely */
	
	buf[0] = (con->conIdentifier >> 8) & 0xFF;
	buf[1] = con->conIdentifier & 0xFF;
	buf[2] = state & 0xFF;
	
	xbee_connTx(data->bc_conSleep, &txRet, buf, sizeof(buf));
	
	if (xbee_conRx(data->bc_conSleep, &pkt, NULL) != XBEE_ENONE || !pkt) return XBEE_EREMOTE;
	
	if (txRet == 0 && pkt->dataLen == 1) {
		ret = XBEE_ENONE;
	} else {
		ret = XBEE_EREMOTE;
	}
	
	xbee_pktFree(pkt);
	
	return ret;
}

xbee_err xbee_netSupport_conSleepGet(struct xbee_con *con) {
	xbee_err ret;
	unsigned char conTypeId;
	unsigned char buf[2];
	unsigned char txRet;
	struct xbee_pkt *pkt;
	struct xbee_modeData *data;
	if (!con) return XBEE_EMISSINGPARAM;
	if (!con->xbee || !con->xbee->modeData) return XBEE_EINVAL;
	data = con->xbee->modeData;
	if (getConTypeId(con->xbee->iface.conTypes, con->conType, &conTypeId) != XBEE_ENONE) return XBEE_EINVAL;
	if (conTypeId == 0) return XBEE_ENONE; /* backchannel (0) is always successful */
	if (con->conIdentifier == -1) return XBEE_EINVAL; /* this indicates that it has been ended remotely */
	
	buf[0] = (con->conIdentifier >> 8) & 0xFF;
	buf[1] = con->conIdentifier & 0xFF;
	
	xbee_connTx(data->bc_conSleep, &txRet, buf, sizeof(buf));
	
	if (xbee_conRx(data->bc_conSleep, &pkt, NULL) != XBEE_ENONE || !pkt) return XBEE_EREMOTE;
	
	if (txRet == 0 && pkt->dataLen == 1) {
		con->sleepState = pkt->data[0];
		ret = XBEE_ENONE;
	} else {
		ret = XBEE_EREMOTE;
	}
	
	xbee_pktFree(pkt);
	
	return ret;
}

xbee_err xbee_netSupport_conSettings(struct xbee_con *con, struct xbee_conSettings *newSettings) {
	xbee_err ret;
	unsigned char conTypeId;
	unsigned char buf[5];
	unsigned char txRet;
	struct xbee_pkt *pkt;
	struct xbee_modeData *data;
	if (!con) return XBEE_EMISSINGPARAM;
	if (!con->xbee || !con->xbee->modeData) return XBEE_EINVAL;
	data = con->xbee->modeData;
	if (getConTypeId(con->xbee->iface.conTypes, con->conType, &conTypeId) != XBEE_ENONE) return XBEE_EINVAL;
	if (conTypeId == 0) return XBEE_ENONE; /* backchannel (0) is always successful */
	if (con->conIdentifier == -1) return XBEE_EINVAL; /* this indicates that it has been ended remotely */
	
	/* the following data should match the format found in
	    net_callback.sc - xbee_net_conSettings() */

	buf[0] = (con->conIdentifier >> 8) & 0xFF;
	buf[1] = con->conIdentifier & 0xFF;
	
	if (newSettings != NULL) {
		buf[2] = 0;
		if (newSettings->noBlock)          buf[2] |= 0x01;
		if (newSettings->catchAll)         buf[2] |= 0x02;
		if (newSettings->queueChanges)     buf[2] |= 0x04;
		if (newSettings->disableAck)       buf[2] |= 0x08;
		if (newSettings->broadcast)        buf[2] |= 0x10;
		if (newSettings->multicast)        buf[2] |= 0x20;
		if (newSettings->disableRetries)   buf[2] |= 0x40;
		if (newSettings->enableEncryption) buf[3] |= 0x80;
		/* - */
		buf[3] = 0;
		if (newSettings->extendTimeout)    buf[3] |= 0x01;
		if (newSettings->noRoute)          buf[3] |= 0x02;

		buf[4] = newSettings->broadcastRadius;
		
		xbee_connTx(data->bc_conSettings, &txRet, buf, sizeof(buf));
	} else {
		xbee_connTx(data->bc_conSettings, &txRet, buf, 2);
	}
	
	if (xbee_conRx(data->bc_conSettings, &pkt, NULL) != XBEE_ENONE || !pkt) return XBEE_EREMOTE;
	
	if (txRet == 0 && pkt->dataLen == 3) {
		con->settings.noBlock =          !!(pkt->data[0] & 0x01);
		con->settings.catchAll =         !!(pkt->data[0] & 0x02);
		con->settings.queueChanges =     !!(pkt->data[0] & 0x04);
		con->settings.disableAck =       !!(pkt->data[0] & 0x08);
		con->settings.broadcast =        !!(pkt->data[0] & 0x10);
		con->settings.multicast =        !!(pkt->data[0] & 0x20);
		con->settings.disableRetries =   !!(pkt->data[0] & 0x40);
		con->settings.enableEncryption = !!(pkt->data[1] & 0x80);
		/* - */
		con->settings.extendTimeout =    !!(pkt->data[1] & 0x01);
		con->settings.noRoute =          !!(pkt->data[1] & 0x02);

		con->settings.broadcastRadius = pkt->data[2];
		ret = XBEE_ENONE;
	} else {
		ret = XBEE_EREMOTE;
	}
	
	xbee_pktFree(pkt);
	
	return ret;
}

xbee_err xbee_netSupport_conEnd(struct xbee_con *con) {
	unsigned char conTypeId;
	unsigned char buf[2];
	struct xbee_pkt *pkt;
	unsigned char txRet;
	struct xbee_modeData *data;
	if (!con) return XBEE_EMISSINGPARAM;
	if (!con->xbee || !con->xbee->modeData) return XBEE_EINVAL;
	data = con->xbee->modeData;
	if (getConTypeId(con->xbee->iface.conTypes, con->conType, &conTypeId) != XBEE_ENONE) return XBEE_EINVAL;
	if (conTypeId == 0) return XBEE_ENONE; /* backchannel (0) is always successful */
	if (con->conIdentifier == -1) return XBEE_EINVAL; /* this indicates that it has been ended remotely */
	
	buf[0] = (con->conIdentifier >> 8) & 0xFF;
	buf[1] = con->conIdentifier & 0xFF;
	
	xbee_connTx(data->bc_conEnd, &txRet, buf, sizeof(buf));
	
	if (xbee_conRx(data->bc_conEnd, &pkt, NULL) != XBEE_ENONE || !pkt) return XBEE_EREMOTE;
	
	xbee_pktFree(pkt);
	
	if (txRet != 0) return XBEE_EREMOTE;
	
	con->conIdentifier = -1;
	
	return XBEE_ENONE;
}
