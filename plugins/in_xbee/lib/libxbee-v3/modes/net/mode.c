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
#include <sys/socket.h>

#include "../../internal.h"
#include "../../xbee_int.h"
#include "../../log.h"
#include "../../net_io.h"
#include "../../mode.h"
#include "../../conn.h"
#include "../../frame.h"
#include "../../pkt.h"
#include "../../ll.h"
#include "mode.h"
#include "net.h"
#include "handlers.h"
#include "support.h"

static xbee_err init(struct xbee *xbee, va_list ap);
static xbee_err prepare(struct xbee *xbee);
static xbee_err mode_shutdown(struct xbee *xbee);

/* ######################################################################### */

static xbee_err init(struct xbee *xbee, va_list ap) {
	xbee_err ret;
	char *t;
	struct xbee_modeData *data;
	if (!xbee) return XBEE_EMISSINGPARAM;
	
	if ((data = malloc(sizeof(*data))) == NULL) return XBEE_ENOMEM;
	memset(data, 0, sizeof(*data));
	xbee->modeData = data;
	
	data->conList = xbee_ll_alloc();
	
	ret = XBEE_ENONE;
	
	/* get the hostname */
	t = va_arg(ap, char*);
	if ((data->netInfo.host = malloc(strlen(t) + 1)) == NULL) { ret = XBEE_ENOMEM; goto die; }
	strcpy(data->netInfo.host, t);
	
	/* get the port number */
	data->netInfo.port = va_arg(ap, int);
	
	/* setup the network interface */
	if ((ret = xbee_netSetup(&data->netInfo)) != XBEE_ENONE) goto die;
	
	return XBEE_ENONE;
die:
	mode_shutdown(xbee);
	return ret;
}

/* ######################################################################### */

static xbee_err prepare_backchannel(struct xbee *xbee) {
	xbee_err ret;
	struct xbee_modeData *data;
	unsigned char retVal;
	struct xbee_conAddress address;
	struct xbee_pkt *pkt;
	int callbackCount;
	int i, pos, slen;
	struct xbee_con *bc_start;
	
	data = xbee->modeData;
	pkt = NULL;
	
	/* create the 'start' backchannel connection - this is ALWAYS ON ENDPOINT 0x00 */
	memset(&address, 0, sizeof(address));
	address.endpoints_enabled = 1;
	address.endpoint_local = 0;
	address.endpoint_remote = 0;
	
	if ((ret = _xbee_conNew(xbee, &xbee->iface, 1, &bc_start, "backchannel", &address)) != XBEE_ENONE) return ret;
	
	/* transmit our libxbee_commit string - the git commit id */
	if ((ret = xbee_conTx(bc_start, &retVal, "%s", libxbee_commit)) != XBEE_ENONE) {
		switch (retVal) {
			case 1:
				xbee_log(0, "The server encountered an internal error");
				break;
			case 2:
				xbee_log(0, "The server is running a different version of libxbee");
				break;
			default:
				xbee_log(0, "Failed to initialize connection to server for an unknown reason...");
		}
		goto done;
	}
	
	/* grab the returned data (an in-order list of the back channel endpoints, starting at 0x01) */
	if ((ret = xbee_conRx(bc_start, &pkt, NULL)) != XBEE_ENONE) goto done;
	
	/* pick out the remote system's mode name, and try to locate it */
	for (i = 0; i < pkt->dataLen && pkt->data[i] != '\0'; i++);
	if (i > 0) {
		if ((data->serverModeName = malloc(sizeof(char) * (i + 1))) == NULL) {
			ret = XBEE_ENOMEM;
			goto done;
		}
		strncpy(data->serverModeName, (char*)pkt->data, i);
		data->serverModeName[i] = '\0';
		
		if (xbee_modeRetrieve(data->serverModeName, &data->serverMode) != XBEE_ENONE) {
			xbee_log(-10, "WARNING: remote mode '%s' is not avaliable on this system... Some packets may not be fully processed", data->serverModeName);
		}
	}
	
	callbackCount = pkt->data[i + 1];
	
	memset(&address, 0, sizeof(address));
	address.endpoints_enabled = 1;
	
	for (pos = i + 2, i = 1; pos < pkt->dataLen && i < callbackCount + 1; pos += slen + 1, i++) {
		char *name;
		struct xbee_con **retCon;
		
		name = (char *)&(pkt->data[pos]);
		slen = strnlen(name, pkt->dataLen - pos);
		
		/* check for a buffer overflow */
		if (slen > pkt->dataLen - pos) {
			slen = pkt->dataLen - pos;
			name[slen] = '\0';
		}
		
		retCon = NULL;
		
		/* try to match the string with an element in struct xbee_modeData */
#define TRY(conName)  if (!data->bc_##conName && !strncasecmp(name, #conName, slen))
		TRY (conValidate) {
			retCon = &data->bc_conValidate;
		} else TRY (conSleep) {
			retCon = &data->bc_conSleep;
		} else TRY (conSettings) {
			retCon = &data->bc_conSettings;
		} else TRY (conNew) {
			retCon = &data->bc_conNew;
		} else TRY (conEnd) {
			retCon = &data->bc_conEnd;
		} else TRY (conGetTypes) {
			retCon = &data->bc_conGetTypes;
		} else TRY (echo) {
			retCon = &data->bc_echo;
		}
#undef TRY

		/* if we dont know about that type, then continue - unlikely, but possible
		   e.g: if XBEE_NO_NET_STRICT_VERSIONS is set */
		if (!retCon) {
			xbee_log(-10, "WARNING: the remote system specified a support function that we don't know about! there may be dragons coming...");
			xbee_log(1, "  unknown function name: '%s'", name);
			continue;
		}
		
		/* setup the connection */
		address.endpoint_local = i;
		address.endpoint_remote = i;
		if ((ret = _xbee_conNew(xbee, &xbee->iface, 1, retCon, "backchannel", &address)) != XBEE_ENONE) goto done;
		
		/* add it to the conList */
		xbee_ll_add_tail(data->conList, *retCon);
		
		xbee_log(5, "registered support function '%s'", name);
	}
	
	/* check that we aren't missing any connections */
	if (data->bc_conValidate == NULL)  { ret = XBEE_EUNKNOWN; goto done; }
	if (data->bc_conSleep == NULL)     { ret = XBEE_EUNKNOWN; goto done; }
	if (data->bc_conSettings == NULL)  { ret = XBEE_EUNKNOWN; goto done; }
	if (data->bc_conNew == NULL)       { ret = XBEE_EUNKNOWN; goto done; }
	if (data->bc_conEnd == NULL)       { ret = XBEE_EUNKNOWN; goto done; }
	if (data->bc_conGetTypes == NULL)  { ret = XBEE_EUNKNOWN; goto done; }
	if (data->bc_echo == NULL)         { ret = XBEE_EUNKNOWN; goto done; }

	ret = XBEE_ENONE;
	
done:
	if (pkt) xbee_pktFree(pkt);
	xbee_conEnd(bc_start);
	return ret;
}

static xbee_err prepare_conTypes(struct xbee *xbee) {
	xbee_err ret;
	struct xbee_modeData *data;
	int typeCount;
	unsigned char retVal;
	struct xbee_pkt *pkt;
	int i, o, pos, slen;
	struct xbee_modeConType newConType;
	const struct xbee_modeConType *localVersion;
	
	char *mName;
	struct xbee_modeDataHandlerRx *rx;
	struct xbee_modeDataHandlerTx *tx;
	
	data = xbee->modeData;
	/* transmit our libxbee_commit string - the git commit id */
	if ((ret = xbee_connTx(data->bc_conGetTypes, &retVal, NULL, 0)) != XBEE_ENONE) {
		switch (retVal) {
			case 1:
				xbee_log(0, "The server encountered an internal error");
				break;
			default:
				xbee_log(0, "Failed to initialize connection to server for an unknown reason...");
		}
		return ret;
	}
	/* grab the returned data (an in-order list of the back channel endpoints, starting at 0x01) */
	if ((ret = xbee_conRx(data->bc_conGetTypes, &pkt, NULL)) != XBEE_ENONE) return ret;
	
	typeCount = pkt->data[0];
	
	ret = XBEE_ENONE;
	
	rx = NULL;
	tx = NULL;
	mName = NULL;
	
	for (pos = 1, i = 0; pos < pkt->dataLen && i < typeCount; pos += slen, i++) {
		char flags;
		char *name;
		
		flags = pkt->data[pos];
		pos++;
		name = (char *)&(pkt->data[pos]);
		slen = strnlen(name, pkt->dataLen - pos) + 1;
		
		/* can we use the frameId? */
		if (flags & 0x01) {
			memcpy(&newConType, &xbee_net_frontchannel_template_fid, sizeof(newConType));
		} else {
			memcpy(&newConType, &xbee_net_frontchannel_template    , sizeof(newConType));
		}
		
		localVersion = NULL;
		if (data->serverMode && data->serverMode->conTypes) {
			for (o = 0; data->serverMode->conTypes[o]->name; o++) {
				if (!strcasecmp(data->serverMode->conTypes[o]->name, name)) {
					localVersion = data->serverMode->conTypes[o];
					break;
				}
			}
		}
		
		/* can we receive? */
		if (flags & 0x02) {
			if ((rx = malloc(sizeof(*rx))) == NULL) { ret = XBEE_ENOMEM; break; }
			memset(rx, 0, sizeof(*rx));
			
			rx->identifier = i;
			rx->func = xbee_net_frontchannel_rx_func;
			
			/* pull in the post-processing function */
			if (localVersion) rx->funcPost = localVersion->rxHandler->funcPost;
			
			rx->needsFree = 1;
			
			newConType.rxHandler = rx;
		}
		
		/* can we transmit? */
		if (flags & 0x04) {
			if ((tx = malloc(sizeof(*tx))) == NULL) { ret = XBEE_ENOMEM; break; }
			memset(tx, 0, sizeof(*tx));
			
			tx->identifier = i;
			tx->func = xbee_net_frontchannel_tx_func;
			tx->needsFree = 1;
			
			newConType.txHandler = tx;
		}
		
		if ((mName = malloc(sizeof(*name) * (slen + 1))) == NULL) { ret = XBEE_ENOMEM; break; }
		strncpy(mName, name, slen);
		newConType.name = mName;
		newConType.nameNeedsFree = 1;
		
		if ((ret = xbee_modeAddConType(&xbee->iface.conTypes, &newConType)) != XBEE_ENONE) {
			if (rx) free(rx);
			rx = NULL;
			if (tx) free(tx);
			tx = NULL;
			if (mName) free(mName);
			mName = NULL;
			continue;
		}
		
		rx = NULL;
		tx = NULL;
		mName = NULL;
		
		xbee_log(3, "registered conType '%s' from server, identifier is 0x%02X", name, i);
	}
	
	xbee_pktFree(pkt);
	if (rx) free(rx);
	if (tx) free(tx);
	if (mName) free(mName);
	
	return ret;
}

static xbee_err prepare(struct xbee *xbee) {
	xbee_err ret;
	
	if (!xbee) return XBEE_EMISSINGPARAM;
	if (!xbee->mode || !xbee->modeData) return XBEE_EINVAL;
	
	if ((ret = prepare_backchannel(xbee)) != XBEE_ENONE) return ret;
	if ((ret = prepare_conTypes(xbee)) != XBEE_ENONE) return ret;
	
	return XBEE_ENONE;
}

/* ######################################################################### */

static xbee_err mode_shutdown(struct xbee *xbee) {
	struct xbee_modeData *data;
	
	if (!xbee) return XBEE_EMISSINGPARAM;
	if (!xbee->mode || !xbee->modeData) return XBEE_EINVAL;
	
	data = xbee->modeData;
	
	xbee_ll_free(data->conList, (void(*)(void*))xbee_conEnd);
	
	xbee->modeData = NULL; /* pull the rug */
	
	if (data->netInfo.f) xsys_fclose(data->netInfo.f);
	if (data->netInfo.fd != -1) {	
		shutdown(data->netInfo.fd, SHUT_RDWR);
		xsys_close(data->netInfo.fd);
	}
	if (data->netInfo.host) free(data->netInfo.host);
	if (data->netInfo.txBuf) {
		xbee_ll_ext_item(needsFree, data->netInfo.txBuf);
		free(data->netInfo.txBuf);
	}
	
	if (data->serverModeName) free(data->serverModeName);
	free(data);

	return XBEE_ENONE;
}

/* ######################################################################### */

static const struct xbee_modeConType *conTypes[] = {
	&xbee_net_backchannel,
	NULL,
};

const struct xbee_mode mode_net = {
	.name = "net",
	
	.conTypes = conTypes,
	
	.init = init,
	.prepare = prepare,
	.shutdown = mode_shutdown,
	
	.rx_io = xbee_netRx,
	.tx_io = xbee_netTx,
	
	.thread = NULL,
	
	.support = {
		.conNew = xbee_netSupport_conNew,
		.conValidate = xbee_netSupport_conValidate,
		.conSleepSet = xbee_netSupport_conSleepSet,
		.conSleepGet = xbee_netSupport_conSleepGet,
		.conSettings = xbee_netSupport_conSettings,
		.conEnd = xbee_netSupport_conEnd,
	},
};
